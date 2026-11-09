use crate::{
    decode::Packet,
    offline::{OfflineCapture, MAX_PACKET_BYTES},
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

// 64 batches × 256 KiB, plus at most one in-flight packet/batch per side.
const BATCH_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub enum SourceSpec {
    File(PathBuf),
    Live {
        interface: String,
        filter: String,
        snaplen: i32,
        promiscuous: bool,
    },
}

impl SourceSpec {
    pub fn label(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            Self::Live { interface, .. } => interface.clone(),
        }
    }
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Live { .. })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub packets: u64,
    pub bytes: u64,
    pub app_drops: u64,
    pub kernel_drops: Option<u32>,
    pub done: bool,
    pub error: Option<String>,
}

pub struct Worker {
    pub packets: Receiver<Vec<Packet>>,
    status: Arc<Mutex<Status>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn start(spec: SourceSpec) -> std::io::Result<Self> {
        let (tx, packets) = mpsc::sync_channel(64);
        let status = Arc::new(Mutex::new(Status::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::clone(&status);
        let cancelled = Arc::clone(&stop);
        let join = thread::Builder::new()
            .name("capture".into())
            .spawn(move || {
                let mut current = Status::default();
                if let Err(error) = capture(spec, tx, &cancelled, &shared, &mut current) {
                    current.error = Some(error.to_string());
                }
                current.done = true;
                *shared.lock().unwrap_or_else(|e| e.into_inner()) = current;
            })?;
        Ok(Self {
            packets,
            status,
            stop,
            join: Some(join),
        })
    }
    pub fn status(&self) -> Status {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

enum Handle {
    Live(pcap::Capture<pcap::Active>),
    File(OfflineCapture),
}

enum ReadEvent {
    Packet(Packet),
    Dropped(u32),
    Idle,
    Eof,
}

impl Handle {
    fn next(
        &mut self,
        id: u64,
        stop: &AtomicBool,
    ) -> Result<ReadEvent, Box<dyn std::error::Error>> {
        match self {
            Self::File(capture) => Ok(capture
                .next_packet(stop)?
                .map_or(ReadEvent::Eof, ReadEvent::Packet)),
            Self::Live(capture) => {
                let link = capture.get_datalink().0;
                match capture.next_packet() {
                    Ok(packet) if packet.data.len() > MAX_PACKET_BYTES => {
                        Ok(ReadEvent::Dropped(packet.header.len))
                    }
                    Ok(packet) => Ok(ReadEvent::Packet(Packet::new(
                        id,
                        i128::from(packet.header.ts.tv_sec) * 1_000_000_000
                            + i128::from(packet.header.ts.tv_usec) * 1000,
                        packet.header.len,
                        link,
                        packet.data.into(),
                    ))),
                    Err(pcap::Error::TimeoutExpired) => Ok(ReadEvent::Idle),
                    Err(pcap::Error::NoMorePackets) => Ok(ReadEvent::Eof),
                    Err(error) => Err(error.into()),
                }
            }
        }
    }
}

fn capture(
    spec: SourceSpec,
    tx: SyncSender<Vec<Packet>>,
    stop: &AtomicBool,
    shared: &Mutex<Status>,
    status: &mut Status,
) -> Result<(), Box<dyn std::error::Error>> {
    let live = spec.is_live();
    let mut handle = match spec {
        SourceSpec::File(path) => Handle::File(OfflineCapture::open(path)?),
        SourceSpec::Live {
            interface,
            filter,
            snaplen,
            promiscuous,
        } => {
            let mut capture = pcap::Capture::from_device(interface.as_str())?
                .promisc(promiscuous)
                .snaplen(snaplen)
                .buffer_size(4 * 1024 * 1024)
                .timeout(20)
                .open()?
                .setnonblock()?;
            if !filter.trim().is_empty() {
                capture.filter(&filter, true)?;
            }
            Handle::Live(capture)
        }
    };
    let mut batch = Vec::with_capacity(256);
    let mut batch_bytes = 0;
    let mut last_flush = Instant::now();
    let mut last_stats = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let mut idle = false;
        let mut eof = false;
        match handle.next(status.packets + 1, stop) {
            Ok(ReadEvent::Packet(packet)) => {
                status.packets += 1;
                status.bytes += u64::from(packet.wire_len);
                if batch_bytes + packet.memory_size() > BATCH_BYTES && !batch.is_empty() {
                    if !send_batch(&tx, std::mem::take(&mut batch), live, stop, status) {
                        break;
                    }
                    batch_bytes = 0;
                }
                batch_bytes += packet.memory_size();
                batch.push(packet);
            }
            Ok(ReadEvent::Dropped(wire_len)) => {
                status.packets += 1;
                status.bytes += u64::from(wire_len);
                status.app_drops += 1;
            }
            Ok(ReadEvent::Idle) => idle = true,
            Ok(ReadEvent::Eof) => eof = true,
            Err(error) => {
                status.error = Some(error.to_string());
                *shared.lock().unwrap_or_else(|e| e.into_inner()) = status.clone();
                if !batch.is_empty() {
                    send_batch(&tx, std::mem::take(&mut batch), live, stop, status);
                }
                return Err(error);
            }
        }
        if batch.len() >= 256
            || batch_bytes >= BATCH_BYTES
            || last_flush.elapsed() >= Duration::from_millis(16)
            || eof
        {
            if !batch.is_empty() && !send_batch(&tx, std::mem::take(&mut batch), live, stop, status)
            {
                break;
            }
            batch_bytes = 0;
            last_flush = Instant::now();
            *shared.lock().unwrap_or_else(|e| e.into_inner()) = status.clone();
        }
        if live && last_stats.elapsed() >= Duration::from_millis(500) {
            if let Handle::Live(capture) = &mut handle {
                status.kernel_drops = capture.stats().ok().map(|s| s.dropped);
            }
            last_stats = Instant::now();
        }
        if eof {
            break;
        }
        if idle {
            thread::sleep(Duration::from_millis(2));
        }
    }
    if !batch.is_empty() {
        send_batch(&tx, batch, live, stop, status);
    }
    Ok(())
}

fn send_batch(
    tx: &SyncSender<Vec<Packet>>,
    mut batch: Vec<Packet>,
    live: bool,
    stop: &AtomicBool,
    status: &mut Status,
) -> bool {
    loop {
        match tx.try_send(batch) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(returned)) => {
                if live {
                    status.app_drops += returned.len() as u64;
                    return true;
                }
                if stop.load(Ordering::Relaxed) {
                    return false;
                }
                batch = returned;
                thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn live_queue_overload_is_counted() {
        let (tx, _rx) = mpsc::sync_channel(1);
        tx.try_send(Vec::new()).unwrap();
        let packet = Packet::new(1, 0, 1, 999, vec![0].into_boxed_slice());
        let mut status = Status::default();
        assert!(send_batch(
            &tx,
            vec![packet],
            true,
            &AtomicBool::new(false),
            &mut status
        ));
        assert_eq!(status.app_drops, 1);
    }
    #[test]
    fn offline_backpressure_can_be_cancelled() {
        let (tx, _rx) = mpsc::sync_channel(1);
        tx.try_send(Vec::new()).unwrap();
        assert!(!send_batch(
            &tx,
            Vec::new(),
            false,
            &AtomicBool::new(true),
            &mut Status::default()
        ));
    }
}
