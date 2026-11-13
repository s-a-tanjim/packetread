//! Capture worker thread. Saved files are read in-process; live traffic comes
//! from the privileged `packetread-capture` helper, so this process never
//! opens a capture device. The worker also runs the stateful analyzer, saves
//! live traffic to (optionally rotating) capture files and enforces stop limits.
use crate::{
    analysis::Analyzer,
    decode::Packet,
    export::Writer,
    filter::Filter,
    helper::{Frame, HELPER_ENV, HELPER_NAME},
    offline::{OfflineCapture, MAX_PACKET_BYTES},
    tls::KeyLog,
};
use std::{
    collections::VecDeque,
    fs::File,
    io::{self, BufReader, BufWriter, Read},
    path::PathBuf,
    process::{Child, ChildStdout, Command, Stdio},
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
    Live(LiveSpec),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveSpec {
    pub interfaces: Vec<String>,
    pub filter: String,
    pub snaplen: u32,
    pub promiscuous: bool,
    pub output: Option<Output>,
    pub limits: Limits,
    /// Capture on this SSH host (with its tcpdump) instead of locally.
    pub remote: Option<String>,
}

/// Environment variable naming the SSH client for remote capture.
pub const SSH_ENV: &str = "PACKETREAD_SSH";

/// Starts `tcpdump` on `host` over SSH; its output is a PCAP stream.
/// Authentication must not need a prompt (keys or an agent).
fn spawn_remote(
    spec: &LiveSpec,
    host: &str,
    slot: &Mutex<Option<Child>>,
) -> io::Result<OfflineCapture> {
    let invalid = |message: &str| io::Error::new(io::ErrorKind::InvalidInput, message);
    // The host is an argument to ssh: it must not look like an option.
    if host.is_empty() || host.starts_with('-') || host.chars().any(char::is_whitespace) {
        return Err(invalid("Invalid remote host"));
    }
    let [interface] = spec.interfaces.as_slice() else {
        return Err(invalid("Remote capture takes exactly one interface"));
    };
    // ssh hands the command to the remote shell: quote every value.
    let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
    let mut command = format!(
        "tcpdump -U -n -w - -s {} -i {}",
        spec.snaplen,
        quote(interface)
    );
    if !spec.promiscuous {
        command += " -p";
    }
    if !spec.filter.trim().is_empty() {
        command += &format!(" {}", quote(&spec.filter));
    }
    let program = std::env::var_os(SSH_ENV).unwrap_or_else(|| "ssh".into());
    let mut child = Command::new(program)
        .args(["-o", "BatchMode=yes", "--", host, &command])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| io::Error::new(error.kind(), format!("Cannot start ssh: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("ssh has no output"))?;
    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
    OfflineCapture::from_reader(stdout).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("Remote capture on {host} produced no capture stream ({error}); check SSH access and that tcpdump may capture there"),
        )
    })
}

impl Default for LiveSpec {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            filter: String::new(),
            snaplen: 65_535,
            promiscuous: false,
            output: None,
            limits: Limits::default(),
            remote: None,
        }
    }
}

/// Where live traffic is saved. With any rotation setting the files are
/// named `stem_00001.ext`, `stem_00002.ext`, …
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub path: PathBuf,
    pub rotate_bytes: Option<u64>,
    pub rotate_seconds: Option<u64>,
    /// Keep only the newest files (a ring buffer).
    pub keep_files: Option<usize>,
}

/// Conditions that end a live capture automatically.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    pub seconds: Option<u64>,
    pub packets: Option<u64>,
    pub bytes: Option<u64>,
}

/// Where delivery starts: packets before `from`, and before the first match
/// of `find`, are read (keeping analysis state exact) but not delivered.
#[derive(Clone, Debug, Default)]
pub struct Seek {
    pub from: u64,
    pub find: Option<Filter>,
    /// Secrets for decrypting TLS while packets are analyzed.
    pub keylog: Option<Arc<KeyLog>>,
}

impl SourceSpec {
    pub fn label(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            Self::Live(spec) => match &spec.remote {
                Some(host) => format!("{host}:{}", spec.interfaces.join("+")),
                None => spec.interfaces.join("+"),
            },
        }
    }
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Live(_))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub packets: u64,
    pub bytes: u64,
    pub app_drops: u64,
    pub kernel_drops: Option<u32>,
    /// Packets saved to the capture file(s).
    pub saved: u64,
    pub limit_reached: bool,
    pub done: bool,
    pub error: Option<String>,
    /// The live capture could not be opened for lack of `CAP_NET_RAW`.
    pub permission_denied: bool,
}

pub struct Worker {
    /// Capture completion and errors are published before this channel disconnects.
    pub packets: Receiver<Vec<Packet>>,
    status: Arc<Mutex<Status>>,
    stop: Arc<AtomicBool>,
    helper: Arc<Mutex<Option<Child>>>,
    join: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn start(spec: SourceSpec, seek: Seek) -> io::Result<Self> {
        let (tx, packets) = mpsc::sync_channel(64);
        let status = Arc::new(Mutex::new(Status::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let helper = Arc::new(Mutex::new(None));
        let (shared, cancelled, child) =
            (Arc::clone(&status), Arc::clone(&stop), Arc::clone(&helper));
        let join = thread::Builder::new()
            .name("capture".into())
            .spawn(move || run_worker(spec, seek, tx, &cancelled, &shared, &child))?;
        Ok(Self {
            packets,
            status,
            stop,
            helper,
            join: Some(join),
        })
    }
    pub fn status(&self) -> Status {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    /// Cancels the worker. Killing the helper also ends a blocked read.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(child) = self
            .helper
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            let _ = child.kill();
        }
    }
}

fn run_worker(
    spec: SourceSpec,
    seek: Seek,
    tx: SyncSender<Vec<Packet>>,
    stop: &AtomicBool,
    shared: &Mutex<Status>,
    helper: &Mutex<Option<Child>>,
) {
    let mut current = Status::default();
    if let Err(error) = capture(spec, seek, &tx, stop, shared, helper, &mut current) {
        current.error = Some(error.to_string());
    }
    if let Some(mut child) = helper.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    current.done = true;
    *shared.lock().unwrap_or_else(|e| e.into_inner()) = current;
    // Receivers use disconnection as completion, so publish before waking them.
    drop(tx);
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Location of the capture helper: `PACKETREAD_CAPTURE_HELPER`, or next to
/// the running executable.
pub fn helper_path() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os(HELPER_ENV) {
        return Ok(path.into());
    }
    let path = std::env::current_exe()?.with_file_name(HELPER_NAME);
    if path.is_file() {
        Ok(path)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "capture helper not found at {} (install {HELPER_NAME} next to packetread)",
                path.display()
            ),
        ))
    }
}

/// Capture interfaces as (name, description), listed by the helper.
pub fn interfaces() -> io::Result<Vec<(String, String)>> {
    let mut child = Command::new(helper_path()?)
        .arg("--list")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut text = String::new();
    if let Some(stdout) = child.stdout.take() {
        stdout.take(1024 * 1024).read_to_string(&mut text)?;
    }
    if !child.wait()?.success() {
        return Err(io::Error::other(
            "the capture helper could not list interfaces",
        ));
    }
    Ok(text
        .lines()
        .map(|line| line.split_once('\t').unwrap_or((line, "")))
        .map(|(name, description)| (name.to_string(), description.to_string()))
        .collect())
}

fn spawn_helper(
    spec: &LiveSpec,
    slot: &Mutex<Option<Child>>,
) -> io::Result<BufReader<ChildStdout>> {
    let mut command = Command::new(helper_path()?);
    for interface in &spec.interfaces {
        command.arg("-i").arg(interface);
    }
    command.arg("--snaplen").arg(spec.snaplen.to_string());
    if !spec.filter.trim().is_empty() {
        command.arg("--filter").arg(&spec.filter);
    }
    if spec.promiscuous {
        command.arg("--promiscuous");
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("capture helper has no output"))?;
    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
    Ok(BufReader::new(stdout))
}

/// Saves live packets, rotating files by size or age.
struct Recorder {
    output: Output,
    writer: Option<Writer<BufWriter<File>>>,
    opened: Instant,
    index: u32,
    files: VecDeque<PathBuf>,
    saved: u64,
}

impl Recorder {
    fn new(output: Output) -> Self {
        Self {
            output,
            writer: None,
            opened: Instant::now(),
            index: 0,
            files: VecDeque::new(),
            saved: 0,
        }
    }

    fn write(&mut self, packet: &Packet) -> io::Result<()> {
        let full = self.writer.as_ref().is_some_and(|writer| {
            let (bytes, seconds) = (self.output.rotate_bytes, self.output.rotate_seconds);
            bytes.is_some_and(|limit| writer.bytes >= limit)
                || seconds.is_some_and(|limit| self.opened.elapsed().as_secs() >= limit)
        });
        if full {
            self.finish()?;
        }
        if self.writer.is_none() {
            let output = &self.output;
            let rotating = output.rotate_bytes.is_some()
                || output.rotate_seconds.is_some()
                || output.keep_files.is_some();
            self.index += 1;
            let path = if rotating {
                let stem = output
                    .path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy();
                let extension = output
                    .path
                    .extension()
                    .unwrap_or_default()
                    .to_string_lossy();
                output
                    .path
                    .with_file_name(format!("{stem}_{:05}.{extension}", self.index))
            } else {
                output.path.clone()
            };
            self.writer = Some(Writer::create(&path)?);
            self.opened = Instant::now();
            self.files.push_back(path);
            while output
                .keep_files
                .is_some_and(|keep| self.files.len() > keep.max(1))
            {
                if let Some(oldest) = self.files.pop_front() {
                    std::fs::remove_file(oldest)?;
                }
            }
        }
        if let Some(writer) = &mut self.writer {
            writer.write(packet)?;
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        if let Some(writer) = self.writer.take() {
            self.saved += writer.finish()?.written;
        }
        Ok(())
    }
}

enum Handle {
    Live(BufReader<ChildStdout>),
    File(OfflineCapture),
    Remote(Box<OfflineCapture>),
}

enum ReadEvent {
    Packet(Box<Packet>),
    Idle,
    Eof,
}

impl Handle {
    fn next(
        &mut self,
        id: u64,
        stop: &AtomicBool,
        status: &mut Status,
    ) -> Result<ReadEvent, Box<dyn std::error::Error>> {
        match self {
            Self::File(capture) => Ok(capture
                .next_packet(stop)?
                .map_or(ReadEvent::Eof, |packet| ReadEvent::Packet(Box::new(packet)))),
            // ponytail: reads block while the remote link is idle, so time
            // limits are only checked when a packet arrives.
            Self::Remote(capture) => match capture.next_packet(stop) {
                Ok(Some(mut packet)) => {
                    packet.id = id;
                    Ok(ReadEvent::Packet(Box::new(packet)))
                }
                // Stopping kills ssh, which ends the stream mid-packet.
                Ok(None) | Err(_) if stop.load(Ordering::Relaxed) => Ok(ReadEvent::Eof),
                Ok(None) => Err("The remote capture ended".into()),
                Err(error) => Err(error.into()),
            },
            Self::Live(helper) => match Frame::read(helper) {
                Ok(Some(Frame::Packet {
                    link,
                    timestamp_ns,
                    wire_len,
                    data,
                })) if data.len() <= MAX_PACKET_BYTES => Ok(ReadEvent::Packet(Box::new(
                    Packet::new(id, i128::from(timestamp_ns), wire_len, link, data.into()),
                ))),
                Ok(Some(Frame::Packet { .. })) => {
                    Err("Capture helper sent an oversized packet".into())
                }
                Ok(Some(Frame::Stats { dropped })) => {
                    status.kernel_drops = Some(dropped);
                    Ok(ReadEvent::Idle)
                }
                Ok(Some(Frame::Tick)) => Ok(ReadEvent::Idle),
                Ok(Some(Frame::Error(message))) => {
                    // libpcap reports a missing capability only as text.
                    status.permission_denied = ["CAP_NET_RAW", "permission", "not permitted"]
                        .iter()
                        .any(|hint| message.contains(hint));
                    Err(message.into())
                }
                // A killed helper ends the stream mid-frame; that is not an error.
                Ok(None) | Err(_) if stop.load(Ordering::Relaxed) => Ok(ReadEvent::Eof),
                Ok(None) => Err("The capture helper exited unexpectedly".into()),
                Err(error) => Err(error.into()),
            },
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn capture(
    spec: SourceSpec,
    seek: Seek,
    tx: &SyncSender<Vec<Packet>>,
    stop: &AtomicBool,
    shared: &Mutex<Status>,
    helper: &Mutex<Option<Child>>,
    status: &mut Status,
) -> Result<(), Box<dyn std::error::Error>> {
    let live = spec.is_live();
    let (mut handle, mut recorder, limits) = match spec {
        SourceSpec::File(path) => (
            Handle::File(OfflineCapture::open(path)?),
            None,
            Limits::default(),
        ),
        SourceSpec::Live(spec) => (
            match &spec.remote {
                Some(host) => Handle::Remote(Box::new(spawn_remote(&spec, host, helper)?)),
                None => Handle::Live(spawn_helper(&spec, helper)?),
            },
            spec.output.clone().map(Recorder::new),
            spec.limits,
        ),
    };
    let mut analyzer = Analyzer::new(seek.keylog.clone());
    let mut skipping = seek.from > 1 || seek.find.is_some();
    let started = Instant::now();
    let mut batch = Vec::with_capacity(256);
    let mut batch_bytes = 0;
    let mut last_flush = Instant::now();
    let mut result = Ok(());
    while !stop.load(Ordering::Relaxed) {
        let mut eof = false;
        match handle.next(status.packets + 1, stop, status) {
            Ok(ReadEvent::Packet(packet)) => {
                let mut packet = *packet;
                status.packets += 1;
                status.bytes += u64::from(packet.wire_len);
                analyzer.observe(&mut packet);
                if let Some(recorder) = &mut recorder {
                    if let Err(error) = recorder.write(&packet) {
                        result = Err(error.into());
                        break;
                    }
                }
                skipping = skipping
                    && (packet.id < seek.from
                        || seek
                            .find
                            .as_ref()
                            .is_some_and(|find| !find.matches(&packet)));
                if !skipping {
                    if batch_bytes + packet.memory_size() > BATCH_BYTES && !batch.is_empty() {
                        if !send_batch(tx, std::mem::take(&mut batch), live, stop, status) {
                            break;
                        }
                        batch_bytes = 0;
                    }
                    batch_bytes += packet.memory_size();
                    batch.push(packet);
                }
            }
            Ok(ReadEvent::Idle) => {}
            Ok(ReadEvent::Eof) => eof = true,
            Err(error) => {
                status.error = Some(error.to_string());
                *shared.lock().unwrap_or_else(|e| e.into_inner()) = status.clone();
                result = Err(error);
                break;
            }
        }
        status.limit_reached = limits.packets.is_some_and(|limit| status.packets >= limit)
            || limits.bytes.is_some_and(|limit| status.bytes >= limit)
            || limits
                .seconds
                .is_some_and(|limit| started.elapsed().as_secs() >= limit);
        let finished = eof || status.limit_reached;
        if batch.len() >= 256
            || batch_bytes >= BATCH_BYTES
            || last_flush.elapsed() >= Duration::from_millis(16)
            || finished
        {
            if !batch.is_empty() && !send_batch(tx, std::mem::take(&mut batch), live, stop, status)
            {
                break;
            }
            batch_bytes = 0;
            last_flush = Instant::now();
            status.saved = recorder
                .as_ref()
                .map_or(0, |r| r.saved + r.writer.as_ref().map_or(0, |w| w.written));
            *shared.lock().unwrap_or_else(|e| e.into_inner()) = status.clone();
        }
        if finished {
            break;
        }
    }
    if !batch.is_empty() {
        send_batch(tx, batch, live, stop, status);
    }
    if let Some(mut recorder) = recorder {
        let finished = recorder.finish();
        status.saved = recorder.saved;
        if result.is_ok() {
            finished?;
        }
    }
    result
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
    fn failed_worker_publishes_error_before_closing_packet_channel() {
        let temp = tempfile::tempdir().unwrap();
        let spec = SourceSpec::File(temp.path().join("missing.pcap"));
        let (tx, rx) = mpsc::sync_channel(64);
        let shared = Arc::new(Mutex::new(Status::default()));
        // Delay publication to expose the ordering regardless of CPU scheduling.
        let unpublished = shared.lock().unwrap();
        let worker_status = Arc::clone(&shared);
        let worker = thread::spawn(move || {
            run_worker(
                spec,
                Seek::default(),
                tx,
                &AtomicBool::new(false),
                &worker_status,
                &Mutex::new(None),
            );
        });

        let before_publication = rx.recv_timeout(Duration::from_millis(100));
        drop(unpublished);
        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(3)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
        worker.join().unwrap();
        assert!(
            matches!(before_publication, Err(mpsc::RecvTimeoutError::Timeout)),
            "packet channel closed before the final error could be published: {before_publication:?}"
        );
        let status = shared.lock().unwrap();
        assert!(status.done);
        assert!(status.error.as_deref().unwrap().contains("missing.pcap"));
        assert_eq!(status.packets, 0);
    }

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
