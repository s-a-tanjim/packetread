//! Moves packets from the capture worker into the session on the UI thread.
//!
//! Retention policy by source kind is decided here: a live capture keeps
//! inserting and lets the session evict its oldest packets, while a file
//! pauses when the session is full until `next_window` is requested. (The
//! worker's side of the same split is in `source.rs`: drop batches when live,
//! block when reading a file.)
use crate::{
    decode::Packet,
    session::Session,
    source::{Seek, SourceSpec, Status, Worker},
};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

const HISTORY: usize = 60;

pub struct Ingest {
    worker: Option<Worker>,
    pending: VecDeque<Packet>,
    live: bool,
    pub status: Status,
    pub window_full: bool,
    pub packet_rate: u64,
    pub byte_rate: u64,
    pub packet_history: VecDeque<u64>,
    pub byte_history: VecDeque<u64>,
    rate_time: Instant,
    rate_packets: u64,
    rate_bytes: u64,
}

impl Default for Ingest {
    fn default() -> Self {
        Self {
            worker: None,
            pending: VecDeque::new(),
            live: false,
            status: Status::default(),
            window_full: false,
            packet_rate: 0,
            byte_rate: 0,
            packet_history: VecDeque::from(vec![0; HISTORY]),
            byte_history: VecDeque::from(vec![0; HISTORY]),
            rate_time: Instant::now(),
            rate_packets: 0,
            rate_bytes: 0,
        }
    }
}

impl Ingest {
    pub fn start(spec: SourceSpec, seek: Seek) -> std::io::Result<Self> {
        Ok(Self {
            live: spec.is_live(),
            worker: Some(Worker::start(spec, seek)?),
            ..Self::default()
        })
    }

    pub fn has_worker(&self) -> bool {
        self.worker.is_some()
    }

    /// Asks the worker to stop; already queued packets are still delivered.
    pub fn stop(&self) {
        if let Some(worker) = &self.worker {
            worker.stop();
        }
    }

    /// Cancels the worker and discards anything not yet in the session.
    pub fn detach(&mut self) {
        self.worker.take();
        self.pending.clear();
        self.status.done = true;
    }

    /// Starts the next file window. Returns false unless the window was full.
    pub fn next_window(&mut self, session: &mut Session) -> bool {
        if self.window_full {
            session.next_window();
            self.window_full = false;
            return true;
        }
        false
    }

    /// Ingests for at most `budget`. Returns true when the rates were updated.
    pub fn tick(&mut self, session: &mut Session, budget: Duration) -> bool {
        let started = Instant::now();
        if let Some(worker) = &self.worker {
            self.status = worker.status();
            while !self.window_full && started.elapsed() < budget {
                if self.pending.is_empty() {
                    match worker.packets.try_recv() {
                        Ok(batch) => self.pending = batch.into(),
                        Err(_) => break,
                    }
                }
                let Some(packet) = self.pending.front() else {
                    break;
                };
                if !self.live && !session.has_room(packet) {
                    self.window_full = true;
                    break;
                }
                if let Some(packet) = self.pending.pop_front() {
                    session.insert(packet);
                }
            }
        }
        let elapsed = self.rate_time.elapsed().as_secs_f64();
        if elapsed < 1.0 {
            return false;
        }
        self.packet_rate =
            (self.status.packets.saturating_sub(self.rate_packets) as f64 / elapsed) as u64;
        self.byte_rate =
            (self.status.bytes.saturating_sub(self.rate_bytes) as f64 / elapsed) as u64;
        self.packet_history.pop_front();
        self.packet_history.push_back(self.packet_rate);
        self.byte_history.pop_front();
        self.byte_history.push_back(self.byte_rate);
        self.rate_packets = self.status.packets;
        self.rate_bytes = self.status.bytes;
        self.rate_time = Instant::now();
        true
    }
}
