//! Bounded, cancellable reads of regular PCAP/PCAPNG files.
mod state;

use crate::decode::Packet;
use pcap_parser::{create_reader, traits::PcapReaderIterator, PcapError};
use state::CaptureState;
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

pub(crate) const MAX_PACKET_BYTES: usize = 256 * 1024;
const MAX_BLOCK_BYTES: usize = 1024 * 1024;

pub struct OfflineCapture {
    reader: Box<dyn PcapReaderIterator + Send>,
    state: CaptureState,
}

impl OfflineCapture {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let file = open_regular_file(path).map_err(|error| {
            io::Error::new(error.kind(), format!("{}: {error}", path.display()))
        })?;
        Self::from_reader(file)
    }

    fn from_reader(reader: impl Read + Send + 'static) -> io::Result<Self> {
        Ok(Self {
            // The parser needs one spare byte to distinguish a full buffer.
            reader: create_reader(MAX_BLOCK_BYTES + 1, reader).map_err(parse_error)?,
            state: CaptureState::default(),
        })
    }

    /// Returns `None` at EOF or when cancelled. Checks cancellation between
    /// metadata blocks as well as packets; the input buffer is never grown.
    pub fn next_packet(&mut self, stop: &AtomicBool) -> io::Result<Option<Packet>> {
        while !stop.load(Ordering::Relaxed) {
            self.state.validate_input(self.reader.data())?;
            match self.reader.next() {
                Ok((size, block)) => {
                    let packet = self.state.process(block)?;
                    self.reader.consume(size);
                    if packet.is_some() {
                        return Ok(packet);
                    }
                }
                Err(PcapError::Eof) => return Ok(None),
                Err(PcapError::Incomplete(_)) => {
                    self.reader.refill().map_err(parse_error)?;
                }
                Err(error) => return Err(parse_error(error)),
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;

fn open_regular_file(path: &Path) -> io::Result<File> {
    // Check the opened descriptor, not the path: a symlink/path replacement
    // must not turn validation into a blocking FIFO open (or reopen).
    #[cfg(unix)]
    let file = {
        use rustix::fs::{open, Mode, OFlags};
        File::from(open(
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
            Mode::empty(),
        )?)
    };
    #[cfg(not(unix))]
    let file = {
        if !path.metadata()?.is_file() {
            return Err(invalid("Capture input must be a regular file"));
        }
        File::open(path)?
    };
    if !file.metadata()?.is_file() {
        return Err(invalid("Capture input must be a regular file"));
    }
    Ok(file)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn parse_error<I>(error: PcapError<I>) -> io::Error {
    // Parser debug errors can contain the entire input buffer. Never render it.
    invalid(match error {
        PcapError::BufferTooSmall => "Capture block exceeds the 1 MiB reader limit",
        PcapError::UnexpectedEof | PcapError::Incomplete(_) | PcapError::Eof => {
            "Truncated capture header or block"
        }
        PcapError::ReadError => "Cannot read capture file",
        _ => "Invalid PCAP/PCAPNG header or block",
    })
}
