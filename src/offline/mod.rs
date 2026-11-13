//! Bounded, cancellable reads of PCAP and PCAPNG captures, also gzip
//! compressed, and of snoop (RFC 1761) Ethernet captures.
mod state;

pub use state::Metadata;

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
    /// Opens a regular file, or standard input when `path` is `-`.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        if path == Path::new("-") {
            return Self::from_reader(io::stdin());
        }
        let file = open_regular_file(path).map_err(|error| {
            io::Error::new(error.kind(), format!("{}: {error}", path.display()))
        })?;
        Self::from_reader(file)
    }

    /// Reads a capture stream, such as a pipe from a remote capture.
    pub fn from_reader(reader: impl Read + Send + 'static) -> io::Result<Self> {
        let reader = sniff(Box::new(reader), true)?;
        Ok(Self {
            // The parser needs one spare byte to distinguish a full buffer.
            reader: create_reader(MAX_BLOCK_BYTES + 1, reader).map_err(parse_error)?,
            state: CaptureState::default(),
        })
    }

    /// PCAPNG section, interface and name-resolution metadata read so far.
    pub fn metadata(&self) -> &Metadata {
        &self.state.metadata
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

/// Reads until `buffer` is full or the input ends; returns the bytes read.
fn read_full(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Unwraps gzip compression and converts snoop captures, by magic number.
/// Decompression is streamed, so its output is bounded like any other input.
fn sniff(mut reader: Box<dyn Read + Send>, outer: bool) -> io::Result<Box<dyn Read + Send>> {
    let mut head = [0u8; 8];
    let filled = read_full(&mut reader, &mut head)?;
    let head = &head[..filled];
    let rest = Prefixed {
        head: head.to_vec(),
        at: 0,
        inner: reader,
    };
    if head.starts_with(&[0x1f, 0x8b]) && outer {
        sniff(Box::new(flate2::read::MultiGzDecoder::new(rest)), false)
    } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Err(invalid(
            "Zstandard-compressed capture: decompress it first (gzip is read directly)",
        ))
    } else if head == b"snoop\0\0\0" {
        Ok(Box::new(Snoop::new(rest)?))
    } else {
        Ok(Box::new(rest))
    }
}

/// `head` followed by `inner`. Unlike `Read::chain`, one read may span
/// both, so the capture parser sees a whole header on its first read.
struct Prefixed<R> {
    head: Vec<u8>,
    at: usize,
    inner: R,
}

impl<R: Read> Read for Prefixed<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = buffer.len().min(self.head.len() - self.at);
        buffer[..count].copy_from_slice(&self.head[self.at..self.at + count]);
        self.at += count;
        if count == buffer.len() {
            return Ok(count);
        }
        Ok(count + self.inner.read(&mut buffer[count..])?)
    }
}

/// Presents a snoop capture as a big-endian PCAP stream.
struct Snoop<R> {
    inner: R,
    out: Vec<u8>,
    at: usize,
    done: bool,
}

impl<R: Read> Snoop<R> {
    fn new(mut inner: R) -> io::Result<Self> {
        let mut header = [0u8; 16];
        if read_full(&mut inner, &mut header)? != 16 {
            return Err(invalid("Truncated snoop header"));
        }
        if header[8..12] != [0, 0, 0, 2] || header[12..16] != [0, 0, 0, 4] {
            return Err(invalid(
                "Only version 2 Ethernet snoop captures are supported",
            ));
        }
        let mut out = vec![0xa1, 0xb2, 0xc3, 0xd4, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0];
        out.extend((MAX_PACKET_BYTES as u32).to_be_bytes());
        out.extend(1u32.to_be_bytes());
        Ok(Self {
            inner,
            out,
            at: 0,
            done: false,
        })
    }
}

impl<R: Read> Read for Snoop<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.at == self.out.len() && !self.done {
            self.out.clear();
            self.at = 0;
            // Record: original, included and record lengths, drops, time.
            let mut header = [0u8; 24];
            match read_full(&mut self.inner, &mut header)? {
                0 => self.done = true,
                24 => {
                    let word = |at: usize| {
                        u32::from_be_bytes([
                            header[at],
                            header[at + 1],
                            header[at + 2],
                            header[at + 3],
                        ])
                    };
                    let (included, record) = (word(4) as usize, word(8) as usize);
                    if included > MAX_PACKET_BYTES
                        || record < 24 + included
                        || record > 32 + included
                    {
                        return Err(invalid("Invalid snoop record length"));
                    }
                    let mut data = vec![0; record - 24];
                    if read_full(&mut self.inner, &mut data)? != data.len() {
                        return Err(invalid("Truncated snoop record"));
                    }
                    self.out.extend(&header[16..24]);
                    self.out.extend(&header[4..8]);
                    self.out.extend(&header[..4]);
                    self.out.extend(&data[..included]);
                }
                _ => return Err(invalid("Truncated snoop record")),
            }
        }
        let count = buffer.len().min(self.out.len() - self.at);
        buffer[..count].copy_from_slice(&self.out[self.at..self.at + count]);
        self.at += count;
        Ok(count)
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
