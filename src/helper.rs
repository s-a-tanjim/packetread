//! Wire protocol between the unprivileged application and the
//! `packetread-capture` helper, the only process that opens capture devices.
//!
//! The helper writes frames to its stdout: one kind byte, a little-endian
//! `u32` body length, then the body. The application treats the stream as
//! untrusted input and bounds every frame.
use crate::offline::MAX_PACKET_BYTES;
use std::io::{self, Read, Write};

#[cfg(not(windows))]
pub const HELPER_NAME: &str = "packetread-capture";
#[cfg(windows)]
pub const HELPER_NAME: &str = "packetread-capture.exe";
/// Overrides the helper location (default: next to the running executable).
pub const HELPER_ENV: &str = "PACKETREAD_CAPTURE_HELPER";
const MAX_FRAME: usize = MAX_PACKET_BYTES + 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Packet {
        link: i32,
        timestamp_ns: i64,
        wire_len: u32,
        data: Vec<u8>,
    },
    /// Packets dropped by the kernel, summed over all interfaces.
    Stats { dropped: u32 },
    /// A fatal capture error; the helper exits after sending it.
    Error(String),
    /// Sent while idle so the reader can notice cancellation.
    Tick,
}

impl Frame {
    pub fn write(&self, out: &mut impl Write) -> io::Result<()> {
        let (kind, body) = match self {
            Self::Packet {
                link,
                timestamp_ns,
                wire_len,
                data,
            } => {
                let mut body = link.to_le_bytes().to_vec();
                body.extend(timestamp_ns.to_le_bytes());
                body.extend(wire_len.to_le_bytes());
                body.extend(data);
                (0u8, body)
            }
            Self::Stats { dropped } => (1, dropped.to_le_bytes().to_vec()),
            Self::Error(message) => (2, message.as_bytes().to_vec()),
            Self::Tick => (3, Vec::new()),
        };
        out.write_all(&[kind])?;
        out.write_all(&(body.len() as u32).to_le_bytes())?;
        out.write_all(&body)
    }

    /// Returns `None` at a clean end of stream.
    pub fn read(input: &mut impl Read) -> io::Result<Option<Self>> {
        let mut header = [0; 5];
        if input.read(&mut header[..1])? == 0 {
            return Ok(None);
        }
        input.read_exact(&mut header[1..])?;
        let length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid frame from capture helper",
            )
        };
        if length > MAX_FRAME {
            return Err(invalid());
        }
        let mut body = vec![0; length];
        input.read_exact(&mut body)?;
        Ok(Some(match (header[0], length) {
            (0, 16..) => Self::Packet {
                link: i32::from_le_bytes(body[..4].try_into().map_err(|_| invalid())?),
                timestamp_ns: i64::from_le_bytes(body[4..12].try_into().map_err(|_| invalid())?),
                wire_len: u32::from_le_bytes(body[12..16].try_into().map_err(|_| invalid())?),
                data: body.split_off(16),
            },
            (1, 4) => Self::Stats {
                dropped: u32::from_le_bytes(body[..4].try_into().map_err(|_| invalid())?),
            },
            (2, _) => Self::Error(String::from_utf8_lossy(&body).into_owned()),
            (3, 0) => Self::Tick,
            _ => return Err(invalid()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_bad_input_is_rejected() {
        let frames = [
            Frame::Packet {
                link: 1,
                timestamp_ns: 1_700_000_000_000_000_001,
                wire_len: 90,
                data: vec![1, 2, 3],
            },
            Frame::Stats { dropped: 7 },
            Frame::Error("no permission".into()),
            Frame::Tick,
        ];
        let mut wire = Vec::new();
        frames
            .iter()
            .for_each(|frame| frame.write(&mut wire).unwrap());
        let mut input = &wire[..];
        for frame in &frames {
            assert_eq!(Frame::read(&mut input).unwrap().as_ref(), Some(frame));
        }
        assert_eq!(Frame::read(&mut input).unwrap(), None);
        for bad in [
            &[9, 0, 0, 0, 0][..],         // unknown kind
            &[0, 4, 0, 0, 0, 1, 2, 3, 4], // packet without a header
            &[0, 0xff, 0xff, 0xff, 0x7f], // oversized
            &[3, 1, 0, 0, 0, 0],          // tick with a body
            &[1, 4, 0],                   // truncated
        ] {
            assert!(Frame::read(&mut &bad[..]).is_err(), "{bad:?}");
        }
    }
}
