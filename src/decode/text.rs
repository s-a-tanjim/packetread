//! Line-based protocols: SSH banners, SIP, and FTP/SMTP/POP3/IMAP by port.
//! Only the lines in this packet are shown.
use super::{Decoder, Protocol};

/// The first line when the payload starts with printable, terminated text.
fn first_line(payload: &[u8]) -> Option<&str> {
    let head = &payload[..payload.len().min(1024)];
    let line = &head[..head.iter().position(|b| *b == b'\n')?];
    let line = std::str::from_utf8(line.strip_suffix(b"\r").unwrap_or(line)).ok()?;
    (!line.is_empty() && line.bytes().all(|b| (32..127).contains(&b) || b == b'\t')).then_some(line)
}

impl Decoder<'_> {
    pub(super) fn text(&mut self, protocol: Protocol, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        let Some(line) = first_line(&bytes[start..end]) else {
            return false;
        };
        self.summary.protocol = protocol;
        self.summary.info = line.chars().take(200).collect();
        if !self.detailed {
            return true;
        }
        self.layer(protocol.name(), start, end);
        let mut cursor = start;
        for line in bytes[start..end].split_inclusive(|b| *b == b'\n').take(32) {
            let text = String::from_utf8_lossy(line).trim_end().to_string();
            self.field(cursor, cursor + line.len(), || text);
            cursor += line.len();
        }
        true
    }

    /// The identification banner; later packets on port 22 are encrypted.
    pub(super) fn ssh(&mut self, start: usize, end: usize, port: bool) -> bool {
        if self.bytes[start..end].starts_with(b"SSH-") {
            return self.text(Protocol::Ssh, start, end);
        }
        if port {
            self.summary.protocol = Protocol::Ssh;
            self.summary.info = "Encrypted or key-exchange packet · assumed from port 22".into();
            self.layer("SSH (assumed from port)", start, end);
        }
        port
    }

    pub(super) fn sip(&mut self, start: usize, end: usize) -> bool {
        let sip = first_line(&self.bytes[start..end])
            .is_some_and(|line| line.starts_with("SIP/2.0 ") || line.ends_with(" SIP/2.0"));
        sip && self.text(Protocol::Sip, start, end)
    }
}
