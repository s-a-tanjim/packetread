//! HTTP/1.x start line and headers. Only the head inside this packet is
//! decoded; bodies and messages split across segments are left as payload.
use super::{Decoder, Protocol};

const METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// The start line when `payload` begins an HTTP/1.x request or response.
pub fn http_summary(payload: &[u8]) -> Option<String> {
    let head = &payload[..payload.len().min(2048)];
    let line = &head[..head.windows(2).position(|w| w == b"\r\n")?];
    let line = std::str::from_utf8(line).ok()?;
    if !line.bytes().all(|b| (32..127).contains(&b)) {
        return None;
    }
    let mut parts = line.splitn(3, ' ');
    let (first, second, third) = (parts.next()?, parts.next()?, parts.next());
    let request = METHODS.contains(&first) && third.is_some_and(|v| v.starts_with("HTTP/1."));
    let response = first.starts_with("HTTP/1.") && second.parse::<u16>().is_ok();
    (request || response).then(|| line.chars().take(200).collect())
}

/// Bytes of the first HTTP message in `data` (head plus `Content-Length`
/// body); `None` until the head is complete.
pub fn message_length(data: &[u8]) -> Option<usize> {
    let head = data.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let body = data[..head]
        .split(|b| *b == b'\n')
        .filter_map(|line| std::str::from_utf8(line).ok()?.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok());
    head.checked_add(body.unwrap_or(0))
}

impl Decoder<'_> {
    pub(super) fn http(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        let Some(info) = http_summary(&bytes[start..end]) else {
            return false;
        };
        self.summary.protocol = Protocol::Http;
        self.summary.info = info;
        if !self.detailed {
            return true;
        }
        self.layer("HTTP", start, end);
        let mut cursor = start;
        for _ in 0..65 {
            let Some(length) = bytes[cursor..end].windows(2).position(|w| w == b"\r\n") else {
                break;
            };
            if length == 0 {
                break;
            }
            let line = String::from_utf8_lossy(&bytes[cursor..cursor + length]).into_owned();
            self.field(cursor, cursor + length, || line);
            cursor += length + 2;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recognises_requests_and_responses_only() {
        assert_eq!(
            http_summary(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n").unwrap(),
            "GET /a HTTP/1.1"
        );
        assert_eq!(
            http_summary(b"HTTP/1.1 404 Not Found\r\n\r\n").unwrap(),
            "HTTP/1.1 404 Not Found"
        );
        for bad in [
            &b"GET /a HTTP/1.1"[..],
            b"HELLO x HTTP/1.1\r\n",
            b"GET /\x1b[2J HTTP/1.1\r\n",
            b"",
        ] {
            assert!(http_summary(bad).is_none());
        }
    }
}
