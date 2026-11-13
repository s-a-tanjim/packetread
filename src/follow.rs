//! Stream reconstruction: orders TCP segments per direction, drops
//! retransmitted bytes and yields the conversation as alternating chunks.
//! UDP conversations keep one chunk per datagram.
use crate::decode::Packet;
use std::{collections::BTreeMap, net::IpAddr};

/// Out-of-order bytes buffered per direction before a gap is declared.
const MAX_PENDING: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub from_client: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Stream {
    pub id: u32,
    pub tcp: bool,
    /// The side that sent the first packet (the SYN when it was captured).
    pub client: Option<(IpAddr, u16)>,
    pub server: Option<(IpAddr, u16)>,
    pub chunks: Vec<Chunk>,
    /// Bytes that were never captured.
    pub missing: u64,
    pub truncated: bool,
}

#[derive(Default)]
struct Half {
    base: Option<u32>,
    next: u32,
    pending: BTreeMap<u32, Vec<u8>>,
    pending_bytes: usize,
}

pub struct Follower {
    stream: Stream,
    halves: [Half; 2],
    limit: usize,
    size: usize,
}

impl Follower {
    /// Follows conversation `id`, keeping at most `limit` payload bytes.
    pub fn new(id: u32, limit: usize) -> Self {
        Self {
            stream: Stream {
                id,
                ..Stream::default()
            },
            halves: Default::default(),
            limit,
            size: 0,
        }
    }

    pub fn push(&mut self, packet: &Packet) {
        let summary = &packet.summary;
        let (Some(src), Some(port)) = (summary.src, summary.src_port) else {
            return;
        };
        if summary.stream != Some(self.stream.id) {
            return;
        }
        if self.stream.client.is_none() {
            self.stream.tcp = summary.tcp.is_some();
            let (from, to) = (Some((src, port)), summary.dst.zip(summary.dst_port));
            // A lone SYN/ACK means the capture started mid-handshake.
            let reply = summary.tcp.is_some_and(|t| t.flags & 0x12 == 0x12);
            (self.stream.client, self.stream.server) = if reply { (to, from) } else { (from, to) };
        }
        let from_client = self.stream.client == Some((src, port));
        let data = packet.payload();
        let Some(tcp) = summary.tcp else {
            if !data.is_empty() {
                self.emit(from_client, data, false);
            }
            return;
        };
        let half = &mut self.halves[usize::from(!from_client)];
        let syn = tcp.flags & 2 != 0;
        let base = *half
            .base
            .get_or_insert(tcp.seq.wrapping_add(u32::from(syn)));
        let offset = tcp.seq.wrapping_add(u32::from(syn)).wrapping_sub(base);
        // Data from before the first captured segment cannot be placed.
        if data.is_empty() || offset > u32::MAX / 2 {
            return;
        }
        half.pending_bytes += data.len();
        if let Some(replaced) = half.pending.insert(offset, data.to_vec()) {
            half.pending_bytes -= replaced.len();
        }
        self.drain(from_client, false);
    }

    /// Emits contiguous pending data; with `force`, skips over gaps.
    fn drain(&mut self, from_client: bool, force: bool) {
        loop {
            let half = &mut self.halves[usize::from(!from_client)];
            let Some((&offset, _)) = half.pending.first_key_value() else {
                return;
            };
            if offset > half.next {
                if !force && half.pending_bytes <= MAX_PENDING {
                    return;
                }
                self.stream.missing += u64::from(offset - half.next);
                half.next = offset;
            }
            let data = half.pending.remove(&offset).unwrap_or_default();
            half.pending_bytes -= data.len();
            let skip = (half.next - offset) as usize;
            if skip < data.len() {
                half.next += (data.len() - skip) as u32;
                self.emit(from_client, &data[skip..], true);
            }
        }
    }

    fn emit(&mut self, from_client: bool, data: &[u8], merge: bool) {
        let room = self.limit - self.size;
        self.stream.truncated |= data.len() > room;
        let data = &data[..data.len().min(room)];
        if data.is_empty() {
            return;
        }
        self.size += data.len();
        match self.stream.chunks.last_mut() {
            Some(last) if merge && last.from_client == from_client => last.data.extend(data),
            _ => self.stream.chunks.push(Chunk {
                from_client,
                data: data.to_vec(),
            }),
        }
    }

    pub fn finish(mut self) -> Stream {
        self.drain(true, true);
        self.drain(false, true);
        self.stream
    }
}

/// Removes HTTP chunked transfer coding; `None` when the body is cut short.
fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line = body.windows(2).position(|w| w == b"\r\n")?;
        let size = std::str::from_utf8(&body[..line])
            .ok()?
            .split(';')
            .next()?
            .trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        body = &body[line + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend(body.get(..size)?);
        body = body.get(size + 2..)?;
    }
}

fn endpoint(endpoint: Option<(IpAddr, u16)>) -> String {
    match endpoint {
        Some((IpAddr::V6(address), port)) => format!("[{address}]:{port}"),
        Some((address, port)) => format!("{address}:{port}"),
        None => "?".into(),
    }
}

impl Stream {
    pub fn title(&self) -> String {
        format!(
            "{} stream {}: {} ↔ {}",
            if self.tcp { "TCP" } else { "UDP" },
            self.id,
            endpoint(self.client),
            endpoint(self.server)
        )
    }

    /// Bodies of the HTTP/1.x messages in this stream, with a file extension
    /// guessed from the content type. Incomplete bodies are left out.
    pub fn http_objects(&self) -> Vec<(&'static str, Vec<u8>)> {
        let mut objects = Vec::new();
        for chunk in &self.chunks {
            let mut rest = &chunk.data[..];
            while crate::decode::http_summary(rest).is_some() {
                let Some(head) = rest
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|at| at + 4)
                else {
                    break;
                };
                let headers = String::from_utf8_lossy(&rest[..head]).to_ascii_lowercase();
                let header = |name: &str| {
                    let line = headers.lines().find(|line| line.starts_with(name))?;
                    Some(line[name.len()..].trim().to_string())
                };
                let (body, used) =
                    if header("transfer-encoding:").is_some_and(|v| v.contains("chunked")) {
                        // Chunked bodies end the scan: their encoded length is not tracked.
                        (dechunk(&rest[head..]), rest.len())
                    } else {
                        let total = crate::decode::http_message_length(rest).unwrap_or(head);
                        (rest.get(head..total).map(<[u8]>::to_vec), total)
                    };
                let extension = match header("content-type:")
                    .unwrap_or_default()
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                {
                    "text/html" => "html",
                    "text/plain" => "txt",
                    "text/css" => "css",
                    "application/json" => "json",
                    "application/javascript" | "text/javascript" => "js",
                    "application/pdf" => "pdf",
                    "image/png" => "png",
                    "image/jpeg" => "jpg",
                    "image/gif" => "gif",
                    _ => "bin",
                };
                if let Some(body) = body.filter(|body| !body.is_empty()) {
                    objects.push((extension, body));
                }
                rest = rest.get(used..).unwrap_or_default();
            }
        }
        objects
    }

    /// Renders the conversation as terminal-safe lines: text with
    /// non-printable bytes as `.`, or a hex dump.
    pub fn lines(&self, hex: bool) -> Vec<String> {
        let mut lines = Vec::new();
        for chunk in &self.chunks {
            lines.push(format!(
                "{} ({} bytes){}",
                if chunk.from_client {
                    "→ client"
                } else {
                    "← server"
                },
                chunk.data.len(),
                crate::decode::http_summary(&chunk.data)
                    .map_or_else(String::new, |http| format!(" · HTTP: {http}"))
            ));
            let printable = |b: &u8| {
                if (32..127).contains(b) {
                    char::from(*b)
                } else {
                    '.'
                }
            };
            if hex {
                for (index, row) in chunk.data.chunks(16).enumerate() {
                    let bytes: String = row.iter().map(|b| format!("{b:02x} ")).collect();
                    let text: String = row.iter().map(printable).collect();
                    lines.push(format!("  {:06x}  {bytes:<48} {text}", index * 16));
                }
            } else {
                for line in chunk.data.split(|b| *b == b'\n') {
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    lines.push(format!(
                        "  {}",
                        line.iter().map(printable).collect::<String>()
                    ));
                }
            }
        }
        if self.missing > 0 {
            lines.push(format!("[{} bytes were not captured]", self.missing));
        }
        if self.truncated {
            lines.push("[stream truncated at the follow limit]".into());
        }
        if self.chunks.is_empty() {
            lines.push("[no payload in this conversation]".into());
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::LINK_RAW;

    fn segment(from_client: bool, seq: u32, flags: u8, data: &[u8]) -> Packet {
        let (src, dst, sport, dport) = if from_client {
            (1, 2, 1000u16, 80u16)
        } else {
            (2, 1, 80, 1000)
        };
        let mut bytes = vec![0x45, 0];
        bytes.extend(((40 + data.len()) as u16).to_be_bytes());
        bytes.extend([0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, src, 192, 0, 2, dst]);
        bytes.extend(sport.to_be_bytes());
        bytes.extend(dport.to_be_bytes());
        bytes.extend(seq.to_be_bytes());
        bytes.extend([0, 0, 0, 0, 0x50, flags, 1, 0, 0, 0, 0, 0]);
        bytes.extend(data);
        let mut packet = Packet::new(0, 0, bytes.len() as u32, LINK_RAW, bytes.into());
        packet.summary.stream = Some(4);
        packet
    }

    fn follow(packets: &[Packet], limit: usize) -> Stream {
        let mut follower = Follower::new(4, limit);
        packets.iter().for_each(|packet| follower.push(packet));
        follower.finish()
    }

    #[test]
    fn orders_segments_and_drops_retransmissions() {
        let stream = follow(
            &[
                segment(true, u32::MAX - 2, 0x02, b""),
                segment(false, 900, 0x12, b""),
                segment(true, 4, 0x18, b"world"), // wraps; arrives early
                segment(true, u32::MAX - 1, 0x18, b"hel"),
                segment(true, u32::MAX - 1, 0x18, b"hello "), // overlapping retransmission
                segment(false, 901, 0x18, b"ok"),
                segment(true, 9, 0x18, b"!"),
            ],
            1024,
        );
        let chunks: Vec<_> = stream
            .chunks
            .iter()
            .map(|c| (c.from_client, c.data.as_slice()))
            .collect();
        assert_eq!(
            chunks,
            [(true, &b"hello world"[..]), (false, b"ok"), (true, b"!")]
        );
        assert_eq!(
            stream.title(),
            "TCP stream 4: 192.0.2.1:1000 ↔ 192.0.2.2:80"
        );
        assert_eq!((stream.missing, stream.truncated), (0, false));
    }

    #[test]
    fn extracts_http_bodies_including_chunked_ones() {
        let stream = Stream {
            chunks: vec![
                Chunk { from_client: true, data: b"POST /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\n\r\n".to_vec() },
                Chunk {
                    from_client: false,
                    data: b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 2\r\n\r\n{}\
                        HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;x=1\r\npedia\r\n0\r\n\r\n"
                        .to_vec(),
                },
                Chunk { from_client: false, data: b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort".to_vec() },
                Chunk { from_client: false, data: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".to_vec() },
            ],
            ..Stream::default()
        };
        let objects = stream.http_objects();
        let expected: [(&str, &[u8]); 3] =
            [("bin", b"abc"), ("json", b"{}"), ("bin", b"Wikipedia")];
        assert_eq!(objects.len(), 3);
        for ((extension, body), (wanted, data)) in objects.iter().zip(expected) {
            assert_eq!((*extension, body.as_slice()), (wanted, data));
        }
    }

    #[test]
    fn reports_gaps_truncation_and_escapes_control_bytes() {
        let stream = follow(
            &[
                segment(true, 10, 0x18, b"ab\x1b[2J\r\nc"),
                segment(true, 30, 0x18, b"late"),
            ],
            12,
        );
        assert_eq!(stream.missing, 11);
        assert!(stream.truncated);
        let lines = stream.lines(false);
        assert_eq!(&lines[..3], ["→ client (12 bytes)", "  ab.[2J", "  clat"]);
        assert!(stream.lines(true)[1].contains("61 62 1b"));
        let mut other = segment(true, 1, 0x18, b"x");
        other.summary.stream = Some(9);
        assert!(follow(&[other], 10).chunks.is_empty());
    }
}
