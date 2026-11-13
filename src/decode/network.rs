//! ARP, IPv4 and IPv6. Each IP parser returns the transport protocol number
//! and the byte range the transport decoder may read.
use super::{be16, be32, checksum_ok, ipv4, ipv6, Decoder, Fragment, Protocol};

type Transport = (u8, usize, usize);

impl Decoder<'_> {
    pub(super) fn network(&mut self, ethertype: u16, start: usize) {
        let transport = match ethertype {
            0x0806 => {
                self.arp(start);
                None
            }
            0x88cc => {
                self.lldp(start);
                None
            }
            0x888e => {
                self.eapol(start);
                None
            }
            0x8847 | 0x8848 => {
                self.mpls(start);
                None
            }
            0x8863 | 0x8864 => {
                self.pppoe(start);
                None
            }
            0x0800 | 0x86dd if start >= self.bytes.len() => {
                self.warn("Missing IP header");
                None
            }
            0x0800 => self.ipv4(start),
            0x86dd => self.ipv6(start),
            _ => None,
        };
        if let Some((protocol, start, end)) = transport {
            self.transport(protocol, start, end);
        }
    }

    fn arp(&mut self, start: usize) {
        let bytes = self.bytes;
        self.summary.protocol = Protocol::Arp;
        self.layer("ARP", start, start + 28);
        if bytes.len() < start + 28 {
            self.warn("Truncated ARP header");
            return;
        }
        let operation = be16(bytes, start + 6);
        self.summary.info = format!("ARP operation {operation}");
        self.field(start + 6, start + 8, || format!("Operation: {operation}"));
        if be16(bytes, start + 2) == 0x0800 && bytes[start + 4] == 6 && bytes[start + 5] == 4 {
            let src = ipv4(&bytes[start + 14..start + 18]);
            let dst = ipv4(&bytes[start + 24..start + 28]);
            self.summary.src = Some(src);
            self.summary.dst = Some(dst);
            self.field(start + 14, start + 18, || format!("Sender IP: {src}"));
            self.field(start + 24, start + 28, || format!("Target IP: {dst}"));
        }
    }

    fn ipv4(&mut self, start: usize) -> Option<Transport> {
        let bytes = self.bytes;
        self.summary.protocol = Protocol::Ipv4;
        if bytes.len() < start + 20 {
            self.warn("Truncated IPv4 header");
            return None;
        }
        let header_len = usize::from(bytes[start] & 15) * 4;
        let total_len = usize::from(be16(bytes, start + 2));
        if bytes[start] >> 4 != 4 || header_len < 20 || total_len < header_len {
            self.warn("Invalid IPv4 lengths or version");
            return None;
        }
        if bytes.len() < start + header_len {
            self.warn("Truncated IPv4 options");
            return None;
        }
        if bytes.len() < start + total_len {
            self.warn("IPv4 total length exceeds captured bytes");
        }
        let src = ipv4(&bytes[start + 12..start + 16]);
        let dst = ipv4(&bytes[start + 16..start + 20]);
        self.summary.src = Some(src);
        self.summary.dst = Some(dst);
        self.layer("IPv4", start, start + header_len);
        self.field(start, start + 1, || {
            format!("Version: 4 · header: {header_len} bytes")
        });
        self.field(start + 2, start + 4, || {
            format!("Total length: {total_len}")
        });
        self.field(start + 8, start + 9, || {
            format!("TTL: {}", bytes[start + 8])
        });
        self.field(start + 10, start + 12, || {
            format!(
                "Header checksum: 0x{:04x} ({})",
                be16(bytes, start + 10),
                if checksum_ok(&[&bytes[start..start + header_len]]) {
                    "correct"
                } else {
                    "incorrect"
                }
            )
        });
        self.field(start + 12, start + 16, || format!("Source: {src}"));
        self.field(start + 16, start + 20, || format!("Destination: {dst}"));
        self.summary.ttl = Some(bytes[start + 8]);
        let fragment = be16(bytes, start + 6);
        if fragment & 0x3fff != 0 {
            let offset = u32::from(fragment & 0x1fff) * 8;
            let id = u32::from(be16(bytes, start + 4));
            self.summary.info = format!("IPv4 fragment · id 0x{id:04x} · offset {offset}");
            self.summary.fragment = Some(Fragment {
                id,
                offset,
                more: fragment & 0x2000 != 0,
                protocol: bytes[start + 9],
                start: (start + header_len) as u32,
                end: (start + total_len).min(bytes.len()) as u32,
            });
            return None;
        }
        Some((
            bytes[start + 9],
            start + header_len,
            (start + total_len).min(bytes.len()),
        ))
    }

    fn ipv6(&mut self, start: usize) -> Option<Transport> {
        let bytes = self.bytes;
        self.summary.protocol = Protocol::Ipv6;
        if bytes.len() < start + 40 {
            self.warn("Truncated IPv6 header");
            return None;
        }
        if bytes[start] >> 4 != 6 {
            self.warn("Invalid IPv6 version");
            return None;
        }
        let src = ipv6(&bytes[start + 8..start + 24]);
        let dst = ipv6(&bytes[start + 24..start + 40]);
        self.summary.src = Some(src);
        self.summary.dst = Some(dst);
        self.layer("IPv6", start, start + 40);
        self.field(start + 8, start + 24, || format!("Source: {src}"));
        self.field(start + 24, start + 40, || format!("Destination: {dst}"));
        self.field(start + 7, start + 8, || {
            format!("Hop limit: {}", bytes[start + 7])
        });
        self.summary.ttl = Some(bytes[start + 7]);
        let length = usize::from(be16(bytes, start + 4));
        if length == 0 {
            self.warn("Empty IPv6 payload or unsupported jumbogram");
            return None;
        }
        if bytes.len() < start + 40 + length {
            self.warn("IPv6 payload length exceeds captured bytes");
        }
        let end = (start + 40 + length).min(bytes.len());
        let mut protocol = bytes[start + 6];
        let mut cursor = start + 40;
        let mut extensions = 0;
        while matches!(protocol, 0 | 43 | 44 | 51 | 60) {
            if extensions >= 16 || cursor + 2 > end {
                self.warn("Invalid or excessive IPv6 extension headers");
                return None;
            }
            let length = match protocol {
                44 => 8,
                51 => (usize::from(bytes[cursor + 1]) + 2) * 4,
                _ => (usize::from(bytes[cursor + 1]) + 1) * 8,
            };
            if cursor + length > end {
                self.warn("Truncated IPv6 extension");
                return None;
            }
            self.layer("IPv6 extension", cursor, cursor + length);
            let fragment = be16(bytes, cursor + 2);
            if protocol == 44 && fragment & 0xfff9 != 0 {
                let offset = u32::from(fragment & 0xfff8);
                let id = be32(bytes, cursor + 4);
                self.summary.info = format!("IPv6 fragment · id 0x{id:08x} · offset {offset}");
                self.summary.fragment = Some(Fragment {
                    id,
                    offset,
                    more: fragment & 1 != 0,
                    protocol: bytes[cursor],
                    start: (cursor + 8) as u32,
                    end: end as u32,
                });
                return None;
            }
            protocol = bytes[cursor];
            cursor += length;
            extensions += 1;
        }
        Some((protocol, cursor, end))
    }
}

#[cfg(test)]
mod tests {
    use crate::decode::decode;

    #[test]
    fn ip_length_beyond_the_captured_bytes_is_flagged() {
        // Raw IPv4 claiming 40 bytes with only the 20-byte header captured.
        let mut v4 = [0u8; 20];
        v4[0] = 0x45;
        v4[3] = 40;
        v4[9] = 253;
        assert!(decode(&v4, 101)
            .warning
            .unwrap()
            .contains("IPv4 total length"));
        v4[3] = 20;
        assert!(decode(&v4, 101).warning.is_none());

        // Raw IPv6 claiming an 8-byte payload that was not captured.
        let mut v6 = [0u8; 40];
        v6[0] = 0x60;
        v6[5] = 8;
        v6[6] = 253;
        assert!(decode(&v6, 101)
            .warning
            .unwrap()
            .contains("IPv6 payload length"));
    }
}
