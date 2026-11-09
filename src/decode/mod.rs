mod dns;

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Range,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Arp,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmp,
    Dns,
    Unknown,
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Self::Arp => "ARP",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
            Self::Dns => "DNS",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Summary {
    pub protocol: Protocol,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub info: String,
    pub warning: Option<String>,
}

impl Default for Summary {
    fn default() -> Self {
        Self {
            protocol: Protocol::Unknown,
            src: None,
            dst: None,
            src_port: None,
            dst_port: None,
            info: String::new(),
            warning: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Field {
    pub label: String,
    pub range: Range<usize>,
}

#[derive(Clone, Debug)]
pub struct Layer {
    pub label: String,
    pub range: Range<usize>,
    pub fields: Vec<Field>,
}

#[derive(Debug)]
pub struct Packet {
    pub id: u64,
    pub timestamp_ns: i128,
    pub wire_len: u32,
    pub link: i32,
    pub bytes: Box<[u8]>,
    pub summary: Summary,
}

impl Packet {
    pub fn new(id: u64, timestamp_ns: i128, wire_len: u32, link: i32, bytes: Box<[u8]>) -> Self {
        let mut summary = decode(&bytes, link);
        if wire_len as usize > bytes.len() {
            summary
                .warning
                .get_or_insert_with(|| "Capture truncated by snap length".into());
        }
        Self {
            id,
            timestamp_ns,
            wire_len,
            link,
            bytes,
            summary,
        }
    }

    pub fn memory_size(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.bytes.len()
            + self.summary.info.capacity()
            + self.summary.warning.as_ref().map_or(0, String::capacity)
            + 32
    }
}

pub fn decode(bytes: &[u8], link: i32) -> Summary {
    inspect(bytes, link, false).0
}
pub fn details(bytes: &[u8], link: i32) -> Vec<Layer> {
    inspect(bytes, link, true).1
}

// Ranges always refer to captured bytes, including for truncated headers.
struct Decoder<'a> {
    bytes: &'a [u8],
    summary: Summary,
    layers: Vec<Layer>,
    detailed: bool,
}

impl Decoder<'_> {
    fn warn(&mut self, message: impl Into<String>) {
        self.summary.warning.get_or_insert_with(|| message.into());
    }
    fn layer(&mut self, label: &str, start: usize, end: usize) {
        if self.detailed {
            self.layers.push(Layer {
                label: label.into(),
                range: start.min(self.bytes.len())..end.min(self.bytes.len()),
                fields: Vec::new(),
            });
        }
    }
    fn field(&mut self, start: usize, end: usize, label: impl FnOnce() -> String) {
        if self.detailed {
            if let Some(layer) = self.layers.last_mut() {
                layer.fields.push(Field {
                    label: label(),
                    range: start.min(self.bytes.len())..end.min(self.bytes.len()),
                });
            }
        }
    }
    fn network(&mut self, ethertype: u16, start: usize) {
        let bytes = self.bytes;
        if ethertype == 0x0806 {
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
            return;
        }
        if !matches!(ethertype, 0x0800 | 0x86dd) {
            return;
        }
        if start >= bytes.len() {
            self.warn("Missing IP header");
            return;
        }
        if let Err(error) = etherparse::SlicedPacket::from_ip(&bytes[start..]) {
            self.warn(format!("Malformed/truncated: {error}"));
        }
        let (protocol, mut cursor, end, fragmented) = if ethertype == 0x0800 {
            self.summary.protocol = Protocol::Ipv4;
            if bytes.len() < start + 20 {
                self.warn("Truncated IPv4 header");
                return;
            }
            let header_len = usize::from(bytes[start] & 15) * 4;
            let total_len = usize::from(be16(bytes, start + 2));
            if bytes[start] >> 4 != 4 || header_len < 20 || total_len < header_len {
                self.warn("Invalid IPv4 lengths or version");
                return;
            }
            if bytes.len() < start + header_len {
                self.warn("Truncated IPv4 options");
                return;
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
            self.field(start + 12, start + 16, || format!("Source: {src}"));
            self.field(start + 16, start + 20, || format!("Destination: {dst}"));
            (
                bytes[start + 9],
                start + header_len,
                (start + total_len).min(bytes.len()),
                be16(bytes, start + 6) & 0x3fff != 0,
            )
        } else {
            self.summary.protocol = Protocol::Ipv6;
            if bytes.len() < start + 40 {
                self.warn("Truncated IPv6 header");
                return;
            }
            if bytes[start] >> 4 != 6 {
                self.warn("Invalid IPv6 version");
                return;
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
            let length = usize::from(be16(bytes, start + 4));
            if length == 0 {
                self.warn("Empty IPv6 payload or unsupported jumbogram");
                return;
            }
            (
                bytes[start + 6],
                start + 40,
                (start + 40 + length).min(bytes.len()),
                false,
            )
        };
        if fragmented {
            self.summary.info = "IP fragment · reassembly unavailable".into();
            return;
        }
        let mut protocol = protocol;
        if ethertype == 0x86dd {
            let mut extensions = 0;
            while matches!(protocol, 0 | 43 | 44 | 51 | 60) {
                if extensions >= 16 || cursor + 2 > end {
                    self.warn("Invalid or excessive IPv6 extension headers");
                    return;
                }
                let length = match protocol {
                    44 => 8,
                    51 => (usize::from(bytes[cursor + 1]) + 2) * 4,
                    _ => (usize::from(bytes[cursor + 1]) + 1) * 8,
                };
                if cursor + length > end {
                    self.warn("Truncated IPv6 extension");
                    return;
                }
                self.layer("IPv6 extension", cursor, cursor + length);
                if protocol == 44 && be16(bytes, cursor + 2) & 0xfff9 != 0 {
                    self.summary.info = "IPv6 fragment · reassembly unavailable".into();
                    return;
                }
                protocol = bytes[cursor];
                cursor += length;
                extensions += 1;
            }
        }
        self.transport(protocol, cursor, end);
    }

    fn transport(&mut self, protocol: u8, start: usize, end: usize) {
        let bytes = self.bytes;
        match protocol {
            6 | 17 => {
                self.summary.protocol = if protocol == 6 {
                    Protocol::Tcp
                } else {
                    Protocol::Udp
                };
                let min_len = if protocol == 6 { 20 } else { 8 };
                if start + min_len > end {
                    self.warn("Truncated transport header");
                    return;
                }
                let src = be16(bytes, start);
                let dst = be16(bytes, start + 2);
                self.summary.src_port = Some(src);
                self.summary.dst_port = Some(dst);
                let length = if protocol == 6 {
                    usize::from(bytes[start + 12] >> 4) * 4
                } else {
                    8
                };
                if length < min_len || start + length > end {
                    self.warn("Invalid transport header length");
                    return;
                }
                self.layer(
                    if protocol == 6 { "TCP" } else { "UDP" },
                    start,
                    start + length,
                );
                self.field(start, start + 2, || format!("Source port: {src}"));
                self.field(start + 2, start + 4, || format!("Destination port: {dst}"));
                if protocol == 6 {
                    let flags = bytes[start + 13];
                    let names: Vec<_> = [
                        (0x02, "SYN"),
                        (0x10, "ACK"),
                        (0x01, "FIN"),
                        (0x04, "RST"),
                        (0x08, "PSH"),
                        (0x20, "URG"),
                        (0x40, "ECE"),
                        (0x80, "CWR"),
                    ]
                    .into_iter()
                    .filter_map(|(mask, name)| (flags & mask != 0).then_some(name))
                    .collect();
                    self.summary.info = format!(
                        "{} · {} payload bytes",
                        names.join(","),
                        end - start - length
                    );
                    self.field(start + 4, start + 8, || {
                        format!("Sequence: {}", be32(bytes, start + 4))
                    });
                    self.field(start + 8, start + 12, || {
                        format!("Acknowledgment: {}", be32(bytes, start + 8))
                    });
                    self.field(start + 13, start + 14, || {
                        format!("Flags: {}", names.join(", "))
                    });
                    self.field(start + 14, start + 16, || {
                        format!("Window: {}", be16(bytes, start + 14))
                    });
                } else {
                    let udp_length = usize::from(be16(bytes, start + 4));
                    self.field(start + 4, start + 6, || format!("Length: {udp_length}"));
                    if udp_length < 8 || start + udp_length > end {
                        self.warn("Invalid or truncated UDP length");
                        return;
                    }
                    self.summary.info = format!("{} payload bytes", udp_length - 8);
                    if src == 53 || dst == 53 {
                        let dns_start = start + 8;
                        match dns::summary(&bytes[dns_start..start + udp_length]) {
                            Ok(info) => {
                                self.summary.protocol = Protocol::Dns;
                                self.summary.info = info;
                                self.layer("DNS (UDP)", dns_start, start + udp_length);
                                self.field(dns_start, dns_start + 2, || {
                                    format!("Transaction ID: 0x{:04x}", be16(bytes, dns_start))
                                });
                                self.field(dns_start + 2, dns_start + 4, || {
                                    format!("Flags: 0x{:04x}", be16(bytes, dns_start + 2))
                                });
                                self.field(dns_start + 4, dns_start + 6, || {
                                    format!("Questions: {}", be16(bytes, dns_start + 4))
                                });
                                self.field(dns_start + 6, dns_start + 8, || {
                                    format!("Answers: {}", be16(bytes, dns_start + 6))
                                });
                            }
                            Err(error) => self.warn(format!("Port 53: {error}")),
                        }
                    }
                }
                if start + length < end {
                    self.layer("Payload", start + length, end);
                }
            }
            1 | 58 => {
                self.summary.protocol = Protocol::Icmp;
                if start + 4 > end {
                    self.warn("Truncated ICMP header");
                    return;
                }
                self.summary.info = format!("Type {} · code {}", bytes[start], bytes[start + 1]);
                self.layer(if protocol == 1 { "ICMPv4" } else { "ICMPv6" }, start, end);
                self.field(start, start + 1, || format!("Type: {}", bytes[start]));
                self.field(start + 1, start + 2, || {
                    format!("Code: {}", bytes[start + 1])
                });
            }
            _ => {
                self.summary.info = format!("IP protocol {protocol}");
                self.layer("Payload", start, end);
            }
        }
    }
}

fn inspect(bytes: &[u8], link: i32, detailed: bool) -> (Summary, Vec<Layer>) {
    let mut decoder = Decoder {
        bytes,
        summary: Summary::default(),
        layers: Vec::new(),
        detailed,
    };
    let header = match link {
        1 if bytes.len() >= 14 => {
            decoder.layer("Ethernet II", 0, 14);
            decoder.field(0, 6, || format!("Destination: {}", mac(&bytes[..6])));
            decoder.field(6, 12, || format!("Source: {}", mac(&bytes[6..12])));
            decoder.field(12, 14, || format!("EtherType: 0x{:04x}", be16(bytes, 12)));
            Some((be16(bytes, 12), 14))
        }
        113 if bytes.len() >= 16 => {
            decoder.layer("Linux cooked capture (SLL)", 0, 16);
            Some((be16(bytes, 14), 16))
        }
        276 if bytes.len() >= 20 => {
            decoder.layer("Linux cooked capture (SLL2)", 0, 20);
            Some((be16(bytes, 0), 20))
        }
        12 | 101 | 228 | 229 if !bytes.is_empty() => {
            Some((if bytes[0] >> 4 == 6 { 0x86dd } else { 0x0800 }, 0))
        }
        1 | 113 | 276 | 12 | 101 | 228 | 229 => {
            decoder.warn("Truncated link header");
            None
        }
        _ => {
            decoder.warn(format!("Unsupported link type {link}"));
            None
        }
    };
    if let Some((mut ethertype, mut offset)) = header {
        let mut vlans = 0;
        while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
            if offset + 4 > bytes.len() || vlans == 8 {
                decoder.warn("Truncated or excessive VLAN headers");
                return (decoder.summary, decoder.layers);
            }
            decoder.layer("802.1Q VLAN", offset, offset + 4);
            decoder.field(offset, offset + 2, || {
                format!("VLAN ID: {}", be16(bytes, offset) & 0xfff)
            });
            ethertype = be16(bytes, offset + 2);
            offset += 4;
            vlans += 1;
        }
        decoder.network(ethertype, offset);
    }
    if detailed && decoder.layers.is_empty() {
        decoder.layer("Raw bytes", 0, bytes.len());
    }
    (decoder.summary, decoder.layers)
}

fn be16(bytes: &[u8], start: usize) -> u16 {
    u16::from_be_bytes([bytes[start], bytes[start + 1]])
}
fn be32(bytes: &[u8], start: usize) -> u32 {
    u32::from_be_bytes([
        bytes[start],
        bytes[start + 1],
        bytes[start + 2],
        bytes[start + 3],
    ])
}
fn ipv4(bytes: &[u8]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}
fn ipv6(bytes: &[u8]) -> IpAddr {
    let mut address = [0; 16];
    address.copy_from_slice(bytes);
    IpAddr::V6(Ipv6Addr::from(address))
}
fn mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Render untrusted text as a single line without terminal control characters.
pub fn safe_text(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                '�'
            } else {
                c
            }
        })
        .collect()
}
