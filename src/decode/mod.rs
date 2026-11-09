mod dns;
mod network;
mod transport;

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
