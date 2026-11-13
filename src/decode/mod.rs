pub(crate) mod apps;
mod dhcp;
mod dns;
mod extension;
mod hpack_table;
mod http;
mod link;
mod lua;
mod misc;
mod network;
pub(crate) mod quic;
mod smb;
mod text;
pub(crate) mod tls;
mod transport;
mod tunnel;

pub use extension::{register, Decoded, Extension, SchemaDecoder};
pub use http::{http_summary, message_length as http_message_length};
pub use link::{wlan_data, WlanData};
pub use lua::LuaDecoder;
pub use transport::decode_as;

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
    Http,
    Tls,
    Quic,
    Dhcp,
    Smb,
    Ntp,
    Ssh,
    Ftp,
    Smtp,
    Pop3,
    Imap,
    Sip,
    Mqtt,
    Igmp,
    Lldp,
    Http2,
    Grpc,
    Http3,
    WebSocket,
    Kerberos,
    Ldap,
    Snmp,
    Rdp,
    Nfs,
    Mysql,
    Postgres,
    Bgp,
    Ospf,
    Rip,
    Stp,
    Rtp,
    Rtcp,
    Esp,
    Ah,
    Wlan,
    Eapol,
    Ppp,
    Mpls,
    Bluetooth,
    Usb,
    Can,
    Zigbee,
    Extension,
    Unknown,
}

impl Protocol {
    /// `Extension` is decoded by a registered [`Extension`]; the decoder's
    /// name leads the info text.
    pub const ALL: [Self; 51] = [
        Self::Arp,
        Self::Ipv4,
        Self::Ipv6,
        Self::Tcp,
        Self::Udp,
        Self::Icmp,
        Self::Dns,
        Self::Http,
        Self::Tls,
        Self::Quic,
        Self::Dhcp,
        Self::Smb,
        Self::Ntp,
        Self::Ssh,
        Self::Ftp,
        Self::Smtp,
        Self::Pop3,
        Self::Imap,
        Self::Sip,
        Self::Mqtt,
        Self::Igmp,
        Self::Lldp,
        Self::Http2,
        Self::Grpc,
        Self::Http3,
        Self::WebSocket,
        Self::Kerberos,
        Self::Ldap,
        Self::Snmp,
        Self::Rdp,
        Self::Nfs,
        Self::Mysql,
        Self::Postgres,
        Self::Bgp,
        Self::Ospf,
        Self::Rip,
        Self::Stp,
        Self::Rtp,
        Self::Rtcp,
        Self::Esp,
        Self::Ah,
        Self::Wlan,
        Self::Eapol,
        Self::Ppp,
        Self::Mpls,
        Self::Bluetooth,
        Self::Usb,
        Self::Can,
        Self::Zigbee,
        Self::Extension,
        Self::Unknown,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Arp => "ARP",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Icmp => "ICMP",
            Self::Dns => "DNS",
            Self::Http => "HTTP",
            Self::Tls => "TLS",
            Self::Quic => "QUIC",
            Self::Dhcp => "DHCP",
            Self::Smb => "SMB",
            Self::Ntp => "NTP",
            Self::Ssh => "SSH",
            Self::Ftp => "FTP",
            Self::Smtp => "SMTP",
            Self::Pop3 => "POP3",
            Self::Imap => "IMAP",
            Self::Sip => "SIP",
            Self::Mqtt => "MQTT",
            Self::Igmp => "IGMP",
            Self::Lldp => "LLDP",
            Self::Http2 => "HTTP2",
            Self::Grpc => "GRPC",
            Self::Http3 => "HTTP3",
            Self::WebSocket => "WEBSOCKET",
            Self::Kerberos => "KERBEROS",
            Self::Ldap => "LDAP",
            Self::Snmp => "SNMP",
            Self::Rdp => "RDP",
            Self::Nfs => "NFS",
            Self::Mysql => "MYSQL",
            Self::Postgres => "PGSQL",
            Self::Bgp => "BGP",
            Self::Ospf => "OSPF",
            Self::Rip => "RIP",
            Self::Stp => "STP",
            Self::Rtp => "RTP",
            Self::Rtcp => "RTCP",
            Self::Esp => "ESP",
            Self::Ah => "AH",
            Self::Wlan => "WLAN",
            Self::Eapol => "EAPOL",
            Self::Ppp => "PPP",
            Self::Mpls => "MPLS",
            Self::Bluetooth => "BLUETOOTH",
            Self::Usb => "USB",
            Self::Can => "CAN",
            Self::Zigbee => "ZIGBEE",
            Self::Extension => "EXT",
            Self::Unknown => "Unknown",
        }
    }

    /// This protocol's bit in [`Summary::seen`].
    pub fn bit(self) -> u64 {
        1 << (self as u8)
    }
}

/// TCP header values kept for stream tracking and diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tcp {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}

/// One IP fragment; `start..end` is its data within the captured bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub id: u32,
    pub offset: u32,
    pub more: bool,
    pub protocol: u8,
    pub start: u32,
    pub end: u32,
}

/// TCP diagnostics set by [`crate::analysis::Analyzer`].
pub mod diag {
    pub const RETRANSMISSION: u8 = 1;
    pub const OUT_OF_ORDER: u8 = 2;
    pub const DUP_ACK: u8 = 4;
    pub const ZERO_WINDOW: u8 = 8;
    pub const KEEP_ALIVE: u8 = 16;
    /// Set together with `RETRANSMISSION` when duplicate ACKs triggered it.
    pub const FAST_RETRANSMISSION: u8 = 32;
    pub const RESET: u8 = 64;
    pub const NAMES: [(u8, &str); 7] = [
        (RETRANSMISSION, "retransmission"),
        (OUT_OF_ORDER, "out-of-order"),
        (DUP_ACK, "dup-ack"),
        (ZERO_WINDOW, "zero-window"),
        (KEEP_ALIVE, "keep-alive"),
        (FAST_RETRANSMISSION, "fast-retransmission"),
        (RESET, "reset"),
    ];
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
    /// IP protocol number of the transport (6 TCP, 17 UDP, …).
    pub ip_proto: Option<u8>,
    pub ttl: Option<u8>,
    pub vlan: Option<u16>,
    pub tcp: Option<Tcp>,
    /// Transport payload within the decoded bytes; empty when there is none.
    pub payload: (u32, u32),
    pub fragment: Option<Fragment>,
    /// Conversation number and TCP diagnostics, assigned by the analyzer.
    pub stream: Option<u32>,
    pub diag: u8,
    /// Bits ([`Protocol::bit`]) of enclosing protocols such as MPLS or ESP
    /// that `protocol` no longer names once an inner packet was decoded.
    pub seen: u64,
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
            ip_proto: None,
            ttl: None,
            vlan: None,
            tcp: None,
            payload: (0, 0),
            fragment: None,
            stream: None,
            diag: 0,
            seen: 0,
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
    /// Raw IP datagram that the details and hex views show instead of
    /// `bytes`: rebuilt from IP fragments, or (with `stream_message`) a
    /// reassembled or decrypted TCP message.
    pub reassembled: Option<Box<[u8]>>,
    /// `reassembled` is an application message from the TCP stream. The
    /// summary's protocol and info describe it, while its addresses, TCP
    /// values and payload range still describe the captured segment.
    pub stream_message: bool,
    /// Link type of `reassembled` (raw IP unless a decrypted frame says otherwise).
    pub reassembled_link: i32,
    /// Application protocol the analyzer learned from the conversation
    /// (HTTP/2 after its preface, WebSocket after an upgrade, RTP from SDP).
    pub hint: Option<Protocol>,
    pub mark: bool,
    pub comment: Option<String>,
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
            reassembled: None,
            stream_message: false,
            reassembled_link: LINK_RAW,
            hint: None,
            mark: false,
            comment: None,
        }
    }

    /// The bytes and link type that `summary` and `details` describe.
    pub fn view(&self) -> (&[u8], i32) {
        match &self.reassembled {
            Some(datagram) => (datagram, self.reassembled_link),
            None => (&self.bytes, self.link),
        }
    }

    /// The protocol tree of the bytes `view` returns.
    pub fn layers(&self) -> Vec<Layer> {
        let (bytes, link) = self.view();
        inspect(bytes, link, true, self.hint).1
    }

    /// Transport payload of the captured packet (or of the IP datagram
    /// rebuilt from fragments).
    pub fn payload(&self) -> &[u8] {
        let (start, end) = self.summary.payload;
        let bytes = if self.stream_message {
            &self.bytes
        } else {
            self.view().0
        };
        bytes.get(start as usize..end as usize).unwrap_or_default()
    }

    /// The application message the summary describes: the reassembled or
    /// decrypted stream message when there is one, else the payload.
    pub fn message(&self) -> &[u8] {
        match &self.reassembled {
            // Synthetic header: IPv4 (20) or IPv6 (40) plus a 20-byte TCP header.
            Some(raw) if self.stream_message => raw
                .get(if raw[0] >> 4 == 4 { 40 } else { 60 }..)
                .unwrap_or_default(),
            _ => self.payload(),
        }
    }

    pub fn memory_size(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.bytes.len()
            + self.reassembled.as_ref().map_or(0, |b| b.len())
            + self.comment.as_ref().map_or(0, String::capacity)
            + self.summary.info.capacity()
            + self.summary.warning.as_ref().map_or(0, String::capacity)
            + 32
    }
}

/// LINKTYPE_RAW: the bytes start with an IPv4 or IPv6 header.
pub const LINK_RAW: i32 = 101;

pub fn decode(bytes: &[u8], link: i32) -> Summary {
    inspect(bytes, link, false, None).0
}
/// Decodes with the application protocol `hint` tried first.
pub fn decode_hinted(bytes: &[u8], link: i32, hint: Option<Protocol>) -> Summary {
    inspect(bytes, link, false, hint).0
}
pub fn details(bytes: &[u8], link: i32) -> Vec<Layer> {
    inspect(bytes, link, true, None).1
}

// Ranges always refer to captured bytes, including for truncated headers.
struct Decoder<'a> {
    bytes: &'a [u8],
    summary: Summary,
    layers: Vec<Layer>,
    detailed: bool,
    /// Tunnel nesting depth.
    depth: u8,
    hint: Option<Protocol>,
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

impl Decoder<'_> {
    /// Ethernet II at `start`, continuing into its payload.
    fn ethernet(&mut self, start: usize) {
        let bytes = self.bytes;
        if bytes.len() < start + 14 {
            self.warn("Truncated link header");
            return;
        }
        self.layer("Ethernet II", start, start + 14);
        self.field(start, start + 6, || {
            format!("Destination: {}", mac(&bytes[start..start + 6]))
        });
        self.field(start + 6, start + 12, || {
            format!("Source: {}", mac(&bytes[start + 6..start + 12]))
        });
        self.field(start + 12, start + 14, || {
            format!("EtherType: 0x{:04x}", be16(bytes, start + 12))
        });
        // Values up to 1500 are an 802.3 length followed by LLC.
        if be16(bytes, start + 12) <= 1500 {
            let end = (start + 14 + usize::from(be16(bytes, start + 12))).min(bytes.len());
            self.llc(start + 14, end);
        } else {
            self.ethertype(be16(bytes, start + 12), start + 14);
        }
    }

    /// VLAN tags, then the network layer named by `ethertype`.
    fn ethertype(&mut self, mut ethertype: u16, mut offset: usize) {
        let bytes = self.bytes;
        let mut vlans = 0;
        while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
            if offset + 4 > bytes.len() || vlans == 8 {
                self.warn("Truncated or excessive VLAN headers");
                return;
            }
            self.layer("802.1Q VLAN", offset, offset + 4);
            self.field(offset, offset + 2, || {
                format!("VLAN ID: {}", be16(bytes, offset) & 0xfff)
            });
            self.summary.vlan.get_or_insert(be16(bytes, offset) & 0xfff);
            ethertype = be16(bytes, offset + 2);
            offset += 4;
            vlans += 1;
        }
        self.network(ethertype, offset);
    }
}

fn inspect(
    bytes: &[u8],
    link: i32,
    detailed: bool,
    hint: Option<Protocol>,
) -> (Summary, Vec<Layer>) {
    let mut decoder = Decoder {
        bytes,
        summary: Summary::default(),
        layers: Vec::new(),
        detailed,
        depth: 0,
        hint,
    };
    match link {
        1 => decoder.ethernet(0),
        113 if bytes.len() >= 16 => {
            decoder.layer("Linux cooked capture (SLL)", 0, 16);
            decoder.ethertype(be16(bytes, 14), 16);
        }
        276 if bytes.len() >= 20 => {
            decoder.layer("Linux cooked capture (SLL2)", 0, 20);
            decoder.ethertype(be16(bytes, 0), 20);
        }
        12 | 101 | 228 | 229 if !bytes.is_empty() => {
            decoder.ethertype(if bytes[0] >> 4 == 6 { 0x86dd } else { 0x0800 }, 0);
        }
        113 | 276 | 12 | 101 | 228 | 229 => decoder.warn("Truncated link header"),
        _ if decoder.link(link) => {}
        _ => decoder.warn(format!("Unsupported link type {link}")),
    }
    if detailed && decoder.layers.is_empty() {
        decoder.layer("Raw bytes", 0, bytes.len());
    }
    (decoder.summary, decoder.layers)
}

/// True when the ones-complement sum of `parts` verifies (RFC 1071).
fn checksum_ok(parts: &[&[u8]]) -> bool {
    let mut sum = 0u32;
    for part in parts {
        for pair in part.chunks(2) {
            sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
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
