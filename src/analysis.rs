//! Stateful analysis of packets in capture order: IP fragment reassembly,
//! conversation (stream) numbering, TCP diagnostics, reassembly of
//! application messages that span TCP segments, and TLS decryption with a
//! key log. All tables and buffers are bounded.
use crate::{
    crypto,
    decode::{
        decode, decode_hinted, diag, http_message_length, http_summary,
        quic::{self, Frame},
        tls::{hello, is_record},
        wlan_data, Packet, Protocol, Summary, LINK_RAW,
    },
    tls::{Decryptor, KeyLog},
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
};

const MAX_FLOWS: usize = 65_536;
const MAX_DATAGRAMS: usize = 256;
const MAX_DATAGRAM_BYTES: usize = 65_535;
const FLOW_IDLE_NS: i128 = 60_000_000_000;
/// Largest reassembled or decrypted message; it must fit a synthetic IP datagram.
const MAX_MESSAGE: usize = 60_000;
/// Bytes of incomplete messages buffered across all conversations.
const MAX_BUFFERED: usize = 64 * 1024 * 1024;
/// Conversations with TLS decryption state.
const MAX_TLS: usize = 4096;
/// WPA handshakes and RTP ports remembered.
const MAX_WPA: usize = 1024;
const MAX_RTP_PORTS: usize = 4096;
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

type Endpoint = (IpAddr, u16);

#[derive(Default)]
struct Side {
    next_seq: Option<u32>,
    /// Sequence ranges skipped by segments that arrived ahead (at most 8).
    holes: Vec<(u32, u32)>,
    last_ack: Option<(u32, u16)>,
    dup_acks: u8,
    /// Start of an application message still waiting for more segments.
    pending: Vec<u8>,
    segments: u16,
}

struct Flow {
    stream: u32,
    last_ns: i128,
    sides: [Side; 2],
    tls: Option<Box<Decryptor>>,
    /// Which side sent the ClientHello.
    tls_client: Option<usize>,
    /// Application protocol learned from earlier packets.
    hint: Option<Protocol>,
    quic: Option<Box<Quic>>,
}

/// Packet protection state of one QUIC connection. Arrays are indexed by
/// the sending side; `largest` also by packet number space.
#[derive(Default)]
struct Quic {
    v2: bool,
    client: usize,
    initial: [Option<quic::Keys>; 2],
    handshake: [Option<quic::Keys>; 2],
    application: [Option<quic::Keys>; 2],
    /// Handshake messages carried by each side's Initial packets.
    crypto: [Vec<u8>; 2],
    client_random: Option<[u8; 32]>,
    suite: Option<u16>,
    /// Length of the connection ID each side chose for itself.
    scid_len: [usize; 2],
    largest: [[Option<u64>; 3]; 2],
}

impl Quic {
    /// Reads the hellos collected so far and derives the keys they unlock.
    fn learn(&mut self, keylog: Option<&KeyLog>) {
        for side in 0..2 {
            let data = &self.crypto[side];
            let Some(body) = data.get(4..).filter(|_| data[0] == 1 || data[0] == 2) else {
                continue;
            };
            let Some(hello) = hello(data[0], body) else {
                continue;
            };
            if data[0] == 1 {
                self.client_random = Some(hello.random);
            } else {
                self.suite = hello.cipher;
            }
        }
        let (Some(random), Some(suite), Some(log)) = (self.client_random, self.suite, keylog)
        else {
            return;
        };
        let secrets = log.quic_secrets(random);
        let keys = |index: usize| secrets[index].and_then(|s| quic::keys(suite, s, self.v2));
        let server = 1 - self.client;
        if self.handshake[self.client].is_none() {
            self.handshake[self.client] = keys(0);
            self.handshake[server] = keys(1);
            self.application[self.client] = keys(2);
            self.application[server] = keys(3);
        }
    }
}

/// Decrypts the QUIC packets of one UDP `payload` sent by side `mine` and
/// returns their frames, concatenated.
fn quic_datagram(
    state: &mut Option<Box<Quic>>,
    keylog: Option<&KeyLog>,
    payload: &[u8],
    mine: usize,
) -> Option<Vec<u8>> {
    let mut plain = Vec::new();
    let mut at = 0;
    // A datagram may coalesce several packets; each consumes at least a byte.
    for _ in 0..8 {
        let first = *payload.get(at)?;
        let (space, pn_offset, end) = if first & 0x80 != 0 {
            let Some(long) = quic::long_header(payload, at) else {
                break;
            };
            if long.kind == 0 && state.is_none() {
                let dcid = &payload[long.dcid.clone()];
                let mut quic = Quic {
                    v2: long.version == 0x6b33_43cf,
                    client: mine,
                    ..Quic::default()
                };
                quic.initial[mine] = quic::initial_keys(long.version, dcid, true);
                quic.initial[1 - mine] = quic::initial_keys(long.version, dcid, false);
                *state = Some(Box::new(quic));
            }
            let Some(quic) = state.as_mut() else {
                break;
            };
            quic.scid_len[mine] = long.scid.len();
            match long.kind {
                0 => (0, long.pn_offset, long.end),
                2 => (1, long.pn_offset, long.end),
                _ => {
                    at = long.end;
                    continue;
                }
            }
        } else {
            let peer_id = state.as_ref()?.scid_len[1 - mine];
            (2, at + 1 + peer_id, payload.len())
        };
        let quic = state.as_mut()?;
        let keys = match space {
            0 => &quic.initial[mine],
            1 => &quic.handshake[mine],
            _ => &quic.application[mine],
        };
        let opened = keys.as_ref().and_then(|keys| {
            quic::open(keys, payload, at, pn_offset, end, quic.largest[mine][space])
        });
        if let Some((number, frames)) = opened {
            let largest = &mut quic.largest[mine][space];
            *largest = Some(largest.map_or(number, |l| l.max(number)));
            if space == 0 {
                for (frame, _) in quic::frames(&frames) {
                    if let Frame::Crypto { offset, data } = frame {
                        // In-order handshake data only, and a bounded amount.
                        if offset as usize == quic.crypto[mine].len() && offset < 1 << 16 {
                            quic.crypto[mine].extend(&frames[data]);
                        }
                    }
                }
                quic.learn(keylog);
            }
            plain.extend(frames);
        }
        at = end;
        if at >= payload.len() {
            break;
        }
    }
    (!plain.is_empty()).then_some(plain)
}

/// One station's WPA 4-way handshake with an access point.
struct Wpa {
    anonce: [u8; 32],
    key: Option<[u8; 16]>,
}

struct Datagram {
    first_ns: i128,
    pieces: BTreeMap<u32, Vec<u8>>,
    bytes: usize,
    total: Option<u32>,
}

#[derive(Default)]
pub struct Analyzer {
    flows: HashMap<(Endpoint, Endpoint, u8), Flow>,
    next_stream: u32,
    datagrams: HashMap<(IpAddr, IpAddr, u32, u8), Datagram>,
    keylog: Option<Arc<KeyLog>>,
    buffered: usize,
    tls_flows: usize,
    /// Keyed by (BSSID, station).
    wpa: HashMap<([u8; 6], [u8; 6]), Wpa>,
    /// UDP ports that SDP offers announced for media.
    rtp_ports: HashSet<u16>,
}

/// An IP header for `length` payload bytes of `protocol`.
fn ip_header(src: IpAddr, dst: IpAddr, protocol: u8, ttl: u8, length: usize) -> Option<Vec<u8>> {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut header = vec![0x45, 0];
            header.extend(u16::try_from(length + 20).ok()?.to_be_bytes());
            header.extend([0, 0, 0, 0, ttl, protocol, 0, 0]);
            header.extend(src.octets());
            header.extend(dst.octets());
            Some(header)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut header = vec![0x60, 0, 0, 0];
            header.extend(u16::try_from(length).ok()?.to_be_bytes());
            header.extend([protocol, ttl]);
            header.extend(src.octets());
            header.extend(dst.octets());
            Some(header)
        }
        _ => None,
    }
}

/// `a` precedes `b` in TCP sequence space.
fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Length of the complete application messages at the start of `data`:
/// `Some(0)` while the first one is incomplete, `None` when `data` does not
/// start with a message whose length can be told (TLS records, HTTP/1.x,
/// DNS over TCP, SMB).
fn complete_messages(data: &[u8], dns: bool) -> Option<usize> {
    let fits = |total: usize| Some(if total <= data.len() { total } else { 0 });
    if is_record(data) || (data.len() < 5 && matches!(data.first(), Some(20..=23))) {
        let mut end = 0;
        while is_record(&data[end..]) {
            let next = end + 5 + (usize::from(data[end + 3]) << 8 | usize::from(data[end + 4]));
            if next > data.len() {
                break;
            }
            end = next;
        }
        Some(end)
    } else if http_summary(data).is_some() {
        match http_message_length(data) {
            // A body too large to reassemble: decode the head alone.
            Some(total) if total > MAX_MESSAGE => {
                Some(data.windows(4).position(|w| w == b"\r\n\r\n")? + 4)
            }
            Some(total) => fits(total),
            None => (data.len() <= 16 * 1024).then_some(0),
        }
    } else if data.len() >= 8 && data[0] == 0 && &data[5..8] == b"SMB" {
        fits(4 + (usize::from(data[1]) << 16 | usize::from(data[2]) << 8 | usize::from(data[3])))
    } else if dns && data.len() >= 2 {
        let length = usize::from(data[0]) << 8 | usize::from(data[1]);
        (length >= 12).then(|| fits(2 + length)).flatten()
    } else {
        None
    }
}

/// A raw IP datagram carrying `message` as the TCP payload of `summary`'s
/// endpoints, so the ordinary decoders can describe it.
fn synthesize(summary: &Summary, message: &[u8]) -> Option<Vec<u8>> {
    let tcp = summary.tcp?;
    let length = (20 + message.len()) as u16;
    let mut raw = match (summary.src?, summary.dst?) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut header = vec![0x45, 0];
            header.extend((length + 20).to_be_bytes());
            header.extend([0, 0, 0, 0, summary.ttl.unwrap_or(0), 6, 0, 0]);
            header.extend(src.octets());
            header.extend(dst.octets());
            header
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut header = vec![0x60, 0, 0, 0];
            header.extend(length.to_be_bytes());
            header.extend([6, summary.ttl.unwrap_or(0)]);
            header.extend(src.octets());
            header.extend(dst.octets());
            header
        }
        _ => return None,
    };
    raw.extend(summary.src_port?.to_be_bytes());
    raw.extend(summary.dst_port?.to_be_bytes());
    raw.extend(tcp.seq.to_be_bytes());
    raw.extend(tcp.ack.to_be_bytes());
    raw.extend([0x50, tcp.flags]);
    raw.extend(tcp.window.to_be_bytes());
    raw.extend([0; 4]);
    raw.extend(message);
    Some(raw)
}

impl Analyzer {
    /// An analyzer that also decrypts TLS sessions found in `keylog`.
    pub fn new(keylog: Option<Arc<KeyLog>>) -> Self {
        Self {
            keylog: KeyLog::or_private_keys(keylog),
            ..Self::default()
        }
    }

    /// Annotates `packet`; call once per packet, in capture order.
    pub fn observe(&mut self, packet: &mut Packet) {
        if matches!(packet.link, 105 | 127) {
            self.wpa(packet);
        }
        self.defragment(packet);
        self.esp(packet);
        let summary = &mut packet.summary;
        let (Some(protocol @ (6 | 17)), Some(src), Some(dst), Some(sport), Some(dport)) = (
            summary.ip_proto,
            summary.src,
            summary.dst,
            summary.src_port,
            summary.dst_port,
        ) else {
            return;
        };
        let (from, to) = ((src, sport), (dst, dport));
        let forward = from <= to;
        let key = if forward {
            (from, to, protocol)
        } else {
            (to, from, protocol)
        };
        if !self.flows.contains_key(&key) && self.flows.len() >= MAX_FLOWS {
            // ponytail: idle flows are pruned, then the table is reset; a
            // resumed conversation gets a new number. Use an LRU if that hurts.
            let now = packet.timestamp_ns;
            self.flows
                .retain(|_, flow| now - flow.last_ns < FLOW_IDLE_NS);
            if self.flows.len() >= MAX_FLOWS {
                self.flows.clear();
            }
            let sides = self.flows.values().flat_map(|flow| &flow.sides);
            self.buffered = sides.map(|side| side.pending.len()).sum();
            self.tls_flows = self
                .flows
                .values()
                .filter(|flow| flow.tls.is_some() || flow.quic.is_some())
                .count();
        }
        let flow = self.flows.entry(key).or_insert_with(|| {
            self.next_stream += 1;
            Flow {
                stream: self.next_stream - 1,
                last_ns: 0,
                sides: Default::default(),
                tls: None,
                tls_client: None,
                hint: None,
                quic: None,
            }
        });
        flow.last_ns = packet.timestamp_ns;
        summary.stream = Some(flow.stream);
        let Some(tcp) = summary.tcp else {
            if summary.protocol == Protocol::Quic && packet.reassembled.is_none() {
                let (start, end) = (summary.payload.0 as usize, summary.payload.1 as usize);
                let payload = packet.bytes.get(start..end).unwrap_or_default();
                if flow.quic.is_none() && self.tls_flows >= MAX_TLS {
                    return;
                }
                let had_state = flow.quic.is_some();
                let plain = quic_datagram(
                    &mut flow.quic,
                    self.keylog.as_deref(),
                    payload,
                    usize::from(!forward),
                );
                self.tls_flows += usize::from(!had_state && flow.quic.is_some());
                let raw = plain.and_then(|plain| {
                    let ttl = summary.ttl.unwrap_or(0);
                    let mut raw = ip_header(src, dst, 17, ttl, 8 + plain.len())?;
                    raw.extend(sport.to_be_bytes());
                    raw.extend(dport.to_be_bytes());
                    raw.extend(u16::try_from(8 + plain.len()).ok()?.to_be_bytes());
                    raw.extend([0, 0]);
                    raw.extend(plain);
                    Some(raw)
                });
                if let Some(raw) = raw {
                    let mut described = decode_hinted(&raw, LINK_RAW, Some(Protocol::Http3));
                    described.info = format!("[Decrypted QUIC] {}", described.info);
                    described.stream = summary.stream;
                    described.vlan = summary.vlan;
                    described.seen |= Protocol::Quic.bit();
                    packet.summary = described;
                    packet.reassembled = Some(raw.into());
                    packet.reassembled_link = LINK_RAW;
                    packet.hint = Some(Protocol::Http3);
                }
                return;
            }
            // Media on a port that an SDP offer announced.
            if summary.protocol == Protocol::Udp
                && (self.rtp_ports.contains(&sport) || self.rtp_ports.contains(&dport))
            {
                let (bytes, link) = match &packet.reassembled {
                    Some(datagram) => (&**datagram, packet.reassembled_link),
                    None => (&*packet.bytes, packet.link),
                };
                let described = decode_hinted(bytes, link, Some(Protocol::Rtp));
                if described.protocol != Protocol::Udp {
                    summary.protocol = described.protocol;
                    summary.info = described.info;
                    packet.hint = Some(Protocol::Rtp);
                }
            } else if summary.protocol == Protocol::Sip {
                let (start, end) = (summary.payload.0 as usize, summary.payload.1 as usize);
                let bytes = packet.reassembled.as_deref().unwrap_or(&packet.bytes);
                let ports = bytes
                    .get(start..end)
                    .unwrap_or_default()
                    .split(|b| *b == b'\n')
                    .filter_map(|line| std::str::from_utf8(line).ok()?.strip_prefix("m="))
                    .filter_map(|media| media.split(' ').nth(1)?.trim().parse::<u16>().ok());
                for port in ports {
                    if self.rtp_ports.len() < MAX_RTP_PORTS {
                        // RTCP uses the next port.
                        self.rtp_ports.extend([port, port.saturating_add(1)]);
                    }
                }
            }
            return;
        };
        let (syn, fin, rst, ack) = (
            tcp.flags & 2 != 0,
            tcp.flags & 1 != 0,
            tcp.flags & 4 != 0,
            tcp.flags & 0x10 != 0,
        );
        let data = summary.payload.1 - summary.payload.0;
        let length = data + u32::from(syn) + u32::from(fin);
        let (mine, peer) = (usize::from(!forward), usize::from(forward));
        if tcp.window == 0 && !rst && !syn {
            summary.diag |= diag::ZERO_WINDOW;
        }
        if rst {
            summary.diag |= diag::RESET;
        }
        let peer_dup_acks = flow.sides[peer]
            .last_ack
            .map(|(ack, _)| (ack, flow.sides[peer].dup_acks));
        let side = &mut flow.sides[mine];
        let keep_alive =
            data <= 1 && !(syn || fin || rst) && side.next_seq == Some(tcp.seq.wrapping_add(1));
        let in_order = side.next_seq.is_none_or(|next| next == tcp.seq);
        if keep_alive {
            summary.diag |= diag::KEEP_ALIVE;
        } else if length > 0 {
            let end = tcp.seq.wrapping_add(length);
            match side.next_seq {
                Some(next) if seq_before(tcp.seq, next) => {
                    // A segment filling a recorded hole is late, not retransmitted.
                    let hole = side.holes.iter().position(|(start, end)| {
                        !seq_before(tcp.seq, *start) && seq_before(tcp.seq, *end)
                    });
                    match hole {
                        Some(index)
                            if side.holes[index].0 == tcp.seq
                                && seq_before(end, side.holes[index].1) =>
                        {
                            side.holes[index].0 = end;
                        }
                        Some(index) => drop(side.holes.remove(index)),
                        None => {
                            summary.diag |= diag::RETRANSMISSION;
                            if peer_dup_acks
                                .is_some_and(|(ack, count)| ack == tcp.seq && count >= 2)
                            {
                                summary.diag |= diag::FAST_RETRANSMISSION;
                            }
                        }
                    }
                }
                Some(next) if seq_before(next, tcp.seq) => {
                    summary.diag |= diag::OUT_OF_ORDER;
                    if side.holes.len() == 8 {
                        side.holes.remove(0);
                    }
                    side.holes.push((next, tcp.seq));
                }
                _ => {}
            }
            let next = &mut side.next_seq;
            if next.is_none_or(|next| seq_before(next, end)) {
                *next = Some(end);
            }
        } else if ack && !rst {
            let outstanding = flow.sides[peer]
                .next_seq
                .is_some_and(|next| seq_before(tcp.ack, next));
            let side = &mut flow.sides[mine];
            if outstanding && side.last_ack == Some((tcp.ack, tcp.window)) {
                summary.diag |= diag::DUP_ACK;
                side.dup_acks = side.dup_acks.saturating_add(1);
            } else {
                side.dup_acks = 0;
            }
        }
        if ack {
            flow.sides[mine].last_ack = Some((tcp.ack, tcp.window));
        }

        // Application messages: complete ones at this point of the stream.
        let side = &mut flow.sides[mine];
        let mut ready: Option<(Vec<u8>, u16)> = None;
        if data > 0 && !keep_alive {
            let (start, end) = (summary.payload.0 as usize, summary.payload.1 as usize);
            let bytes = packet.reassembled.as_deref().unwrap_or(&packet.bytes);
            let payload = bytes.get(start..end).unwrap_or_default();
            self.buffered -= side.pending.len();
            if !in_order {
                // Reassembly follows the first copy of in-order data only.
                side.pending.clear();
            } else if side.pending.is_empty() {
                if let Some(complete) = complete_messages(payload, sport == 53 || dport == 53) {
                    if complete > 0 {
                        ready = Some((payload[..complete].to_vec(), 1));
                    }
                    if self.buffered < MAX_BUFFERED {
                        side.pending = payload[complete..].to_vec();
                        side.segments = 1;
                    }
                }
            } else {
                side.pending.extend_from_slice(payload);
                side.segments = side.segments.saturating_add(1);
                match complete_messages(&side.pending, sport == 53 || dport == 53) {
                    Some(0) if side.pending.len() <= MAX_MESSAGE => {}
                    Some(complete) if complete > 0 => {
                        ready = Some((side.pending.drain(..complete).collect(), side.segments));
                        side.segments = 1;
                    }
                    _ => side.pending.clear(),
                }
            }
            self.buffered += side.pending.len();
        }

        // Protocols recognised from the conversation rather than one packet.
        if data > 0 && !keep_alive {
            let (start, end) = (summary.payload.0 as usize, summary.payload.1 as usize);
            let (bytes, link) = match &packet.reassembled {
                Some(datagram) => (&**datagram, packet.reassembled_link),
                None => (&*packet.bytes, packet.link),
            };
            let payload = bytes.get(start..end).unwrap_or_default();
            if payload.starts_with(HTTP2_PREFACE) {
                flow.hint = Some(Protocol::Http2);
            }
            if summary.protocol == Protocol::Tcp && flow.hint.is_some() {
                let described = decode_hinted(bytes, link, flow.hint);
                if described.protocol != Protocol::Tcp {
                    summary.protocol = described.protocol;
                    summary.info = described.info;
                    summary.seen |= described.seen;
                    packet.hint = flow.hint;
                }
            }
            let head = &payload[..payload.len().min(2048)];
            if head.starts_with(b"HTTP/1.1 101")
                && head
                    .windows(9)
                    .any(|w| w.eq_ignore_ascii_case(b"websocket"))
            {
                flow.hint = Some(Protocol::WebSocket);
            }
        }

        let mut shown: Option<(Vec<u8>, String)> = None;
        if let Some((message, segments)) = ready {
            // TLS: decrypt the complete records when the key log allows.
            if is_record(&message) {
                if flow.tls.is_none() && self.tls_flows < MAX_TLS {
                    if let Some(log) = &self.keylog {
                        flow.tls = Some(Box::new(Decryptor::new(Arc::clone(log))));
                        self.tls_flows += 1;
                    }
                }
                if let Some(tls) = &mut flow.tls {
                    let mut plain = Vec::new();
                    let mut at = 0;
                    while at + 5 <= message.len() {
                        let next = at
                            + 5
                            + (usize::from(message[at + 3]) << 8 | usize::from(message[at + 4]));
                        let Some(record) = message.get(at..next) else {
                            break;
                        };
                        // The side sending the first ClientHello is the client.
                        if flow.tls_client.is_none() && record[0] == 22 && record.get(5) == Some(&1)
                        {
                            flow.tls_client = Some(mine);
                        }
                        for chunk in tls.feed(flow.tls_client == Some(mine), record) {
                            plain.extend(chunk.data);
                        }
                        at = next;
                    }
                    if !plain.is_empty() {
                        if plain.starts_with(HTTP2_PREFACE) {
                            flow.hint = Some(Protocol::Http2);
                        }
                        plain.truncate(MAX_MESSAGE);
                        shown = Some((plain, "Decrypted TLS".into()));
                    }
                }
            }
            if shown.is_none() && segments > 1 && message.len() <= MAX_MESSAGE {
                shown = Some((message, format!("Reassembled {segments} segments")));
            }
        }
        // A datagram rebuilt from IP fragments keeps its own view.
        if let Some((message, note)) = shown.filter(|_| packet.reassembled.is_none()) {
            if let Some(raw) = synthesize(summary, &message) {
                let described = decode_hinted(&raw, LINK_RAW, flow.hint);
                packet.hint = flow.hint;
                summary.protocol = described.protocol;
                summary.seen |= described.seen;
                summary.info = if described.protocol == Protocol::Tcp {
                    format!("[{note}] {} bytes of application data", message.len())
                } else {
                    format!("[{note}] {}", described.info)
                };
                packet.reassembled = Some(raw.into());
                packet.stream_message = true;
            }
        }
        let summary = &mut packet.summary;
        for (bit, name) in diag::NAMES {
            if summary.diag & bit != 0 {
                summary.info += &format!(" · [{name}]");
            }
        }
    }

    /// Follows WPA 4-way handshakes and decrypts CCMP data frames of stations
    /// whose handshake a configured passphrase confirms.
    fn wpa(&mut self, packet: &mut Packet) {
        let Some(frame) = wlan_data(&packet.bytes, packet.link) else {
            return;
        };
        let key = (frame.bssid, frame.station);
        let body = &packet.bytes[frame.body..frame.end];
        if !frame.protected {
            // EAPOL-Key inside LLC/SNAP.
            let Some(eapol) = body
                .strip_prefix(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e])
                .filter(|eapol| eapol.len() >= 99 && eapol[1] == 3)
            else {
                return;
            };
            let info = u16::from(eapol[5]) << 8 | u16::from(eapol[6]);
            if info & 0x80 != 0 {
                // Messages 1 and 3 carry the access point's nonce.
                if info & 0x100 == 0 || !self.wpa.contains_key(&key) {
                    if self.wpa.len() >= MAX_WPA {
                        self.wpa.clear();
                    }
                    let anonce = eapol[17..49].try_into().unwrap_or_default();
                    self.wpa.insert(key, Wpa { anonce, key: None });
                }
            } else if info & 0x100 != 0 && eapol[17..49] != [0; 32] {
                if let Some(entry) = self.wpa.get_mut(&key) {
                    if let Some(temporal) =
                        crypto::wpa_temporal_key(&frame.bssid, &frame.station, &entry.anonce, eapol)
                    {
                        entry.key = Some(temporal);
                    }
                }
            }
            return;
        }
        // ponytail: pairwise CCMP only; broadcast frames need the group key
        // from handshake message 3 (AES key unwrap) and stay encrypted.
        let Some(temporal) = self.wpa.get(&key).and_then(|entry| entry.key) else {
            return;
        };
        let header = &packet.bytes[frame.header..frame.body];
        let Some(plain) = crypto::ccmp_decrypt(&temporal, header, frame.qos, body) else {
            return;
        };
        let Some(inner) = plain.strip_prefix(&[0xaa, 0xaa, 3, 0, 0, 0]) else {
            return;
        };
        let mut ethernet = frame.destination.to_vec();
        ethernet.extend(frame.source);
        ethernet.extend(inner);
        let mut summary = decode(&ethernet, 1);
        summary.info = format!("[Decrypted WPA] {}", summary.info);
        summary.seen |= Protocol::Wlan.bit();
        packet.summary = summary;
        packet.reassembled = Some(ethernet.into());
        packet.reassembled_link = 1;
    }

    /// Decrypts ESP with a configured security association and re-decodes
    /// the packet from the inner datagram.
    fn esp(&mut self, packet: &mut Packet) {
        let summary = &packet.summary;
        if summary.protocol != Protocol::Esp {
            return;
        }
        let (start, end) = (summary.payload.0 as usize, summary.payload.1 as usize);
        let bytes = packet.reassembled.as_deref().unwrap_or(&packet.bytes);
        let Some((next, inner)) = bytes
            .get(start..end)
            .and_then(crypto::esp_decrypt)
            .filter(|(_, inner)| inner.len() <= MAX_DATAGRAM_BYTES)
        else {
            return;
        };
        // Tunnel mode carries a whole IP packet; transport mode its payload.
        let raw = if matches!(next, 4 | 41) {
            inner
        } else {
            let (Some(src), Some(dst)) = (summary.src, summary.dst) else {
                return;
            };
            let Some(mut raw) = ip_header(src, dst, next, summary.ttl.unwrap_or(0), inner.len())
            else {
                return;
            };
            raw.extend(inner);
            raw
        };
        let mut decoded = decode(&raw, LINK_RAW);
        decoded.info = format!("[Decrypted ESP] {}", decoded.info);
        decoded.seen |= Protocol::Esp.bit();
        decoded.vlan = summary.vlan;
        packet.summary = decoded;
        packet.reassembled = Some(raw.into());
        packet.reassembled_link = LINK_RAW;
    }

    /// Collects IP fragments; the packet completing a datagram is re-decoded
    /// from the rebuilt datagram.
    fn defragment(&mut self, packet: &mut Packet) {
        let (Some(fragment), Some(src), Some(dst)) = (
            packet.summary.fragment,
            packet.summary.src,
            packet.summary.dst,
        ) else {
            return;
        };
        let Some(data) = packet
            .bytes
            .get(fragment.start as usize..fragment.end as usize)
        else {
            return;
        };
        let key = (src, dst, fragment.id, fragment.protocol);
        if !self.datagrams.contains_key(&key) && self.datagrams.len() >= MAX_DATAGRAMS {
            let oldest = self
                .datagrams
                .iter()
                .min_by_key(|(_, d)| d.first_ns)
                .map(|(k, _)| *k);
            oldest.and_then(|oldest| self.datagrams.remove(&oldest));
        }
        let datagram = self.datagrams.entry(key).or_insert_with(|| Datagram {
            first_ns: packet.timestamp_ns,
            pieces: BTreeMap::new(),
            bytes: 0,
            total: None,
        });
        let end = fragment.offset as usize + data.len();
        if end > MAX_DATAGRAM_BYTES || datagram.bytes + data.len() > 2 * MAX_DATAGRAM_BYTES {
            self.datagrams.remove(&key);
            packet
                .summary
                .warning
                .get_or_insert_with(|| "Fragments exceed the datagram size limit".into());
            return;
        }
        if !fragment.more {
            datagram.total = Some(end as u32);
        }
        datagram.bytes += data.len();
        datagram.pieces.insert(fragment.offset, data.to_vec());
        let Some(total) = datagram.total else {
            return;
        };
        let mut payload = Vec::with_capacity(total as usize);
        for (offset, piece) in &datagram.pieces {
            let offset = *offset as usize;
            if offset > payload.len() {
                return; // A hole remains.
            }
            payload.extend_from_slice(piece.get(payload.len() - offset..).unwrap_or_default());
        }
        if payload.len() < total as usize {
            return;
        }
        payload.truncate(total as usize);
        let count = datagram.pieces.len();
        self.datagrams.remove(&key);
        let mut raw = match (src, dst) {
            (IpAddr::V4(src), IpAddr::V4(dst)) if payload.len() + 20 <= MAX_DATAGRAM_BYTES => {
                let mut header = vec![0x45, 0];
                header.extend(((payload.len() + 20) as u16).to_be_bytes());
                header.extend((fragment.id as u16).to_be_bytes());
                header.extend([
                    0,
                    0,
                    packet.summary.ttl.unwrap_or(0),
                    fragment.protocol,
                    0,
                    0,
                ]);
                header.extend(src.octets());
                header.extend(dst.octets());
                header
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let mut header = vec![0x60, 0, 0, 0];
                header.extend((payload.len() as u16).to_be_bytes());
                header.extend([fragment.protocol, packet.summary.ttl.unwrap_or(0)]);
                header.extend(src.octets());
                header.extend(dst.octets());
                header
            }
            _ => return,
        };
        raw.extend(payload);
        let mut summary = decode(&raw, LINK_RAW);
        summary.info = format!("[Reassembled {count} fragments] {}", summary.info);
        summary.vlan = packet.summary.vlan;
        packet.summary = summary;
        packet.reassembled = Some(raw.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Raw IPv4 TCP segment between 192.0.2.1:1000 (client) and 192.0.2.2:80.
    fn segment(
        from_client: bool,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        data: &[u8],
    ) -> Packet {
        let (src, dst, sport, dport) = if from_client {
            ([192, 0, 2, 1], [192, 0, 2, 2], 1000u16, 80u16)
        } else {
            ([192, 0, 2, 2], [192, 0, 2, 1], 80, 1000)
        };
        let mut bytes = vec![0x45, 0];
        bytes.extend(((40 + data.len()) as u16).to_be_bytes());
        bytes.extend([0, 0, 0, 0, 64, 6, 0, 0]);
        bytes.extend(src);
        bytes.extend(dst);
        bytes.extend(sport.to_be_bytes());
        bytes.extend(dport.to_be_bytes());
        bytes.extend(seq.to_be_bytes());
        bytes.extend(ack.to_be_bytes());
        bytes.extend([0x50, flags]);
        bytes.extend(window.to_be_bytes());
        bytes.extend([0; 4]);
        bytes.extend(data);
        Packet::new(0, 0, bytes.len() as u32, LINK_RAW, bytes.into())
    }

    #[test]
    fn numbers_streams_and_flags_tcp_problems() {
        let mut analyzer = Analyzer::default();
        let mut run = |mut packet: Packet| {
            analyzer.observe(&mut packet);
            (packet.summary.stream, packet.summary.diag)
        };
        assert_eq!(run(segment(true, 100, 0, 0x02, 1000, b"")), (Some(0), 0));
        assert_eq!(run(segment(false, 500, 101, 0x12, 1000, b"")), (Some(0), 0));
        assert_eq!(
            run(segment(true, 101, 501, 0x18, 1000, b"hello")),
            (Some(0), 0)
        );
        assert_eq!(
            run(segment(true, 101, 501, 0x18, 1000, b"hello")).1,
            diag::RETRANSMISSION
        );
        assert_eq!(
            run(segment(true, 116, 501, 0x18, 1000, b"later")).1,
            diag::OUT_OF_ORDER
        );
        assert_eq!(run(segment(false, 501, 106, 0x10, 1000, b"")).1, 0);
        assert_eq!(
            run(segment(false, 501, 106, 0x10, 1000, b"")).1,
            diag::DUP_ACK
        );
        assert_eq!(
            run(segment(false, 501, 121, 0x10, 0, b"")).1,
            diag::ZERO_WINDOW
        );
        // Sequence numbers wrap without being reported.
        let mut wrap = Analyzer::default();
        let mut first = segment(true, u32::MAX - 1, 0, 0x18, 1, b"abcd");
        let mut second = segment(true, 2, 0, 0x18, 1, b"efgh");
        wrap.observe(&mut first);
        wrap.observe(&mut second);
        assert_eq!((first.summary.diag, second.summary.diag), (0, 0));
        assert!(second.summary.info.ends_with("payload bytes"));
    }

    fn fragment(offset: u16, more: bool, data: &[u8]) -> Packet {
        let mut bytes = vec![0x45, 0];
        bytes.extend(((20 + data.len()) as u16).to_be_bytes());
        bytes.extend([0, 7]);
        bytes.extend(((offset / 8) | if more { 0x2000 } else { 0 }).to_be_bytes());
        bytes.extend([64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
        bytes.extend(data);
        Packet::new(0, 0, bytes.len() as u32, LINK_RAW, bytes.into())
    }

    #[test]
    fn reassembles_fragments_in_any_order_and_bounds_them() {
        let mut datagram = vec![0x13, 0x88, 0x13, 0x89, 0, 32, 0, 0];
        datagram.extend(b"0123456789abcdefghijklmn");
        let mut analyzer = Analyzer::default();
        let mut last = fragment(16, false, &datagram[16..]);
        let mut middle = fragment(8, true, &datagram[8..16]);
        let mut first = fragment(0, true, &datagram[..8]);
        for packet in [&mut last, &mut middle] {
            analyzer.observe(packet);
            assert!(packet.reassembled.is_none());
            assert_eq!(packet.summary.protocol, Protocol::Ipv4);
        }
        analyzer.observe(&mut first);
        assert_eq!(first.summary.protocol, Protocol::Udp);
        assert_eq!(first.summary.dst_port, Some(5001));
        assert_eq!(first.payload(), &datagram[8..]);
        assert!(first.summary.info.starts_with("[Reassembled 3 fragments]"));
        assert_eq!(first.summary.stream, Some(0));
        assert!(analyzer.datagrams.is_empty());

        // An oversized datagram is discarded and pending state stays bounded.
        let mut huge = fragment(65_528, true, &[0; 64]);
        analyzer.observe(&mut huge);
        assert!(huge.summary.warning.is_some());
        for id in 0..2 * MAX_DATAGRAMS as u32 {
            let mut packet = fragment(0, true, &[0; 8]);
            packet.summary.fragment.as_mut().unwrap().id = id;
            analyzer.observe(&mut packet);
        }
        assert_eq!(analyzer.datagrams.len(), MAX_DATAGRAMS);
    }
}
