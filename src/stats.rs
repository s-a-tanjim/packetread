//! Conversation, endpoint, protocol-hierarchy, response-time and traffic
//! statistics over analyzed packets. Every table is bounded.
use crate::decode::{diag, safe_text, Packet, Protocol};
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
};

const MAX_ENTRIES: usize = 50_000;
const MAX_PENDING: usize = 10_000;
const MAX_BUCKETS: usize = 10_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

impl Counter {
    fn add(&mut self, packet: &Packet) {
        self.packets += 1;
        self.bytes += u64::from(packet.wire_len);
    }
}

#[derive(Debug)]
pub struct Conversation {
    pub tcp: bool,
    /// The side that sent the first packet, then its peer.
    pub ends: [(IpAddr, u16); 2],
    pub sent: [Counter; 2],
    pub first_ns: i128,
    pub last_ns: i128,
    /// Count per `diag::NAMES` entry.
    pub problems: [u64; diag::NAMES.len()],
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Timing {
    pub count: u64,
    pub total_ns: i128,
    pub min_ns: i128,
    pub max_ns: i128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    Packets,
    Bytes,
}

pub struct Stats {
    pub total: Counter,
    pub first_ns: Option<i128>,
    pub last_ns: i128,
    pub conversations: BTreeMap<u32, Conversation>,
    /// Sent and received counters per address.
    pub endpoints: HashMap<IpAddr, [Counter; 2]>,
    pub hierarchy: BTreeMap<String, Counter>,
    pub timings: BTreeMap<&'static str, Timing>,
    pub buckets: Vec<Counter>,
    pub interval_ns: i128,
    /// Packets left out of a table because it was full.
    pub untracked: u64,
    // (kind, stream, transaction) → request time.
    pending: HashMap<(&'static str, u32, u16), i128>,
}

impl Stats {
    /// `interval` is the width of one traffic-graph bucket in seconds.
    pub fn new(interval: f64) -> Self {
        Self {
            total: Counter::default(),
            first_ns: None,
            last_ns: 0,
            conversations: BTreeMap::new(),
            endpoints: HashMap::new(),
            hierarchy: BTreeMap::new(),
            timings: BTreeMap::new(),
            buckets: Vec::new(),
            interval_ns: ((interval * 1e9) as i128).max(1_000_000),
            untracked: 0,
            pending: HashMap::new(),
        }
    }

    pub fn add(&mut self, packet: &Packet) {
        let summary = &packet.summary;
        let now = packet.timestamp_ns;
        self.total.add(packet);
        let first = *self.first_ns.get_or_insert(now);
        self.last_ns = self.last_ns.max(now);
        let bucket = ((now - first).max(0) / self.interval_ns) as usize;
        if bucket < MAX_BUCKETS {
            if self.buckets.len() <= bucket {
                self.buckets.resize(bucket + 1, Counter::default());
            }
            self.buckets[bucket].add(packet);
        }

        let network = match (summary.src, summary.protocol) {
            (_, Protocol::Arp) => "ARP",
            (Some(IpAddr::V4(_)), _) => "IPv4",
            (Some(IpAddr::V6(_)), _) => "IPv6",
            _ => "Other",
        };
        let mut path = network.to_string();
        if let Some(protocol) = summary.ip_proto {
            path += &match protocol {
                6 => " › TCP".into(),
                17 => " › UDP".into(),
                1 | 58 => " › ICMP".into(),
                _ => format!(" › IP protocol {protocol}"),
            };
            if !matches!(
                summary.protocol,
                Protocol::Tcp | Protocol::Udp | Protocol::Icmp
            ) {
                path += &format!(" › {}", summary.protocol.name());
            }
        } else if summary.fragment.is_some() {
            path += " › Fragment";
        }
        self.hierarchy.entry(path).or_default().add(packet);

        for (index, address) in [summary.src, summary.dst].into_iter().enumerate() {
            let Some(address) = address else { continue };
            if self.endpoints.len() < MAX_ENTRIES || self.endpoints.contains_key(&address) {
                self.endpoints.entry(address).or_default()[index].add(packet);
            } else if index == 0 {
                self.untracked += 1;
            }
        }

        let (Some(stream), Some(src), Some(dst)) = (
            summary.stream,
            summary.src.zip(summary.src_port),
            summary.dst.zip(summary.dst_port),
        ) else {
            return;
        };
        if self.conversations.len() >= MAX_ENTRIES && !self.conversations.contains_key(&stream) {
            self.untracked += 1;
            return;
        }
        let conversation = self
            .conversations
            .entry(stream)
            .or_insert_with(|| Conversation {
                tcp: summary.ip_proto == Some(6),
                ends: [src, dst],
                sent: Default::default(),
                first_ns: now,
                last_ns: now,
                problems: [0; diag::NAMES.len()],
            });
        conversation.sent[usize::from(conversation.ends[0] != src)].add(packet);
        conversation.last_ns = now;
        for (index, (bit, _)) in diag::NAMES.iter().enumerate() {
            conversation.problems[index] += u64::from(summary.diag & bit != 0);
        }

        // Request/response pairs: (kind, transaction id, is request).
        let payload = packet.message();
        let pair = match (summary.protocol, summary.tcp) {
            (Protocol::Dns, _) => {
                let dns = if summary.tcp.is_some() {
                    payload.get(2..)
                } else {
                    Some(payload)
                };
                dns.filter(|d| d.len() > 2)
                    .map(|d| ("DNS", u16::from_be_bytes([d[0], d[1]]), d[2] & 0x80 == 0))
            }
            (Protocol::Http, _) => Some(("HTTP", 0, !payload.starts_with(b"HTTP/"))),
            (_, Some(tcp)) if tcp.flags & 0x02 != 0 => {
                Some(("TCP handshake", 0, tcp.flags & 0x10 == 0))
            }
            _ => None,
        };
        let Some((kind, id, request)) = pair else {
            return;
        };
        if request {
            if self.pending.len() >= MAX_PENDING {
                self.pending.clear();
            }
            self.pending.entry((kind, stream, id)).or_insert(now);
        } else if let Some(sent) = self.pending.remove(&(kind, stream, id)) {
            let elapsed = (now - sent).max(0);
            let timing = self.timings.entry(kind).or_insert(Timing {
                min_ns: elapsed,
                ..Timing::default()
            });
            timing.count += 1;
            timing.total_ns += elapsed;
            timing.min_ns = timing.min_ns.min(elapsed);
            timing.max_ns = timing.max_ns.max(elapsed);
        }
    }

    /// Terminal-safe report lines; `top` bounds each ranking.
    pub fn report(&self, top: usize, unit: Unit) -> Vec<String> {
        let seconds = |ns: i128| ns as f64 / 1e9;
        let millis = |ns: i128| format!("{:.3} ms", ns as f64 / 1e6);
        let count = |c: Counter| format!("{} pkts / {}", c.packets, size(c.bytes));
        let endpoint = |(address, port): (IpAddr, u16)| match address {
            IpAddr::V6(_) => format!("[{address}]:{port}"),
            IpAddr::V4(_) => format!("{address}:{port}"),
        };
        let duration = self
            .first_ns
            .map_or(0.0, |first| seconds(self.last_ns - first));
        let mut lines = vec![format!(
            "{} packets · {} · {duration:.3} s",
            self.total.packets,
            size(self.total.bytes)
        )];

        lines.extend([String::new(), "PROTOCOL HIERARCHY".into()]);
        for (path, counter) in &self.hierarchy {
            lines.push(format!("  {path:<28} {}", count(*counter)));
        }

        let mut conversations: Vec<_> = self.conversations.iter().collect();
        conversations.sort_by_key(|(_, c)| std::cmp::Reverse(c.sent[0].bytes + c.sent[1].bytes));
        lines.extend([
            String::new(),
            format!(
                "CONVERSATIONS · top {top} of {} by bytes",
                conversations.len()
            ),
        ]);
        for (stream, c) in conversations.iter().take(top) {
            let problems: Vec<_> = diag::NAMES
                .iter()
                .zip(c.problems)
                .filter(|(_, n)| *n > 0)
                .map(|((_, name), n)| format!("{n} {name}"))
                .collect();
            lines.push(format!(
                "  #{stream} {} {} ↔ {}",
                if c.tcp { "TCP" } else { "UDP" },
                endpoint(c.ends[0]),
                endpoint(c.ends[1])
            ));
            lines.push(format!(
                "      → {} · ← {} · {:.3} s{}",
                count(c.sent[0]),
                count(c.sent[1]),
                seconds(c.last_ns - c.first_ns),
                if problems.is_empty() {
                    String::new()
                } else {
                    format!(" · {}", problems.join(", "))
                }
            ));
        }

        let mut endpoints: Vec<_> = self.endpoints.iter().collect();
        endpoints
            .sort_by_key(|(address, c)| (std::cmp::Reverse(c[0].bytes + c[1].bytes), **address));
        lines.extend([
            String::new(),
            format!("ENDPOINTS · top {top} of {} by bytes", endpoints.len()),
        ]);
        for (address, [sent, received]) in endpoints.into_iter().take(top) {
            lines.push(format!(
                "  {address:<39} sent {} · received {}",
                count(*sent),
                count(*received)
            ));
        }

        let mut problems = [0u64; diag::NAMES.len()];
        for conversation in self.conversations.values() {
            problems
                .iter_mut()
                .zip(conversation.problems)
                .for_each(|(total, n)| *total += n);
        }
        lines.extend([String::new(), "TCP DIAGNOSTICS".into()]);
        for ((_, name), total) in diag::NAMES.iter().zip(problems) {
            lines.push(format!("  {name:<20} {total}"));
        }

        lines.extend([String::new(), "RESPONSE TIMES".into()]);
        for (kind, timing) in &self.timings {
            lines.push(format!(
                "  {kind:<14} n={} · min {} · avg {} · max {}",
                timing.count,
                millis(timing.min_ns),
                millis(timing.total_ns / i128::from(timing.count.max(1))),
                millis(timing.max_ns)
            ));
        }
        if self.timings.is_empty() {
            lines.push("  no request/response pairs (DNS, HTTP, TCP handshake)".into());
        }

        let value = |c: &Counter| {
            if unit == Unit::Bytes {
                c.bytes
            } else {
                c.packets
            }
        };
        let peak = self.buckets.iter().map(value).max().unwrap_or(0).max(1);
        lines.extend([
            String::new(),
            format!(
                "TRAFFIC · {} per {} s interval",
                if unit == Unit::Bytes {
                    "bytes"
                } else {
                    "packets"
                },
                seconds(self.interval_ns)
            ),
        ]);
        // Show the most recent intervals when there are more than fit a report.
        let skip = self.buckets.len().saturating_sub(top.max(20) * 3);
        for (index, bucket) in self.buckets.iter().enumerate().skip(skip) {
            let bar = "█".repeat((value(bucket) * 40).div_ceil(peak) as usize);
            let amount = if unit == Unit::Bytes {
                size(bucket.bytes)
            } else {
                bucket.packets.to_string()
            };
            lines.push(format!(
                "  {:>9.3}s {bar:<40} {amount}",
                seconds(index as i128 * self.interval_ns)
            ));
        }
        if self.untracked > 0 {
            lines.extend([
                String::new(),
                format!("{} packets fell outside the bounded tables", self.untracked),
            ]);
        }
        lines.iter().map(|line| safe_text(line)).collect()
    }
}

pub fn size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

/// Every anomaly in the analyzed packets, grouped by severity and message.
#[derive(Default)]
pub struct Expert {
    // (severity, message) → (count, first packet numbers).
    entries: BTreeMap<(u8, String), (u64, Vec<u64>)>,
}

impl Expert {
    pub fn add(&mut self, packet: &Packet) {
        let summary = &packet.summary;
        let mut note = |severity: u8, message: &str| {
            let key = (severity, message.to_string());
            // A flood of distinct messages collapses into one bucket.
            let key = if self.entries.len() >= 1000 && !self.entries.contains_key(&key) {
                (severity, "Other messages".to_string())
            } else {
                key
            };
            let (count, first) = self.entries.entry(key).or_default();
            *count += 1;
            if first.len() < 5 {
                first.push(packet.id);
            }
        };
        if let Some(warning) = &summary.warning {
            note(0, warning);
        }
        for (bit, name) in diag::NAMES {
            if summary.diag & bit != 0 {
                let severe =
                    bit & (diag::DUP_ACK | diag::KEEP_ALIVE | diag::FAST_RETRANSMISSION) == 0;
                note(if severe { 1 } else { 2 }, &format!("TCP {name}"));
            }
        }
        if packet.reassembled.is_some() && !packet.stream_message {
            note(3, "IP datagram reassembled from fragments");
        }
    }

    /// Terminal-safe report lines, most severe first.
    pub fn report(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let mut section = None;
        for ((severity, message), (count, first)) in &self.entries {
            if section != Some(*severity) {
                section = Some(*severity);
                let title = [
                    "ERRORS · malformed or truncated",
                    "WARNINGS",
                    "NOTES",
                    "CHAT",
                ][usize::from(*severity).min(3)];
                lines.extend([String::new(), title.to_string()]);
            }
            let ids: Vec<_> = first.iter().map(u64::to_string).collect();
            lines.push(format!(
                "  {count:>7} × {} · packets {}{}",
                safe_text(message),
                ids.join(", "),
                if *count > first.len() as u64 {
                    ", …"
                } else {
                    ""
                }
            ));
        }
        if lines.is_empty() {
            lines.push("No anomalies in these packets.".into());
        } else {
            lines.remove(0);
        }
        lines
    }
}
