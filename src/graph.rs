//! Text renderings for analysis: TCP stream graphs (time-sequence,
//! throughput, window), flow diagrams between endpoints, and VoIP call and
//! RTP stream summaries. All tables are bounded.
use crate::decode::{safe_text, Packet, Protocol};
use std::{collections::BTreeMap, net::IpAddr};

const MAX_POINTS: usize = 200_000;
const MAX_ROWS: usize = 10_000;
const MAX_HOSTS: usize = 6;

/// A scatter chart of `points` drawn with text, `width` × `height` cells.
pub fn chart(
    title: &str,
    unit: &str,
    points: &[(f64, f64)],
    width: usize,
    height: usize,
) -> Vec<String> {
    let (width, height) = (width.clamp(20, 400), height.clamp(4, 100));
    let mut out = vec![title.to_string()];
    if points.is_empty() {
        out.push("  (no data)".into());
        return out;
    }
    let span = |values: &mut dyn Iterator<Item = f64>| {
        let (low, high) = values.fold((f64::MAX, f64::MIN), |(l, h), v| (l.min(v), h.max(v)));
        (low, if high > low { high } else { low + 1.0 })
    };
    let (x0, x1) = span(&mut points.iter().map(|p| p.0));
    let (y0, y1) = span(&mut points.iter().map(|p| p.1));
    let mut grid = vec![vec![' '; width]; height];
    for (x, y) in points {
        let column = (((x - x0) / (x1 - x0)) * (width - 1) as f64).round() as usize;
        let row = (((y - y0) / (y1 - y0)) * (height - 1) as f64).round() as usize;
        grid[height - 1 - row.min(height - 1)][column.min(width - 1)] = '•';
    }
    for (index, row) in grid.iter().enumerate() {
        let label = match index {
            0 => format!("{y1:>12.0}"),
            i if i == height - 1 => format!("{y0:>12.0}"),
            _ => " ".repeat(12),
        };
        out.push(format!("{label} │{}", row.iter().collect::<String>()));
    }
    out.push(format!("{} └{}", " ".repeat(12), "─".repeat(width)));
    out.push(format!(
        "{} {x0:<.3} s{}{x1:>.3} s   ({unit})",
        " ".repeat(13),
        " ".repeat(width.saturating_sub(20))
    ));
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphKind {
    Sequence,
    Throughput,
    Window,
}

/// Samples of one TCP conversation, split by direction.
pub struct TcpGraph {
    stream: u32,
    first: Option<(i128, IpAddr, u16)>,
    /// Per direction: (seconds, sequence number, payload bytes, window).
    points: [Vec<(f64, u32, u32, u16)>; 2],
    labels: [String; 2],
}

impl TcpGraph {
    pub fn new(stream: u32) -> Self {
        Self {
            stream,
            first: None,
            points: Default::default(),
            labels: Default::default(),
        }
    }

    pub fn add(&mut self, packet: &Packet) {
        let summary = &packet.summary;
        let (Some(tcp), Some(src), Some(port), Some(dst), Some(dport)) = (
            summary.tcp,
            summary.src,
            summary.src_port,
            summary.dst,
            summary.dst_port,
        ) else {
            return;
        };
        if summary.stream != Some(self.stream) {
            return;
        }
        let (start, address, first_port) =
            *self.first.get_or_insert((packet.timestamp_ns, src, port));
        let side = usize::from((address, first_port) != (src, port));
        if self.labels[side].is_empty() {
            self.labels[side] = format!("{src}:{port} → {dst}:{dport}");
        }
        if self.points[side].len() < MAX_POINTS {
            let seconds = (packet.timestamp_ns - start) as f64 / 1e9;
            let length = summary.payload.1 - summary.payload.0;
            self.points[side].push((seconds, tcp.seq, length, tcp.window));
        }
    }

    /// The chart for the direction that carried more data.
    pub fn render(&self, kind: GraphKind, width: usize, height: usize) -> Vec<String> {
        let bytes = |side: usize| {
            self.points[side]
                .iter()
                .map(|p| u64::from(p.2))
                .sum::<u64>()
        };
        let side = usize::from(bytes(1) > bytes(0));
        let points = &self.points[side];
        if self.first.is_none() {
            return vec![format!("No TCP conversation numbered {}", self.stream)];
        }
        let label = &self.labels[side];
        let base = points.first().map_or(0, |p| p.1);
        match kind {
            GraphKind::Sequence => chart(
                &format!("Time-sequence · stream {} · {label}", self.stream),
                "relative sequence number over time",
                &points
                    .iter()
                    .map(|p| (p.0, f64::from(p.1.wrapping_sub(base))))
                    .collect::<Vec<_>>(),
                width,
                height,
            ),
            GraphKind::Window => chart(
                &format!("Window · stream {} · {label}", self.stream),
                "advertised receive window in bytes over time",
                &points
                    .iter()
                    .map(|p| (p.0, f64::from(p.3)))
                    .collect::<Vec<_>>(),
                width,
                height,
            ),
            GraphKind::Throughput => {
                // Payload bytes per interval, as bytes per second.
                let end = points.last().map_or(0.0, |p| p.0);
                let buckets = width.clamp(20, 400);
                let interval = (end / buckets as f64).max(0.001);
                let mut sums = vec![0u64; buckets + 1];
                for point in points {
                    sums[((point.0 / interval) as usize).min(buckets)] += u64::from(point.2);
                }
                chart(
                    &format!("Throughput · stream {} · {label}", self.stream),
                    "payload bytes per second over time",
                    &sums
                        .iter()
                        .enumerate()
                        .map(|(index, sum)| (index as f64 * interval, *sum as f64 / interval))
                        .collect::<Vec<_>>(),
                    width,
                    height,
                )
            }
        }
    }
}

/// A sequence diagram: one column per host, one arrow per packet.
#[derive(Default)]
pub struct Flow {
    hosts: Vec<IpAddr>,
    rows: Vec<(f64, usize, usize, String)>,
    first: Option<i128>,
    omitted: u64,
}

impl Flow {
    pub fn add(&mut self, packet: &Packet) {
        let (Some(src), Some(dst)) = (packet.summary.src, packet.summary.dst) else {
            return;
        };
        let mut column = |address: IpAddr| {
            let known = self.hosts.iter().position(|host| *host == address);
            known.or_else(|| {
                (self.hosts.len() < MAX_HOSTS).then(|| {
                    self.hosts.push(address);
                    self.hosts.len() - 1
                })
            })
        };
        let (Some(from), Some(to), true) = (column(src), column(dst), self.rows.len() < MAX_ROWS)
        else {
            self.omitted += 1;
            return;
        };
        let start = *self.first.get_or_insert(packet.timestamp_ns);
        let ports = match (packet.summary.src_port, packet.summary.dst_port) {
            (Some(a), Some(b)) => format!("{a} → {b} "),
            _ => String::new(),
        };
        let label = format!(
            "{} {ports}{}",
            packet.summary.protocol.name(),
            packet.summary.info.chars().take(70).collect::<String>()
        );
        self.rows.push((
            (packet.timestamp_ns - start) as f64 / 1e9,
            from,
            to,
            safe_text(&label),
        ));
    }

    pub fn report(&self) -> Vec<String> {
        const WIDTH: usize = 24;
        if self.rows.is_empty() {
            return vec!["No packets with network addresses".into()];
        }
        let mut header = format!("{:>12}  ", "Time");
        for host in &self.hosts {
            header += &format!(
                "{:^WIDTH$}",
                host.to_string().chars().take(WIDTH - 2).collect::<String>()
            );
        }
        let mut out = vec![header];
        for (seconds, from, to, label) in &self.rows {
            let mut cells = vec![' '; WIDTH * self.hosts.len()];
            for host in 0..self.hosts.len() {
                cells[host * WIDTH + WIDTH / 2] = '│';
            }
            let (left, right) = (
                from.min(to) * WIDTH + WIDTH / 2,
                from.max(to) * WIDTH + WIDTH / 2,
            );
            if from == to {
                cells[left + 1] = '↺';
            } else {
                for cell in &mut cells[left + 1..right] {
                    *cell = '─';
                }
                if from < to {
                    cells[right - 1] = '▶';
                } else {
                    cells[left + 1] = '◀';
                }
            }
            out.push(format!(
                "{seconds:>12.6}  {}  {label}",
                cells.iter().collect::<String>()
            ));
        }
        if self.omitted > 0 {
            out.push(format!(
                "{} packets omitted (more than {MAX_HOSTS} hosts or {MAX_ROWS} rows; narrow the filter)",
                self.omitted
            ));
        }
        out
    }
}

struct Call {
    from: String,
    to: String,
    first_ns: i128,
    last_ns: i128,
    messages: u32,
    state: &'static str,
}

struct RtpStream {
    route: String,
    payload_type: u8,
    packets: u64,
    first_seq: u16,
    /// Highest sequence number, extended past 16 bits.
    highest: u32,
    first_ns: i128,
    last_ns: i128,
    last_transit: Option<f64>,
    jitter: f64,
}

/// SIP calls and RTP streams.
#[derive(Default)]
pub struct Voip {
    calls: BTreeMap<String, Call>,
    streams: BTreeMap<u32, RtpStream>,
}

impl Voip {
    pub fn add(&mut self, packet: &Packet) {
        match packet.summary.protocol {
            Protocol::Sip => self.sip(packet),
            Protocol::Rtp => self.rtp(packet),
            _ => {}
        }
    }

    fn sip(&mut self, packet: &Packet) {
        let text = String::from_utf8_lossy(packet.message());
        let mut lines = text.lines();
        let start = lines.next().unwrap_or_default();
        let header = |name: &str| {
            text.lines()
                .take(64)
                .filter_map(|line| line.split_once(':'))
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.trim().chars().take(80).collect::<String>())
        };
        let Some(id) = header("call-id").or_else(|| header("i")) else {
            return;
        };
        if !self.calls.contains_key(&id) && self.calls.len() >= MAX_ROWS {
            return;
        }
        let call = self.calls.entry(id).or_insert_with(|| Call {
            from: header("from").unwrap_or_default(),
            to: header("to").unwrap_or_default(),
            first_ns: packet.timestamp_ns,
            last_ns: packet.timestamp_ns,
            messages: 0,
            state: "in progress",
        });
        call.messages += 1;
        call.last_ns = packet.timestamp_ns;
        let invite = header("cseq").is_none_or(|cseq| cseq.ends_with("INVITE"));
        call.state = match start.split(' ').next().unwrap_or_default() {
            "INVITE" if call.state == "in progress" => "calling",
            "BYE" => "ended",
            "CANCEL" => "cancelled",
            "SIP/2.0" if invite => match start.split(' ').nth(1).unwrap_or_default().as_bytes() {
                [b'1', ..] if call.state == "calling" => "ringing",
                [b'2', ..] => "answered",
                [b'3'..=b'6', ..] => "rejected",
                _ => call.state,
            },
            _ => call.state,
        };
    }

    fn rtp(&mut self, packet: &Packet) {
        let payload = packet.payload();
        let Some(header) = payload.get(..12) else {
            return;
        };
        let sequence = u16::from_be_bytes([header[2], header[3]]);
        let timestamp = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let ssrc = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        if !self.streams.contains_key(&ssrc) && self.streams.len() >= MAX_ROWS {
            return;
        }
        let summary = &packet.summary;
        let stream = self.streams.entry(ssrc).or_insert_with(|| RtpStream {
            route: match (summary.src, summary.src_port, summary.dst, summary.dst_port) {
                (Some(a), Some(b), Some(c), Some(d)) => format!("{a}:{b} → {c}:{d}"),
                _ => String::new(),
            },
            payload_type: header[1] & 0x7f,
            packets: 0,
            first_seq: sequence,
            highest: u32::from(sequence),
            first_ns: packet.timestamp_ns,
            last_ns: packet.timestamp_ns,
            last_transit: None,
            jitter: 0.0,
        });
        stream.packets += 1;
        stream.last_ns = packet.timestamp_ns;
        // Extend the 16-bit sequence number across wraps.
        let delta = sequence.wrapping_sub(stream.highest as u16) as i16;
        if delta > 0 {
            stream.highest += delta as u32;
        }
        // RFC 3550 interarrival jitter, in milliseconds.
        // ponytail: assumes the 8 kHz clock of the static audio payload
        // types; read the rate from SDP rtpmap lines for other codecs.
        let transit = packet.timestamp_ns as f64 / 1e6 - f64::from(timestamp) / 8.0;
        if let Some(last) = stream.last_transit {
            stream.jitter += ((transit - last).abs() - stream.jitter) / 16.0;
        }
        stream.last_transit = Some(transit);
    }

    pub fn report(&self) -> Vec<String> {
        let seconds = |first: i128, last: i128| (last - first) as f64 / 1e9;
        let mut out = vec![format!("SIP calls: {}", self.calls.len())];
        for (id, call) in &self.calls {
            out.push(safe_text(&format!(
                "  {id} · {} → {} · {} · {} messages · {:.3} s",
                call.from,
                call.to,
                call.state,
                call.messages,
                seconds(call.first_ns, call.last_ns)
            )));
        }
        out.push(format!("RTP streams: {}", self.streams.len()));
        for (ssrc, stream) in &self.streams {
            let expected = u64::from(stream.highest - u32::from(stream.first_seq)) + 1;
            let lost = expected.saturating_sub(stream.packets);
            out.push(format!(
                "  SSRC 0x{ssrc:08x} · {} · payload type {} · {} packets · {lost} lost ({:.1}%) · jitter {:.2} ms · {:.3} s",
                stream.route,
                stream.payload_type,
                stream.packets,
                lost as f64 * 100.0 / expected as f64,
                stream.jitter,
                seconds(stream.first_ns, stream.last_ns)
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chart_scales_points_and_handles_empty_and_flat_data() {
        let lines = chart("Title", "unit", &[(0.0, 0.0), (1.0, 10.0)], 20, 4);
        assert_eq!(lines.len(), 7);
        assert!(lines[1].ends_with('•') && lines[1].contains("10 │"));
        assert!(lines[4].contains("0 │•"));
        assert_eq!(chart("T", "u", &[], 20, 4)[1], "  (no data)");
        // A single point or a flat line must not divide by zero.
        assert!(chart("T", "u", &[(5.0, 5.0)], 1, 1).len() > 4);
    }
}
