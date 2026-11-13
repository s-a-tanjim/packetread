//! TCP, UDP and ICMP. `start..end` is the IP payload within the captured bytes.
use super::{be16, be32, checksum_ok, extension, Decoder, Protocol, Tcp};
use std::{net::IpAddr, sync::RwLock};

/// Decode As: (is TCP, port seen on the wire, port whose decoder to use).
static ALIASES: RwLock<Vec<(bool, u16, u16)>> = RwLock::new(Vec::new());

/// Registers a Decode As rule such as `udp:5300=dns` or `tcp:8025=25`: traffic
/// on the first port is decoded as if it used the named protocol's port.
pub fn decode_as(rule: &str) -> Result<(), String> {
    let usage =
        || format!("Invalid --decode-as {rule}: use tcp:PORT=PROTOCOL or udp:PORT=PROTOCOL");
    let (transport, rest) = rule.split_once(':').ok_or_else(usage)?;
    let (port, target) = rest.split_once('=').ok_or_else(usage)?;
    let tcp = match transport {
        "tcp" => true,
        "udp" => false,
        _ => return Err(usage()),
    };
    let target = match target.to_ascii_lowercase().as_str() {
        "dns" => 53,
        "dhcp" => 67,
        "ntp" => 123,
        "quic" => 443,
        "ssh" => 22,
        "ftp" => 21,
        "smtp" => 25,
        "pop3" => 110,
        "imap" => 143,
        "mqtt" => 1883,
        "vxlan" => 4789,
        "mdns" => 5353,
        "kerberos" => 88,
        "ldap" => 389,
        "rdp" => 3389,
        "nfs" => 2049,
        "mysql" => 3306,
        "postgres" | "pgsql" => 5432,
        "bgp" => 179,
        "snmp" => 161,
        "rip" => 520,
        "rtp" => 5004,
        "rtcp" => 5005,
        other => other.parse().map_err(|_| usage())?,
    };
    let port = port.parse().map_err(|_| usage())?;
    ALIASES
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .push((tcp, port, target));
    Ok(())
}

/// The pseudo-header that TCP and UDP checksums cover.
fn pseudo_header(src: Option<IpAddr>, dst: Option<IpAddr>, protocol: u8, length: usize) -> Vec<u8> {
    let mut header = Vec::with_capacity(40);
    for address in [src, dst].into_iter().flatten() {
        match address {
            IpAddr::V4(v4) => header.extend(v4.octets()),
            IpAddr::V6(v6) => header.extend(v6.octets()),
        }
    }
    header.extend((length as u32).to_be_bytes());
    header.extend([0, 0, 0, protocol]);
    header
}

impl Decoder<'_> {
    pub(super) fn transport(&mut self, protocol: u8, start: usize, end: usize) {
        self.summary.ip_proto = Some(protocol);
        match protocol {
            6 => self.tcp(start, end),
            17 => self.udp(start, end),
            1 | 58 => self.icmp(protocol, start, end),
            2 => self.igmp(start, end),
            47 => self.gre(start, end),
            50 | 51 => self.ipsec(protocol, start, end),
            89 => self.ospf(start, end),
            _ => {
                self.summary.info = format!("IP protocol {protocol}");
                self.layer("Payload", start, end);
            }
        }
    }

    fn ports(&mut self, start: usize) -> (u16, u16) {
        let src = be16(self.bytes, start);
        let dst = be16(self.bytes, start + 2);
        self.summary.src_port = Some(src);
        self.summary.dst_port = Some(dst);
        (src, dst)
    }

    fn port_fields(&mut self, start: usize, src: u16, dst: u16) {
        self.field(start, start + 2, || format!("Source port: {src}"));
        self.field(start + 2, start + 4, || format!("Destination port: {dst}"));
    }

    fn tcp(&mut self, start: usize, end: usize) {
        let bytes = self.bytes;
        self.summary.protocol = Protocol::Tcp;
        if start + 20 > end {
            self.warn("Truncated transport header");
            return;
        }
        let (src, dst) = self.ports(start);
        let length = usize::from(bytes[start + 12] >> 4) * 4;
        if length < 20 || start + length > end {
            self.warn("Invalid transport header length");
            return;
        }
        self.layer("TCP", start, start + length);
        self.port_fields(start, src, dst);
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
        self.checksum_field(6, start, end, start + 16);
        self.tcp_options(start + 20, start + length);
        self.summary.tcp = Some(Tcp {
            seq: be32(bytes, start + 4),
            ack: be32(bytes, start + 8),
            flags,
            window: be16(bytes, start + 14),
        });
        self.summary.payload = ((start + length) as u32, end as u32);
        if start + length < end && !self.application(true, src, dst, start + length, end) {
            self.layer("Payload", start + length, end);
        }
    }

    /// Checksum with a verdict; skipped when the segment was not fully captured.
    fn checksum_field(&mut self, protocol: u8, start: usize, end: usize, at: usize) {
        let bytes = self.bytes;
        let (src, dst) = (self.summary.src, self.summary.dst);
        let complete = self.summary.warning.is_none();
        self.field(at, at + 2, || {
            let value = be16(bytes, at);
            let verdict = if !complete {
                "not verified: truncated"
            } else if value == 0 && protocol == 17 {
                "not used"
            } else if checksum_ok(&[
                &pseudo_header(src, dst, protocol, end - start),
                &bytes[start..end],
            ]) {
                "correct"
            } else {
                "incorrect, or left to the network card"
            };
            format!("Checksum: 0x{value:04x} ({verdict})")
        });
    }

    fn tcp_options(&mut self, mut cursor: usize, end: usize) {
        let bytes = self.bytes;
        if !self.detailed {
            return;
        }
        // Every iteration consumes at least one byte.
        while cursor < end {
            let kind = bytes[cursor];
            if kind == 0 {
                break;
            }
            let length = if kind == 1 {
                1
            } else {
                usize::from(*bytes.get(cursor + 1).unwrap_or(&0))
            };
            if length == 0 || (kind != 1 && length < 2) || cursor + length > end {
                self.field(cursor, end, || "Malformed TCP option".into());
                break;
            }
            let value = &bytes[cursor..cursor + length];
            let label = match (kind, length) {
                (1, _) => None,
                (2, 4) => Some(format!("Option: maximum segment size {}", be16(value, 2))),
                (3, 3) => Some(format!(
                    "Option: window scale {} (×{})",
                    value[2],
                    1u32 << value[2].min(14)
                )),
                (4, 2) => Some("Option: SACK permitted".into()),
                (5, _) => Some(format!(
                    "Option: SACK {}",
                    value[2..]
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|block| format!("{}–{}", be32(block, 0), be32(block, 4)))
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
                (8, 10) => Some(format!(
                    "Option: timestamps value {} echo {}",
                    be32(value, 2),
                    be32(value, 6)
                )),
                _ => Some(format!("Option: kind {kind} ({length} bytes)")),
            };
            if let Some(label) = label {
                self.field(cursor, cursor + length, || label);
            }
            cursor += length;
        }
    }

    /// Tries the application decoders; returns true when one claimed the payload.
    fn application(&mut self, tcp: bool, src: u16, dst: u16, start: usize, end: usize) -> bool {
        let (src, dst) = {
            let aliases = ALIASES.read().unwrap_or_else(|e| e.into_inner());
            let alias = |port: u16| {
                let rule = aliases
                    .iter()
                    .find(|(t, from, _)| *t == tcp && *from == port);
                rule.map_or(port, |(_, _, to)| *to)
            };
            (alias(src), alias(dst))
        };
        let port = |p: u16| src == p || dst == p;
        let hinted = match self.hint {
            Some(Protocol::Http2) if tcp => self.http2(start, end, true),
            Some(Protocol::WebSocket) if tcp => self.websocket(start, end),
            Some(Protocol::Rtp) if !tcp => self.rtp(start, end),
            Some(Protocol::Http3) if !tcp => self.quic_plain(start, end),
            _ => false,
        };
        if hinted {
            return true;
        }
        if tcp {
            (port(53) && self.dns(start, end, true, true))
                || self.http(start, end)
                || self.http2(start, end, false)
                || self.tls(start, end)
                || self.smb(start, end)
                || self.ssh(start, end, port(22))
                || self.sip(start, end)
                || (port(21) && self.text(Protocol::Ftp, start, end))
                || ((port(25) || port(587)) && self.text(Protocol::Smtp, start, end))
                || (port(110) && self.text(Protocol::Pop3, start, end))
                || (port(143) && self.text(Protocol::Imap, start, end))
                || (port(1883) && self.mqtt(start, end))
                || (port(88) && self.kerberos(start, end, true))
                || (port(389) && self.ldap(start, end))
                || (port(3389) && self.rdp(start, end))
                || ((port(2049) || port(111)) && self.rpc(start, end, true))
                || (port(3306) && self.mysql(start, end, dst == 3306))
                || (port(5432) && self.postgres(start, end, dst == 5432))
                || (port(179) && self.bgp(start, end))
                || self.extension(extension::Transport::Tcp, src, dst, start, end)
        } else {
            (port(53) && self.dns(start, end, false, true))
                || ((port(5353) || port(5355)) && self.dns(start, end, false, false))
                || ((port(67) || port(68)) && self.dhcp(start, end))
                || (port(123) && self.ntp(start, end))
                || (port(4789) && self.vxlan(start, end))
                || (port(88) && self.kerberos(start, end, false))
                || ((port(161) || port(162)) && self.snmp(start, end))
                || (port(520) && self.rip(start, end))
                || ((port(2049) || port(111)) && self.rpc(start, end, false))
                || ((port(5004) || port(5005)) && self.rtp(start, end))
                || self.sip(start, end)
                || self.quic(start, end, port(443))
                || self.extension(extension::Transport::Udp, src, dst, start, end)
        }
    }

    fn udp(&mut self, start: usize, end: usize) {
        self.summary.protocol = Protocol::Udp;
        if start + 8 > end {
            self.warn("Truncated transport header");
            return;
        }
        let (src, dst) = self.ports(start);
        self.layer("UDP", start, start + 8);
        self.port_fields(start, src, dst);
        let length = usize::from(be16(self.bytes, start + 4));
        self.field(start + 4, start + 6, || format!("Length: {length}"));
        if length < 8 || start + length > end {
            self.warn("Invalid or truncated UDP length");
            return;
        }
        self.checksum_field(17, start, start + length, start + 6);
        self.summary.info = format!("{} payload bytes", length - 8);
        self.summary.payload = ((start + 8) as u32, (start + length) as u32);
        if length > 8 && !self.application(false, src, dst, start + 8, start + length) {
            self.layer("Payload", start + 8, start + length);
        }
    }

    fn icmp(&mut self, protocol: u8, start: usize, end: usize) {
        let bytes = self.bytes;
        self.summary.protocol = Protocol::Icmp;
        if start + 4 > end {
            self.warn("Truncated ICMP header");
            return;
        }
        let (kind, code) = (bytes[start], bytes[start + 1]);
        let name = match (protocol, kind) {
            (1, 0) | (58, 129) => "Echo reply",
            (1, 8) | (58, 128) => "Echo request",
            (1, 3) | (58, 1) => "Destination unreachable",
            (1, 11) | (58, 3) => "Time exceeded",
            (1, 5) | (58, 137) => "Redirect",
            (58, 2) => "Packet too big",
            (58, 133) => "Router solicitation",
            (58, 134) => "Router advertisement",
            (58, 135) => "Neighbor solicitation",
            (58, 136) => "Neighbor advertisement",
            _ => "ICMP message",
        };
        // Neighbour discovery names its target address.
        let target = (protocol == 58 && matches!(kind, 135 | 136) && start + 24 <= end)
            .then(|| super::ipv6(&bytes[start + 8..start + 24]));
        self.summary.info = format!("{name} · type {kind} · code {code}");
        if let Some(target) = target {
            self.summary.info += &format!(" · target {target}");
        }
        self.layer(if protocol == 1 { "ICMPv4" } else { "ICMPv6" }, start, end);
        self.field(start, start + 1, || format!("Type: {kind} ({name})"));
        self.field(start + 1, start + 2, || format!("Code: {code}"));
        if let Some(target) = target {
            self.field(start + 8, start + 24, || {
                format!("Target address: {target}")
            });
        }
    }
}
