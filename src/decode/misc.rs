//! Small fixed-header protocols: NTP, MQTT, IGMP and LLDP.
use super::{be16, ipv4, Decoder, Protocol};

impl Decoder<'_> {
    pub(super) fn ntp(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        let (version, mode) = ((bytes[start] >> 3) & 7, bytes[start] & 7);
        if end - start < 48 || !(1..=4).contains(&version) {
            return false;
        }
        let name = match mode {
            1 => "Symmetric active",
            2 => "Symmetric passive",
            3 => "Client",
            4 => "Server",
            5 => "Broadcast",
            6 => "Control",
            _ => "Reserved mode",
        };
        self.summary.protocol = Protocol::Ntp;
        self.summary.info = format!("NTP v{version} {name} · stratum {}", bytes[start + 1]);
        self.layer("NTP", start, end);
        self.field(start, start + 1, || {
            format!("Version {version} · mode {mode} ({name})")
        });
        self.field(start + 1, start + 2, || {
            format!("Stratum: {}", bytes[start + 1])
        });
        true
    }

    pub(super) fn mqtt(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        const NAMES: [&str; 14] = [
            "CONNECT",
            "CONNACK",
            "PUBLISH",
            "PUBACK",
            "PUBREC",
            "PUBREL",
            "PUBCOMP",
            "SUBSCRIBE",
            "SUBACK",
            "UNSUBSCRIBE",
            "UNSUBACK",
            "PINGREQ",
            "PINGRESP",
            "DISCONNECT",
        ];
        let Some(name) = NAMES.get(usize::from(bytes[start] >> 4).wrapping_sub(1)) else {
            return false;
        };
        // Remaining length: a base-128 varint of at most four bytes.
        let mut length = 0usize;
        let mut used = 0;
        for byte in bytes[start + 1..end].iter().take(4) {
            length |= usize::from(byte & 0x7f) << (7 * used);
            used += 1;
            if byte & 0x80 == 0 {
                self.summary.protocol = Protocol::Mqtt;
                self.summary.info = format!("MQTT {name} · {length} bytes");
                self.layer("MQTT", start, end);
                self.field(start, start + 1, || format!("Packet type: {name}"));
                self.field(start + 1, start + 1 + used, || {
                    format!("Remaining length: {length}")
                });
                return true;
            }
        }
        false
    }

    pub(super) fn igmp(&mut self, start: usize, end: usize) {
        let bytes = self.bytes;
        self.summary.protocol = Protocol::Igmp;
        if start + 8 > end {
            self.warn("Truncated IGMP message");
            return;
        }
        let name = match bytes[start] {
            0x11 => "Membership query",
            0x12 | 0x16 | 0x22 => "Membership report",
            0x17 => "Leave group",
            _ => "IGMP message",
        };
        let group = ipv4(&bytes[start + 4..start + 8]);
        self.summary.info = format!("{name} · group {group}");
        self.layer("IGMP", start, end);
        self.field(start, start + 1, || {
            format!("Type: 0x{:02x} ({name})", bytes[start])
        });
        self.field(start + 4, start + 8, || format!("Group address: {group}"));
    }

    pub(super) fn lldp(&mut self, start: usize) {
        let bytes = self.bytes;
        self.summary.protocol = Protocol::Lldp;
        self.layer("LLDP", start, bytes.len());
        let mut cursor = start;
        let mut system = String::new();
        // Each TLV consumes at least its two-byte header.
        while cursor + 2 <= bytes.len() {
            let header = be16(bytes, cursor);
            let (kind, length) = (header >> 9, usize::from(header & 0x1ff));
            let Some(value) = bytes.get(cursor + 2..cursor + 2 + length) else {
                self.warn("Truncated LLDP TLV");
                break;
            };
            if kind == 0 {
                break;
            }
            let text = || String::from_utf8_lossy(value).into_owned();
            let label = match kind {
                1 => format!("Chassis ID ({length} bytes)"),
                2 => format!("Port ID ({length} bytes)"),
                3 if length == 2 => format!("Time to live: {} s", be16(value, 0)),
                4 => format!("Port description: {}", text()),
                5 => {
                    system = text();
                    format!("System name: {system}")
                }
                6 => format!("System description: {}", text()),
                _ => format!("TLV type {kind} ({length} bytes)"),
            };
            self.field(cursor, cursor + 2 + length, || label);
            cursor += 2 + length;
        }
        self.summary.info = if system.is_empty() {
            "LLDP advertisement".into()
        } else {
            format!("LLDP advertisement · {system}")
        };
    }
}
