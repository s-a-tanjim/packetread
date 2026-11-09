//! TCP, UDP and ICMP. `start..end` is the IP payload within the captured bytes.
use super::{be16, be32, Decoder, Protocol};

impl Decoder<'_> {
    pub(super) fn transport(&mut self, protocol: u8, start: usize, end: usize) {
        match protocol {
            6 => self.tcp(start, end),
            17 => self.udp(start, end),
            1 | 58 => self.icmp(protocol, start, end),
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
        if start + length < end {
            self.layer("Payload", start + length, end);
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
        self.summary.info = format!("{} payload bytes", length - 8);
        if src == 53 || dst == 53 {
            self.dns(start + 8, start + length);
        }
        if start + 8 < end {
            self.layer("Payload", start + 8, end);
        }
    }

    fn icmp(&mut self, protocol: u8, start: usize, end: usize) {
        let bytes = self.bytes;
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
}
