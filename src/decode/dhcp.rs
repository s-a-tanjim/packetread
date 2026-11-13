//! DHCPv4 (BOOTP with the DHCP magic cookie) on UDP ports 67/68.
use super::{be32, ipv4, mac, Decoder, Protocol};

impl Decoder<'_> {
    pub(super) fn dhcp(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        if end - start < 240 || be32(bytes, start + 236) != 0x6382_5363 {
            return false;
        }
        let xid = be32(bytes, start + 4);
        let mut kind = if bytes[start] == 1 {
            "Request"
        } else {
            "Reply"
        }
        .to_string();
        let mut host = String::new();
        self.summary.protocol = Protocol::Dhcp;
        self.layer("DHCP", start, end);
        self.field(start + 4, start + 8, || {
            format!("Transaction ID: 0x{xid:08x}")
        });
        self.field(start + 16, start + 20, || {
            format!("Your address: {}", ipv4(&bytes[start + 16..start + 20]))
        });
        self.field(start + 28, start + 34, || {
            format!("Client MAC: {}", mac(&bytes[start + 28..start + 34]))
        });
        let mut cursor = start + 240;
        // Each option consumes at least two bytes, so this loop is bounded by the payload.
        while cursor + 2 <= end && bytes[cursor] != 255 {
            if bytes[cursor] == 0 {
                cursor += 1;
                continue;
            }
            let (code, length) = (bytes[cursor], usize::from(bytes[cursor + 1]));
            let Some(value) = bytes
                .get(cursor + 2..cursor + 2 + length)
                .filter(|_| cursor + 2 + length <= end)
            else {
                self.warn("Truncated DHCP option");
                break;
            };
            let address = || {
                value
                    .get(..4)
                    .map_or_else(String::new, |v| ipv4(v).to_string())
            };
            let label = match code {
                53 => {
                    kind = match value.first() {
                        Some(1) => "Discover",
                        Some(2) => "Offer",
                        Some(3) => "Request",
                        Some(4) => "Decline",
                        Some(5) => "ACK",
                        Some(6) => "NAK",
                        Some(7) => "Release",
                        Some(8) => "Inform",
                        _ => "Unknown message",
                    }
                    .into();
                    format!("Message type: {kind}")
                }
                12 => {
                    host = String::from_utf8_lossy(value).into_owned();
                    format!("Host name: {host}")
                }
                1 => format!("Subnet mask: {}", address()),
                3 => format!("Router: {}", address()),
                6 => format!("DNS server: {}", address()),
                50 => format!("Requested address: {}", address()),
                54 => format!("Server identifier: {}", address()),
                51 if length == 4 => format!("Lease time: {} s", be32(value, 0)),
                _ => format!("Option {code} ({length} bytes)"),
            };
            self.field(cursor, cursor + 2 + length, || label);
            cursor += 2 + length;
        }
        self.summary.info = format!("DHCP {kind} · xid 0x{xid:08x}");
        if !host.is_empty() {
            self.summary.info += &format!(" · {host}");
        }
        true
    }
}
