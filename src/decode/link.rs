//! Link layers beyond Ethernet II: 802.11 with radiotap, EAPOL, PPP and PPPoE,
//! MPLS, LLC/SNAP with STP, BSD loopback, Bluetooth HCI, USB, CAN and
//! 802.15.4 with the Zigbee network header.
use super::{be16, be32, mac, Decoder, Protocol};

fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// An 802.11 data frame, located for the decoder and for WPA decryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WlanData {
    /// Start of the 802.11 header and of the frame body (after QoS/HT fields).
    pub header: usize,
    pub body: usize,
    /// End of the frame body (the FCS, when captured, is excluded).
    pub end: usize,
    pub protected: bool,
    pub qos: bool,
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub bssid: [u8; 6],
    /// The station (non-AP) address.
    pub station: [u8; 6],
    pub transmitter: [u8; 6],
}

/// Length of the radiotap header, and whether the frame ends with an FCS.
fn radiotap(bytes: &[u8]) -> Option<(usize, bool, Vec<String>)> {
    if bytes.len() < 8 || bytes[0] != 0 {
        return None;
    }
    let length = usize::from(le16(bytes, 2));
    if length < 8 || length > bytes.len() {
        return None;
    }
    // Further presence words follow while bit 31 is set.
    let present = le32(bytes, 4);
    let mut cursor = 8;
    let mut word = present;
    while word & 0x8000_0000 != 0 {
        if cursor + 4 > length {
            return None;
        }
        word = le32(bytes, cursor);
        cursor += 4;
    }
    let mut fields = Vec::new();
    let mut fcs = false;
    // (bit, size, alignment) of the leading fields, in presence-bit order.
    for (bit, size, align) in [
        (0, 8, 8),
        (1, 1, 1),
        (2, 1, 1),
        (3, 4, 2),
        (4, 2, 2),
        (5, 1, 1),
        (6, 1, 1),
    ] {
        if present & (1 << bit) == 0 {
            continue;
        }
        cursor = cursor.next_multiple_of(align);
        if cursor + size > length {
            break;
        }
        match bit {
            1 => fcs = bytes[cursor] & 0x10 != 0,
            2 => fields.push(format!("Rate: {} Mb/s", f32::from(bytes[cursor]) / 2.0)),
            3 => fields.push(format!("Channel frequency: {} MHz", le16(bytes, cursor))),
            5 => fields.push(format!("Signal: {} dBm", bytes[cursor] as i8)),
            6 => fields.push(format!("Noise: {} dBm", bytes[cursor] as i8)),
            _ => {}
        }
        cursor += size;
    }
    Some((length, fcs, fields))
}

/// Locates the 802.11 data frame in `bytes` of link type 105 or 127.
pub fn wlan_data(bytes: &[u8], link: i32) -> Option<WlanData> {
    let (header, fcs) = match link {
        127 => radiotap(bytes).map(|(length, fcs, _)| (length, fcs))?,
        105 => (0, false),
        _ => return None,
    };
    let end = bytes.len().checked_sub(if fcs { 4 } else { 0 })?;
    if header + 24 > end {
        return None;
    }
    let control = bytes[header];
    let flags = bytes[header + 1];
    if control & 0x0c != 0x08 {
        return None;
    }
    let qos = control & 0x80 != 0;
    let (to_ds, from_ds) = (flags & 1 != 0, flags & 2 != 0);
    let mut body = header + 24;
    if to_ds && from_ds {
        body += 6;
    }
    if qos {
        body += 2;
        if flags & 0x80 != 0 {
            body += 4;
        }
    }
    if body > end {
        return None;
    }
    let address = |index: usize| -> [u8; 6] {
        let at = header + 4 + index * 6;
        bytes[at..at + 6].try_into().unwrap_or_default()
    };
    let (a1, a2, a3) = (address(0), address(1), address(2));
    let (destination, source, bssid, station) = match (to_ds, from_ds) {
        (false, false) => (a1, a2, a3, a2),
        (true, false) => (a3, a2, a1, a2),
        (false, true) => (a1, a3, a2, a1),
        // ponytail: four-address (WDS) frames report address 3 and 4 loosely.
        (true, true) => (a3, a2, a2, a1),
    };
    Some(WlanData {
        header,
        body,
        end,
        protected: flags & 0x40 != 0,
        qos,
        destination,
        source,
        bssid,
        station,
        transmitter: a2,
    })
}

impl Decoder<'_> {
    pub(super) fn proto(&mut self, protocol: Protocol) {
        self.summary.protocol = protocol;
        self.summary.seen |= protocol.bit();
    }

    /// Handles the link types this module knows; false for the others.
    pub(super) fn link(&mut self, link: i32) -> bool {
        let bytes = self.bytes;
        match link {
            105 | 127 => self.wlan(link),
            9 | 50 => {
                let start = if bytes.starts_with(&[0xff, 0x03]) {
                    2
                } else {
                    0
                };
                self.ppp(start);
            }
            51 => self.pppoe(0),
            0 | 108 if bytes.len() > 4 => {
                self.layer("Loopback", 0, 4);
                self.ethertype(if bytes[4] >> 4 == 6 { 0x86dd } else { 0x0800 }, 4);
            }
            187 => self.bluetooth(0),
            201 if bytes.len() >= 4 => {
                self.layer("Bluetooth direction", 0, 4);
                let received = bytes[3] & 1 != 0;
                self.field(0, 4, || {
                    format!("Direction: {}", if received { "received" } else { "sent" })
                });
                self.bluetooth(4);
            }
            189 | 220 => self.usb_linux(if link == 189 { 48 } else { 64 }),
            249 => self.usbpcap(),
            227 => self.can(),
            195 | 230 => self.ieee802154(link == 195),
            0 | 108 | 201 => self.warn("Truncated link header"),
            _ => return false,
        }
        true
    }

    fn wlan(&mut self, link: i32) {
        let bytes = self.bytes;
        self.proto(Protocol::Wlan);
        let mut start = 0;
        let mut fcs = false;
        if link == 127 {
            let Some((length, has_fcs, fields)) = radiotap(bytes) else {
                self.warn("Invalid radiotap header");
                return;
            };
            self.layer("Radiotap", 0, length);
            for field in fields {
                self.field(0, length, || field);
            }
            start = length;
            fcs = has_fcs;
        }
        let end = bytes.len().saturating_sub(if fcs { 4 } else { 0 });
        if start + 10 > end {
            self.warn("Truncated 802.11 header");
            return;
        }
        let (control, flags) = (bytes[start], bytes[start + 1]);
        let (kind, subtype) = ((control >> 2) & 3, control >> 4);
        let name = match (kind, subtype) {
            (0, 0) => "Association request",
            (0, 1) => "Association response",
            (0, 4) => "Probe request",
            (0, 5) => "Probe response",
            (0, 8) => "Beacon",
            (0, 10) => "Disassociation",
            (0, 11) => "Authentication",
            (0, 12) => "Deauthentication",
            (0, 13) => "Action",
            (0, _) => "Management frame",
            (1, 8) => "Block ACK request",
            (1, 9) => "Block ACK",
            (1, 11) => "Request to send",
            (1, 12) => "Clear to send",
            (1, 13) => "Acknowledgement",
            (1, _) => "Control frame",
            (2, 4 | 12) => "Null data",
            (2, s) if s & 8 != 0 => "QoS data",
            (2, _) => "Data",
            _ => "Reserved frame",
        };
        let header_end = (start + 24).min(end);
        self.layer("IEEE 802.11", start, header_end);
        self.field(start, start + 2, || {
            format!("Type: {name} (type {kind}, subtype {subtype})")
        });
        self.field(start + 1, start + 2, || {
            format!(
                "Flags: 0x{flags:02x}{}",
                if flags & 0x40 != 0 {
                    " (protected)"
                } else {
                    ""
                }
            )
        });
        self.field(start + 4, start + 10, || {
            format!("Receiver: {}", mac(&bytes[start + 4..start + 10]))
        });
        self.summary.info = format!("802.11 {name}");
        if start + 16 <= end {
            self.field(start + 10, start + 16, || {
                format!("Transmitter: {}", mac(&bytes[start + 10..start + 16]))
            });
            self.summary.info += &format!(
                " · {} → {}",
                mac(&bytes[start + 10..start + 16]),
                mac(&bytes[start + 4..start + 10])
            );
        }
        if kind == 0 && matches!(subtype, 5 | 8) && start + 36 <= end {
            // Fixed fields (12 bytes), then tagged parameters.
            let mut cursor = start + 36;
            self.layer("802.11 management", start + 24, end);
            while cursor + 2 <= end {
                let (tag, length) = (bytes[cursor], usize::from(bytes[cursor + 1]));
                let Some(value) = bytes.get(cursor + 2..cursor + 2 + length) else {
                    break;
                };
                if tag == 0 {
                    let ssid = String::from_utf8_lossy(value).into_owned();
                    self.summary.info += &format!(" · SSID {ssid}");
                    self.field(cursor, cursor + 2 + length, || format!("SSID: {ssid}"));
                } else if tag == 3 && length == 1 {
                    self.field(cursor, cursor + 3, || format!("Channel: {}", value[0]));
                }
                cursor += 2 + length;
            }
        }
        if let Some(data) = wlan_data(bytes, link) {
            self.field(data.header + 4, data.header + 22, || {
                format!("BSSID: {}", mac(&data.bssid))
            });
            if data.protected {
                self.summary.info += " · protected";
                self.layer("Encrypted data", data.body, data.end);
            } else if data.body + 8 <= data.end {
                self.llc(data.body, data.end);
            }
        }
    }

    /// 802.2 LLC: spanning tree, or SNAP carrying an EtherType.
    pub(super) fn llc(&mut self, start: usize, end: usize) {
        let bytes = self.bytes;
        if start + 3 > end {
            self.warn("Truncated LLC header");
            return;
        }
        if bytes[start..].starts_with(&[0xaa, 0xaa, 0x03]) && start + 8 <= end {
            self.layer("LLC/SNAP", start, start + 8);
            self.field(start + 6, start + 8, || {
                format!("EtherType: 0x{:04x}", be16(bytes, start + 6))
            });
            self.ethertype(be16(bytes, start + 6), start + 8);
        } else if bytes[start..].starts_with(&[0x42, 0x42, 0x03]) {
            self.layer("LLC", start, start + 3);
            self.stp(start + 3, end);
        } else {
            self.layer("LLC", start, start + 3);
            self.summary.info = format!(
                "LLC · DSAP 0x{:02x} · SSAP 0x{:02x}",
                bytes[start],
                bytes[start + 1]
            );
        }
    }

    fn stp(&mut self, start: usize, end: usize) {
        let bytes = self.bytes;
        self.proto(Protocol::Stp);
        if start + 4 > end {
            self.warn("Truncated spanning tree BPDU");
            return;
        }
        let name = match (bytes[start + 2], bytes[start + 3]) {
            (_, 0x80) => "Topology change notification",
            (0, _) => "Configuration",
            (2, _) => "Rapid spanning tree",
            (3, _) => "Multiple spanning tree",
            _ => "BPDU",
        };
        self.layer("Spanning Tree Protocol", start, end);
        self.field(start + 2, start + 4, || format!("BPDU type: {name}"));
        self.summary.info = format!("STP {name}");
        if start + 35 <= end {
            let root = format!(
                "{} / {}",
                be16(bytes, start + 5),
                mac(&bytes[start + 7..start + 13])
            );
            let cost = be32(bytes, start + 13);
            let bridge = format!(
                "{} / {}",
                be16(bytes, start + 17),
                mac(&bytes[start + 19..start + 25])
            );
            self.summary.info += &format!(" · root {root} · cost {cost}");
            self.field(start + 5, start + 13, || format!("Root bridge: {root}"));
            self.field(start + 13, start + 17, || format!("Root path cost: {cost}"));
            self.field(start + 17, start + 25, || format!("Bridge: {bridge}"));
            self.field(start + 25, start + 27, || {
                format!("Port: 0x{:04x}", be16(bytes, start + 25))
            });
        }
    }

    /// EAPOL (802.1X), including the WPA 4-way handshake messages.
    pub(super) fn eapol(&mut self, start: usize) {
        let bytes = self.bytes;
        self.proto(Protocol::Eapol);
        if start + 4 > bytes.len() {
            self.warn("Truncated EAPOL header");
            return;
        }
        let kind = bytes[start + 1];
        self.layer("EAPOL", start, bytes.len());
        self.field(start, start + 1, || format!("Version: {}", bytes[start]));
        let name = match kind {
            0 => "EAP packet",
            1 => "Start",
            2 => "Logoff",
            3 => "Key",
            _ => "EAPOL message",
        };
        self.field(start + 1, start + 2, || format!("Type: {kind} ({name})"));
        self.summary.info = format!("EAPOL {name}");
        if kind == 3 && start + 99 <= bytes.len() {
            let info = be16(bytes, start + 5);
            // Pairwise handshake messages by ACK, MIC, install and secure bits.
            let message = match (
                info & 0x08 != 0,
                info & 0x80 != 0,
                info & 0x100 != 0,
                info & 0x200 != 0,
            ) {
                (true, true, false, _) => "4-way handshake message 1",
                (true, false, true, false) => "4-way handshake message 2",
                (true, true, true, _) => "4-way handshake message 3",
                (true, false, true, true) => "4-way handshake message 4",
                _ => "group key handshake",
            };
            self.summary.info = format!("EAPOL Key · {message}");
            self.field(start + 5, start + 7, || {
                format!("Key information: 0x{info:04x} ({message})")
            });
            self.field(start + 9, start + 17, || {
                format!(
                    "Replay counter: {}",
                    u64::from(be32(bytes, start + 9)) << 32 | u64::from(be32(bytes, start + 13))
                )
            });
        }
    }

    fn ppp(&mut self, start: usize) {
        let bytes = self.bytes;
        if start + 2 > bytes.len() {
            self.warn("Truncated PPP header");
            return;
        }
        self.proto(Protocol::Ppp);
        let protocol = be16(bytes, start);
        let name = match protocol {
            0x0021 => "IPv4",
            0x0057 => "IPv6",
            0xc021 => "Link Control Protocol",
            0xc023 => "Password Authentication Protocol",
            0xc223 => "Challenge Handshake Authentication Protocol",
            0x8021 => "IP Control Protocol",
            0x8057 => "IPv6 Control Protocol",
            _ => "unknown protocol",
        };
        self.layer("PPP", start, start + 2);
        self.field(start, start + 2, || {
            format!("Protocol: 0x{protocol:04x} ({name})")
        });
        self.summary.info = format!("PPP {name}");
        match protocol {
            0x0021 => self.ethertype(0x0800, start + 2),
            0x0057 => self.ethertype(0x86dd, start + 2),
            _ if start + 6 <= bytes.len() => {
                let code = match bytes[start + 2] {
                    1 => "Configure-Request",
                    2 => "Configure-Ack",
                    3 => "Configure-Nak",
                    4 => "Configure-Reject",
                    5 => "Terminate-Request",
                    6 => "Terminate-Ack",
                    9 => "Echo-Request",
                    10 => "Echo-Reply",
                    _ => "message",
                };
                self.summary.info += &format!(" · {code}");
                self.field(start + 2, start + 3, || format!("Code: {code}"));
            }
            _ => {}
        }
    }

    /// PPPoE session (EtherType 0x8864) or discovery (0x8863) header.
    pub(super) fn pppoe(&mut self, start: usize) {
        let bytes = self.bytes;
        if start + 6 > bytes.len() {
            self.warn("Truncated PPPoE header");
            return;
        }
        self.proto(Protocol::Ppp);
        let (code, session) = (bytes[start + 1], be16(bytes, start + 2));
        self.layer("PPPoE", start, start + 6);
        self.field(start + 2, start + 4, || {
            format!("Session ID: 0x{session:04x}")
        });
        if code == 0 {
            self.ppp(start + 6);
        } else {
            let name = match code {
                0x09 => "Active Discovery Initiation",
                0x07 => "Active Discovery Offer",
                0x19 => "Active Discovery Request",
                0x65 => "Active Discovery Session-confirmation",
                0xa7 => "Active Discovery Terminate",
                _ => "discovery",
            };
            self.field(start + 1, start + 2, || {
                format!("Code: 0x{code:02x} ({name})")
            });
            self.summary.info = format!("PPPoE {name}");
        }
    }

    pub(super) fn mpls(&mut self, mut start: usize) {
        let bytes = self.bytes;
        self.proto(Protocol::Mpls);
        // At most 16 labels, each four bytes.
        for _ in 0..16 {
            if start + 4 > bytes.len() {
                self.warn("Truncated MPLS label stack");
                return;
            }
            let entry = be32(bytes, start);
            self.layer("MPLS", start, start + 4);
            self.field(start, start + 3, || format!("Label: {}", entry >> 12));
            self.field(start + 3, start + 4, || format!("TTL: {}", entry & 0xff));
            self.summary.info = format!("MPLS label {}", entry >> 12);
            start += 4;
            if entry & 0x100 != 0 {
                match bytes.get(start).map(|b| b >> 4) {
                    Some(4) => self.ethertype(0x0800, start),
                    Some(6) => self.ethertype(0x86dd, start),
                    _ => {}
                }
                return;
            }
        }
        self.warn("Excessive MPLS label stack");
    }

    fn bluetooth(&mut self, start: usize) {
        let bytes = self.bytes;
        self.proto(Protocol::Bluetooth);
        let Some(kind) = bytes.get(start).copied() else {
            self.warn("Truncated Bluetooth HCI packet");
            return;
        };
        self.layer("Bluetooth HCI", start, bytes.len());
        let body = start + 1;
        match kind {
            1 if body + 3 <= bytes.len() => {
                let opcode = le16(bytes, body);
                self.summary.info = format!(
                    "HCI command · OGF 0x{:02x} · OCF 0x{:03x}",
                    opcode >> 10,
                    opcode & 0x3ff
                );
                self.field(body, body + 2, || format!("Opcode: 0x{opcode:04x}"));
                self.field(body + 2, body + 3, || {
                    format!("Parameter length: {}", bytes[body + 2])
                });
            }
            2 if body + 4 <= bytes.len() => {
                let handle = le16(bytes, body) & 0x0fff;
                self.summary.info = format!("HCI ACL data · handle {handle}");
                self.field(body, body + 2, || format!("Connection handle: {handle}"));
                if body + 8 <= bytes.len() {
                    let cid = le16(bytes, body + 6);
                    let channel = match cid {
                        1 => "signaling",
                        4 => "attribute protocol",
                        5 => "LE signaling",
                        6 => "security manager",
                        _ => "dynamic channel",
                    };
                    self.summary.info += &format!(" · L2CAP {channel}");
                    self.field(body + 6, body + 8, || {
                        format!("L2CAP channel: 0x{cid:04x} ({channel})")
                    });
                    if cid == 4 && body + 9 <= bytes.len() {
                        let name = match bytes[body + 8] {
                            0x01 => "Error response",
                            0x02 | 0x03 => "Exchange MTU",
                            0x08 | 0x09 => "Read by type",
                            0x0a | 0x0b => "Read",
                            0x10 | 0x11 => "Read by group type",
                            0x12 | 0x13 => "Write",
                            0x52 => "Write command",
                            0x1b => "Handle value notification",
                            0x1d | 0x1e => "Handle value indication",
                            _ => "attribute operation",
                        };
                        self.summary.info += &format!(" · {name}");
                        self.field(body + 8, body + 9, || {
                            format!("ATT opcode: 0x{:02x} ({name})", bytes[body + 8])
                        });
                    }
                }
            }
            3 => self.summary.info = "HCI SCO data".into(),
            4 if body + 2 <= bytes.len() => {
                let name = match bytes[body] {
                    0x03 => "Connection complete",
                    0x05 => "Disconnection complete",
                    0x0e => "Command complete",
                    0x0f => "Command status",
                    0x13 => "Number of completed packets",
                    0x3e => "LE meta event",
                    _ => "event",
                };
                self.summary.info = format!("HCI event · {name}");
                self.field(body, body + 1, || {
                    format!("Event code: 0x{:02x} ({name})", bytes[body])
                });
            }
            1 | 2 | 4 => self.warn("Truncated Bluetooth HCI packet"),
            _ => self.summary.info = format!("HCI packet type {kind}"),
        }
    }

    fn usb_fields(&mut self, transfer: u8, endpoint: u8, bus: u16, device: u16, event: &str) {
        let kind = match transfer {
            0 => "isochronous",
            1 => "interrupt",
            2 => "control",
            3 => "bulk",
            _ => "unknown",
        };
        let direction = if endpoint & 0x80 != 0 { "in" } else { "out" };
        self.summary.info = format!(
            "USB {kind} {direction} · {event} · bus {bus} device {device} endpoint {}",
            endpoint & 0x7f
        );
    }

    fn usb_linux(&mut self, header: usize) {
        let bytes = self.bytes;
        self.proto(Protocol::Usb);
        if bytes.len() < header {
            self.warn("Truncated USB header");
            return;
        }
        self.layer("USB (Linux usbmon)", 0, header);
        let event = match bytes[8] {
            b'S' => "submit",
            b'C' => "complete",
            b'E' => "error",
            _ => "event",
        };
        let (transfer, endpoint, device, bus) = (bytes[9], bytes[10], bytes[11], le16(bytes, 12));
        self.usb_fields(transfer, endpoint, bus, u16::from(device), event);
        self.field(8, 9, || format!("Event: {event}"));
        self.field(9, 10, || format!("Transfer type: {transfer}"));
        self.field(10, 11, || format!("Endpoint: 0x{endpoint:02x}"));
        self.field(11, 12, || format!("Device: {device}"));
        self.field(12, 14, || format!("Bus: {bus}"));
        self.field(36, 40, || format!("Data length: {}", le32(bytes, 36)));
        // A control submission carries the setup packet.
        if transfer == 2 && bytes[8] == b'S' && bytes[14] == 0 {
            let request = match bytes[41] {
                0 => "GET_STATUS",
                1 => "CLEAR_FEATURE",
                3 => "SET_FEATURE",
                5 => "SET_ADDRESS",
                6 => "GET_DESCRIPTOR",
                7 => "SET_DESCRIPTOR",
                8 => "GET_CONFIGURATION",
                9 => "SET_CONFIGURATION",
                _ => "request",
            };
            self.summary.info += &format!(" · {request}");
            self.field(40, 48, || {
                format!(
                    "Setup: {request} · value 0x{:04x} · index {} · length {}",
                    le16(bytes, 42),
                    le16(bytes, 44),
                    le16(bytes, 46)
                )
            });
        }
        if bytes.len() > header {
            self.layer("USB data", header, bytes.len());
        }
    }

    fn usbpcap(&mut self) {
        let bytes = self.bytes;
        self.proto(Protocol::Usb);
        if bytes.len() < 27 || usize::from(le16(bytes, 0)) > bytes.len() {
            self.warn("Truncated USBPcap header");
            return;
        }
        let header = usize::from(le16(bytes, 0)).max(27);
        self.layer("USB (USBPcap)", 0, header);
        let event = if bytes[16] & 1 != 0 {
            "complete"
        } else {
            "submit"
        };
        self.usb_fields(
            bytes[22],
            bytes[21],
            le16(bytes, 17),
            le16(bytes, 19),
            event,
        );
        self.field(17, 19, || format!("Bus: {}", le16(bytes, 17)));
        self.field(19, 21, || format!("Device: {}", le16(bytes, 19)));
        self.field(21, 22, || format!("Endpoint: 0x{:02x}", bytes[21]));
        self.field(23, 27, || format!("Data length: {}", le32(bytes, 23)));
    }

    fn can(&mut self) {
        let bytes = self.bytes;
        self.proto(Protocol::Can);
        if bytes.len() < 8 {
            self.warn("Truncated CAN frame");
            return;
        }
        let word = be32(bytes, 0);
        let extended = word & 0x8000_0000 != 0;
        let id = word & if extended { 0x1fff_ffff } else { 0x7ff };
        let length = usize::from(bytes[4]).min(bytes.len() - 8);
        let kind = if word & 0x2000_0000 != 0 {
            "error frame"
        } else if word & 0x4000_0000 != 0 {
            "remote request"
        } else {
            "data frame"
        };
        let data: Vec<String> = bytes[8..8 + length]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        self.summary.info = format!("CAN {kind} · ID 0x{id:x} · {}", data.join(" "));
        self.layer("CAN", 0, bytes.len());
        self.field(0, 4, || {
            format!(
                "Identifier: 0x{id:x} ({})",
                if extended { "extended" } else { "standard" }
            )
        });
        self.field(4, 5, || format!("Data length: {length}"));
        self.field(8, 8 + length, || format!("Data: {}", data.join(" ")));
    }

    fn ieee802154(&mut self, fcs: bool) {
        let bytes = self.bytes;
        self.proto(Protocol::Zigbee);
        let end = bytes.len().saturating_sub(if fcs { 2 } else { 0 });
        if end < 3 {
            self.warn("Truncated 802.15.4 frame");
            return;
        }
        let control = le16(bytes, 0);
        let name = match control & 7 {
            0 => "Beacon",
            1 => "Data",
            2 => "Acknowledgement",
            3 => "Command",
            _ => "Reserved frame",
        };
        let mut cursor = 3;
        let mut addresses = Vec::new();
        // Destination, then source: PAN identifier and a short or long address.
        for (mode, source) in [((control >> 10) & 3, false), ((control >> 14) & 3, true)] {
            let size = match mode {
                2 => 2,
                3 => 8,
                _ => continue,
            };
            let pan = !(source && control & 0x40 != 0);
            let total = size + if pan { 2 } else { 0 };
            if cursor + total > end {
                self.warn("Truncated 802.15.4 addresses");
                return;
            }
            let address: String = bytes[cursor + total - size..cursor + total]
                .iter()
                .rev()
                .map(|b| format!("{b:02x}"))
                .collect();
            addresses.push((cursor, cursor + total, source, address));
            cursor += total;
        }
        self.layer("IEEE 802.15.4", 0, cursor);
        self.field(0, 2, || format!("Frame type: {name}"));
        self.field(2, 3, || format!("Sequence: {}", bytes[2]));
        self.summary.info = format!("802.15.4 {name} · sequence {}", bytes[2]);
        for (from, to, source, address) in addresses {
            let label = if source { "Source" } else { "Destination" };
            self.summary.info += &format!(" · {} 0x{address}", label.to_lowercase());
            self.field(from, to, || format!("{label}: 0x{address}"));
        }
        // Zigbee network header: an unsecured data frame with protocol version 2.
        if control & 0x0f == 1 && cursor + 8 <= end && (le16(bytes, cursor) >> 2) & 0xf == 2 {
            let network = le16(bytes, cursor);
            let kind = if network & 3 == 1 { "command" } else { "data" };
            let (dst, src) = (le16(bytes, cursor + 2), le16(bytes, cursor + 4));
            self.layer("Zigbee network", cursor, cursor + 8);
            self.field(cursor + 2, cursor + 4, || {
                format!("Destination: 0x{dst:04x}")
            });
            self.field(cursor + 4, cursor + 6, || format!("Source: 0x{src:04x}"));
            self.field(cursor + 6, cursor + 7, || {
                format!("Radius: {}", bytes[cursor + 6])
            });
            self.summary.info = format!("Zigbee {kind} · 0x{src:04x} → 0x{dst:04x}");
            if cursor + 8 < end {
                self.layer("Zigbee payload", cursor + 8, end);
            }
        }
    }
}
