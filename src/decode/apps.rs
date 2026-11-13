//! Application protocols with binary framing: HTTP/2 (with gRPC), WebSocket,
//! Kerberos, LDAP, SNMP, RDP, ONC RPC/NFS, MySQL, PostgreSQL, BGP, OSPF, RIP,
//! RTP and RTCP.
use super::{
    be16, be32,
    hpack_table::{HUFFMAN, STATIC},
    ipv4, Decoder, Protocol,
};
use std::{collections::HashMap, sync::OnceLock};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// One BER element at `at`: its tag byte and the range of its contents.
pub(crate) fn ber(data: &[u8], at: usize) -> Option<(u8, usize, usize)> {
    let tag = *data.get(at)?;
    let first = *data.get(at + 1)?;
    let (length, start) = if first < 0x80 {
        (usize::from(first), at + 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let digits = data.get(at + 2..at + 2 + count)?;
        (
            digits.iter().fold(0, |n, b| n << 8 | usize::from(*b)),
            at + 2 + count,
        )
    };
    let end = start.checked_add(length)?;
    (end <= data.len()).then_some((tag, start, end))
}

/// The elements directly inside `start..end`, at most 64.
pub(crate) fn ber_children(data: &[u8], start: usize, end: usize) -> Vec<(u8, usize, usize)> {
    let mut out = Vec::new();
    let mut cursor = start;
    while cursor < end && out.len() < 64 {
        match ber(&data[..end], cursor) {
            Some(element) => {
                cursor = element.2;
                out.push(element);
            }
            None => break,
        }
    }
    out
}

fn ber_int(data: &[u8]) -> i64 {
    data.iter().take(8).fold(
        if data.first().is_some_and(|b| b & 0x80 != 0) {
            -1
        } else {
            0
        },
        |n, b| n << 8 | i64::from(*b),
    )
}

fn oid(data: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut value = 0u64;
    for (index, byte) in data.iter().take(64).enumerate() {
        value = value << 7 | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            if index == 0 {
                parts.push((value / 40).to_string());
                parts.push((value % 40).to_string());
            } else {
                parts.push(value.to_string());
            }
            value = 0;
        }
    }
    parts.join(".")
}

fn text(data: &[u8]) -> String {
    String::from_utf8_lossy(&data[..data.len().min(200)]).into_owned()
}

/// HPACK integer with an `prefix`-bit prefix; returns the value and bytes used.
pub(super) fn hpack_int(data: &[u8], prefix: u8) -> Option<(usize, usize)> {
    let mask = (1usize << prefix) - 1;
    let mut value = usize::from(*data.first()?) & mask;
    if value < mask {
        return Some((value, 1));
    }
    for (index, byte) in data[1..].iter().take(4).enumerate() {
        value += usize::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((value, index + 2));
        }
    }
    None
}

fn huffman(data: &[u8]) -> String {
    static CODES: OnceLock<HashMap<(u8, u32), u8>> = OnceLock::new();
    let codes = CODES.get_or_init(|| {
        HUFFMAN[..256]
            .iter()
            .enumerate()
            .map(|(byte, (code, bits))| ((*bits, *code), byte as u8))
            .collect()
    });
    let mut out = Vec::new();
    let (mut code, mut bits) = (0u32, 0u8);
    for byte in data {
        for shift in (0..8).rev() {
            code = code << 1 | u32::from(byte >> shift & 1);
            bits += 1;
            if let Some(symbol) = codes.get(&(bits, code)) {
                out.push(*symbol);
                (code, bits) = (0, 0);
            } else if bits >= 30 {
                return String::from_utf8_lossy(&out).into_owned();
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A string literal whose length has a `prefix`-bit prefix; the bit above
/// the prefix marks Huffman coding.
pub(super) fn hpack_string(data: &[u8], prefix: u8) -> Option<(String, usize)> {
    let (length, used) = hpack_int(data, prefix)?;
    let value = data.get(used..used.checked_add(length)?)?;
    let string = if data[0] & (1 << prefix) != 0 {
        huffman(value)
    } else {
        String::from_utf8_lossy(value).into_owned()
    };
    Some((string, used + length))
}

/// Header fields of an HPACK block. The dynamic table belongs to the
/// connection, so entries that refer to it are shown as placeholders.
pub(crate) fn hpack(mut block: &[u8]) -> Vec<(String, String)> {
    let named = |index: usize| match STATIC.get(index.wrapping_sub(1)) {
        Some((name, value)) => (name.to_string(), value.to_string()),
        None => (
            format!("(dynamic table entry {})", index - 61),
            String::new(),
        ),
    };
    let mut out = Vec::new();
    while let (Some(first), true) = (block.first().copied(), out.len() < 64) {
        let used = if first & 0x80 != 0 {
            let Some((index, used)) = hpack_int(block, 7) else {
                break;
            };
            if index == 0 {
                break;
            }
            out.push(named(index));
            used
        } else if first & 0xe0 == 0x20 {
            // Dynamic table size update.
            match hpack_int(block, 5) {
                Some((_, used)) => used,
                None => break,
            }
        } else {
            let prefix = if first & 0x40 != 0 { 6 } else { 4 };
            let Some((index, mut used)) = hpack_int(block, prefix) else {
                break;
            };
            let name = if index == 0 {
                let Some((name, length)) = hpack_string(&block[used..], 7) else {
                    break;
                };
                used += length;
                name
            } else {
                named(index).0
            };
            let Some((value, length)) = hpack_string(&block[used..], 7) else {
                break;
            };
            out.push((name, value));
            used + length
        };
        block = &block[used..];
    }
    out
}

impl Decoder<'_> {
    /// HTTP/2 frames. Without the connection preface the payload is only
    /// accepted when the conversation is `hinted` to be HTTP/2.
    pub(super) fn http2(&mut self, start: usize, end: usize, hinted: bool) -> bool {
        let bytes = self.bytes;
        let preface = bytes[start..end].starts_with(PREFACE);
        if !preface && !hinted {
            return false;
        }
        self.proto(Protocol::Http2);
        self.layer("HTTP/2", start, end);
        let mut cursor = start;
        let mut parts: Vec<String> = Vec::new();
        if preface {
            self.field(start, start + 24, || "Connection preface".into());
            parts.push("Preface".into());
            cursor += 24;
        }
        let mut grpc = false;
        // Each frame consumes at least its nine-byte header.
        for _ in 0..32 {
            if cursor + 9 > end {
                break;
            }
            let length = usize::from(be16(bytes, cursor)) << 8 | usize::from(bytes[cursor + 2]);
            let (kind, flags) = (bytes[cursor + 3], bytes[cursor + 4]);
            let stream = be32(bytes, cursor + 5) & 0x7fff_ffff;
            if kind > 9 {
                if parts.is_empty() {
                    parts.push("continuation of an earlier frame".into());
                }
                break;
            }
            let name = [
                "DATA",
                "HEADERS",
                "PRIORITY",
                "RST_STREAM",
                "SETTINGS",
                "PUSH_PROMISE",
                "PING",
                "GOAWAY",
                "WINDOW_UPDATE",
                "CONTINUATION",
            ][usize::from(kind)];
            let body = cursor + 9;
            let body_end = (body + length).min(end);
            self.field(cursor, body_end, || {
                format!("Frame: {name} · stream {stream} · {length} bytes · flags 0x{flags:02x}")
            });
            let mut part = format!("{name}[{stream}]");
            match kind {
                0 if length >= 5
                    && bytes[body] <= 1
                    && body + 5 <= body_end
                    && be32(bytes, body + 1) as usize + 5 == length =>
                {
                    grpc = true;
                    self.field(body, body + 5, || {
                        format!("gRPC message: {} bytes", length - 5)
                    });
                }
                1 | 9 => {
                    let mut from = body;
                    let mut to = body_end;
                    if kind == 1 && flags & 0x08 != 0 && from < to {
                        to = to.saturating_sub(usize::from(bytes[from])).max(from + 1);
                        from += 1;
                    }
                    if kind == 1 && flags & 0x20 != 0 {
                        from = (from + 5).min(to);
                    }
                    let headers = hpack(&bytes[from..to]);
                    let find = |wanted: &str| {
                        headers
                            .iter()
                            .find(|(name, _)| name == wanted)
                            .map(|(_, value)| value.clone())
                    };
                    if let Some(method) = find(":method") {
                        part += &format!(" {method} {}", find(":path").unwrap_or_default());
                    } else if let Some(status) = find(":status") {
                        part += &format!(" {status}");
                    }
                    grpc |= find("content-type").is_some_and(|v| v.starts_with("application/grpc"));
                    for (name, value) in headers {
                        self.field(from, to, || format!("Header: {name}: {value}"));
                    }
                }
                3 | 7 if body + 4 <= body_end => {
                    let code = be32(bytes, body_end - 4);
                    self.field(body, body_end, || format!("Error code: {code}"));
                }
                4 => {
                    for setting in bytes[body..body_end].as_chunks::<6>().0.iter().take(16) {
                        let name = match be16(setting, 0) {
                            1 => "header table size",
                            2 => "enable push",
                            3 => "max concurrent streams",
                            4 => "initial window size",
                            5 => "max frame size",
                            6 => "max header list size",
                            _ => "unknown",
                        };
                        let value = be32(setting, 2);
                        self.field(body, body_end, || format!("Setting: {name} = {value}"));
                    }
                }
                8 if body + 4 <= body_end => {
                    let increment = be32(bytes, body) & 0x7fff_ffff;
                    self.field(body, body_end, || format!("Window increment: {increment}"));
                }
                _ => {}
            }
            if parts.len() < 6 {
                parts.push(std::mem::take(&mut part));
            }
            cursor = body + length;
        }
        if grpc {
            self.proto(Protocol::Grpc);
        }
        self.summary.info = format!(
            "{} {}",
            if grpc {
                "gRPC over HTTP/2 ·"
            } else {
                "HTTP/2 ·"
            },
            parts.join(", ")
        );
        true
    }

    /// WebSocket frames; only tried for conversations that upgraded.
    pub(super) fn websocket(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        let mut cursor = start;
        let mut parts = Vec::new();
        for _ in 0..8 {
            if cursor + 2 > end {
                break;
            }
            let (first, second) = (bytes[cursor], bytes[cursor + 1]);
            let name = match first & 0x0f {
                0 => "continuation",
                1 => "text",
                2 => "binary",
                8 => "close",
                9 => "ping",
                10 => "pong",
                _ => break,
            };
            let mut header = 2;
            let length = match second & 0x7f {
                126 if cursor + 4 <= end => {
                    header += 2;
                    usize::from(be16(bytes, cursor + 2))
                }
                127 if cursor + 10 <= end => {
                    header += 8;
                    be32(bytes, cursor + 6) as usize
                }
                short @ 0..=125 => usize::from(short),
                _ => break,
            };
            let masked = second & 0x80 != 0;
            let key_at = cursor + header;
            if masked {
                header += 4;
            }
            let body = cursor + header;
            if body > end {
                break;
            }
            let body_end = body.saturating_add(length).min(end);
            if parts.is_empty() {
                self.proto(Protocol::WebSocket);
                self.layer("WebSocket", start, end);
            }
            let mut label = format!("{name} · {length} bytes");
            if first & 0x0f == 1 {
                let shown: Vec<u8> = bytes[body..body_end]
                    .iter()
                    .take(120)
                    .enumerate()
                    .map(|(i, b)| {
                        if masked {
                            b ^ bytes[key_at + i % 4]
                        } else {
                            *b
                        }
                    })
                    .collect();
                label += &format!(" · {}", String::from_utf8_lossy(&shown));
            }
            self.field(cursor, body_end, || format!("Frame: {label}"));
            parts.push(label);
            cursor = body.saturating_add(length);
        }
        if parts.is_empty() {
            return false;
        }
        self.summary.info = format!("WebSocket {}", parts.join(", "));
        true
    }

    pub(super) fn snmp(&mut self, start: usize, end: usize) -> bool {
        let data = &self.bytes[..end];
        let Some((0x30, from, to)) = ber(data, start) else {
            return false;
        };
        let parts = ber_children(data, from, to);
        let [(2, v0, v1), rest @ ..] = parts.as_slice() else {
            return false;
        };
        let version = match ber_int(&data[*v0..*v1]) {
            0 => "v1",
            1 => "v2c",
            3 => "v3",
            _ => return false,
        };
        self.proto(Protocol::Snmp);
        self.layer("SNMP", start, end);
        self.field(*v0, *v1, || format!("Version: {version}"));
        self.summary.info = format!("SNMP{version}");
        let [(4, c0, c1), (pdu, p0, p1), ..] = rest else {
            self.summary.info += " message";
            return true;
        };
        let community = text(&data[*c0..*c1]);
        self.field(*c0, *c1, || format!("Community: {community}"));
        let name = match pdu {
            0xa0 => "get-request",
            0xa1 => "get-next-request",
            0xa2 => "response",
            0xa3 => "set-request",
            0xa4 => "trap",
            0xa5 => "get-bulk-request",
            0xa6 => "inform-request",
            0xa7 => "trap",
            _ => "PDU",
        };
        self.field(*p0, *p1, || format!("PDU: {name}"));
        self.summary.info += &format!(" {name} · community {community}");
        let fields = ber_children(data, *p0, *p1);
        if let Some((2, r0, r1)) = fields.first() {
            let id = ber_int(&data[*r0..*r1]);
            self.field(*r0, *r1, || format!("Request ID: {id}"));
        }
        if let (Some((2, e0, e1)), true) = (fields.get(1), *pdu == 0xa2) {
            let status = ber_int(&data[*e0..*e1]);
            self.field(*e0, *e1, || format!("Error status: {status}"));
        }
        // Variable bindings: SEQUENCE OF SEQUENCE { name, value }.
        if let Some((0x30, b0, b1)) = fields.last() {
            for (index, (_, s0, s1)) in ber_children(data, *b0, *b1).into_iter().enumerate() {
                if let Some((6, o0, o1)) = ber(&data[..s1], s0) {
                    let name = oid(&data[o0..o1]);
                    if index == 0 {
                        self.summary.info += &format!(" · {name}");
                    }
                    self.field(s0, s1, || format!("Object: {name}"));
                }
            }
        }
        true
    }

    pub(super) fn ldap(&mut self, start: usize, end: usize) -> bool {
        let data = &self.bytes[..end];
        let Some((0x30, from, to)) = ber(data, start) else {
            return false;
        };
        let parts = ber_children(data, from, to);
        let [(2, i0, i1), (op, o0, o1), ..] = parts.as_slice() else {
            return false;
        };
        if op & 0xc0 != 0x40 {
            return false;
        }
        let name = match op & 0x1f {
            0 => "bindRequest",
            1 => "bindResponse",
            2 => "unbindRequest",
            3 => "searchRequest",
            4 => "searchResultEntry",
            5 => "searchResultDone",
            6 => "modifyRequest",
            7 => "modifyResponse",
            8 => "addRequest",
            9 => "addResponse",
            10 => "deleteRequest",
            11 => "deleteResponse",
            23 => "extendedRequest",
            24 => "extendedResponse",
            _ => "operation",
        };
        let id = ber_int(&data[*i0..*i1]);
        self.proto(Protocol::Ldap);
        self.layer("LDAP", start, end);
        self.field(*i0, *i1, || format!("Message ID: {id}"));
        self.field(*o0, *o1, || format!("Operation: {name}"));
        self.summary.info = format!("LDAP {name} · id {id}");
        let fields = ber_children(data, *o0, *o1);
        let string = |index: usize| {
            fields
                .get(index)
                .filter(|(tag, ..)| *tag == 4)
                .map(|(_, a, b)| (*a, *b, text(&data[*a..*b])))
        };
        match op & 0x1f {
            0 => {
                if let Some((a, b, name)) = string(1) {
                    self.summary.info += &format!(" · {name}");
                    self.field(a, b, || format!("Name: {name}"));
                }
            }
            3 | 4 => {
                if let Some((a, b, name)) = string(0) {
                    self.summary.info += &format!(" · {name}");
                    self.field(a, b, || format!("Object: {name}"));
                }
            }
            1 | 5 | 7 | 9 | 11 | 24 => {
                if let Some((0x0a, a, b)) = fields.first() {
                    let code = ber_int(&data[*a..*b]);
                    self.summary.info += &format!(" · result {code}");
                    self.field(*a, *b, || format!("Result code: {code}"));
                }
            }
            _ => {}
        }
        true
    }

    /// Kerberos; over TCP the message follows a four-byte length.
    pub(super) fn kerberos(&mut self, mut start: usize, end: usize, tcp: bool) -> bool {
        if tcp {
            start += 4;
        }
        let data = &self.bytes[..end];
        let Some((tag, from, to)) = ber(data, start) else {
            return false;
        };
        let name = match tag {
            0x6a => "AS-REQ",
            0x6b => "AS-REP",
            0x6c => "TGS-REQ",
            0x6d => "TGS-REP",
            0x6e => "AP-REQ",
            0x6f => "AP-REP",
            0x7e => "KRB-ERROR",
            _ => return false,
        };
        let Some((0x30, from, to)) = ber(&data[..to], from) else {
            return false;
        };
        self.proto(Protocol::Kerberos);
        self.layer("Kerberos", start, end);
        self.field(start, start + 1, || format!("Message type: {name}"));
        self.summary.info = format!("Kerberos {name}");
        let mut notes = Vec::new();
        self.kerberos_walk(from, to, 0, &mut notes);
        let decrypted = notes.iter().any(|note| note == "decrypted");
        notes.retain(|note| note != "decrypted");
        notes.dedup();
        for note in notes.iter().take(3) {
            self.summary.info += &format!(" · {note}");
        }
        if decrypted {
            self.summary.info += " · decrypted with a keytab key";
        }
        true
    }

    /// Lists realms, principals and encrypted parts; decrypts the parts a
    /// configured keytab key opens.
    fn kerberos_walk(&mut self, start: usize, end: usize, depth: u8, notes: &mut Vec<String>) {
        let data = &self.bytes[..end];
        for (tag, from, to) in ber_children(data, start, end) {
            match tag {
                0x1b => {
                    let value = text(&data[from..to]);
                    self.field(from, to, || format!("Name: {value}"));
                    notes.push(value);
                }
                // EncryptedData: SEQUENCE { [0] etype, [1] kvno?, [2] cipher }.
                0x30 if depth < 12 => {
                    let parts = ber_children(data, from, to);
                    let cipher = parts.iter().find(|(tag, ..)| *tag == 0xa2);
                    let etype = parts
                        .first()
                        .filter(|(tag, ..)| *tag == 0xa0 && parts.len() <= 3)
                        .and_then(|(_, a, b)| ber(&data[..*b], *a))
                        .filter(|(tag, ..)| *tag == 2)
                        .map(|(_, a, b)| ber_int(&data[a..b]));
                    let octets = cipher
                        .and_then(|(_, a, b)| ber(&data[..*b], *a))
                        .filter(|(tag, ..)| *tag == 4);
                    match (etype, octets) {
                        (Some(etype), Some((_, a, b))) => {
                            self.field(from, to, || {
                                format!("Encrypted part: etype {etype} · {} bytes", b - a)
                            });
                            if let Some(plain) = crate::crypto::kerberos_decrypt(&data[a..b]) {
                                let strings = printable_strings(&plain);
                                self.field(a, b, || {
                                    format!(
                                        "Decrypted: {} bytes · {}",
                                        plain.len(),
                                        strings.join(" ")
                                    )
                                });
                                notes.push("decrypted".into());
                            }
                        }
                        _ => self.kerberos_walk(from, to, depth + 1, notes),
                    }
                }
                constructed if constructed & 0x20 != 0 && depth < 12 => {
                    self.kerberos_walk(from, to, depth + 1, notes);
                }
                _ => {}
            }
        }
    }

    pub(super) fn rdp(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        if end - start < 7 || bytes[start] != 3 || bytes[start + 1] != 0 {
            return false;
        }
        let name = match bytes[start + 5] & 0xf0 {
            0xe0 => "Connection request",
            0xd0 => "Connection confirm",
            0x80 => "Disconnect request",
            0xf0 => "Data",
            _ => return false,
        };
        self.proto(Protocol::Rdp);
        self.layer("RDP (TPKT/X.224)", start, end);
        self.field(start + 2, start + 4, || {
            format!("Length: {}", be16(bytes, start + 2))
        });
        self.field(start + 5, start + 6, || format!("X.224: {name}"));
        self.summary.info = format!("RDP {name}");
        if let Some(at) = bytes[start..end].windows(7).position(|w| w == b"Cookie:") {
            let line = bytes[start + at..end]
                .split(|b| *b == b'\r')
                .next()
                .unwrap_or_default();
            let cookie = text(line);
            self.summary.info += &format!(" · {cookie}");
            self.field(start + at, start + at + line.len(), || cookie);
        }
        true
    }

    /// ONC RPC with NFS, mount and portmap procedure names.
    pub(super) fn rpc(&mut self, mut start: usize, end: usize, tcp: bool) -> bool {
        let bytes = self.bytes;
        if tcp {
            start += 4;
        }
        if start + 12 > end {
            return false;
        }
        let xid = be32(bytes, start);
        match be32(bytes, start + 4) {
            0 if start + 24 <= end && be32(bytes, start + 8) == 2 => {
                let (program, version, procedure) = (
                    be32(bytes, start + 12),
                    be32(bytes, start + 16),
                    be32(bytes, start + 20),
                );
                let service = match program {
                    100_000 => "Portmap",
                    100_003 => "NFS",
                    100_005 => "Mount",
                    100_021 => "NLM",
                    _ => "RPC",
                };
                let name = match (program, version, procedure) {
                    (_, _, 0) => "NULL",
                    (100_003, 4, 1) => "COMPOUND",
                    (100_003, 3, p) => [
                        "NULL",
                        "GETATTR",
                        "SETATTR",
                        "LOOKUP",
                        "ACCESS",
                        "READLINK",
                        "READ",
                        "WRITE",
                        "CREATE",
                        "MKDIR",
                        "SYMLINK",
                        "MKNOD",
                        "REMOVE",
                        "RMDIR",
                        "RENAME",
                        "LINK",
                        "READDIR",
                        "READDIRPLUS",
                        "FSSTAT",
                        "FSINFO",
                        "PATHCONF",
                        "COMMIT",
                    ]
                    .get(p as usize)
                    .copied()
                    .unwrap_or("procedure"),
                    (100_005, _, 1) => "MNT",
                    (100_005, _, 3) => "UMNT",
                    (100_000, _, 3) => "GETPORT",
                    _ => "procedure",
                };
                self.proto(Protocol::Nfs);
                self.layer("ONC RPC", start, end);
                self.field(start, start + 4, || format!("Transaction ID: 0x{xid:08x}"));
                self.field(start + 12, start + 16, || {
                    format!("Program: {program} ({service})")
                });
                self.field(start + 16, start + 20, || format!("Version: {version}"));
                self.field(start + 20, start + 24, || {
                    format!("Procedure: {procedure} ({name})")
                });
                self.summary.info = format!("{service} v{version} {name} call · xid 0x{xid:08x}");
                true
            }
            1 if be32(bytes, start + 8) <= 1 => {
                let accepted = be32(bytes, start + 8) == 0;
                self.proto(Protocol::Nfs);
                self.layer("ONC RPC", start, end);
                self.field(start, start + 4, || format!("Transaction ID: 0x{xid:08x}"));
                self.field(start + 8, start + 12, || {
                    format!("Reply: {}", if accepted { "accepted" } else { "denied" })
                });
                self.summary.info = format!(
                    "RPC reply · xid 0x{xid:08x} · {}",
                    if accepted { "accepted" } else { "denied" }
                );
                true
            }
            _ => false,
        }
    }

    pub(super) fn mysql(&mut self, start: usize, end: usize, to_server: bool) -> bool {
        let bytes = self.bytes;
        if end - start < 5 {
            return false;
        }
        let length = usize::from(bytes[start])
            | usize::from(bytes[start + 1]) << 8
            | usize::from(bytes[start + 2]) << 16;
        let (sequence, first) = (bytes[start + 3], bytes[start + 4]);
        if length == 0 {
            return false;
        }
        let body = &bytes[start + 5..end.min(start + 4 + length)];
        let info = match (to_server, sequence, first) {
            (false, 0, 10) => {
                let version = body.split(|b| *b == 0).next().unwrap_or_default();
                format!("Server greeting · version {}", text(version))
            }
            (true, 0, 0x03) => format!("Query · {}", text(body)),
            (true, 0, 0x02) => format!("Use database · {}", text(body)),
            (true, 0, 0x16) => format!("Prepare · {}", text(body)),
            (true, 0, 0x17) => "Execute statement".into(),
            (true, 0, 0x01) => "Quit".into(),
            (true, 0, 0x0e) => "Ping".into(),
            (true, 1, _) => "Login request".into(),
            (false, _, 0x00) => "OK".into(),
            (false, _, 0xff) if body.len() >= 2 => format!(
                "Error {} · {}",
                u16::from_le_bytes([body[0], body[1]]),
                text(body.get(8..).unwrap_or_default())
            ),
            (false, _, 0xfe) => "End of data".into(),
            (false, _, _) => "Result set".into(),
            _ => "Command".into(),
        };
        self.proto(Protocol::Mysql);
        self.layer("MySQL", start, end);
        self.field(start, start + 3, || format!("Packet length: {length}"));
        self.field(start + 3, start + 4, || format!("Sequence: {sequence}"));
        self.field(start + 4, end, || format!("Message: {info}"));
        self.summary.info = format!("MySQL {info}");
        true
    }

    pub(super) fn postgres(&mut self, start: usize, end: usize, to_server: bool) -> bool {
        let bytes = self.bytes;
        if end - start < 5 {
            return false;
        }
        self.proto(Protocol::Postgres);
        self.layer("PostgreSQL", start, end);
        // Startup packets have no type byte: length, then a protocol code.
        if to_server && bytes[start] == 0 && end - start >= 8 {
            let code = be32(bytes, start + 4);
            let info = match code {
                80_877_103 => "SSL request".to_string(),
                80_877_102 => "Cancel request".to_string(),
                _ => {
                    let parameters: Vec<String> = bytes[start + 8..end]
                        .split(|b| *b == 0)
                        .filter(|part| !part.is_empty())
                        .take(8)
                        .map(text)
                        .collect();
                    format!("Startup · {}", parameters.join(" "))
                }
            };
            self.field(start, end, || format!("Message: {info}"));
            self.summary.info = format!("PostgreSQL {info}");
            return true;
        }
        let mut cursor = start;
        let mut parts = Vec::new();
        // Each message consumes at least five bytes.
        while cursor + 5 <= end && parts.len() < 8 {
            let kind = bytes[cursor];
            let length = be32(bytes, cursor + 1) as usize;
            if length < 4 {
                break;
            }
            let body_end = cursor.saturating_add(1 + length).min(end);
            let body = &bytes[cursor + 5..body_end];
            let string = || text(body.split(|b| *b == 0).next().unwrap_or_default());
            let label = match (to_server, kind) {
                (true, b'Q') => format!("Query · {}", string()),
                (true, b'P') => format!(
                    "Parse · {}",
                    text(body.split(|b| *b == 0).nth(1).unwrap_or_default())
                ),
                (true, b'B') => "Bind".into(),
                (true, b'E') => "Execute".into(),
                (true, b'S') => "Sync".into(),
                (true, b'X') => "Terminate".into(),
                (true, b'p') => "Password message".into(),
                (false, b'R') => "Authentication".into(),
                (false, b'S') => format!("Parameter status · {}", string()),
                (false, b'K') => "Backend key data".into(),
                (false, b'Z') => "Ready for query".into(),
                (false, b'T') => "Row description".into(),
                (false, b'D') => "Data row".into(),
                (false, b'C') => format!("Command complete · {}", string()),
                (false, b'E') => "Error".into(),
                (false, b'1') => "Parse complete".into(),
                (false, b'2') => "Bind complete".into(),
                _ => format!("Message '{}'", char::from(kind).escape_default()),
            };
            self.field(cursor, body_end, || format!("Message: {label}"));
            parts.push(label);
            cursor = cursor.saturating_add(1 + length);
        }
        self.summary.info = format!("PostgreSQL {}", parts.join(", "));
        true
    }

    pub(super) fn bgp(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        let mut cursor = start;
        let mut parts = Vec::new();
        // Each message is at least its 19-byte header.
        while cursor + 19 <= end && parts.len() < 16 {
            if bytes[cursor..cursor + 16] != [0xff; 16] {
                break;
            }
            let length = usize::from(be16(bytes, cursor + 16));
            if length < 19 {
                break;
            }
            let body = cursor + 19;
            let body_end = (cursor + length).min(end);
            if parts.is_empty() {
                self.proto(Protocol::Bgp);
                self.layer("BGP", start, end);
            }
            let label = match bytes[cursor + 18] {
                1 if body + 10 <= body_end => format!(
                    "OPEN · AS {} · hold {} s · router {}",
                    be16(bytes, body + 1),
                    be16(bytes, body + 3),
                    ipv4(&bytes[body + 5..body + 9])
                ),
                2 if body + 4 <= body_end => {
                    let withdrawn = usize::from(be16(bytes, body));
                    let attributes = bytes
                        .get(body + 2 + withdrawn..body + 4 + withdrawn)
                        .map_or(0, |b| usize::from(be16(b, 0)));
                    let mut prefixes = Vec::new();
                    let mut at = body + 4 + withdrawn + attributes;
                    // Announced prefixes: a bit length, then that many bits.
                    while at < body_end && prefixes.len() < 8 {
                        let bits = usize::from(bytes[at]);
                        let size = bits.div_ceil(8);
                        if bits > 32 || at + 1 + size > body_end {
                            break;
                        }
                        let mut address = [0u8; 4];
                        address[..size].copy_from_slice(&bytes[at + 1..at + 1 + size]);
                        prefixes.push(format!("{}/{bits}", ipv4(&address)));
                        at += 1 + size;
                    }
                    format!(
                        "UPDATE · {} withdrawn bytes · {}",
                        withdrawn,
                        if prefixes.is_empty() {
                            "no prefixes".into()
                        } else {
                            prefixes.join(" ")
                        }
                    )
                }
                3 if body + 2 <= body_end => format!(
                    "NOTIFICATION · code {} subcode {}",
                    bytes[body],
                    bytes[body + 1]
                ),
                4 => "KEEPALIVE".into(),
                5 => "ROUTE-REFRESH".into(),
                other => format!("message type {other}"),
            };
            self.field(cursor, body_end, || format!("Message: {label}"));
            parts.push(label);
            cursor += length;
        }
        if parts.is_empty() {
            return false;
        }
        self.summary.info = format!("BGP {}", parts.join(", "));
        true
    }

    pub(super) fn ospf(&mut self, start: usize, end: usize) {
        let bytes = self.bytes;
        self.proto(Protocol::Ospf);
        if start + 24 > end {
            self.warn("Truncated OSPF header");
            return;
        }
        let name = match bytes[start + 1] {
            1 => "Hello",
            2 => "Database description",
            3 => "Link state request",
            4 => "Link state update",
            5 => "Link state acknowledgement",
            _ => "message",
        };
        let router = ipv4(&bytes[start + 4..start + 8]);
        let area = ipv4(&bytes[start + 8..start + 12]);
        self.layer("OSPF", start, end);
        self.field(start, start + 1, || format!("Version: {}", bytes[start]));
        self.field(start + 1, start + 2, || format!("Type: {name}"));
        self.field(start + 4, start + 8, || format!("Router ID: {router}"));
        self.field(start + 8, start + 12, || format!("Area: {area}"));
        self.summary.info = format!("OSPF {name} · router {router} · area {area}");
    }

    pub(super) fn rip(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        if end - start < 4 || !matches!(bytes[start], 1 | 2) || !matches!(bytes[start + 1], 1 | 2) {
            return false;
        }
        let name = if bytes[start] == 1 {
            "request"
        } else {
            "response"
        };
        self.proto(Protocol::Rip);
        self.layer("RIP", start, end);
        self.field(start, start + 1, || format!("Command: {name}"));
        self.field(start + 1, start + 2, || {
            format!("Version: {}", bytes[start + 1])
        });
        let mut routes = 0;
        for (index, entry) in bytes[start + 4..end]
            .as_chunks::<20>()
            .0
            .iter()
            .take(25)
            .enumerate()
        {
            let at = start + 4 + index * 20;
            if be16(entry, 0) == 2 {
                routes += 1;
                self.field(at, at + 20, || {
                    format!(
                        "Route: {} mask {} metric {}",
                        ipv4(&entry[4..8]),
                        ipv4(&entry[8..12]),
                        be32(entry, 16)
                    )
                });
            }
        }
        self.summary.info = format!("RIPv{} {name} · {routes} routes", bytes[start + 1]);
        true
    }

    /// RTP or RTCP; only tried when the port is known to carry media.
    pub(super) fn rtp(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        if end - start < 8 || bytes[start] >> 6 != 2 {
            return false;
        }
        let kind = bytes[start + 1];
        if (200..=204).contains(&kind) {
            let name = match kind {
                200 => "Sender report",
                201 => "Receiver report",
                202 => "Source description",
                203 => "Goodbye",
                _ => "Application-defined",
            };
            let ssrc = be32(bytes, start + 4);
            self.proto(Protocol::Rtcp);
            self.layer("RTCP", start, end);
            self.field(start + 1, start + 2, || {
                format!("Packet type: {kind} ({name})")
            });
            self.field(start + 4, start + 8, || format!("SSRC: 0x{ssrc:08x}"));
            self.summary.info = format!("RTCP {name} · SSRC 0x{ssrc:08x}");
            return true;
        }
        if end - start < 12 {
            return false;
        }
        let payload = kind & 0x7f;
        let codec = match payload {
            0 => "PCMU",
            3 => "GSM",
            4 => "G723",
            8 => "PCMA",
            9 => "G722",
            18 => "G729",
            26 => "JPEG",
            31 => "H261",
            34 => "H263",
            96..=127 => "dynamic",
            _ => "unassigned",
        };
        let (sequence, timestamp, ssrc) = (
            be16(bytes, start + 2),
            be32(bytes, start + 4),
            be32(bytes, start + 8),
        );
        self.proto(Protocol::Rtp);
        self.layer("RTP", start, end);
        self.field(start + 1, start + 2, || {
            format!("Payload type: {payload} ({codec})")
        });
        self.field(start + 2, start + 4, || format!("Sequence: {sequence}"));
        self.field(start + 4, start + 8, || format!("Timestamp: {timestamp}"));
        self.field(start + 8, start + 12, || format!("SSRC: 0x{ssrc:08x}"));
        self.summary.info = format!(
            "RTP {codec} · SSRC 0x{ssrc:08x} · seq {sequence} · time {timestamp}{}",
            if kind & 0x80 != 0 { " · mark" } else { "" }
        );
        true
    }

    /// IPsec ESP and AH headers. ESP payloads are decrypted by the analyzer
    /// when a security association was configured.
    pub(super) fn ipsec(&mut self, protocol: u8, start: usize, end: usize) {
        let bytes = self.bytes;
        if start + 12 > end {
            self.warn("Truncated IPsec header");
            return;
        }
        if protocol == 50 {
            let (spi, sequence) = (be32(bytes, start), be32(bytes, start + 4));
            self.proto(Protocol::Esp);
            self.layer("ESP", start, end);
            self.field(start, start + 4, || format!("SPI: 0x{spi:08x}"));
            self.field(start + 4, start + 8, || format!("Sequence: {sequence}"));
            self.summary.info = format!("ESP · SPI 0x{spi:08x} · sequence {sequence}");
            self.summary.payload = (start as u32, end as u32);
        } else {
            let length = (usize::from(bytes[start + 1]) + 2) * 4;
            let (spi, sequence) = (be32(bytes, start + 4), be32(bytes, start + 8));
            self.proto(Protocol::Ah);
            self.layer("Authentication Header", start, (start + length).min(end));
            self.field(start + 4, start + 8, || format!("SPI: 0x{spi:08x}"));
            self.field(start + 8, start + 12, || format!("Sequence: {sequence}"));
            self.summary.info = format!("AH · SPI 0x{spi:08x} · sequence {sequence}");
            if start + length < end && self.enter() {
                self.transport(bytes[start], start + length, end);
            }
        }
    }
}

/// Runs of printable ASCII (four or more characters), at most eight.
fn printable_strings(data: &[u8]) -> Vec<String> {
    data.split(|b| !(32..127).contains(b))
        .filter(|run| run.len() >= 4)
        .take(8)
        .map(text)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpack_reads_static_literal_and_huffman_fields() {
        // RFC 7541 C.4.1: GET http://www.example.com/ with a Huffman authority.
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let headers = hpack(&block);
        assert_eq!(headers[0], (":method".into(), "GET".into()));
        assert_eq!(headers[3], (":authority".into(), "www.example.com".into()));
        // A dynamic reference and a truncated literal do not panic.
        assert!(hpack(&[0xbe])[0].0.contains("dynamic"));
        assert!(hpack(&[0x40, 0x85, 1]).is_empty());
    }

    #[test]
    fn ber_rejects_lengths_beyond_the_data() {
        assert_eq!(ber(&[0x30, 2, 1, 2], 0), Some((0x30, 2, 4)));
        assert_eq!(ber(&[0x30, 0x82, 0, 1, 9], 0), Some((0x30, 4, 5)));
        for bad in [
            &[0x30][..],
            &[0x30, 5, 1],
            &[0x30, 0x85, 1, 1, 1, 1, 1],
            &[0x30, 0x80],
        ] {
            assert_eq!(ber(bad, 0), None);
        }
        assert_eq!(oid(&[0x2b, 6, 1, 2, 1]), "1.3.6.1.2.1");
        assert_eq!(ber_int(&[0xff]), -1);
    }
}
