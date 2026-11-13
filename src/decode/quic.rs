//! QUIC (RFC 9000, 9001, 9369): long headers, packet protection, frames, and
//! HTTP/3 with QPACK field sections. A client's first Initial packet is
//! decrypted here with the keys its connection ID implies; everything else
//! needs connection state and a key log (see `crate::analysis`).
use super::{
    apps::{hpack_int, hpack_string},
    be32,
    hpack_table::QPACK_STATIC,
    tls::hello,
    Decoder, Protocol,
};
use crate::tls::expand_label;
use ring::{aead, hkdf, hmac};
use std::ops::Range;

/// A variable-length integer at `at`: its value and the offset after it.
pub(crate) fn varint(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *data.get(at)?;
    let size = 1usize << (first >> 6);
    let bytes = data.get(at..at + size)?;
    let value = bytes[1..]
        .iter()
        .fold(u64::from(first & 0x3f), |v, b| v << 8 | u64::from(*b));
    Some((value, at + size))
}

/// Packet protection keys of one direction and encryption level.
pub(crate) struct Keys {
    key: aead::LessSafeKey,
    iv: [u8; 12],
    header: aead::quic::HeaderProtectionKey,
}

/// Keys for a TLS 1.3 traffic `secret` of cipher `suite`.
pub(crate) fn keys(suite: u16, secret: &[u8], v2: bool) -> Option<Keys> {
    let (algorithm, hash, protection) = match suite {
        0x1301 => (&aead::AES_128_GCM, hkdf::HKDF_SHA256, &aead::quic::AES_128),
        0x1302 => (&aead::AES_256_GCM, hkdf::HKDF_SHA384, &aead::quic::AES_256),
        0x1303 => (
            &aead::CHACHA20_POLY1305,
            hkdf::HKDF_SHA256,
            &aead::quic::CHACHA20,
        ),
        _ => return None,
    };
    let label = |name: &str| format!("{} {name}", if v2 { "quicv2" } else { "quic" });
    let key = expand_label(hash, secret, &label("key"), algorithm.key_len())?;
    let iv = expand_label(hash, secret, &label("iv"), 12)?;
    let header = expand_label(hash, secret, &label("hp"), algorithm.key_len())?;
    Some(Keys {
        key: aead::LessSafeKey::new(aead::UnboundKey::new(algorithm, &key).ok()?),
        iv: iv.try_into().ok()?,
        header: aead::quic::HeaderProtectionKey::new(protection, &header).ok()?,
    })
}

/// Initial keys: derived from the first client Initial's destination
/// connection ID, so anyone who sees that packet can read both directions.
pub(crate) fn initial_keys(version: u32, dcid: &[u8], client: bool) -> Option<Keys> {
    let (salt, v2): (&[u8; 20], bool) = match version {
        1 => (
            b"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a",
            false,
        ),
        0x6b33_43cf => (
            b"\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93\x81\xbe\x6e\x26\x9d\xcb\xf9\xbd\x2e\xd9",
            true,
        ),
        _ => return None,
    };
    let initial = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, salt), dcid);
    let label = if client { "client in" } else { "server in" };
    let secret = expand_label(hkdf::HKDF_SHA256, initial.as_ref(), label, 32)?;
    keys(0x1301, &secret, v2)
}

/// A long header, parsed up to its packet number.
pub(crate) struct Long {
    /// 0 Initial, 1 0-RTT, 2 Handshake, 3 Retry (version 2 is normalised).
    pub kind: u8,
    pub version: u32,
    pub dcid: Range<usize>,
    pub scid: Range<usize>,
    pub pn_offset: usize,
    /// End of this packet; another may follow in the same datagram.
    pub end: usize,
}

pub(crate) fn long_header(data: &[u8], start: usize) -> Option<Long> {
    let first = *data.get(start)?;
    if first & 0x80 == 0 || start + 7 > data.len() {
        return None;
    }
    let version = be32(data, start + 1);
    let dcid_len = usize::from(data[start + 5]);
    let dcid = start + 6..start + 6 + dcid_len;
    let scid_len = usize::from(*data.get(dcid.end)?);
    let scid = dcid.end + 1..dcid.end + 1 + scid_len;
    if dcid_len > 20 || scid_len > 20 || scid.end > data.len() {
        return None;
    }
    let bits = (first >> 4) & 3;
    let kind = if version == 0x6b33_43cf {
        (bits + 3) % 4
    } else {
        bits
    };
    let mut cursor = scid.end;
    if version == 0 || kind == 3 {
        return Some(Long {
            kind: 3,
            version,
            dcid,
            scid,
            pn_offset: data.len(),
            end: data.len(),
        });
    }
    if kind == 0 {
        let (token, after) = varint(data, cursor)?;
        cursor = after.checked_add(usize::try_from(token).ok()?)?;
    }
    let (length, pn_offset) = varint(data, cursor)?;
    let end = pn_offset.checked_add(usize::try_from(length).ok()?)?;
    (end <= data.len()).then_some(Long {
        kind,
        version,
        dcid,
        scid,
        pn_offset,
        end,
    })
}

/// Removes header protection from the packet at `start..end` and decrypts
/// it. `largest` is the highest packet number seen so far in its space.
pub(crate) fn open(
    keys: &Keys,
    data: &[u8],
    start: usize,
    pn_offset: usize,
    end: usize,
    largest: Option<u64>,
) -> Option<(u64, Vec<u8>)> {
    let mask = keys
        .header
        .new_mask(data.get(pn_offset + 4..pn_offset + 20)?)
        .ok()?;
    let long = data[start] & 0x80 != 0;
    let first = data[start] ^ (mask[0] & if long { 0x0f } else { 0x1f });
    let pn_len = usize::from(first & 3) + 1;
    let mut header = data.get(start..pn_offset + pn_len)?.to_vec();
    header[0] = first;
    let mut truncated = 0u64;
    for index in 0..pn_len {
        let byte = data[pn_offset + index] ^ mask[1 + index];
        header[pn_offset - start + index] = byte;
        truncated = truncated << 8 | u64::from(byte);
    }
    // RFC 9000 appendix A.3: the full number closest to the expected one.
    let expected = largest.map_or(0, |largest| largest + 1);
    let window = 1u64 << (pn_len * 8);
    let mut number = (expected & !(window - 1)) | truncated;
    if number + window / 2 <= expected && number < (1 << 62) - window {
        number += window;
    } else if number > expected + window / 2 && number >= window {
        number -= window;
    }
    let mut nonce = keys.iv;
    for (byte, part) in nonce[4..].iter_mut().zip(number.to_be_bytes()) {
        *byte ^= part;
    }
    let mut buffer = data.get(pn_offset + pn_len..end)?.to_vec();
    let length = keys
        .key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&header),
            &mut buffer,
        )
        .ok()?
        .len();
    buffer.truncate(length);
    Some((number, buffer))
}

#[derive(Debug, PartialEq)]
pub(crate) enum Frame {
    Padding,
    Ack,
    Crypto {
        offset: u64,
        data: Range<usize>,
    },
    Stream {
        id: u64,
        offset: u64,
        fin: bool,
        data: Range<usize>,
    },
    Close(u64),
    Other(&'static str),
}

/// The frames of a decrypted packet payload, with the range each occupies.
/// Parsing stops at the first frame that is unknown or malformed.
pub(crate) fn frames(plain: &[u8]) -> Vec<(Frame, Range<usize>)> {
    let mut out = Vec::new();
    let mut at = 0;
    // Every frame consumes at least its type byte.
    while at < plain.len() && out.len() < 64 {
        let start = at;
        let parsed = (|| {
            let (kind, mut at) = varint(plain, at)?;
            let skip = |mut at: usize, count: usize| {
                for _ in 0..count {
                    at = varint(plain, at)?.1;
                }
                Some(at)
            };
            let frame = match kind {
                0 => {
                    while plain.get(at) == Some(&0) {
                        at += 1;
                    }
                    return Some((Frame::Padding, at));
                }
                1 => Frame::Other("PING"),
                2 | 3 => {
                    at = skip(at, 2)?;
                    let (ranges, after) = varint(plain, at)?;
                    at = after;
                    let count = usize::try_from(ranges).ok()?.checked_mul(2)?;
                    if count > plain.len() {
                        return None;
                    }
                    at = skip(at, 1 + count + if kind == 3 { 3 } else { 0 })?;
                    Frame::Ack
                }
                4 => {
                    at = skip(at, 3)?;
                    Frame::Other("RESET_STREAM")
                }
                5 => {
                    at = skip(at, 2)?;
                    Frame::Other("STOP_SENDING")
                }
                6 | 7 => {
                    let offset = if kind == 6 {
                        let (offset, after) = varint(plain, at)?;
                        at = after;
                        offset
                    } else {
                        0
                    };
                    let (length, after) = varint(plain, at)?;
                    let end = after.checked_add(usize::try_from(length).ok()?)?;
                    if end > plain.len() {
                        return None;
                    }
                    at = end;
                    if kind == 6 {
                        Frame::Crypto {
                            offset,
                            data: after..end,
                        }
                    } else {
                        Frame::Other("NEW_TOKEN")
                    }
                }
                8..=15 => {
                    let (id, after) = varint(plain, at)?;
                    at = after;
                    let mut offset = 0;
                    if kind & 4 != 0 {
                        (offset, at) = varint(plain, at)?;
                    }
                    let end = if kind & 2 != 0 {
                        let (length, after) = varint(plain, at)?;
                        at = after;
                        at.checked_add(usize::try_from(length).ok()?)?
                    } else {
                        plain.len()
                    };
                    if end > plain.len() {
                        return None;
                    }
                    let data = at..end;
                    at = end;
                    Frame::Stream {
                        id,
                        offset,
                        fin: kind & 1 != 0,
                        data,
                    }
                }
                0x10 | 0x12 | 0x13 | 0x14 | 0x16 | 0x17 | 0x19 => {
                    at = skip(at, 1)?;
                    Frame::Other("flow control")
                }
                0x11 | 0x15 => {
                    at = skip(at, 2)?;
                    Frame::Other("flow control")
                }
                0x18 => {
                    at = skip(at, 2)?;
                    at = at.checked_add(1 + usize::from(*plain.get(at)?) + 16)?;
                    Frame::Other("NEW_CONNECTION_ID")
                }
                0x1a | 0x1b => {
                    at += 8;
                    Frame::Other("path validation")
                }
                0x1c | 0x1d => {
                    let (code, after) = varint(plain, at)?;
                    at = after;
                    if kind == 0x1c {
                        at = skip(at, 1)?;
                    }
                    let (reason, after) = varint(plain, at)?;
                    at = after.checked_add(usize::try_from(reason).ok()?)?;
                    Frame::Close(code)
                }
                0x1e => Frame::Other("HANDSHAKE_DONE"),
                _ => return None,
            };
            (at <= plain.len()).then_some((frame, at))
        })();
        let Some((frame, next)) = parsed else {
            break;
        };
        out.push((frame, start..next));
        at = next;
    }
    out
}

/// Field lines of a QPACK field section. Like HPACK, references to the
/// connection's dynamic table are shown as placeholders.
fn qpack(block: &[u8]) -> Vec<(String, String)> {
    let named = |index: usize, fixed: bool| match QPACK_STATIC.get(index).filter(|_| fixed) {
        Some((name, value)) => (name.to_string(), value.to_string()),
        None => (format!("(dynamic table entry {index})"), String::new()),
    };
    let mut out = Vec::new();
    // Prefix: required insert count, then the delta base.
    let Some(mut at) = hpack_int(block, 8).and_then(|(_, used)| {
        let (_, more) = hpack_int(block.get(used..)?, 7)?;
        Some(used + more)
    }) else {
        return out;
    };
    while let (Some(first), true) = (block.get(at).copied(), out.len() < 64) {
        let rest = &block[at..];
        let used = if first & 0x80 != 0 {
            let Some((index, used)) = hpack_int(rest, 6) else {
                break;
            };
            out.push(named(index, first & 0x40 != 0));
            used
        } else if first & 0x40 != 0 || first & 0xf0 == 0 {
            // A name reference (static, dynamic or post-base) with a literal value.
            let prefix = if first & 0x40 != 0 { 4 } else { 3 };
            let Some((index, used)) = hpack_int(rest, prefix) else {
                break;
            };
            let Some((value, length)) = hpack_string(&rest[used..], 7) else {
                break;
            };
            out.push((named(index, first & 0x50 == 0x50).0, value));
            used + length
        } else if first & 0x20 != 0 {
            let Some((name, used)) = hpack_string(rest, 3) else {
                break;
            };
            let Some((value, length)) = hpack_string(&rest[used..], 7) else {
                break;
            };
            out.push((name, value));
            used + length
        } else {
            let Some((index, used)) = hpack_int(rest, 4) else {
                break;
            };
            out.push(named(index, false));
            used
        };
        at += used;
    }
    out
}

/// One line per HTTP/3 frame at the start of QUIC stream `id`, with the
/// header fields of HEADERS frames.
fn http3(id: u64, data: &[u8]) -> Vec<(String, Vec<(String, String)>)> {
    let mut out = Vec::new();
    let mut at = 0;
    if id & 2 != 0 {
        // Unidirectional streams start with their type.
        let Some((kind, after)) = varint(data, 0) else {
            return out;
        };
        let name = match kind {
            0 => "control stream",
            1 => "push stream",
            2 => "QPACK encoder stream",
            3 => "QPACK decoder stream",
            _ => "reserved stream",
        };
        out.push((name.to_string(), Vec::new()));
        if kind != 0 {
            return out;
        }
        at = after;
    }
    while out.len() < 16 {
        let Some(((kind, length), body)) = varint(data, at).and_then(|(kind, after)| {
            let (length, body) = varint(data, after)?;
            Some(((kind, usize::try_from(length).ok()?), body))
        }) else {
            break;
        };
        let end = body.saturating_add(length).min(data.len());
        let mut fields = Vec::new();
        let label = match kind {
            0 => format!("DATA {length} bytes"),
            1 => {
                fields = qpack(&data[body..end]);
                let find = |wanted: &str| {
                    fields
                        .iter()
                        .find(|(name, _)| name == wanted)
                        .map(|(_, value)| value.clone())
                };
                match (find(":method"), find(":status")) {
                    (Some(method), _) => {
                        format!("HEADERS {method} {}", find(":path").unwrap_or_default())
                    }
                    (_, Some(status)) => format!("HEADERS {status}"),
                    _ => "HEADERS".into(),
                }
            }
            3 => "CANCEL_PUSH".into(),
            4 => "SETTINGS".into(),
            5 => "PUSH_PROMISE".into(),
            7 => "GOAWAY".into(),
            13 => "MAX_PUSH_ID".into(),
            _ => break,
        };
        out.push((label, fields));
        at = body.saturating_add(length);
    }
    out
}

impl Decoder<'_> {
    /// `guess` allows labelling a short header on UDP/443, which cannot be validated.
    pub(super) fn quic(&mut self, start: usize, end: usize, guess: bool) -> bool {
        let bytes = self.bytes;
        let first = bytes[start];
        if first & 0x80 == 0 {
            if guess && first & 0x40 != 0 {
                self.summary.protocol = Protocol::Quic;
                self.summary.info = "Protected payload · short header assumed from port 443".into();
                self.layer("QUIC (assumed from port)", start, end);
                return true;
            }
            return false;
        }
        if start + 7 > end {
            return false;
        }
        let version = be32(bytes, start + 1);
        let v2 = version == 0x6b33_43cf;
        if !(version <= 1 || v2 || version >> 8 == 0x00ff_0000) {
            return false;
        }
        let dcid_len = usize::from(bytes[start + 5]);
        let scid_at = start + 6 + dcid_len;
        if dcid_len > 20 || scid_at >= end {
            return false;
        }
        let scid_len = usize::from(bytes[scid_at]);
        if scid_len > 20 || scid_at + 1 + scid_len > end {
            return false;
        }
        let kind = match (version, (first >> 4) & 3, v2) {
            (0, _, _) => "Version Negotiation",
            (_, 0, false) | (_, 1, true) => "Initial",
            (_, 1, false) | (_, 2, true) => "0-RTT",
            (_, 2, false) | (_, 3, true) => "Handshake",
            _ => "Retry",
        };
        let hex = |range: std::ops::Range<usize>| {
            bytes[range]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let dcid = hex(start + 6..scid_at);
        self.summary.protocol = Protocol::Quic;
        self.summary.info = format!("{kind} · version 0x{version:08x} · DCID {dcid}");
        self.layer("QUIC", start, end);
        self.field(start, start + 1, || format!("Packet type: {kind}"));
        self.field(start + 1, start + 5, || format!("Version: 0x{version:08x}"));
        self.field(start + 5, scid_at, || {
            format!("Destination connection ID: {dcid}")
        });
        self.field(scid_at, scid_at + 1 + scid_len, || {
            format!(
                "Source connection ID: {}",
                hex(scid_at + 1..scid_at + 1 + scid_len)
            )
        });
        // A client's first Initial is protected only by its connection ID.
        // ponytail: a ClientHello split over several Initial packets shows
        // only what this packet carries; the analyzer joins them.
        let plain = (kind == "Initial")
            .then(|| long_header(&bytes[..end], start))
            .flatten()
            .and_then(|long| {
                let keys = initial_keys(version, &bytes[long.dcid.clone()], true)?;
                open(&keys, &bytes[..end], start, long.pn_offset, long.end, None)
            });
        if let Some((_, plain)) = plain {
            let parts = self.quic_frames(&plain, None, (start, end));
            if !parts.is_empty() {
                self.summary.info += &format!(" · {}", parts.join(", "));
            }
        }
        true
    }

    /// Decrypted QUIC frames as the whole UDP payload: the analyzer builds
    /// such datagrams from packets it could decrypt.
    pub(super) fn quic_plain(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        self.summary.protocol = Protocol::Quic;
        self.layer("QUIC (decrypted)", start, end);
        let parts = self.quic_frames(&bytes[start..end], Some(start), (start, end));
        self.summary.info = if parts.is_empty() {
            "QUIC acknowledgements and padding".into()
        } else {
            parts.join(", ")
        };
        true
    }

    /// Adds a field per frame and returns the notable ones for the summary.
    /// `base` is where `plain` sits in the packet bytes, when it does.
    fn quic_frames(
        &mut self,
        plain: &[u8],
        base: Option<usize>,
        whole: (usize, usize),
    ) -> Vec<String> {
        let mut parts = Vec::new();
        let mut crypto = Vec::new();
        for (frame, range) in frames(plain) {
            let (from, to) = base.map_or(whole, |base| (base + range.start, base + range.end));
            match frame {
                Frame::Padding => self.field(from, to, || format!("Frame: PADDING {}", to - from)),
                Frame::Ack => self.field(from, to, || "Frame: ACK".into()),
                Frame::Other(name) => {
                    self.field(from, to, || format!("Frame: {name}"));
                    parts.push(name.to_string());
                }
                Frame::Close(code) => {
                    self.field(from, to, || {
                        format!("Frame: CONNECTION_CLOSE · error {code}")
                    });
                    parts.push(format!("CONNECTION_CLOSE error {code}"));
                }
                Frame::Crypto { offset, data } => {
                    self.field(from, to, || {
                        format!("Frame: CRYPTO · offset {offset} · {} bytes", data.len())
                    });
                    if offset as usize == crypto.len() && crypto.len() < 1 << 16 {
                        crypto.extend(&plain[data]);
                    }
                }
                Frame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                } => {
                    self.field(from, to, || {
                        format!(
                            "Frame: STREAM {id} · offset {offset} · {} bytes{}",
                            data.len(),
                            if fin { " · fin" } else { "" }
                        )
                    });
                    if offset != 0 {
                        parts.push(format!("STREAM {id} continues"));
                        continue;
                    }
                    for (label, fields) in http3(id, &plain[data]) {
                        self.summary.protocol = Protocol::Http3;
                        self.summary.seen |= Protocol::Quic.bit();
                        self.field(from, to, || format!("HTTP/3: {label}"));
                        for (name, value) in fields {
                            self.field(from, to, || format!("Header: {name}: {value}"));
                        }
                        parts.push(format!("HTTP/3 {label}"));
                    }
                }
            }
        }
        // Handshake messages in the CRYPTO stream: type, 24-bit length, body.
        let mut at = 0;
        while let Some(header) = crypto.get(at..at + 4) {
            let length =
                usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
            let body = &crypto[at + 4..(at + 4 + length).min(crypto.len())];
            let name = match header[0] {
                1 => "Client Hello",
                2 => "Server Hello",
                8 => "Encrypted Extensions",
                11 => "Certificate",
                15 => "Certificate Verify",
                20 => "Finished",
                _ => break,
            };
            let mut label = name.to_string();
            if let Some(hello) = Some(header[0])
                .filter(|k| *k <= 2)
                .and_then(|k| hello(k, body))
            {
                if let Some(sni) = &hello.sni {
                    label += &format!(" · SNI {sni}");
                }
                if let Some(alpn) = &hello.alpn {
                    label += &format!(" · ALPN {alpn}");
                }
                if let Some(cipher) = hello.cipher {
                    label += &format!(" · {}", super::tls::cipher_name(cipher));
                }
            }
            self.field(whole.0, whole.1, || format!("TLS handshake: {label}"));
            parts.push(label);
            at += 4 + length;
        }
        parts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_rfc9001_initial_keys_and_parses_frames() {
        // RFC 9001 appendix A.1: client Initial for DCID 8394c8f03e515708.
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let keys = initial_keys(1, &dcid, true).unwrap();
        assert_eq!(
            keys.iv,
            [0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c]
        );
        assert!(initial_keys(2, &dcid, true).is_none());

        assert_eq!(varint(&[0x7b, 0xbd], 0), Some((15293, 2)));
        assert_eq!(varint(&[0x40], 0), None);
        // PING, CRYPTO(offset 0, "ab"), STREAM 0 with fin to the end.
        let plain = [1, 6, 0, 2, b'a', b'b', 0x09, 0, b'x'];
        let parsed: Vec<_> = frames(&plain).into_iter().map(|(frame, _)| frame).collect();
        assert_eq!(
            parsed,
            [
                Frame::Other("PING"),
                Frame::Crypto {
                    offset: 0,
                    data: 4..6
                },
                Frame::Stream {
                    id: 0,
                    offset: 0,
                    fin: true,
                    data: 8..9
                },
            ]
        );
        // Lengths beyond the payload and unknown frames stop the parse.
        assert!(frames(&[6, 0, 9, 1]).is_empty());
        assert!(frames(&[0x3f]).is_empty());
        assert!(frames(&[2, 0, 0, 0x7f, 0xff]).is_empty());
    }

    #[test]
    fn qpack_reads_static_and_literal_field_lines() {
        // Prefix (0, 0); :method GET (static 17); :path literal "/a" on static 1.
        let block = [
            0,
            0,
            0xc0 | 17,
            0x50 | 1,
            2,
            b'/',
            b'a',
            0x23,
            b'x',
            b'-',
            b'y',
            1,
            b'z',
        ];
        assert_eq!(
            qpack(&block),
            [
                (":method".to_string(), "GET".to_string()),
                (":path".to_string(), "/a".to_string()),
                ("x-y".to_string(), "z".to_string()),
            ]
        );
        assert!(qpack(&[0]).is_empty());
        let frames = http3(0, &[1, 3, 0, 0, 0xc0 | 25, 0, 2, b'h', b'i']);
        assert_eq!(frames[0].0, "HEADERS 200");
        assert_eq!(frames[1].0, "DATA 2 bytes");
    }
}
