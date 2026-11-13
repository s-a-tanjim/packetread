//! TLS record headers and cleartext handshake messages (hello SNI, ALPN,
//! version and cipher suite). Decryption lives in `crate::tls`.
use super::{be16, Decoder, Protocol};

/// Bounds-checked cursor over untrusted bytes.
pub(crate) struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(length)?;
        self.0 = tail;
        Some(head)
    }
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| be16(b, 0))
    }
    pub fn vec8(&mut self) -> Option<&'a [u8]> {
        let length = self.u8()?;
        self.take(usize::from(length))
    }
    pub fn vec16(&mut self) -> Option<&'a [u8]> {
        let length = self.u16()?;
        self.take(usize::from(length))
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Hello {
    pub random: [u8; 32],
    pub sni: Option<String>,
    pub alpn: Option<String>,
    /// Selected cipher suite (ServerHello only).
    pub cipher: Option<u16>,
    pub version: u16,
    /// The extended master secret extension is present.
    pub ems: bool,
    /// The encrypt-then-MAC extension is present.
    pub etm: bool,
}

/// Parses the body of a ClientHello (`kind` 1) or ServerHello (`kind` 2).
pub(crate) fn hello(kind: u8, body: &[u8]) -> Option<Hello> {
    let mut reader = Reader(body);
    let mut hello = Hello {
        version: reader.u16()?,
        ..Hello::default()
    };
    hello.random.copy_from_slice(reader.take(32)?);
    reader.vec8()?;
    if kind == 1 {
        reader.vec16()?;
        reader.vec8()?;
    } else {
        hello.cipher = Some(reader.u16()?);
        reader.u8()?;
    }
    // A hello may continue in the next TCP segment: read what is here.
    let declared = usize::from(reader.u16().unwrap_or(0));
    let mut extensions = Reader(&reader.0[..declared.min(reader.0.len())]);
    while let (Some(code), Some(data)) = (extensions.u16(), extensions.vec16()) {
        let mut data = Reader(data);
        match code {
            0 => {
                let mut names = Reader(data.vec16().unwrap_or_default());
                if let (Some(0), Some(name)) = (names.u8(), names.vec16()) {
                    hello.sni = Some(String::from_utf8_lossy(name).into_owned());
                }
            }
            16 => {
                let mut protocols = Reader(data.vec16().unwrap_or_default());
                hello.alpn = protocols
                    .vec8()
                    .map(|p| String::from_utf8_lossy(p).into_owned());
            }
            43 if kind == 1 => {
                let mut versions = Reader(data.vec8().unwrap_or_default());
                while let Some(version) = versions.u16() {
                    // Skip GREASE values (0x?a?a).
                    if version & 0x0f0f != 0x0a0a {
                        hello.version = hello.version.max(version);
                    }
                }
            }
            43 => hello.version = data.u16().unwrap_or(hello.version),
            23 => hello.ems = true,
            22 => hello.etm = true,
            _ => {}
        }
    }
    Some(hello)
}

pub(crate) fn version_name(version: u16) -> String {
    match version {
        0x0300 => "SSL 3.0".into(),
        0x0301..=0x0304 => format!("TLS 1.{}", version - 0x0301),
        _ => format!("version 0x{version:04x}"),
    }
}

pub(crate) fn cipher_name(cipher: u16) -> String {
    match cipher {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        _ => return format!("cipher 0x{cipher:04x}"),
    }
    .into()
}

fn handshake_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        _ => return None,
    })
}

/// True when `data` starts with a plausible TLS record header.
pub(crate) fn is_record(data: &[u8]) -> bool {
    data.len() >= 5
        && (20..=23).contains(&data[0])
        && data[1] == 3
        && data[2] <= 4
        && (1..=16384 + 2048).contains(&be16(data, 3))
}

impl Decoder<'_> {
    pub(super) fn tls(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        if !is_record(&bytes[start..end]) {
            return false;
        }
        self.summary.protocol = Protocol::Tls;
        self.layer("TLS", start, end);
        let mut notes: Vec<String> = Vec::new();
        let mut cursor = start;
        for _ in 0..16 {
            if !is_record(&bytes[cursor..end]) {
                break;
            }
            let length = usize::from(be16(bytes, cursor + 3));
            let body_end = (cursor + 5 + length).min(end);
            let body = &bytes[cursor + 5..body_end];
            let note = match bytes[cursor] {
                20 => "Change Cipher Spec".to_string(),
                21 => "Alert".to_string(),
                23 => "Application Data".to_string(),
                _ => self.handshake(cursor + 5, body),
            };
            self.field(cursor, body_end, || {
                format!("Record: {note} ({length} bytes)")
            });
            if !notes.contains(&note) && notes.len() < 4 {
                notes.push(note);
            }
            cursor += 5 + length;
            if cursor >= end {
                break;
            }
        }
        self.summary.info = notes.join(" · ");
        true
    }

    fn handshake(&mut self, at: usize, body: &[u8]) -> String {
        let declared = body
            .get(1..4)
            .map(|b| (usize::from(b[0]) << 16) | usize::from(be16(b, 1)));
        let name = body.first().and_then(|kind| handshake_name(*kind));
        // After the key exchange, handshake records are ciphertext.
        let (Some(name), Some(declared)) = (name, declared.filter(|d| d + 4 <= 16384 + 2048))
        else {
            return "Encrypted handshake message".into();
        };
        let Some(hello) = (body[0] <= 2)
            .then(|| hello(body[0], &body[4..(4 + declared).min(body.len())]))
            .flatten()
        else {
            return name.into();
        };
        let mut note = format!("{name} · {}", version_name(hello.version));
        self.field(at + 6, at + 38, || "Random".into());
        if let Some(sni) = hello.sni {
            self.field(at, at + body.len(), || format!("Server name: {sni}"));
            note += &format!(" · SNI {sni}");
        }
        if let Some(alpn) = hello.alpn {
            self.field(at, at + body.len(), || format!("ALPN: {alpn}"));
        }
        if let Some(cipher) = hello.cipher {
            let cipher = cipher_name(cipher);
            self.field(at, at + body.len(), || format!("Cipher suite: {cipher}"));
            note += &format!(" · {cipher}");
        }
        note
    }
}
