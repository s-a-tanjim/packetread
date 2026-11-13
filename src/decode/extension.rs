//! Extension interface for custom decoders.
//!
//! An [`Extension`] is offered every TCP/UDP payload that no built-in decoder
//! claimed. Library users implement the trait; users of the binary describe a
//! fixed-layout protocol in a decoder file (see [`SchemaDecoder`]), which is
//! data only and never executes code.
use super::{Decoder, Protocol};
use std::{
    ops::Range,
    sync::{Arc, RwLock},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// Result of a custom decoder; field ranges are relative to the payload.
pub struct Decoded {
    pub info: String,
    pub fields: Vec<(String, Range<usize>)>,
}

pub trait Extension: Send + Sync {
    fn name(&self) -> &str;
    /// Returns `None` when the payload is not this protocol. The payload is
    /// untrusted and never empty.
    fn decode(&self, transport: Transport, src: u16, dst: u16, payload: &[u8]) -> Option<Decoded>;
}

static REGISTRY: RwLock<Vec<Arc<dyn Extension>>> = RwLock::new(Vec::new());

/// Adds a decoder for the rest of the process lifetime. Earlier registrations win.
pub fn register(extension: Arc<dyn Extension>) {
    REGISTRY
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .push(extension);
}

impl Decoder<'_> {
    pub(super) fn extension(
        &mut self,
        transport: Transport,
        src: u16,
        dst: u16,
        start: usize,
        end: usize,
    ) -> bool {
        let registry = REGISTRY.read().unwrap_or_else(|e| e.into_inner());
        let payload = &self.bytes[start..end];
        let Some((name, decoded)) = registry
            .iter()
            .find_map(|e| Some((e.name(), e.decode(transport, src, dst, payload)?)))
        else {
            return false;
        };
        self.summary.protocol = Protocol::Extension;
        self.summary.info = format!("{name} · {}", decoded.info);
        self.layer(name, start, end);
        for (label, range) in decoded.fields {
            self.field(
                start + range.start.min(end - start),
                start + range.end.min(end - start),
                || label,
            );
        }
        true
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    /// Unsigned integer of 1–8 bytes.
    Uint {
        size: usize,
        little: bool,
        hex: bool,
    },
    Bytes(usize),
    Text(usize),
}

/// A declarative decoder for fixed-layout protocols, one `key = value` per line:
///
/// ```text
/// name = Telemetry
/// udp.port = 9999          # or tcp.port
/// field = Version u8
/// field = Flags u16 hex
/// field = Sequence u32le
/// field = Device str:8
/// field = Token bytes:4
/// ```
///
/// Types: `u8`, `u16`, `u32`, `u64` (big endian; append `le` for little
/// endian, add `hex` to print in hexadecimal), `bytes:N`, and `str:N`.
/// Payloads shorter than the declared fields are not claimed.
#[derive(Debug)]
pub struct SchemaDecoder {
    name: String,
    transport: Transport,
    port: u16,
    fields: Vec<(String, Kind)>,
}

impl SchemaDecoder {
    pub fn parse(text: &str) -> Result<Self, String> {
        let (mut name, mut binding, mut fields) = (None, None, Vec::new());
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let error = |message: &str| format!("line {}: {message}", number + 1);
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| error("expected key = value"))?;
            let value = value.trim();
            match key.trim() {
                "name" if !value.is_empty() && value.len() <= 32 => name = Some(value.to_string()),
                "name" => return Err(error("name must be 1–32 bytes")),
                key @ ("udp.port" | "tcp.port") => {
                    let port = value.parse().map_err(|_| error("port must be 0–65535"))?;
                    let transport = if key == "udp.port" {
                        Transport::Udp
                    } else {
                        Transport::Tcp
                    };
                    binding = Some((transport, port));
                }
                "field" => {
                    let mut words = value.split_whitespace();
                    let (Some(label), Some(kind)) = (words.next(), words.next()) else {
                        return Err(error("expected field = NAME TYPE"));
                    };
                    let hex = match words.next() {
                        None => false,
                        Some("hex") => true,
                        Some(_) => return Err(error("only `hex` may follow the type")),
                    };
                    let (base, little) =
                        kind.strip_suffix("le").map_or((kind, false), |b| (b, true));
                    let sized = |prefix: &str| {
                        kind.strip_prefix(prefix)
                            .and_then(|n| n.parse().ok())
                            .filter(|n| (1..=1024).contains(n))
                    };
                    let kind = match base {
                        "u8" | "u16" | "u32" | "u64" => Kind::Uint {
                            size: base[1..].parse::<usize>().unwrap_or(8) / 8,
                            little,
                            hex,
                        },
                        _ => match (sized("bytes:"), sized("str:")) {
                            (Some(size), _) => Kind::Bytes(size),
                            (_, Some(size)) => Kind::Text(size),
                            _ => return Err(error("unknown field type")),
                        },
                    };
                    if fields.len() == 64 {
                        return Err(error("at most 64 fields"));
                    }
                    fields.push((label.to_string(), kind));
                }
                _ => return Err(error("unknown key (use name, udp.port, tcp.port, field)")),
            }
        }
        let (transport, port) = binding.ok_or("decoder needs udp.port or tcp.port")?;
        if fields.is_empty() {
            return Err("decoder needs at least one field".into());
        }
        Ok(Self {
            name: name.ok_or("decoder needs a name")?,
            transport,
            port,
            fields,
        })
    }
}

impl Extension for SchemaDecoder {
    fn name(&self) -> &str {
        &self.name
    }

    fn decode(&self, transport: Transport, src: u16, dst: u16, payload: &[u8]) -> Option<Decoded> {
        if transport != self.transport || (src != self.port && dst != self.port) {
            return None;
        }
        let mut fields = Vec::new();
        let mut cursor = 0;
        for (label, kind) in &self.fields {
            let size = match *kind {
                Kind::Uint { size, .. } | Kind::Bytes(size) | Kind::Text(size) => size,
            };
            let raw = payload.get(cursor..cursor + size)?;
            let value = match *kind {
                Kind::Uint { little, hex, .. } => {
                    let fold = |v: u64, b: &u8| (v << 8) | u64::from(*b);
                    let value = if little {
                        raw.iter().rev().fold(0, fold)
                    } else {
                        raw.iter().fold(0, fold)
                    };
                    if hex {
                        format!("0x{value:x}")
                    } else {
                        value.to_string()
                    }
                }
                Kind::Bytes(_) => raw.iter().map(|b| format!("{b:02x}")).collect(),
                Kind::Text(_) => String::from_utf8_lossy(raw)
                    .trim_end_matches('\0')
                    .to_string(),
            };
            fields.push((format!("{label}: {value}"), cursor..cursor + size));
            cursor += size;
        }
        let info = fields
            .iter()
            .take(4)
            .map(|f| f.0.replace(": ", "="))
            .collect::<Vec<_>>();
        Some(Decoded {
            info: info.join(" "),
            fields,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = "name = Telemetry\nudp.port = 9999 # demo\nfield = Version u8\n\
        field = Flags u16 hex\nfield = Sequence u32le\nfield = Device str:4\nfield = Token bytes:2\n";

    #[test]
    fn schema_decoder_reads_fields_and_rejects_short_or_foreign_payloads() {
        let decoder = SchemaDecoder::parse(SCHEMA).unwrap();
        let payload = b"\x02\x01\x00\x05\x00\x00\x00ab\0\0\xde\xadrest";
        let decoded = decoder
            .decode(Transport::Udp, 40000, 9999, payload)
            .unwrap();
        assert_eq!(decoded.info, "Version=2 Flags=0x100 Sequence=5 Device=ab");
        assert_eq!(decoded.fields[4], ("Token: dead".to_string(), 11..13));
        assert!(decoder
            .decode(Transport::Udp, 40000, 9999, &payload[..12])
            .is_none());
        assert!(decoder
            .decode(Transport::Tcp, 40000, 9999, payload)
            .is_none());
        assert!(decoder.decode(Transport::Udp, 1, 2, payload).is_none());
    }

    #[test]
    fn schema_errors_name_the_line() {
        for (text, expected) in [
            ("name = X\nudp.port = 1\nfield = A u24", "line 3"),
            ("name = X\nudp.port = 99999\nfield = A u8", "line 2"),
            ("name = X\nfield = A u8", "udp.port"),
            ("udp.port = 1\nfield = A u8", "name"),
            ("name = X\nudp.port = 1", "at least one field"),
            ("name = X\nudp.port = 1\nfield = A bytes:0", "line 3"),
            ("bogus", "line 1"),
        ] {
            assert!(
                SchemaDecoder::parse(text).unwrap_err().contains(expected),
                "{text}"
            );
        }
    }
}
