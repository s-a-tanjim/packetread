use super::{be16, Decoder, Protocol};

impl Decoder<'_> {
    /// Port 53 is only a guess: the payload is labelled DNS if it parses.
    pub(super) fn dns(&mut self, start: usize, end: usize) {
        let bytes = self.bytes;
        match summary(&bytes[start..end]) {
            Ok(info) => {
                self.summary.protocol = Protocol::Dns;
                self.summary.info = info;
                self.layer("DNS (UDP)", start, end);
                self.field(start, start + 2, || {
                    format!("Transaction ID: 0x{:04x}", be16(bytes, start))
                });
                self.field(start + 2, start + 4, || {
                    format!("Flags: 0x{:04x}", be16(bytes, start + 2))
                });
                self.field(start + 4, start + 6, || {
                    format!("Questions: {}", be16(bytes, start + 4))
                });
                self.field(start + 6, start + 8, || {
                    format!("Answers: {}", be16(bytes, start + 6))
                });
            }
            Err(error) => self.warn(format!("Port 53: {error}")),
        }
    }
}

pub fn summary(data: &[u8]) -> Result<String, &'static str> {
    if data.len() < 12 {
        return Err("truncated DNS header");
    }
    let response = data[2] & 0x80 != 0;
    let kind = if response { "Response" } else { "Query" };
    if be16(data, 4) == 0 {
        return Ok(format!("{kind} · id 0x{:04x}", be16(data, 0)));
    }
    let (name, end) = name(data, 12)?;
    if end + 4 > data.len() {
        return Err("truncated DNS question");
    }
    let qtype = be16(data, end);
    let qtype = match qtype {
        1 => "A".into(),
        28 => "AAAA".into(),
        5 => "CNAME".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        _ => qtype.to_string(),
    };
    Ok(format!("{kind} {qtype} {name}"))
}

fn name(data: &[u8], start: usize) -> Result<(String, usize), &'static str> {
    let mut cursor = start;
    let mut end = None;
    let mut labels = Vec::new();
    let mut wire_length = 1;
    // A fixed traversal budget prevents cyclic compression pointers from hanging.
    for _ in 0..128 {
        let length = *data.get(cursor).ok_or("truncated DNS name")?;
        if length == 0 {
            return Ok((labels.join("."), end.unwrap_or(cursor + 1)));
        }
        if length & 0xc0 == 0xc0 {
            let low = *data.get(cursor + 1).ok_or("truncated DNS pointer")?;
            end.get_or_insert(cursor + 2);
            cursor = (usize::from(length & 0x3f) << 8) | usize::from(low);
            continue;
        }
        if length & 0xc0 != 0 {
            return Err("invalid DNS label");
        }
        let next = cursor + 1 + usize::from(length);
        let label = data.get(cursor + 1..next).ok_or("truncated DNS label")?;
        wire_length += usize::from(length) + 1;
        if wire_length > 255 {
            return Err("DNS name exceeds 255 bytes");
        }
        labels.push(
            label
                .iter()
                .map(|b| {
                    if b.is_ascii_graphic() {
                        char::from(*b)
                    } else {
                        '.'
                    }
                })
                .collect::<String>(),
        );
        cursor = next;
    }
    Err("cyclic or excessive DNS compression")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_compression_cycles() {
        let mut packet = vec![0; 12];
        packet[5] = 1;
        packet.extend([0xc0, 12, 0, 1, 0, 1]);
        assert!(summary(&packet).unwrap_err().contains("compression"));
    }
    #[test]
    fn decodes_a_question() {
        let mut packet = vec![0; 12];
        packet[5] = 1;
        packet.extend(b"\x07example\x03com\x00\x00\x01\x00\x01");
        assert_eq!(summary(&packet).unwrap(), "Query A example.com");
    }
}
