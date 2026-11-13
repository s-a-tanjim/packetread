use super::{be16, be32, ipv4, ipv6, Decoder, Protocol};

impl Decoder<'_> {
    /// Port 53 is only a guess: the payload is labelled DNS if it parses.
    /// Over TCP the message follows a two-byte length and must be complete.
    /// `warn` notes a failed parse; multicast DNS ports stay quiet instead.
    pub(super) fn dns(&mut self, mut start: usize, mut end: usize, tcp: bool, warn: bool) -> bool {
        let bytes = self.bytes;
        if tcp {
            if end - start < 2 || usize::from(be16(bytes, start)) > end - start - 2 {
                return false;
            }
            end = start + 2 + usize::from(be16(bytes, start));
            start += 2;
        }
        match message(&bytes[start..end]) {
            Ok(message) => {
                self.summary.protocol = Protocol::Dns;
                self.summary.info = message.info;
                self.layer(if tcp { "DNS (TCP)" } else { "DNS (UDP)" }, start, end);
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
                for (label, range) in message.records {
                    self.field(start + range.start, start + range.end, || label);
                }
                true
            }
            Err(error) => {
                if warn {
                    self.warn(format!("Port 53: {error}"));
                }
                false
            }
        }
    }
}

struct Message {
    info: String,
    records: Vec<(String, std::ops::Range<usize>)>,
}

#[cfg(test)]
fn summary(data: &[u8]) -> Result<String, &'static str> {
    message(data).map(|message| message.info)
}

fn type_name(kind: u16) -> String {
    match kind {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        _ => kind.to_string(),
    }
}

fn message(data: &[u8]) -> Result<Message, &'static str> {
    if data.len() < 12 {
        return Err("truncated DNS header");
    }
    let response = data[2] & 0x80 != 0;
    let kind = if response { "Response" } else { "Query" };
    let mut records = Vec::new();
    if be16(data, 4) == 0 {
        return Ok(Message {
            info: format!("{kind} · id 0x{:04x}", be16(data, 0)),
            records,
        });
    }
    let mut cursor = 12;
    let mut info = String::new();
    for index in 0..be16(data, 4) {
        let (name, end) = name(data, cursor)?;
        if end + 4 > data.len() {
            return Err("truncated DNS question");
        }
        let qtype = type_name(be16(data, end));
        if index == 0 {
            info = format!("{kind} {qtype} {name}");
        }
        records.push((format!("Question: {qtype} {name}"), cursor..end + 4));
        cursor = end + 4;
    }
    // Answers are best effort: a truncated section keeps the question summary.
    let mut answers = Vec::new();
    for _ in 0..be16(data, 6).min(64) {
        let Ok((owner, end)) = name(data, cursor) else {
            break;
        };
        let Some(header) = data.get(end..end + 10) else {
            break;
        };
        let rdata_at = end + 10;
        let Some(rdata) = data.get(rdata_at..rdata_at + usize::from(be16(header, 8))) else {
            break;
        };
        let kind = be16(header, 0);
        let value = match (kind, rdata.len()) {
            (1, 4) => ipv4(rdata).to_string(),
            (28, 16) => ipv6(rdata).to_string(),
            (2 | 5 | 12, _) => name(data, rdata_at).map(|n| n.0).unwrap_or_default(),
            (15, 3..) => name(data, rdata_at + 2).map(|n| n.0).unwrap_or_default(),
            (33, 7..) => format!(
                "{}:{}",
                name(data, rdata_at + 6).map(|n| n.0).unwrap_or_default(),
                be16(rdata, 4)
            ),
            (16, 1..) => rdata[1..(1 + usize::from(rdata[0])).min(rdata.len())]
                .iter()
                .map(|b| {
                    if b.is_ascii_graphic() || *b == b' ' {
                        char::from(*b)
                    } else {
                        '.'
                    }
                })
                .collect(),
            _ => format!("{} bytes", rdata.len()),
        };
        records.push((
            format!(
                "Answer: {owner} {} TTL {} → {value}",
                type_name(kind),
                be32(header, 4)
            ),
            cursor..rdata_at + rdata.len(),
        ));
        answers.push(value);
        cursor = rdata_at + rdata.len();
    }
    if !answers.is_empty() {
        answers.truncate(4);
        info += &format!(" → {}", answers.join(", "));
    }
    Ok(Message { info, records })
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
    fn decodes_answers_and_survives_truncated_ones() {
        let mut packet = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        packet.extend(b"\x07example\x03com\x00\x00\x01\x00\x01");
        packet.extend(b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x06\x03www\xc0\x0c");
        packet.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x07");
        assert_eq!(
            summary(&packet).unwrap(),
            "Response A example.com → www.example.com, 192.0.2.7"
        );
        for end in 29..packet.len() {
            assert!(summary(&packet[..end])
                .unwrap()
                .starts_with("Response A example.com"));
        }
    }
    #[test]
    fn decodes_a_question() {
        let mut packet = vec![0; 12];
        packet[5] = 1;
        packet.extend(b"\x07example\x03com\x00\x00\x01\x00\x01");
        assert_eq!(summary(&packet).unwrap(), "Query A example.com");
    }
}
