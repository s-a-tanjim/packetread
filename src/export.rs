//! Writes packets as PCAP, PCAPNG, JSON or CSV. Capture formats store the
//! original bytes; JSON and CSV store the decoded summary and protocol tree.
use crate::decode::{safe_text, Packet};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    path::Path,
};

const SNAPLEN: u32 = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Pcap,
    Pcapng,
    Json,
    Csv,
}

impl Format {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("pcap" | "cap") => Ok(Self::Pcap),
            Some("pcapng") => Ok(Self::Pcapng),
            Some("json") => Ok(Self::Json),
            Some("csv") => Ok(Self::Csv),
            _ => Err("Choose the format with a .pcap, .pcapng, .json or .csv extension".into()),
        }
    }
}

pub struct Writer<W: Write> {
    out: W,
    format: Format,
    /// Link types with a header written: one for PCAP, one per interface for PCAPNG.
    links: Vec<i32>,
    pub written: u64,
    /// Packets a single-link PCAP file cannot hold.
    pub skipped: u64,
    pub bytes: u64,
}

impl Writer<BufWriter<File>> {
    /// Creates `path`; an existing file is never overwritten.
    pub fn create(path: &Path) -> io::Result<Self> {
        let format =
            Format::from_path(path).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| {
                io::Error::new(error.kind(), format!("{}: {error}", path.display()))
            })?;
        Self::new(BufWriter::new(file), format)
    }
}

fn block(kind: u32, body: &[u8]) -> Vec<u8> {
    let padding = (4 - body.len() % 4) % 4;
    let length = (body.len() + padding + 12) as u32;
    let mut out = Vec::with_capacity(length as usize);
    out.extend(kind.to_le_bytes());
    out.extend(length.to_le_bytes());
    out.extend(body);
    out.extend(&[0; 3][..padding]);
    out.extend(length.to_le_bytes());
    out
}

fn json(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out += "\\\"",
            '\\' => out += "\\\\",
            c if c.is_control() => out += &format!("\\u{:04x}", c as u32),
            c => out.push(c),
        }
    }
    out + "\""
}

fn csv(text: &str) -> String {
    let text = safe_text(text).replace('"', "\"\"");
    // A leading formula character would be executed by spreadsheet software.
    let guard = if text.starts_with(['=', '+', '-', '@']) {
        "'"
    } else {
        ""
    };
    format!("\"{guard}{text}\"")
}

impl<W: Write> Writer<W> {
    pub fn new(out: W, format: Format) -> io::Result<Self> {
        let mut writer = Self {
            out,
            format,
            links: Vec::new(),
            written: 0,
            skipped: 0,
            bytes: 0,
        };
        match format {
            Format::Pcapng => {
                let mut body = 0x1a2b_3c4du32.to_le_bytes().to_vec();
                body.extend([1, 0, 0, 0]);
                body.extend((-1i64).to_le_bytes());
                writer.put(&block(0x0a0d_0d0a, &body))?;
            }
            Format::Json => writer.put(b"[")?,
            Format::Csv => writer.put(
                b"number,time,source,destination,source_port,destination_port,protocol,length,stream,info,warning,comment\n",
            )?,
            Format::Pcap => {}
        }
        Ok(writer)
    }

    fn put(&mut self, data: &[u8]) -> io::Result<()> {
        self.bytes += data.len() as u64;
        self.out.write_all(data)
    }

    fn pcap_header(&mut self, link: i32) -> io::Result<()> {
        // Nanosecond-resolution PCAP 2.4.
        let mut header = 0xa1b2_3c4du32.to_le_bytes().to_vec();
        header.extend([2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        header.extend(SNAPLEN.to_le_bytes());
        header.extend((link as u32).to_le_bytes());
        self.links.push(link);
        self.put(&header)
    }

    pub fn write(&mut self, packet: &Packet) -> io::Result<()> {
        let time = packet.timestamp_ns.max(0);
        let (seconds, nanos) = ((time / 1_000_000_000) as u64, (time % 1_000_000_000) as u32);
        let summary = &packet.summary;
        match self.format {
            Format::Pcap => {
                if self.links.is_empty() {
                    self.pcap_header(packet.link)?;
                }
                if self.links[0] != packet.link {
                    self.skipped += 1;
                    return Ok(());
                }
                let mut record = (seconds.min(u64::from(u32::MAX)) as u32)
                    .to_le_bytes()
                    .to_vec();
                record.extend(nanos.to_le_bytes());
                record.extend((packet.bytes.len() as u32).to_le_bytes());
                record.extend(packet.wire_len.to_le_bytes());
                self.put(&record)?;
                self.put(&packet.bytes)?;
            }
            Format::Pcapng => {
                let interface = match self.links.iter().position(|link| *link == packet.link) {
                    Some(index) => index,
                    None => {
                        let mut body = (packet.link as u16).to_le_bytes().to_vec();
                        body.extend([0, 0]);
                        body.extend(SNAPLEN.to_le_bytes());
                        // if_tsresol = 10^-9, then end of options.
                        body.extend([9, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0]);
                        self.put(&block(1, &body))?;
                        self.links.push(packet.link);
                        self.links.len() - 1
                    }
                };
                let ticks = time as u64;
                let mut body = (interface as u32).to_le_bytes().to_vec();
                body.extend(((ticks >> 32) as u32).to_le_bytes());
                body.extend((ticks as u32).to_le_bytes());
                body.extend((packet.bytes.len() as u32).to_le_bytes());
                body.extend(packet.wire_len.to_le_bytes());
                body.extend(&packet.bytes[..]);
                body.resize(body.len().next_multiple_of(4), 0);
                if let Some(comment) = packet.comment.as_deref().filter(|c| c.len() <= 4096) {
                    body.extend([1, 0]);
                    body.extend((comment.len() as u16).to_le_bytes());
                    body.extend(comment.as_bytes());
                    body.resize(body.len().next_multiple_of(4), 0);
                    body.extend([0; 4]);
                }
                self.put(&block(6, &body))?;
            }
            Format::Json => {
                let text = |value: Option<String>| value.map_or("null".into(), |v| json(&v));
                let number = |value: Option<u64>| value.map_or("null".into(), |v| v.to_string());
                let layers: Vec<String> = packet
                    .layers()
                    .iter()
                    .map(|layer| {
                        let fields: Vec<_> = layer.fields.iter().map(|f| json(&f.label)).collect();
                        format!(
                            "{{\"name\":{},\"fields\":[{}]}}",
                            json(&layer.label),
                            fields.join(",")
                        )
                    })
                    .collect();
                let object = format!(
                    "{}\n{{\"number\":{},\"time\":\"{seconds}.{nanos:09}\",\"source\":{},\"destination\":{},\
                     \"source_port\":{},\"destination_port\":{},\"protocol\":{},\"length\":{},\"captured\":{},\
                     \"stream\":{},\"info\":{},\"warning\":{},\"comment\":{},\"marked\":{},\"layers\":[{}]}}",
                    if self.written == 0 { "" } else { "," },
                    packet.id,
                    text(summary.src.map(|a| a.to_string())),
                    text(summary.dst.map(|a| a.to_string())),
                    number(summary.src_port.map(u64::from)),
                    number(summary.dst_port.map(u64::from)),
                    json(summary.protocol.name()),
                    packet.wire_len,
                    packet.bytes.len(),
                    number(summary.stream.map(u64::from)),
                    json(&summary.info),
                    text(summary.warning.clone()),
                    text(packet.comment.clone()),
                    packet.mark,
                    layers.join(",")
                );
                self.put(object.as_bytes())?;
            }
            Format::Csv => {
                let number = |value: Option<u64>| value.map_or(String::new(), |v| v.to_string());
                let row = format!(
                    "{},{seconds}.{nanos:09},{},{},{},{},{},{},{},{},{},{}\n",
                    packet.id,
                    summary.src.map_or(String::new(), |a| a.to_string()),
                    summary.dst.map_or(String::new(), |a| a.to_string()),
                    number(summary.src_port.map(u64::from)),
                    number(summary.dst_port.map(u64::from)),
                    summary.protocol.name(),
                    packet.wire_len,
                    number(summary.stream.map(u64::from)),
                    csv(&summary.info),
                    csv(summary.warning.as_deref().unwrap_or_default()),
                    csv(packet.comment.as_deref().unwrap_or_default()),
                );
                self.put(row.as_bytes())?;
            }
        }
        self.written += 1;
        Ok(())
    }

    /// Completes the file and flushes it; returns the writer for its counters.
    pub fn finish(mut self) -> io::Result<Self> {
        match self.format {
            Format::Pcap if self.links.is_empty() => self.pcap_header(1)?,
            Format::Json => self.put(b"\n]\n")?,
            _ => {}
        }
        self.out.flush()?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(id: u64, link: i32) -> Packet {
        let mut packet = Packet::new(
            id,
            1_700_000_000_123_456_789,
            80,
            link,
            vec![id as u8; 5].into(),
        );
        packet.summary.info = "=cmd \"x\"\x1b[2J".into();
        packet
    }

    fn written(format: Format, packets: &[Packet]) -> Writer<Vec<u8>> {
        let mut writer = Writer::new(Vec::new(), format).unwrap();
        packets
            .iter()
            .for_each(|packet| writer.write(packet).unwrap());
        writer.finish().unwrap()
    }

    #[test]
    fn pcap_skips_other_link_types_and_empty_files_are_valid() {
        let writer = written(
            Format::Pcap,
            &[packet(1, 999), packet(2, 1), packet(3, 999)],
        );
        assert_eq!((writer.written, writer.skipped), (2, 1));
        assert_eq!(writer.out.len(), 24 + 2 * (16 + 5));
        assert_eq!(writer.bytes as usize, writer.out.len());
        assert_eq!(written(Format::Pcap, &[]).out.len(), 24);
    }

    #[test]
    fn text_formats_escape_untrusted_values() {
        let json = String::from_utf8(written(Format::Json, &[packet(1, 999), packet(2, 999)]).out)
            .unwrap();
        assert!(json.starts_with("[\n{\"number\":1,\"time\":\"1700000000.123456789\""));
        assert!(json.contains(r#""info":"=cmd \"x\"\u001b[2J""#));
        assert!(json.contains("},\n{\"number\":2") && json.ends_with("}\n]\n"));
        assert_eq!(
            String::from_utf8(written(Format::Json, &[]).out).unwrap(),
            "[\n]\n"
        );
        let csv = String::from_utf8(written(Format::Csv, &[packet(1, 999)]).out).unwrap();
        assert!(csv
            .lines()
            .nth(1)
            .unwrap()
            .contains(",\"'=cmd \"\"x\"\"�[2J\","));
        assert!(!csv.contains('\x1b'));
    }

    #[test]
    fn format_follows_the_extension() {
        assert_eq!(
            Format::from_path(Path::new("a/b.PCAPNG")),
            Ok(Format::Pcapng)
        );
        assert!(Format::from_path(Path::new("capture")).is_err());
    }
}
