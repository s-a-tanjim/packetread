use super::{invalid, MAX_BLOCK_BYTES, MAX_PACKET_BYTES};
use crate::decode::Packet;
use pcap_parser::{Block, OptionCode, PcapBlockOwned, PcapNGOption};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

const MAX_INTERFACES: usize = 1024;
const MAX_NAMES: usize = 10_000;

/// Descriptive PCAPNG metadata. All text comes from the file: pass it
/// through `decode::safe_text` before showing it.
#[derive(Clone, Debug, Default)]
pub struct Metadata {
    /// Section header options, such as the capturing application.
    pub section: Vec<String>,
    /// One description per interface, in interface order.
    pub interfaces: Vec<String>,
    /// Host names from name-resolution blocks.
    pub names: Vec<(IpAddr, String)>,
}

/// The text of the options whose code is in `wanted`, labelled.
fn option_text(options: &[PcapNGOption<'_>], wanted: &[(u16, &str)]) -> Vec<String> {
    let mut out = Vec::new();
    for option in options.iter().take(64) {
        let Some((_, label)) = wanted.iter().find(|(code, _)| *code == option.code.0) else {
            continue;
        };
        let length = usize::from(option.len).min(256).min(option.value.len());
        let text = String::from_utf8_lossy(&option.value[..length]);
        out.push(format!("{label}: {}", text.trim_matches('\0')));
    }
    out
}

struct Interface {
    link: i32,
    snaplen: u32,
    resolution: u64,
    offset: i64,
}

impl Interface {
    fn timestamp(&self, ticks: u64) -> i128 {
        i128::from(self.offset) * 1_000_000_000
            + i128::from(ticks) * 1_000_000_000 / i128::from(self.resolution)
    }
}

#[derive(Default)]
pub(super) struct CaptureState {
    interfaces: Vec<Interface>,
    big_endian: bool,
    pcapng: Option<bool>,
    next_id: u64,
    pub metadata: Metadata,
}

impl CaptureState {
    // Validate declared sizes before parsing/refilling. This also covers
    // unknown blocks whose trailers are not checked by the underlying parser.
    pub fn validate_input(&self, data: &[u8]) -> io::Result<()> {
        let section = data.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]);
        if self.pcapng.unwrap_or(section) && data.len() >= 12 {
            let big = if section {
                match &data[8..12] {
                    [0x1a, 0x2b, 0x3c, 0x4d] => true,
                    [0x4d, 0x3c, 0x2b, 0x1a] => false,
                    _ => return Err(invalid("Invalid PCAPNG byte order")),
                }
            } else {
                self.big_endian
            };
            let size = read_u32(&data[4..8], big) as usize;
            if size > MAX_BLOCK_BYTES {
                return Err(invalid("Capture block exceeds the 1 MiB reader limit"));
            }
            if size < 12 || !size.is_multiple_of(4) {
                return Err(invalid("Invalid PCAPNG block length"));
            }
            if data.len() >= size && read_u32(&data[size - 4..size], big) as usize != size {
                return Err(invalid("Mismatched PCAPNG block lengths"));
            }
        } else if self.pcapng == Some(false)
            && data.len() >= 16
            && read_u32(&data[8..12], self.big_endian) as usize > MAX_PACKET_BYTES
        {
            return Err(invalid(
                "Capture contains a packet larger than the 256 KiB safety limit",
            ));
        }
        Ok(())
    }

    pub fn process(&mut self, block: PcapBlockOwned<'_>) -> io::Result<Option<Packet>> {
        let packet = match block {
            PcapBlockOwned::LegacyHeader(header) => {
                self.pcapng = Some(false);
                self.big_endian = header.is_bigendian();
                if header.version_major != 2
                    || header.version_minor != 4
                    || header.is_modified_format()
                {
                    return Err(invalid("Unsupported PCAP version or modified format"));
                }
                self.interfaces = vec![Interface {
                    link: header.network.0 & 0xffff,
                    snaplen: header.snaplen,
                    resolution: if header.is_nanosecond_precision() {
                        1_000_000_000
                    } else {
                        1_000_000
                    },
                    offset: 0,
                }];
                None
            }
            PcapBlockOwned::Legacy(packet) => {
                let interface = self.interface(0)?;
                let timestamp = i128::from(packet.ts_sec) * 1_000_000_000
                    + interface.timestamp(u64::from(packet.ts_usec));
                Some(self.packet(0, timestamp, packet.origlen, packet.data)?)
            }
            PcapBlockOwned::NG(Block::SectionHeader(header)) => {
                self.pcapng = Some(true);
                if header.major_version != 1 || !matches!(header.minor_version, 0 | 2) {
                    return Err(invalid("Unsupported PCAPNG version"));
                }
                self.big_endian = header.big_endian();
                self.interfaces.clear();
                if self.metadata.section.len() < 16 {
                    self.metadata.section.extend(option_text(
                        &header.options,
                        &[
                            (1, "Comment"),
                            (2, "Hardware"),
                            (3, "Operating system"),
                            (4, "Application"),
                        ],
                    ));
                }
                None
            }
            PcapBlockOwned::NG(Block::InterfaceDescription(interface)) => {
                if self.interfaces.len() == MAX_INTERFACES {
                    return Err(invalid(
                        "Capture section exceeds the limit of 1024 interfaces",
                    ));
                }
                let mut resolution = 1_000_000;
                let mut offset = 0;
                for option in &interface.options {
                    match option.code {
                        OptionCode::IfTsresol => {
                            if option.len != 1 || option.value.is_empty() {
                                return Err(invalid("Invalid timestamp resolution option"));
                            }
                            let value = option.value[0];
                            resolution = if value & 0x80 == 0 {
                                10u64.checked_pow(u32::from(value))
                            } else {
                                1u64.checked_shl(u32::from(value & 0x7f))
                            }
                            .ok_or_else(|| invalid("Unsupported timestamp resolution"))?;
                        }
                        OptionCode::IfTsoffset => {
                            let bytes: [u8; 8] = option
                                .value
                                .as_ref()
                                .try_into()
                                .map_err(|_| invalid("Invalid timestamp offset option"))?;
                            offset = if self.big_endian {
                                i64::from_be_bytes(bytes)
                            } else {
                                i64::from_le_bytes(bytes)
                            };
                        }
                        _ => {}
                    }
                }
                let mut description = vec![format!("link type {}", interface.linktype.0)];
                description.extend(option_text(
                    &interface.options,
                    &[(2, "name"), (3, "description"), (12, "operating system")],
                ));
                self.metadata.interfaces.push(description.join(" · "));
                self.interfaces.push(Interface {
                    link: interface.linktype.0,
                    snaplen: interface.snaplen,
                    resolution,
                    offset,
                });
                None
            }
            PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
                let timestamp = self
                    .interface(packet.if_id)?
                    .timestamp((u64::from(packet.ts_high) << 32) | u64::from(packet.ts_low));
                let data = packet
                    .data
                    .get(..packet.caplen as usize)
                    .ok_or_else(|| invalid("Truncated captured packet"))?;
                let mut decoded = self.packet(packet.if_id, timestamp, packet.origlen, data)?;
                decoded.comment = packet
                    .options
                    .iter()
                    .find(|option| option.code == OptionCode::Comment)
                    .and_then(|option| option.value.get(..usize::from(option.len).min(4096)))
                    .map(|comment| String::from_utf8_lossy(comment).into_owned());
                Some(decoded)
            }
            PcapBlockOwned::NG(Block::SimplePacket(packet)) => {
                let snaplen = self.interface(0)?.snaplen;
                let caplen = if snaplen == 0 {
                    packet.origlen
                } else {
                    packet.origlen.min(snaplen)
                };
                let data = packet
                    .data
                    .get(..caplen as usize)
                    .ok_or_else(|| invalid("Truncated simple packet"))?;
                Some(self.packet(0, 0, packet.origlen, data)?)
            }
            PcapBlockOwned::NG(Block::Unknown(block)) => {
                if block.block_len1 != block.block_len2 {
                    return Err(invalid("Mismatched PCAPNG block lengths"));
                }
                let kind = if self.big_endian {
                    block.block_type.swap_bytes()
                } else {
                    block.block_type
                };
                if kind == 2 {
                    // Obsolete Packet Blocks are still found in libpcap captures.
                    Some(self.old_packet(block.data)?)
                } else {
                    None
                }
            }
            PcapBlockOwned::NG(Block::NameResolution(block)) => {
                for record in block.nr.iter().take(MAX_NAMES) {
                    let value = record.record_value;
                    let (address, names) = match (record.record_type.0, value.len()) {
                        (1, 5..) => (
                            IpAddr::V4(Ipv4Addr::new(value[0], value[1], value[2], value[3])),
                            &value[4..],
                        ),
                        (2, 17..) => {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(&value[..16]);
                            (IpAddr::V6(Ipv6Addr::from(octets)), &value[16..])
                        }
                        _ => continue,
                    };
                    let name = names.split(|b| *b == 0).next().unwrap_or_default();
                    if !name.is_empty()
                        && name.len() <= 255
                        && self.metadata.names.len() < MAX_NAMES
                    {
                        self.metadata
                            .names
                            .push((address, String::from_utf8_lossy(name).into_owned()));
                    }
                }
                None
            }
            PcapBlockOwned::NG(_) => None,
        };
        if packet.is_some() {
            self.next_id += 1;
        }
        Ok(packet)
    }

    fn interface(&self, id: u32) -> io::Result<&Interface> {
        self.interfaces
            .get(id as usize)
            .ok_or_else(|| invalid("Packet refers to an unknown interface"))
    }

    fn packet(
        &self,
        interface: u32,
        timestamp: i128,
        wire_len: u32,
        data: &[u8],
    ) -> io::Result<Packet> {
        if data.len() > MAX_PACKET_BYTES {
            return Err(invalid(
                "Capture contains a packet larger than the 256 KiB safety limit",
            ));
        }
        let interface = self.interface(interface)?;
        if interface.snaplen != 0 && data.len() > interface.snaplen as usize {
            return Err(invalid("Captured packet exceeds interface snapshot length"));
        }
        Ok(Packet::new(
            self.next_id + 1,
            timestamp,
            wire_len,
            interface.link,
            data.into(),
        ))
    }

    fn old_packet(&self, data: &[u8]) -> io::Result<Packet> {
        let header = data
            .get(..20)
            .ok_or_else(|| invalid("Truncated packet block"))?;
        let read = |offset| {
            let bytes = [
                header[offset],
                header[offset + 1],
                header[offset + 2],
                header[offset + 3],
            ];
            if self.big_endian {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            }
        };
        let id = if self.big_endian {
            u16::from_be_bytes([header[0], header[1]])
        } else {
            u16::from_le_bytes([header[0], header[1]])
        };
        let timestamp = self
            .interface(u32::from(id))?
            .timestamp((u64::from(read(4)) << 32) | u64::from(read(8)));
        let data = data[20..]
            .get(..read(12) as usize)
            .ok_or_else(|| invalid("Truncated captured packet"))?;
        self.packet(u32::from(id), timestamp, read(16), data)
    }
}

fn read_u32(data: &[u8], big: bool) -> u32 {
    let bytes = [data[0], data[1], data[2], data[3]];
    if big {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    }
}
