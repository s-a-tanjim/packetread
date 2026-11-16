use packetread::{decode::Packet, offline::OfflineCapture};
use std::{fs, sync::atomic::AtomicBool};

fn u16_bytes(value: u16, big: bool) -> [u8; 2] {
    if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

fn u32_bytes(value: u32, big: bool) -> [u8; 4] {
    if big {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    }
}

fn block(kind: u32, body: &[u8], big: bool) -> Vec<u8> {
    let length = (body.len() as u32 + 15) & !3;
    let mut bytes = Vec::new();
    bytes.extend(u32_bytes(kind, big));
    bytes.extend(u32_bytes(length, big));
    bytes.extend(body);
    bytes.resize(length as usize - 4, 0);
    bytes.extend(u32_bytes(length, big));
    bytes
}

fn section(big: bool) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(u32_bytes(0x1a2b3c4d, big));
    body.extend(u16_bytes(1, big));
    body.extend([0; 2]);
    body.extend([255; 8]);
    block(0x0a0d0d0a, &body, big)
}

fn interface(big: bool, link: u16, snaplen: u32, options: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(u16_bytes(link, big));
    body.extend([0; 2]);
    body.extend(u32_bytes(snaplen, big));
    body.extend(options);
    block(1, &body, big)
}

fn packets(bytes: &[u8]) -> Vec<Packet> {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("capture");
    fs::write(&path, bytes).unwrap();
    let mut reader = OfflineCapture::open(path).unwrap();
    let mut packets = Vec::new();
    while let Some(packet) = reader.next_packet(&AtomicBool::new(false)).unwrap() {
        packets.push(packet);
    }
    packets
}

#[test]
fn classic_pcap_byte_orders_and_timestamp_precisions_are_preserved() {
    for big in [false, true] {
        for nano in [false, true] {
            let mut bytes = Vec::new();
            bytes.extend(u32_bytes(if nano { 0xa1b23c4d } else { 0xa1b2c3d4 }, big));
            bytes.extend(u16_bytes(2, big));
            bytes.extend(u16_bytes(4, big));
            bytes.extend([0; 8]);
            bytes.extend(u32_bytes(65535, big));
            bytes.extend(u32_bytes(101, big));
            assert!(packets(&bytes).is_empty());
            for value in [12, 3456, 3, 100] {
                bytes.extend(u32_bytes(value, big));
            }
            bytes.extend([0x45, 0, 0]);
            let result = packets(&bytes);
            assert_eq!(result.len(), 1);
            assert_eq!(
                result[0].timestamp_ns,
                12_000_000_000 + if nano { 3456 } else { 3_456_000 }
            );
            assert_eq!(result[0].wire_len, 100);
            assert_eq!(result[0].link, 101);
            assert_eq!(&*result[0].bytes, &[0x45, 0, 0]);
            assert!(result[0].summary.warning.is_some());
        }
    }
}

#[test]
fn pcapng_timestamps_handle_byte_order_binary_resolution_and_signed_offset() {
    for big in [false, true] {
        for (resolution, ticks) in [(9u8, 1_500_000_000u32), (0x8a, 1536)] {
            let mut bytes = section(big);
            let mut options = Vec::new();
            options.extend(u16_bytes(9, big));
            options.extend(u16_bytes(1, big));
            options.extend([resolution, 0, 0, 0]);
            options.extend(u16_bytes(14, big));
            options.extend(u16_bytes(8, big));
            options.extend(if big {
                (-2i64).to_be_bytes()
            } else {
                (-2i64).to_le_bytes()
            });
            options.extend([0; 4]);
            bytes.extend(interface(big, 101, 65535, &options));
            let mut body = Vec::new();
            for value in [0, 0, ticks, 3, 3] {
                body.extend(u32_bytes(value, big));
            }
            body.extend([0x45, 0, 0]);
            bytes.extend(block(6, &body, big));
            let result = packets(&bytes);
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].timestamp_ns, -500_000_000);
            assert_eq!(result[0].bytes.len(), 3);
        }
    }
}

#[test]
fn simple_and_obsolete_packet_blocks_preserve_captured_lengths() {
    for big in [false, true] {
        let mut bytes = section(big);
        bytes.extend(interface(big, 101, 3, &[]));
        let mut body = u32_bytes(100, big).to_vec();
        body.extend([0x45, 0, 0]);
        bytes.extend(block(3, &body, big));
        let mut body = vec![0; 4]; // interface 0, drops 0
        for value in [0, 1_500_000, 3, 100] {
            body.extend(u32_bytes(value, big));
        }
        body.extend([0x45, 0, 0]);
        bytes.extend(block(2, &body, big));
        let result = packets(&bytes);
        assert_eq!(result.len(), 2);
        assert_eq!(result[1].timestamp_ns, 1_500_000_000);
        for packet in result {
            assert_eq!(packet.bytes.len(), 3);
            assert_eq!(packet.wire_len, 100);
        }
    }
}

#[test]
fn section_changes_reset_interfaces_and_accept_empty_captures() {
    let mut bytes = Vec::new();
    for big in [false, true, false] {
        bytes.extend(section(big));
        for _ in 0..1024 {
            bytes.extend(interface(big, 1, 65535, &[]));
        }
    }
    assert!(packets(&bytes).is_empty());
    assert!(packets(&section(false)).is_empty());
}

// Uses libpcap as the reference reader; Windows CI has no Npcap runtime.
#[cfg(not(windows))]
#[test]
fn original_fixtures_match_libpcap_packet_bytes_and_timestamps() {
    for file in ["demo.pcap", "demo.pcapng"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(file);
        let mut original = pcap::Capture::from_file(&path).unwrap();
        let actual = packets(&fs::read(path).unwrap());
        for packet in actual {
            let expected = original.next_packet().unwrap();
            assert_eq!(&*packet.bytes, expected.data);
            assert_eq!(packet.wire_len, expected.header.len);
            assert_eq!(
                packet.timestamp_ns,
                i128::from(expected.header.ts.tv_sec) * 1_000_000_000
                    + i128::from(expected.header.ts.tv_usec) * 1000
            );
        }
        assert!(matches!(
            original.next_packet(),
            Err(pcap::Error::NoMorePackets)
        ));
    }
}
