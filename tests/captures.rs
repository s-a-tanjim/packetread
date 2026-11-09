use packetread::{
    decode::{decode, details, Protocol},
    source::{SourceSpec, Worker},
};
use std::{path::PathBuf, process::Command, time::Duration};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn reads_both_formats_and_decodes_expected_protocols() {
    for file in ["demo.pcap", "demo.pcapng"] {
        let mut capture = pcap::Capture::from_file(fixture(file)).unwrap();
        let link = capture.get_datalink().0;
        let mut protocols = Vec::new();
        while let Ok(packet) = capture.next_packet() {
            protocols.push(decode(packet.data, link).protocol);
            for layer in details(packet.data, link) {
                assert!(
                    layer.range.start <= layer.range.end && layer.range.end <= packet.data.len()
                );
                for field in layer.fields {
                    assert!(
                        field.range.start <= field.range.end
                            && field.range.end <= packet.data.len()
                    );
                }
            }
        }
        assert_eq!(
            protocols,
            vec![
                Protocol::Tcp,
                Protocol::Tcp,
                Protocol::Dns,
                Protocol::Dns,
                Protocol::Udp,
                Protocol::Arp,
                Protocol::Icmp,
                Protocol::Udp,
                Protocol::Tcp,
                Protocol::Unknown,
                Protocol::Ipv4
            ]
        );
    }
}

#[test]
fn every_prefix_and_random_header_is_safe_to_inspect() {
    let mut capture = pcap::Capture::from_file(fixture("demo.pcap")).unwrap();
    while let Ok(packet) = capture.next_packet() {
        for end in 0..=packet.data.len() {
            let _ = decode(&packet.data[..end], 1);
            let _ = details(&packet.data[..end], 1);
        }
    }
    let mut seed = 42u32;
    for length in 0..256 {
        let data: Vec<_> = (0..length)
            .map(|_| {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                (seed >> 24) as u8
            })
            .collect();
        for link in [1, 12, 113, 276, 999] {
            let _ = decode(&data, link);
            let _ = details(&data, link);
        }
    }
}

#[test]
fn reads_linux_cooked_headers_and_ipv6_extensions() {
    let mut capture = pcap::Capture::from_file(fixture("demo.pcap")).unwrap();
    let first = capture.next_packet().unwrap().data.to_vec();
    let ip = &first[14..];
    let mut sll = vec![0; 16];
    sll[14..16].copy_from_slice(&[8, 0]);
    sll.extend(ip);
    assert_eq!(decode(&sll, 113).protocol, Protocol::Tcp);
    let mut sll2 = vec![0; 20];
    sll2[..2].copy_from_slice(&[8, 0]);
    sll2.extend(ip);
    assert_eq!(decode(&sll2, 276).protocol, Protocol::Tcp);
    let mut ipv6 = vec![0; 56];
    ipv6[0] = 0x60;
    ipv6[5] = 16;
    ipv6[6] = 0; // hop-by-hop
    ipv6[40] = 17;
    ipv6[48..56].copy_from_slice(&[0, 1, 0, 2, 0, 8, 0, 0]);
    assert_eq!(decode(&ipv6, 12).protocol, Protocol::Udp);
}

#[test]
fn worker_delivers_the_complete_offline_capture() {
    let worker = Worker::start(SourceSpec::File(fixture("demo.pcap"))).unwrap();
    let mut ids = Vec::new();
    loop {
        match worker.packets.recv_timeout(Duration::from_secs(2)) {
            Ok(batch) => ids.extend(batch.into_iter().map(|p| p.id)),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(error) => panic!("worker did not finish: {error}"),
        }
    }
    assert_eq!(ids, (1..=11).collect::<Vec<_>>());
    assert!(worker.status().error.is_none());
    assert_eq!(worker.status().app_drops, 0);
}

#[test]
fn summary_cli_reports_protocol_totals_and_errors() {
    let output = Command::new(env!("CARGO_BIN_EXE_packetread"))
        .arg("summary")
        .arg(fixture("demo.pcap"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Packets: 11"));
    assert!(text.contains("DNS"));
    let missing = Command::new(env!("CARGO_BIN_EXE_packetread"))
        .arg("summary")
        .arg(fixture("does-not-exist.pcap"))
        .output()
        .unwrap();
    assert!(!missing.status.success());
}
