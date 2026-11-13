//! End-to-end analysis of the synthetic fixtures: decoding, reassembly,
//! stream following and TLS decryption.
use packetread::{
    analysis::Analyzer,
    decode::{details, diag, Packet, Protocol},
    follow::{Follower, Stream},
    offline::OfflineCapture,
    stats::{Stats, Unit},
    tls::{decrypt, KeyLog},
};
use std::{path::PathBuf, sync::atomic::AtomicBool};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn analyzed(name: &str) -> Vec<Packet> {
    let mut capture = OfflineCapture::open(fixture(name)).unwrap();
    let mut analyzer = Analyzer::default();
    let mut packets = Vec::new();
    while let Some(mut packet) = capture.next_packet(&AtomicBool::new(false)).unwrap() {
        analyzer.observe(&mut packet);
        packets.push(packet);
    }
    packets
}

fn follow(packets: &[Packet], id: u32) -> Stream {
    let mut follower = Follower::new(id, 1 << 20);
    packets.iter().for_each(|packet| follower.push(packet));
    follower.finish()
}

#[test]
fn decodes_application_protocols() {
    let packets = analyzed("protocols.pcap");
    let find = |protocol: Protocol| {
        let packet = packets.iter().find(|p| p.summary.protocol == protocol);
        packet
            .unwrap_or_else(|| panic!("no {protocol:?} packet"))
            .summary
            .info
            .clone()
    };
    assert_eq!(find(Protocol::Http), "GET /index.html HTTP/1.1");
    assert_eq!(
        find(Protocol::Dhcp),
        "DHCP Discover · xid 0xdeadbeef · laptop"
    );
    assert!(
        find(Protocol::Quic).starts_with("Initial · version 0x00000001 · DCID 0102030405060708")
    );
    assert_eq!(find(Protocol::Smb), "SMB2 Negotiate Request");
    let dns: Vec<_> = packets
        .iter()
        .filter(|p| p.summary.protocol == Protocol::Dns)
        .collect();
    assert_eq!(
        dns[1].summary.info,
        "Response A example.com → www.example.com, 192.0.2.7"
    );
    assert_eq!(dns[2].summary.ip_proto, Some(6), "DNS over TCP");
    let (bytes, link) = dns[2].view();
    assert!(details(bytes, link)
        .iter()
        .any(|layer| layer.label == "DNS (TCP)"));
    // Every layer and field range stays inside the bytes it describes.
    for packet in &packets {
        let (bytes, link) = packet.view();
        for layer in details(bytes, link) {
            assert!(layer.range.end <= bytes.len());
            assert!(layer
                .fields
                .iter()
                .all(|f| f.range.start <= f.range.end && f.range.end <= bytes.len()));
        }
    }
}

#[test]
fn flags_tcp_problems_and_follows_the_stream() {
    let packets = analyzed("protocols.pcap");
    let flagged: Vec<_> = packets
        .iter()
        .filter(|p| p.summary.diag != 0)
        .map(|p| (p.id, p.summary.diag))
        .collect();
    assert_eq!(
        flagged,
        [
            (7, diag::OUT_OF_ORDER),
            (9, diag::DUP_ACK),
            (11, diag::RETRANSMISSION),
            (12, diag::ZERO_WINDOW)
        ]
    );
    assert!(packets[10].summary.info.ends_with("[retransmission]"));
    let stream = follow(&packets, 0);
    assert_eq!(
        stream.title(),
        "TCP stream 0: 192.0.2.10:40000 ↔ 198.51.100.8:80"
    );
    assert_eq!(stream.chunks.len(), 2);
    assert!(stream.chunks[1].data.ends_with(b"\r\n\r\nhello world!"));
    assert_eq!(stream.missing, 0);
    assert!(stream.lines(false)[0].ends_with("HTTP: GET /index.html HTTP/1.1"));
    // The UDP conversation keeps datagram boundaries.
    let udp = follow(&packets, 1);
    assert!(!udp.tcp);
    assert_eq!(
        udp.chunks.iter().map(|c| c.from_client).collect::<Vec<_>>(),
        [true, false]
    );
}

#[test]
fn reassembles_ipv4_and_ipv6_fragments() {
    let packets = analyzed("protocols.pcap");
    let rebuilt: Vec<_> = packets.iter().filter(|p| p.reassembled.is_some()).collect();
    assert_eq!(rebuilt.len(), 2);
    assert_eq!(rebuilt[0].payload(), b"fragmented-payload-0123456789abcdef");
    assert_eq!(rebuilt[0].summary.dst_port, Some(5001));
    assert_eq!(rebuilt[1].payload(), b"ipv6-fragmented-payload!");
    assert!(rebuilt[1].summary.src.unwrap().is_ipv6());
    assert!(rebuilt
        .iter()
        .all(|p| p.summary.info.starts_with("[Reassembled 2 fragments]")));
}

#[test]
fn decrypts_tls_13_and_12_streams_with_a_key_log() {
    let packets = analyzed("tls.pcap");
    let log = std::sync::Arc::new(KeyLog::load(fixture("tls.keys")).unwrap());
    assert!(packets.iter().any(|p| p
        .summary
        .info
        .contains("Client Hello · TLS 1.3 · SNI example.com")));
    for id in 0..3 {
        let stream = follow(&packets, id);
        let plain = decrypt(&stream, &log).unwrap_or_else(|error| panic!("stream {id}: {error}"));
        let chunks: Vec<_> = plain
            .chunks
            .iter()
            .map(|c| (c.from_client, c.data.as_slice()))
            .collect();
        assert_eq!(
            chunks,
            [
                (
                    true,
                    &b"GET /secret HTTP/1.1\r\nHost: example.com\r\n\r\n"[..]
                ),
                (
                    false,
                    b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\ndecrypted body"
                ),
            ],
            "stream {id}"
        );
        assert!(plain.lines(false)[0].contains("HTTP: GET /secret HTTP/1.1"));
        // Without the right secrets nothing is revealed.
        assert!(decrypt(&stream, &Default::default()).is_err());
        // Application secrets alone (no handshake secrets) still decrypt TLS 1.3.
        let text = std::fs::read_to_string(fixture("tls.keys")).unwrap();
        let partial: String = text
            .lines()
            .filter(|l| !l.contains("HANDSHAKE"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(
            decrypt(&stream, &std::sync::Arc::new(KeyLog::parse(&partial)))
                .unwrap()
                .chunks,
            plain.chunks
        );
    }
}

#[test]
fn statistics_group_conversations_endpoints_protocols_and_timing() {
    let mut stats = Stats::new(0.05);
    analyzed("protocols.pcap")
        .iter()
        .for_each(|packet| stats.add(packet));
    assert_eq!(stats.total.packets, 29);
    let http = &stats.conversations[&0];
    assert_eq!((http.sent[0].packets, http.sent[1].packets), (6, 6));
    assert_eq!(http.problems, [1, 1, 1, 1, 0, 0, 0]);
    assert_eq!(stats.hierarchy["IPv4 › TCP › HTTP"].packets, 2);
    assert_eq!(stats.hierarchy["IPv4 › UDP › DNS"].packets, 2);
    assert_eq!(stats.hierarchy["IPv6 › Fragment"].packets, 1);
    let client: std::net::IpAddr = "192.0.2.10".parse().unwrap();
    assert_eq!(stats.endpoints[&client][0].packets, 17);
    assert_eq!(stats.timings["DNS"].count, 1);
    assert_eq!(stats.timings["DNS"].max_ns, 10_000_000);
    assert_eq!(stats.timings["HTTP"].min_ns, 20_000_000);
    assert_eq!(stats.timings["TCP handshake"].count, 3);
    assert_eq!(stats.buckets.iter().map(|b| b.packets).sum::<u64>(), 29);
    let report = stats.report(5, Unit::Packets).join("\n");
    for expected in [
        "29 packets",
        "#0 TCP 192.0.2.10:40000 ↔ 198.51.100.8:80",
        "1 retransmission, 1 out-of-order, 1 dup-ack, 1 zero-window",
        "CONVERSATIONS · top 5 of 9",
        "TRAFFIC · packets per 0.05 s interval",
    ] {
        assert!(
            report.contains(expected),
            "missing {expected:?} in:\n{report}"
        );
    }
    assert!(stats
        .report(5, Unit::Bytes)
        .join("\n")
        .contains("TRAFFIC · bytes"));
}

#[test]
fn reassembles_messages_across_segments_and_refines_tcp_diagnostics() {
    let packets = analyzed("more.pcap");
    let whole = &packets[6];
    assert!(whole.stream_message);
    assert_eq!(
        whole.summary.info,
        "[Reassembled 3 segments] HTTP/1.1 200 OK"
    );
    assert!(whole
        .message()
        .ends_with(b"\r\n\r\n0123456789abcdefghijABCDEFGHIJ"));
    // The segment's own payload still feeds stream following.
    assert_eq!(whole.payload(), b"ABCDEFGHIJ");
    let stream = follow(&packets, 0);
    assert!(stream.chunks[1].data.ends_with(b"ABCDEFGHIJfirstsecond"));
    assert_eq!(
        stream.http_objects()[0],
        ("txt", b"0123456789abcdefghijABCDEFGHIJ".to_vec())
    );
    let (bytes, link) = whole.view();
    let labels: Vec<_> = details(bytes, link)
        .into_iter()
        .flat_map(|l| l.fields)
        .map(|f| f.label)
        .collect();
    assert!(labels.contains(&"Content-Length: 30".to_string()));

    let flagged: Vec<_> = packets
        .iter()
        .filter(|p| p.summary.diag != 0)
        .map(|p| (p.id, p.summary.diag))
        .collect();
    assert_eq!(
        flagged,
        [
            (8, diag::KEEP_ALIVE),
            (11, diag::DUP_ACK),
            (12, diag::DUP_ACK),
            (13, diag::RETRANSMISSION | diag::FAST_RETRANSMISSION),
            (14, diag::RESET),
        ]
    );
}

#[test]
fn decodes_more_protocols_tunnels_options_and_checksums() {
    let packets = analyzed("more.pcap");
    let info = |id: usize| packets[id - 1].summary.info.as_str();
    let fields = |id: usize| -> Vec<String> {
        let (bytes, link) = packets[id - 1].view();
        details(bytes, link)
            .into_iter()
            .flat_map(|l| l.fields)
            .map(|f| f.label)
            .collect()
    };
    for (id, protocol, expected) in [
        (16, Protocol::Ssh, "SSH-2.0-OpenSSH_9.6"),
        (17, Protocol::Ftp, "220 Service ready"),
        (18, Protocol::Smtp, "EHLO client.example"),
        (19, Protocol::Sip, "INVITE sip:bob@example.com SIP/2.0"),
        (20, Protocol::Mqtt, "MQTT CONNECT · 12 bytes"),
        (21, Protocol::Ntp, "NTP v4 Client · stratum 0"),
        (22, Protocol::Igmp, "Membership report · group 224.0.0.251"),
        (23, Protocol::Lldp, "LLDP advertisement · switch1"),
        (24, Protocol::Dns, "Query A example.com"),
        (25, Protocol::Icmp, "Echo request · type 8 · code 0"),
        (
            27,
            Protocol::Icmp,
            "Neighbor solicitation · type 135 · code 0 · target 2001:db8::2",
        ),
        (28, Protocol::Udp, "29 payload bytes"),
    ] {
        assert_eq!(
            (packets[id - 1].summary.protocol, info(id)),
            (protocol, expected),
            "packet {id}"
        );
    }
    // Tunnels are decoded through to the inner packet.
    assert_eq!(packets[24].summary.src.unwrap().to_string(), "10.0.0.1");
    assert_eq!(packets[25].summary.dst_port, Some(80));
    assert!(fields(26).contains(&"VNI: 42".to_string()));

    let options = fields(15);
    for expected in [
        "Option: maximum segment size 1460",
        "Option: SACK permitted",
        "Option: timestamps value 111 echo 0",
        "Option: window scale 7 (×128)",
        "Header checksum: 0x8e76 (correct)",
    ] {
        assert!(
            options.iter().any(|f| f == expected),
            "missing {expected} in {options:?}"
        );
    }
    assert!(options
        .iter()
        .any(|f| f.starts_with("Checksum:") && f.ends_with("(correct)")));
    // A corrupted payload byte is reported, not trusted.
    let mut corrupt = packets[3].bytes.to_vec();
    *corrupt.last_mut().unwrap() ^= 0xff;
    let labels: Vec<_> = details(&corrupt, 1)
        .into_iter()
        .flat_map(|l| l.fields)
        .map(|f| f.label)
        .collect();
    assert!(labels
        .iter()
        .any(|f| f.starts_with("Checksum:") && f.contains("incorrect")));
}

#[test]
fn every_prefix_of_the_new_fixtures_is_safe_to_inspect() {
    for name in ["more.pcap", "protocols.pcap", "tls.pcap"] {
        let mut analyzer = Analyzer::default();
        for packet in analyzed(name) {
            for end in 0..=packet.bytes.len() {
                let mut prefix = Packet::new(
                    packet.id,
                    0,
                    packet.wire_len,
                    packet.link,
                    packet.bytes[..end].into(),
                );
                let _ = details(&prefix.bytes, prefix.link);
                analyzer.observe(&mut prefix);
            }
        }
    }
}

#[test]
fn decrypts_cbc_suites_and_rsa_key_exchange_with_the_server_key() {
    let packets = analyzed("tls-rsa.pcap");
    let request = &b"GET /secret HTTP/1.1\r\nHost: example.com\r\n\r\n"[..];
    let plain = |id: u32, log: &std::sync::Arc<KeyLog>| {
        decrypt(&follow(&packets, id), log).map(|stream| {
            let data: Vec<_> = stream.chunks.iter().map(|c| c.data.clone()).collect();
            assert_eq!(data[0], request, "stream {id}");
            assert!(data[1].ends_with(b"decrypted body"), "stream {id}");
        })
    };
    // The key log opens every session, CBC suites included.
    let log = std::sync::Arc::new(KeyLog::load(fixture("tls-rsa.keys")).unwrap());
    for id in 0..3 {
        plain(id, &log).unwrap_or_else(|error| panic!("stream {id}: {error}"));
    }
    // The server's private key alone opens the RSA key exchanges (0 and 2)
    // but not the ephemeral Diffie-Hellman session.
    let pem = std::fs::read_to_string(fixture("tls-rsa.key")).unwrap();
    packetread::crypto::add_tls_key(&pem).unwrap();
    assert!(packetread::crypto::add_tls_key("-----BEGIN PRIVATE KEY-----\nAAAA\n").is_err());
    let key = KeyLog::or_private_keys(None).unwrap();
    plain(0, &key).unwrap();
    plain(2, &key).unwrap();
    assert!(plain(1, &key).is_err());
}
