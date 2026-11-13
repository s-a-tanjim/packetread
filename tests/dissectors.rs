//! The long tail of protocols, other link layers and decryption with
//! user-supplied keys, on synthetic fixtures (see `fixtures/generate.py`).
use packetread::{
    analysis::Analyzer,
    crypto,
    decode::{decode, details, Packet, Protocol},
    filter::Filter,
    offline::OfflineCapture,
    tls::KeyLog,
};
use std::{path::PathBuf, sync::atomic::AtomicBool, sync::Arc};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn analyzed(name: &str, keylog: Option<Arc<KeyLog>>) -> Vec<Packet> {
    let mut capture = OfflineCapture::open(fixture(name)).unwrap();
    let mut analyzer = Analyzer::new(keylog);
    let mut packets = Vec::new();
    while let Some(mut packet) = capture.next_packet(&AtomicBool::new(false)).unwrap() {
        analyzer.observe(&mut packet);
        packets.push(packet);
    }
    packets
}

/// (protocol, info) of every packet.
fn rows(packets: &[Packet]) -> Vec<(Protocol, &str)> {
    packets
        .iter()
        .map(|p| (p.summary.protocol, p.summary.info.as_str()))
        .collect()
}

fn labels(packet: &Packet) -> String {
    packet
        .layers()
        .iter()
        .flat_map(|layer| {
            std::iter::once(layer.label.clone()).chain(layer.fields.iter().map(|f| f.label.clone()))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn count(packets: &[Packet], filter: &str) -> usize {
    let filter = Filter::parse(filter).unwrap_or_else(|error| panic!("{filter}: {error}"));
    packets.iter().filter(|p| filter.matches(p)).count()
}

#[test]
fn decodes_application_routing_and_tunnel_protocols() {
    let packets = analyzed("apps.pcap", None);
    let rows = rows(&packets);
    for (index, protocol, info) in [
        (
            3,
            Protocol::Http2,
            "HTTP/2 · Preface, SETTINGS[0], HEADERS[1] GET /",
        ),
        // Recognised from the conversation: no preface in this packet.
        (
            4,
            Protocol::Grpc,
            "gRPC over HTTP/2 · SETTINGS[0], HEADERS[1] 200, DATA[1]",
        ),
        (
            10,
            Protocol::WebSocket,
            "WebSocket text · 8 bytes · hello ws",
        ),
        (
            11,
            Protocol::WebSocket,
            "WebSocket text · 7 bytes · welcome",
        ),
        (
            12,
            Protocol::Snmp,
            "SNMPv2c get-request · community public · 1.3.6.1.2.1.1.1.0",
        ),
        (
            13,
            Protocol::Ldap,
            "LDAP searchRequest · id 2 · dc=example,dc=com",
        ),
        (
            14,
            Protocol::Kerberos,
            "Kerberos AS-REQ · alice · EXAMPLE.COM",
        ),
        (
            15,
            Protocol::Rdp,
            "RDP Connection request · Cookie: mstshash=alice",
        ),
        (16, Protocol::Nfs, "NFS v3 GETATTR call · xid 0x1234abcd"),
        (
            17,
            Protocol::Mysql,
            "MySQL Server greeting · version 8.0.36",
        ),
        (18, Protocol::Mysql, "MySQL Query · SELECT 1"),
        (
            19,
            Protocol::Postgres,
            "PostgreSQL Startup · user alice database app",
        ),
        (20, Protocol::Postgres, "PostgreSQL Query · SELECT 1"),
        (
            21,
            Protocol::Postgres,
            "PostgreSQL Command complete · SELECT 1, Ready for query",
        ),
        (
            22,
            Protocol::Bgp,
            "BGP OPEN · AS 65001 · hold 180 s · router 192.0.2.10, KEEPALIVE",
        ),
        (
            23,
            Protocol::Bgp,
            "BGP UPDATE · 0 withdrawn bytes · 203.0.113.0/24",
        ),
        (
            24,
            Protocol::Ospf,
            "OSPF Hello · router 192.0.2.10 · area 0.0.0.0",
        ),
        (25, Protocol::Rip, "RIPv2 response · 1 routes"),
        // RTP is recognised on the port the SDP offer announced.
        (
            28,
            Protocol::Rtp,
            "RTP PCMU · SSRC 0x1234abcd · seq 1 · time 160",
        ),
        (31, Protocol::Rtcp, "RTCP Sender report · SSRC 0x1234abcd"),
        (33, Protocol::Esp, "ESP · SPI 0x00002000 · sequence 1"),
        (34, Protocol::Icmp, "Echo request · type 8 · code 0"),
        (
            35,
            Protocol::Stp,
            "STP Configuration · root 32768 / 02:00:00:00:00:01 · cost 4",
        ),
        (36, Protocol::Icmp, "Echo request · type 8 · code 0"),
        (37, Protocol::Icmp, "Echo request · type 8 · code 0"),
        (38, Protocol::Eapol, "EAPOL Key · 4-way handshake message 1"),
    ] {
        assert_eq!(rows[index], (protocol, info), "packet {}", index + 1);
    }
    let tree = labels(&packets[4]);
    assert!(
        tree.contains("Header: content-type: application/grpc"),
        "{tree}"
    );
    assert!(tree.contains("gRPC message: 5 bytes"));
    assert!(labels(&packets[3]).contains("Header: :authority: example.com"));
    assert!(labels(&packets[34]).contains("Authentication Header"));

    // Enclosing protocols and named fields are filterable.
    for (filter, expected) in [
        ("proto=http2", 2),
        ("proto=grpc", 1),
        ("proto=ah", 1),
        ("proto=ppp", 1),
        ("proto=mpls", 1),
        ("proto=mpls proto=icmp", 1),
        ("http2.header contains \"application/grpc\"", 1),
        ("snmp.community == public", 1),
        ("mysql.message contains select", 1),
        ("bgp.message contains \"203.0.113.0/24\"", 1),
        ("rtp.sequence >= 2", 2),
        ("rtp.payload_type == pcmu", 3),
        ("mpls.label == 100", 1),
        ("ospf.area == 0.0.0.0", 1),
        ("kerberos.name == alice", 1),
    ] {
        assert_eq!(count(&packets, filter), expected, "{filter}");
    }
}

#[test]
fn decodes_other_link_layers() {
    let packets = analyzed("links.pcapng", None);
    let rows = rows(&packets);
    for (index, protocol, info) in [
        (0, Protocol::Icmp, "Echo request"),
        (
            1,
            Protocol::Ppp,
            "PPP Link Control Protocol · Configure-Request",
        ),
        (2, Protocol::Icmp, "Echo request"),
        (
            3,
            Protocol::Wlan,
            "802.11 Beacon · 02:00:00:00:00:01 → ff:ff:ff:ff:ff:ff · SSID example",
        ),
        (4, Protocol::Wlan, "SSID example"),
        (5, Protocol::Bluetooth, "HCI event · Command complete"),
        (
            6,
            Protocol::Bluetooth,
            "HCI ACL data · handle 1 · L2CAP attribute protocol · Write command",
        ),
        (7, Protocol::Bluetooth, "HCI command · OGF 0x03 · OCF 0x003"),
        (
            8,
            Protocol::Usb,
            "USB control in · submit · bus 1 device 3 endpoint 0 · GET_DESCRIPTOR",
        ),
        (9, Protocol::Can, "CAN data frame · ID 0x123 · be ef"),
        (10, Protocol::Zigbee, "Zigbee data · 0x0001 → 0x0000"),
    ] {
        assert_eq!(rows[index].0, protocol, "packet {}", index + 1);
        assert!(
            rows[index].1.contains(info),
            "packet {}: {}",
            index + 1,
            rows[index].1
        );
    }
    let radio = labels(&packets[4]);
    for expected in [
        "Radiotap",
        "Rate: 6 Mb/s",
        "Channel frequency: 2412 MHz",
        "Signal: -40 dBm",
    ] {
        assert!(radio.contains(expected), "{radio}");
    }
    assert!(packets[11]
        .summary
        .warning
        .as_deref()
        .unwrap()
        .contains("Unsupported link type 147"));
    assert_eq!(count(&packets, "proto=ppp"), 2);
    assert_eq!(count(&packets, "wlan.ssid == example"), 2);
}

#[test]
fn decrypts_quic_and_reads_http3() {
    // Initial packets need no secrets: their keys follow from the connection ID.
    let plain = analyzed("quic.pcap", None);
    let rows_plain = rows(&plain);
    assert_eq!(
        rows_plain[0],
        (
            Protocol::Quic,
            "[Decrypted QUIC] Client Hello · SNI example.com · ALPN h3"
        )
    );
    assert_eq!(
        rows_plain[1],
        (
            Protocol::Quic,
            "[Decrypted QUIC] Server Hello · TLS_AES_128_GCM_SHA256"
        )
    );
    assert!(rows_plain[2].1.starts_with("Protected payload"));
    // Stateless decoding still reads the client's first packet.
    let alone = decode(&plain[0].bytes, plain[0].link);
    assert!(
        alone
            .info
            .ends_with("Client Hello · SNI example.com · ALPN h3"),
        "{}",
        alone.info
    );

    let log = Arc::new(KeyLog::load(fixture("quic.keys")).unwrap());
    let packets = analyzed("quic.pcap", Some(log));
    let rows = rows(&packets);
    assert_eq!(
        rows[2],
        (
            Protocol::Http3,
            "[Decrypted QUIC] HTTP/3 control stream, HTTP/3 SETTINGS, HTTP/3 HEADERS GET /index.html"
        )
    );
    assert_eq!(
        rows[3],
        (
            Protocol::Http3,
            "[Decrypted QUIC] HTTP/3 HEADERS 200, HTTP/3 DATA 13 bytes"
        )
    );
    let tree = labels(&packets[2]);
    assert!(tree.contains("Header: :path: /index.html"), "{tree}");
    assert!(tree.contains("Header: :authority: example.com"));
    assert!(packets[3].payload().ends_with(b"hello from h3"));
    assert_eq!(count(&packets, "proto=http3"), 2);
    assert_eq!(count(&packets, "proto=quic"), 4);
}

#[test]
fn decrypts_esp_wpa_and_kerberos_with_supplied_keys() {
    // Without keys everything stays opaque.
    let esp = analyzed("ipsec.pcap", None);
    assert!(esp.iter().all(|p| p.summary.protocol == Protocol::Esp));
    let wpa = analyzed("wpa.pcap", None);
    assert!(wpa[5..]
        .iter()
        .all(|p| p.summary.info.ends_with("protected")));
    let kerberos = analyzed("kerberos.pcap", None);
    assert!(labels(&kerberos[1]).contains("Encrypted part: etype 17"));
    assert!(!labels(&kerberos[1]).contains("Decrypted"));

    crypto::add_esp_sa("0x1000:aes-gcm:000102030405060708090a0b0c0d0e0fa1a2a3a4").unwrap();
    crypto::add_esp_sa("4097:aes-cbc:101112131415161718191a1b1c1d1e1f").unwrap();
    let esp = analyzed("ipsec.pcap", None);
    assert_eq!(
        rows(&esp),
        [
            (Protocol::Dns, "[Decrypted ESP] Query A example.com"),
            (
                Protocol::Icmp,
                "[Decrypted ESP] Echo request · type 8 · code 0"
            ),
            // A packet that fails authentication is left alone.
            (Protocol::Esp, "ESP · SPI 0x00001000 · sequence 2"),
        ]
    );
    // Tunnel mode shows the inner addresses; the filter still finds ESP.
    assert_eq!(esp[1].summary.src.unwrap().to_string(), "10.0.0.1");
    assert_eq!(count(&esp, "proto=esp"), 3);
    assert_eq!(count(&esp, "proto=esp proto=dns"), 1);

    // A wrong passphrase decrypts nothing; the right one confirms the handshake.
    crypto::add_wpa_key("wrong passphrase:example-net").unwrap();
    assert!(analyzed("wpa.pcap", None)[5..]
        .iter()
        .all(|p| p.summary.protocol == Protocol::Wlan));
    crypto::add_wpa_key("correct horse battery:example-net").unwrap();
    let wpa = analyzed("wpa.pcap", None);
    assert_eq!(
        rows(&wpa)[5..],
        [
            (Protocol::Dns, "[Decrypted WPA] Query A example.com"),
            (Protocol::Dns, "[Decrypted WPA] Response A example.com"),
            (Protocol::Arp, "[Decrypted WPA] ARP operation 1"),
        ]
    );
    assert_eq!(wpa[5].summary.stream, wpa[6].summary.stream);
    // Decrypted frames are still 802.11 traffic.
    assert_eq!(count(&wpa, "proto=wlan"), 8);

    let keytab = std::fs::read(fixture("kerberos.keytab")).unwrap();
    assert_eq!(crypto::load_keytab(&keytab), Ok(1));
    let kerberos = analyzed("kerberos.pcap", None);
    assert!(kerberos[1]
        .summary
        .info
        .ends_with("decrypted with a keytab key"));
    let tree = labels(&kerberos[1]);
    assert!(tree.contains("ticket for alice@EXAMPLE.COM"), "{tree}");
    assert!(tree.contains("session key for krbtgt/EXAMPLE.COM"));
}

/// Truncations and byte flips of every fixture packet must decode without
/// panicking, whatever they produce.
#[test]
fn malformed_variants_of_every_packet_do_not_panic() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut random = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for name in [
        "apps.pcap",
        "links.pcapng",
        "quic.pcap",
        "wpa.pcap",
        "ipsec.pcap",
        "kerberos.pcap",
    ] {
        let log = Arc::new(KeyLog::load(fixture("quic.keys")).unwrap());
        let packets = analyzed(name, Some(Arc::clone(&log)));
        let mut analyzer = Analyzer::new(Some(log));
        for packet in &packets {
            let step = (packet.bytes.len() / 64).max(1);
            for length in (0..packet.bytes.len()).step_by(step) {
                decode(&packet.bytes[..length], packet.link);
                details(&packet.bytes[..length], packet.link);
            }
            for _ in 0..60 {
                let mut bytes = packet.bytes.to_vec();
                for _ in 0..1 + random() % 4 {
                    let at = random() as usize % bytes.len().max(1);
                    if let Some(byte) = bytes.get_mut(at) {
                        *byte = random() as u8;
                    }
                }
                bytes.truncate(bytes.len() - random() as usize % 3);
                let mut mutated = Packet::new(0, 0, bytes.len() as u32, packet.link, bytes.into());
                analyzer.observe(&mut mutated);
                mutated.layers();
            }
        }
    }
}
