//! Command-line export, statistics, stream following, custom decoders and
//! the capture helper, all without capture privileges.
use packetread::{
    offline::OfflineCapture,
    source::{Seek, SourceSpec, Worker},
};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output as ProcessOutput},
    sync::atomic::AtomicBool,
    time::Duration,
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn run(args: &[&str]) -> ProcessOutput {
    Command::new(env!("CARGO_BIN_EXE_packetread"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(args: &[&str]) -> String {
    let output = run(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn read(path: &Path) -> Vec<(u64, usize, Option<String>)> {
    let mut capture = OfflineCapture::open(path).unwrap();
    let mut packets = Vec::new();
    while let Some(packet) = capture.next_packet(&AtomicBool::new(false)).unwrap() {
        packets.push((packet.id, packet.bytes.len(), packet.comment));
    }
    packets
}

#[test]
fn exports_filtered_packets_in_every_format() {
    let temp = tempfile::tempdir().unwrap();
    let source = fixture("protocols.pcap");
    let source = source.to_str().unwrap();
    for (name, filter, count) in [
        ("all.pcapng", "", 29),
        ("http.pcap", "proto=http or tcp.analysis=any", 6),
        ("none.pcap", "port=1", 0),
    ] {
        let path = temp.path().join(name);
        let text = stdout(&[
            "export",
            source,
            "-o",
            path.to_str().unwrap(),
            "--filter",
            filter,
        ]);
        assert!(
            text.contains(&format!("Exported {count} packets")),
            "{text}"
        );
        assert_eq!(read(&path).len(), count);
    }
    // Exported captures re-export identically, and existing files are kept.
    let again = temp.path().join("again.pcapng");
    let all = temp.path().join("all.pcapng");
    stdout(&[
        "export",
        all.to_str().unwrap(),
        "-o",
        again.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(&all).unwrap(), std::fs::read(&again).unwrap());
    let refused = run(&["export", source, "-o", again.to_str().unwrap()]);
    assert!(!refused.status.success());

    let json = temp.path().join("dns.json");
    stdout(&[
        "export",
        source,
        "-o",
        json.to_str().unwrap(),
        "-f",
        "proto=dns proto=udp",
    ]);
    let json = std::fs::read_to_string(json).unwrap();
    assert_eq!(json.matches("\"number\":").count(), 2);
    assert!(json.contains("\"info\":\"Response A example.com → www.example.com, 192.0.2.7\""));
    assert!(json.contains("{\"name\":\"DNS (UDP)\",\"fields\":[\"Transaction ID: 0x1234\""));
    let csv = temp.path().join("frag.csv");
    stdout(&[
        "export",
        source,
        "-o",
        csv.to_str().unwrap(),
        "-f",
        "reassembled",
    ]);
    let csv = std::fs::read_to_string(csv).unwrap();
    assert_eq!(csv.lines().count(), 3);
    assert!(csv.contains("192.0.2.10,198.51.100.8,5000,5001,UDP"));

    for bad in [
        &["export", source, "-o", "out.txt"][..],
        &["export", source, "-o", "x.json", "-f", "port="],
    ] {
        let output = run(bad);
        assert!(!output.status.success(), "{bad:?}");
    }
    assert!(
        !Path::new("x.json").exists(),
        "a bad filter must not create the output"
    );
}

#[test]
fn stats_and_follow_report_conversations_and_decrypt_tls() {
    let protocols = fixture("protocols.pcap");
    let stats = stdout(&[
        "stats",
        protocols.to_str().unwrap(),
        "--interval",
        "0.1",
        "--top",
        "3",
    ]);
    for expected in [
        "29 packets",
        "CONVERSATIONS · top 3 of 9",
        "IPv4 › TCP › HTTP",
        "retransmission       1",
        "HTTP ",
    ] {
        assert!(stats.contains(expected), "missing {expected:?} in\n{stats}");
    }
    let filtered = stdout(&[
        "stats",
        protocols.to_str().unwrap(),
        "-f",
        "stream=0",
        "--bytes",
    ]);
    assert!(filtered.contains("12 packets") && filtered.contains("TRAFFIC · bytes"));

    let follow = stdout(&["follow", protocols.to_str().unwrap(), "--stream", "0"]);
    assert!(follow.starts_with("TCP stream 0: 192.0.2.10:40000 ↔ 198.51.100.8:80\n"));
    assert!(follow.contains("  hello world!"));
    assert!(
        stdout(&["follow", protocols.to_str().unwrap(), "-s", "0", "--hex"])
            .contains("47 45 54 20")
    );
    assert!(!run(&["follow", protocols.to_str().unwrap(), "-s", "99"])
        .status
        .success());

    let (tls, keys) = (fixture("tls.pcap"), fixture("tls.keys"));
    let encrypted = stdout(&["follow", tls.to_str().unwrap(), "-s", "1"]);
    assert!(!encrypted.contains("GET /secret"));
    for stream in ["0", "1", "2"] {
        let plain = stdout(&[
            "--keylog",
            keys.to_str().unwrap(),
            "follow",
            tls.to_str().unwrap(),
            "-s",
            stream,
        ]);
        assert!(
            plain.contains("· decrypted\n→ client (43 bytes) · HTTP: GET /secret HTTP/1.1"),
            "{plain}"
        );
        assert!(plain.contains("  decrypted body"));
    }
    // A cleartext stream cannot be "decrypted".
    let wrong = run(&[
        "--keylog",
        keys.to_str().unwrap(),
        "follow",
        protocols.to_str().unwrap(),
        "-s",
        "0",
    ]);
    assert!(!wrong.status.success());
}

#[test]
fn decoder_files_extend_the_protocol_list() {
    let temp = tempfile::tempdir().unwrap();
    let decoder = temp.path().join("telemetry.decoder");
    std::fs::write(
        &decoder,
        "name = Telemetry\nudp.port = 9999\nfield = Version u8\nfield = Flags u16 hex\n\
         field = Sequence u32le\nfield = Device str:4\nfield = Token bytes:2\n",
    )
    .unwrap();
    let out = temp.path().join("ext.json");
    let source = fixture("protocols.pcap");
    stdout(&[
        "--decoder",
        decoder.to_str().unwrap(),
        "export",
        source.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
        "-f",
        "proto=ext",
    ]);
    let json = std::fs::read_to_string(out).unwrap();
    assert!(json.contains("\"protocol\":\"EXT\""));
    assert!(json.contains("\"info\":\"Telemetry · Version=2 Flags=0x100 Sequence=5 Device=ab\""));
    assert!(json.contains("\"Token: dead\""));

    std::fs::write(&decoder, "name = Broken\n").unwrap();
    let bad = run(&[
        "--decoder",
        decoder.to_str().unwrap(),
        "summary",
        source.to_str().unwrap(),
    ]);
    assert!(String::from_utf8_lossy(&bad.stderr).contains("telemetry.decoder"));
}

#[test]
fn seek_skips_delivery_but_not_analysis() {
    let ids = |seek: Seek| {
        let worker = Worker::start(SourceSpec::File(fixture("protocols.pcap")), seek).unwrap();
        let mut packets = Vec::new();
        while let Ok(batch) = worker.packets.recv_timeout(Duration::from_secs(2)) {
            packets.extend(
                batch
                    .into_iter()
                    .map(|p| (p.id, p.summary.stream, p.summary.diag)),
            );
        }
        assert_eq!(worker.status().packets, 29);
        packets
    };
    let tail = ids(Seek {
        from: 11,
        find: None,
        ..Seek::default()
    });
    assert_eq!(tail.len(), 19);
    // Stream numbers and the retransmission flag still reflect the skipped packets.
    assert_eq!(
        tail[0],
        (11, Some(0), packetread::decode::diag::RETRANSMISSION)
    );
    let find = packetread::filter::Filter::containing(b"LAPTOP");
    assert_eq!(
        ids(Seek {
            from: 5,
            find: Some(find),
            ..Seek::default()
        })[0]
            .0,
        19
    );
    let absent = packetread::filter::Filter::containing(b"absent");
    assert!(ids(Seek {
        from: 1,
        find: Some(absent),
        ..Seek::default()
    })
    .is_empty());
}

#[test]
fn expert_decode_as_field_filters_objects_and_stdin() {
    let temp = tempfile::tempdir().unwrap();
    let more = fixture("more.pcap");
    let more = more.to_str().unwrap();
    let expert = stdout(&["expert", more]);
    for expected in [
        "WARNINGS",
        "1 × TCP reset · packets 14",
        "NOTES",
        "2 × TCP dup-ack · packets 11, 12",
        "1 × TCP fast-retransmission · packets 13",
    ] {
        assert!(
            expert.contains(expected),
            "missing {expected:?} in\n{expert}"
        );
    }
    let demo = stdout(&["expert", fixture("demo.pcap").to_str().unwrap()]);
    assert!(demo.starts_with("ERRORS") && demo.contains("1 × Truncated link header · packets 10"));
    assert_eq!(
        stdout(&["expert", more, "-f", "proto=ntp"]).trim(),
        "No anomalies in these packets."
    );

    // Decode As puts the DNS decoder on a non-standard port; bad rules are refused.
    let forced = temp.path().join("forced.csv");
    stdout(&[
        "--decode-as",
        "udp:5300=dns",
        "export",
        more,
        "-o",
        forced.to_str().unwrap(),
        "-f",
        "port=5300",
    ]);
    assert!(std::fs::read_to_string(forced).unwrap().contains(",DNS,"));
    for bad in ["5300=dns", "udp:x=dns", "sctp:1=dns", "udp:1=nothing"] {
        assert!(
            !run(&["--decode-as", bad, "summary", more]).status.success(),
            "{bad}"
        );
    }

    // Any decoded field can be filtered on.
    let by_field = temp.path().join("field.csv");
    stdout(&[
        "export", more, "-o", by_field.to_str().unwrap(),
        "-f", "field contains \"window scale 7\" or field~\"^VNI: 4\\d$\" or field contains \"content-length: 30\"",
    ]);
    let rows: Vec<_> = std::fs::read_to_string(by_field)
        .unwrap()
        .lines()
        .skip(1)
        .map(|l| l.split(',').next().unwrap().to_string())
        .collect();
    assert_eq!(rows, ["5", "7", "15", "26"]);

    let objects = temp.path().join("objects");
    let saved = stdout(&[
        "follow",
        more,
        "-s",
        "0",
        "--objects",
        objects.to_str().unwrap(),
    ]);
    assert!(saved.contains("Saved 1 HTTP objects"), "{saved}");
    assert_eq!(
        std::fs::read(objects.join("stream0_object001.txt")).unwrap(),
        b"0123456789abcdefghijABCDEFGHIJ"
    );
    assert!(!run(&[
        "follow",
        more,
        "-s",
        "0",
        "--objects",
        objects.to_str().unwrap()
    ])
    .status
    .success());

    // Decrypted TLS reaches the non-interactive commands too.
    let (tls, keys) = (fixture("tls.pcap"), fixture("tls.keys"));
    let stats = stdout(&[
        "--keylog",
        keys.to_str().unwrap(),
        "stats",
        tls.to_str().unwrap(),
    ]);
    assert!(
        stats.contains("IPv4 › TCP › HTTP") && stats.contains("HTTP "),
        "{stats}"
    );

    // `-` reads the capture from standard input.
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_packetread"))
        .args(["summary", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&std::fs::read(more).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .starts_with("Packets: 28\n"));
}

#[test]
fn merges_reads_compressed_and_other_formats_and_shows_metadata() {
    use std::io::Write;
    let temp = tempfile::tempdir().unwrap();
    let path = |name: &str| temp.path().join(name).to_str().unwrap().to_string();
    let demo = fixture("demo.pcap");
    let protocols = fixture("protocols.pcap");
    let (demo, protocols) = (demo.to_str().unwrap(), protocols.to_str().unwrap());

    // Merge orders packets by time and never overwrites.
    let merged = path("merged.pcapng");
    let text = stdout(&["merge", "-o", &merged, protocols, demo]);
    assert!(text.starts_with("Merged 40 packets from 2 files"), "{text}");
    let mut capture = OfflineCapture::open(&merged).unwrap();
    let mut times = Vec::new();
    while let Some(packet) = capture.next_packet(&AtomicBool::new(false)).unwrap() {
        times.push(packet.timestamp_ns);
    }
    assert_eq!(times.len(), 40);
    assert!(times.windows(2).all(|pair| pair[0] <= pair[1]));
    assert!(!run(&["merge", "-o", &merged, demo]).status.success());
    assert!(!run(&["merge", "-o", &path("out.json"), demo])
        .status
        .success());
    assert!(!run(&["merge", "-o", &path("none.pcap")]).status.success());

    // Slicing: by packet number or capture time through the display filter.
    let slice = path("slice.pcap");
    let text = stdout(&[
        "export",
        protocols,
        "-o",
        &slice,
        "-f",
        "id=5-9 time=1700000000",
    ]);
    assert!(text.starts_with("Exported 5 packets"), "{text}");
    let none = stdout(&[
        "export",
        protocols,
        "-o",
        &path("late.pcap"),
        "-f",
        "time>1700000000",
    ]);
    assert!(none.starts_with("Exported 0 packets"), "{none}");

    // Gzip is read directly; damaged or other compression is an error.
    let gzip = |name: &str, data: &[u8]| {
        let file = std::fs::File::create(path(name)).unwrap();
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap();
        path(name)
    };
    let raw = std::fs::read(protocols).unwrap();
    let compressed = gzip("protocols.pcap.gz", &raw);
    assert!(stdout(&["summary", &compressed]).starts_with("Packets: 29\n"));
    let bytes = std::fs::read(&compressed).unwrap();
    std::fs::write(path("cut.gz"), &bytes[..bytes.len() / 2]).unwrap();
    assert!(!run(&["summary", &path("cut.gz")]).status.success());
    assert!(
        !run(&["summary", &gzip("junk.gz", b"not a capture at all")])
            .status
            .success()
    );
    std::fs::write(path("x.zst"), [0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0]).unwrap();
    let zstd = run(&["summary", &path("x.zst")]);
    assert!(String::from_utf8_lossy(&zstd.stderr).contains("Zstandard"));

    // A snoop capture built from the demo packets reads the same.
    let demo_bytes = std::fs::read(demo).unwrap();
    let mut snoop = b"snoop\0\0\0\0\0\0\x02\0\0\0\x04".to_vec();
    let mut at = 24;
    while at < demo_bytes.len() {
        let word = |at: usize| u32::from_le_bytes(demo_bytes[at..at + 4].try_into().unwrap());
        let (included, original) = (word(at + 8) as usize, word(at + 12));
        let padding = (4 - included % 4) % 4;
        for value in [
            original,
            included as u32,
            (24 + included + padding) as u32,
            0,
        ] {
            snoop.extend(value.to_be_bytes());
        }
        snoop.extend(word(at).to_be_bytes());
        snoop.extend(word(at + 4).to_be_bytes());
        snoop.extend(&demo_bytes[at + 16..at + 16 + included]);
        snoop.extend(vec![0; padding]);
        at += 16 + included;
    }
    std::fs::write(path("demo.snoop"), &snoop).unwrap();
    assert_eq!(
        stdout(&["summary", &path("demo.snoop")]),
        stdout(&["summary", demo])
    );
    assert!(stdout(&["summary", &gzip("demo.snoop.gz", &snoop)]).starts_with("Packets: 11\n"));
    std::fs::write(path("cut.snoop"), &snoop[..snoop.len() - 7]).unwrap();
    assert!(!run(&["summary", &path("cut.snoop")]).status.success());
    snoop[15] = 9; // Not Ethernet.
    std::fs::write(path("fddi.snoop"), &snoop).unwrap();
    assert!(!run(&["summary", &path("fddi.snoop")]).status.success());

    // PCAPNG section, interface and name-resolution metadata.
    let block = |kind: u32, body: &[u8]| {
        let mut body = body.to_vec();
        body.resize(body.len().next_multiple_of(4), 0);
        let length = (body.len() + 12) as u32;
        let mut out = kind.to_le_bytes().to_vec();
        out.extend(length.to_le_bytes());
        out.extend(body);
        out.extend(length.to_le_bytes());
        out
    };
    let option = |code: u16, value: &[u8]| {
        let mut out = code.to_le_bytes().to_vec();
        out.extend((value.len() as u16).to_le_bytes());
        out.extend(value);
        out.resize(out.len().next_multiple_of(4), 0);
        out
    };
    let mut section = vec![0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0];
    section.extend((-1i64).to_le_bytes());
    section.extend(option(4, b"testapp \x1b[31m"));
    section.extend(option(0, b""));
    let mut interface = vec![1, 0, 0, 0, 0xff, 0xff, 0, 0];
    interface.extend(option(2, b"eth9"));
    interface.extend(option(0, b""));
    let mut names = option(1, b"\xc0\x00\x02\x01host.example\0");
    names.extend(option(0, b""));
    let mut ng = block(0x0a0d_0d0a, &section);
    ng.extend(block(1, &interface));
    ng.extend(block(4, &names));
    std::fs::write(path("meta.pcapng"), ng).unwrap();
    let summary = stdout(&["summary", &path("meta.pcapng")]);
    for expected in [
        "Application: testapp �[31m",
        "Interface 0: link type 1 · name: eth9",
        "Name: 192.0.2.1 host.example",
    ] {
        assert!(
            summary.contains(expected),
            "missing {expected:?} in\n{summary}"
        );
    }
}

#[test]
fn graphs_flows_voip_lua_decoders_and_key_options() {
    let temp = tempfile::tempdir().unwrap();
    let tls = fixture("tls.pcap");
    let graph = stdout(&[
        "graph",
        tls.to_str().unwrap(),
        "--stream",
        "0",
        "--height",
        "6",
    ]);
    assert!(graph.starts_with("Time-sequence · stream 0 · "), "{graph}");
    assert_eq!(graph.lines().count(), 9);
    for kind in ["throughput", "window"] {
        let text = stdout(&[
            "graph",
            tls.to_str().unwrap(),
            "--stream",
            "1",
            "--kind",
            kind,
        ]);
        assert!(text.contains("stream 1") && text.contains('•'), "{text}");
    }
    let missing = stdout(&["graph", tls.to_str().unwrap(), "--stream", "99"]);
    assert_eq!(missing.trim(), "No TCP conversation numbered 99");
    assert!(!run(&[
        "graph",
        tls.to_str().unwrap(),
        "--stream",
        "0",
        "--kind",
        "pie"
    ])
    .status
    .success());

    let protocols = fixture("protocols.pcap");
    let flow = stdout(&["flow", protocols.to_str().unwrap(), "-f", "stream=0"]);
    assert_eq!(flow.lines().count(), 13);
    assert!(flow.contains("192.0.2.10") && flow.contains("198.51.100.8"));
    assert!(flow.contains("▶") && flow.contains("◀") && flow.contains("HTTP 40000 → 80 GET"));
    let apps = fixture("apps.pcap");
    let voip = stdout(&["voip", apps.to_str().unwrap()]);
    assert!(voip.contains("SIP calls: 1") && voip.contains("· ended · 3 messages"));
    assert!(voip.contains("3 packets · 1 lost (25.0%)"), "{voip}");
    assert!(stdout(&["voip", protocols.to_str().unwrap()]).contains("RTP streams: 0"));

    // A Lua decoder claims an otherwise undecoded payload.
    let script = temp.path().join("greeter.lua");
    std::fs::write(
        &script,
        "name = 'Greeter'\ntransport = 'udp'\nports = { 12001 }\n\
         function decode(payload) return { info = 'greeting ' .. payload,\n\
           fields = { { label = 'Text: ' .. payload, offset = 0, length = #payload } } } end\n",
    )
    .unwrap();
    let demo = fixture("demo.pcap");
    let csv = temp.path().join("greeter.csv");
    let text = stdout(&[
        "--decoder",
        script.to_str().unwrap(),
        "export",
        demo.to_str().unwrap(),
        "-o",
        csv.to_str().unwrap(),
        "-f",
        "proto=ext",
    ]);
    assert!(text.starts_with("Exported 1 packets"), "{text}");
    assert!(std::fs::read_to_string(&csv)
        .unwrap()
        .contains("Greeter · greeting hello"));
    std::fs::write(&script, "os.execute('true')").unwrap();
    let refused = run(&[
        "--decoder",
        script.to_str().unwrap(),
        "summary",
        demo.to_str().unwrap(),
    ]);
    assert!(!refused.status.success());

    // Keys: a server private key decrypts RSA key exchange; bad keys are refused.
    let rsa = fixture("tls-rsa.pcap");
    let key = fixture("tls-rsa.key");
    let followed = stdout(&[
        "--tls-key",
        key.to_str().unwrap(),
        "follow",
        rsa.to_str().unwrap(),
        "--stream",
        "0",
    ]);
    assert!(
        followed.contains("decrypted") && followed.contains("GET /secret"),
        "{followed}"
    );
    let summary = ["summary", demo.to_str().unwrap()];
    for bad in [
        ["--wpa-key", "short:net"],
        ["--esp-sa", "1:aes-gcm:00"],
        ["--keytab", demo.to_str().unwrap()],
        ["--tls-key", demo.to_str().unwrap()],
    ] {
        let output = run(&[&bad[..], &summary[..]].concat());
        assert!(!output.status.success(), "{bad:?}");
    }
    // An ESP security association exposes the DNS query inside the tunnel.
    let ipsec = fixture("ipsec.pcap");
    let inner = temp.path().join("inner.csv");
    let text = stdout(&[
        "--esp-sa",
        "0x1000:aes-gcm:000102030405060708090a0b0c0d0e0fa1a2a3a4",
        "export",
        ipsec.to_str().unwrap(),
        "-o",
        inner.to_str().unwrap(),
        "-f",
        "proto=dns",
    ]);
    assert!(text.starts_with("Exported 1 packets"), "{text}");
    assert!(std::fs::read_to_string(&inner)
        .unwrap()
        .contains("[Decrypted ESP] Query A example.com"));
}
