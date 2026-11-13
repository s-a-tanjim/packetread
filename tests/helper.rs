//! Live capture through the helper protocol, using scripted stand-ins for the
//! privileged helper. Kept in its own test binary: it sets the process
//! environment and executes files it has just written.
#![cfg(unix)]
use packetread::{
    helper::{Frame, HELPER_ENV},
    offline::OfflineCapture,
    source::{interfaces, Limits, LiveSpec, Output, Seek, SourceSpec, Worker},
};
use std::{
    path::Path,
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

/// Like the real helper, keep sending idle ticks until killed.
const TICKS: &str = "while sleep 0.05; do printf '\\003\\000\\000\\000\\000'; done";

fn read(path: &Path) -> Vec<(u64, usize, Option<String>)> {
    let mut capture = OfflineCapture::open(path).unwrap();
    let mut packets = Vec::new();
    while let Some(packet) = capture.next_packet(&AtomicBool::new(false)).unwrap() {
        packets.push((packet.id, packet.bytes.len(), packet.comment));
    }
    packets
}

#[test]
fn live_capture_runs_through_the_helper_with_saving_rotation_and_limits() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let script = |name: &str, frames: &[Frame], tail: &str| {
        let path = temp.path().join(name);
        let mut wire = Vec::new();
        frames
            .iter()
            .for_each(|frame| frame.write(&mut wire).unwrap());
        std::fs::write(path.with_extension("frames"), wire).unwrap();
        std::fs::write(
            &path,
            format!("#!/bin/sh\necho \"$@\" > \"$0.args\"\ncat \"${{0%.*}}.frames\"\n{tail}\n"),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    };
    let packet = |link: i32, size: usize| Frame::Packet {
        link,
        timestamp_ns: 1_700_000_000_000_000_000,
        wire_len: size as u32,
        data: vec![0; size],
    };
    let wait = |worker: &Worker, done: &dyn Fn(&packetread::source::Status) -> bool| {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut delivered = 0;
        loop {
            delivered += worker
                .packets
                .try_iter()
                .map(|batch| batch.len())
                .sum::<usize>();
            let status = worker.status();
            if done(&status) {
                return (status, delivered);
            }
            assert!(
                Instant::now() < deadline,
                "helper capture stalled: {status:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    };

    // Two interfaces with different link types, rotating after every packet.
    let frames: Vec<_> = (0..5)
        .map(|n| packet(if n % 2 == 0 { 1 } else { 113 }, 60 + n))
        .collect();
    let mut all = frames.clone();
    all.insert(2, Frame::Stats { dropped: 3 });
    all.push(Frame::Tick);
    std::env::set_var(HELPER_ENV, script("rotate.sh", &all, TICKS));
    let spec = LiveSpec {
        interfaces: vec!["eth0".into(), "wlan0".into()],
        filter: "tcp port 443".into(),
        promiscuous: true,
        output: Some(Output {
            path: temp.path().join("ring.pcapng"),
            rotate_bytes: Some(1),
            keep_files: Some(2),
            ..Output::default()
        }),
        ..LiveSpec::default()
    };
    let worker = Worker::start(SourceSpec::Live(spec), Seek::default()).unwrap();
    let (status, _) = wait(&worker, &|status| {
        status.packets == 5 && status.kernel_drops == Some(3)
    });
    assert!(!status.done && status.error.is_none());
    let started = Instant::now();
    drop(worker);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "stopping must kill the helper"
    );
    let args = std::fs::read_to_string(temp.path().join("rotate.sh.args")).unwrap();
    assert_eq!(
        args.trim(),
        "-i eth0 -i wlan0 --snaplen 65535 --filter tcp port 443 --promiscuous"
    );
    let mut files: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".pcapng"))
        .collect();
    files.sort();
    assert_eq!(files, ["ring_00004.pcapng", "ring_00005.pcapng"]);
    assert_eq!(
        read(&temp.path().join("ring_00005.pcapng")),
        [(1, 64, None)]
    );

    // A packet limit ends the capture and completes the single output file.
    std::env::set_var(HELPER_ENV, script("limit.sh", &frames, TICKS));
    let spec = LiveSpec {
        interfaces: vec!["eth0".into()],
        output: Some(Output {
            path: temp.path().join("limited.pcap"),
            ..Output::default()
        }),
        limits: Limits {
            packets: Some(3),
            ..Limits::default()
        },
        ..LiveSpec::default()
    };
    let worker = Worker::start(SourceSpec::Live(spec), Seek::default()).unwrap();
    let (status, delivered) = wait(&worker, &|status| status.done);
    assert!(status.limit_reached && status.error.is_none());
    assert_eq!((status.packets, status.saved, delivered), (3, 2, 3));
    // PCAP holds one link type: the SLL packet between the two Ethernet ones is skipped.
    assert_eq!(read(&temp.path().join("limited.pcap")).len(), 2);

    // Headless capture saves until its limit without a terminal.
    std::env::set_var(HELPER_ENV, script("headless.sh", &frames, TICKS));
    let headless = temp.path().join("headless.pcapng");
    let output = Command::new(env!("CARGO_BIN_EXE_packetread"))
        .args([
            "capture",
            "-i",
            "eth0",
            "--headless",
            "--stop-after-packets",
            "4",
            "-w",
        ])
        .arg(&headless)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "Captured 4 packets, saved 4"
    );
    assert_eq!(read(&headless).len(), 4);
    // Ctrl+C (SIGINT) completes the file instead of losing it.
    let interrupted = temp.path().join("interrupted.pcap");
    let child = Command::new(env!("CARGO_BIN_EXE_packetread"))
        .args(["capture", "-i", "eth0", "--headless", "-w"])
        .arg(&interrupted)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !interrupted.exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(300));
    Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("saved 3"));
    assert_eq!(read(&interrupted).len(), 3);
    assert!(!Command::new(env!("CARGO_BIN_EXE_packetread"))
        .args(["capture", "-i", "eth0", "--headless"])
        .output()
        .unwrap()
        .status
        .success());

    // Helper errors, including missing privileges, reach the status.
    let denied = [Frame::Error(
        "socket: Operation not permitted - CAP_NET_RAW may be required".into(),
    )];
    std::env::set_var(HELPER_ENV, script("denied.sh", &denied, "exit 1"));
    let spec = LiveSpec {
        interfaces: vec!["eth0".into()],
        ..LiveSpec::default()
    };
    let worker = Worker::start(SourceSpec::Live(spec.clone()), Seek::default()).unwrap();
    let (status, _) = wait(&worker, &|status| status.done);
    assert!(status.permission_denied && status.error.unwrap().contains("CAP_NET_RAW"));
    // A helper that dies or sends garbage is an error, never a hang or panic.
    for (name, bytes) in [
        ("dead.sh", &b""[..]),
        ("garbage.sh", &[9, 255, 255, 255, 255]),
    ] {
        let path = script(name, &[], "exit 0");
        std::fs::write(path.with_extension("frames"), bytes).unwrap();
        std::env::set_var(HELPER_ENV, path);
        let worker = Worker::start(SourceSpec::Live(spec.clone()), Seek::default()).unwrap();
        let (status, _) = wait(&worker, &|status| status.done);
        assert!(
            status.error.is_some() && !status.permission_denied,
            "{name}"
        );
    }

    // Remote capture runs tcpdump through ssh; here a script stands in for
    // ssh, records its arguments and plays back a capture.
    let ssh = script("ssh.sh", &[], "exit 0");
    let demo = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/demo.pcap");
    std::fs::copy(demo, ssh.with_extension("frames")).unwrap();
    std::env::set_var(packetread::source::SSH_ENV, &ssh);
    let remote = |host: &str, interfaces: &[&str]| LiveSpec {
        interfaces: interfaces.iter().map(|name| name.to_string()).collect(),
        filter: "port 53 and not host 'x'; id".into(),
        remote: Some(host.into()),
        ..LiveSpec::default()
    };
    let worker = Worker::start(
        SourceSpec::Live(remote("user@capture.example", &["eth0"])),
        Seek::default(),
    )
    .unwrap();
    let (status, delivered) = wait(&worker, &|status| status.done);
    assert_eq!((status.packets, delivered), (11, 11));
    // The stand-in exits after the file; a real capture would keep running.
    assert!(status.error.unwrap().contains("remote capture ended"));
    // Every value reaches the remote shell quoted, after `--`.
    assert_eq!(
        std::fs::read_to_string(format!("{}.args", ssh.display()))
            .unwrap()
            .trim(),
        "-o BatchMode=yes -- user@capture.example tcpdump -U -n -w - -s 65535 -i 'eth0' -p \
         'port 53 and not host '\\''x'\\''; id'"
    );
    for (host, interfaces) in [
        ("-oProxyCommand=id", &["eth0"][..]),
        ("two words", &["eth0"]),
        ("", &["eth0"]),
        ("capture.example", &["eth0", "eth1"]),
    ] {
        let worker =
            Worker::start(SourceSpec::Live(remote(host, interfaces)), Seek::default()).unwrap();
        let (status, delivered) = wait(&worker, &|status| status.done);
        assert!(status.error.is_some() && delivered == 0, "{host:?}");
    }

    // The real helper lists interfaces without privileges and rejects bad arguments.
    std::env::set_var(HELPER_ENV, env!("CARGO_BIN_EXE_packetread-capture"));
    interfaces().unwrap();
    let helper = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_packetread-capture"))
            .args(args)
            .output()
            .unwrap()
    };
    assert!(helper(&["--list"]).status.success());
    for bad in [
        &[][..],
        &["-i"],
        &["--snaplen", "9"],
        &["-i", "lo", "--bogus"],
    ] {
        let output = helper(bad);
        assert!(!output.status.success(), "{bad:?}");
        assert!(matches!(
            Frame::read(&mut &output.stdout[..]),
            Ok(Some(Frame::Error(_)))
        ));
    }
}
