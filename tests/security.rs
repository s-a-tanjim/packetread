use packetread::source::{SourceSpec, Worker};
use std::{
    fs,
    path::Path,
    process::{Command, Output, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

fn summary(path: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_packetread"))
        .arg("summary")
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("summary blocked on its input");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}

fn worker_error(path: &Path) -> String {
    let path = path.to_owned();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let worker = Worker::start(SourceSpec::File(path), Default::default()).unwrap();
        while worker.packets.recv().is_ok() {}
        let status = worker.status();
        drop(worker);
        tx.send(status).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(3))
        .expect("worker did not finish and shut down")
        .error
        .expect("worker accepted unsafe input")
}

fn block(kind: u32, body: &[u8]) -> Vec<u8> {
    let length = (body.len() as u32 + 15) & !3;
    let mut bytes = Vec::new();
    bytes.extend(kind.to_le_bytes());
    bytes.extend(length.to_le_bytes());
    bytes.extend(body);
    bytes.resize(length as usize - 4, 0);
    bytes.extend(length.to_le_bytes());
    bytes
}

fn section() -> Vec<u8> {
    block(
        0x0a0d0d0a,
        &[
            0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
        ],
    )
}

fn interface() -> Vec<u8> {
    block(1, &[1, 0, 0, 0, 255, 255, 0, 0])
}

fn rejected_by_both(bytes: &[u8], message: &str) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("untrusted.pcapng");
    fs::write(&path, bytes).unwrap();
    let output = summary(&path);
    assert!(!output.status.success(), "summary accepted unsafe input");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(message), "{stderr}");
    let error = worker_error(&path);
    assert!(error.contains(message), "{error}");
}

#[test]
fn cli_errors_do_not_emit_filename_control_sequences() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("missing-\x1b]0;injected\x07\r.pcap");
    let output = summary(&path);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing-"));
    assert!(!output.stderr.iter().any(|b| matches!(b, 0x1b | 7 | 13)));
}

#[test]
fn excessive_interface_metadata_is_rejected_without_any_packets() {
    let mut bytes = section();
    for _ in 0..1025 {
        bytes.extend(interface());
    }
    rejected_by_both(&bytes, "1024 interfaces");
}

#[test]
fn oversized_block_is_rejected_before_its_body_is_read() {
    let mut bytes = section();
    bytes.extend(interface());
    bytes.extend(0xbadu32.to_le_bytes());
    bytes.extend((1024 * 1024 + 4u32).to_le_bytes());
    bytes.extend([0; 4]);
    rejected_by_both(&bytes, "1 MiB");
}

#[test]
fn oversized_packet_is_rejected_in_both_read_paths() {
    let length = 256 * 1024 + 1u32;
    let mut bytes = section();
    bytes.extend(block(1, &[1, 0, 0, 0, 0, 0, 0, 0]));
    let mut body = vec![0; 12];
    body.extend(length.to_le_bytes());
    body.extend(length.to_le_bytes());
    body.resize(20 + length as usize, 0);
    bytes.extend(block(6, &body));
    rejected_by_both(&bytes, "256 KiB");
}

#[test]
fn unknown_interface_and_malformed_blocks_are_rejected() {
    let mut bytes = section();
    bytes.extend(block(6, &[0; 20]));
    rejected_by_both(&bytes, "unknown interface");

    let mut bytes = section();
    bytes.extend(block(0xbad, &[0; 8]));
    *bytes.last_mut().unwrap() = 255;
    rejected_by_both(&bytes, "block lengths");

    let mut bytes = section();
    bytes.extend(interface());
    let mut body = vec![0; 12];
    body.extend(128u32.to_le_bytes());
    body.extend(128u32.to_le_bytes());
    bytes.extend(block(6, &body));
    rejected_by_both(&bytes, "block");
}

#[cfg(unix)]
#[test]
fn directories_and_devices_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    for path in [temp.path(), Path::new("/dev/zero")] {
        let output = summary(path);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("regular file"));
        assert!(worker_error(path).contains("regular file"));
    }
}

#[cfg(unix)]
#[test]
fn named_pipes_and_symlinks_to_them_are_rejected_without_blocking() {
    use rustix::fs::{mkfifoat, Mode, CWD};
    let temp = tempfile::tempdir().unwrap();
    let fifo = temp.path().join("stalled.pcap");
    mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR).unwrap();
    let alias = temp.path().join("alias.pcap");
    std::os::unix::fs::symlink(&fifo, &alias).unwrap();
    for path in [&fifo, &alias] {
        let output = summary(path);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("regular file"));
        assert!(worker_error(path).contains("regular file"));
    }
}
