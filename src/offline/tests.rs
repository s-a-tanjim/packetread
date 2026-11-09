use super::*;
use std::io::Cursor;
use std::sync::Arc;

#[test]
fn every_truncated_fixture_prefix_finishes_without_panicking() {
    for bytes in [
        include_bytes!("../../tests/fixtures/demo.pcap").as_slice(),
        include_bytes!("../../tests/fixtures/demo.pcapng").as_slice(),
    ] {
        for end in 0..bytes.len() {
            if let Ok(mut reader) = OfflineCapture::from_reader(Cursor::new(bytes[..end].to_vec()))
            {
                let mut count = 0;
                while let Ok(Some(_)) = reader.next_packet(&AtomicBool::new(false)) {
                    count += 1;
                    assert!(count <= 11, "reader stopped making progress");
                }
            }
        }
    }
}

#[test]
fn cancellation_is_observed_when_refilling_metadata_before_a_packet() {
    struct CancellingReader {
        bytes: Cursor<Vec<u8>>,
        stop: Arc<AtomicBool>,
        reads: usize,
    }
    impl Read for CancellingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            if self.reads == 3 {
                self.stop.store(true, Ordering::Relaxed);
            }
            // First read supplies the section, second the interface, third
            // supplies packet bytes and cancels the reader during a refill.
            let limit = match self.reads {
                1 => 28,
                2 => 20,
                _ => buffer.len(),
            };
            let length = limit.min(buffer.len());
            self.bytes.read(&mut buffer[..length])
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let mut reader = OfflineCapture::from_reader(CancellingReader {
        bytes: Cursor::new(include_bytes!("../../tests/fixtures/demo.pcapng").to_vec()),
        stop: Arc::clone(&stop),
        reads: 0,
    })
    .unwrap();
    assert!(reader.next_packet(&stop).unwrap().is_none());
    assert!(stop.load(Ordering::Relaxed));
    stop.store(false, Ordering::Relaxed);
    assert_eq!(reader.next_packet(&stop).unwrap().unwrap().id, 1);
}
