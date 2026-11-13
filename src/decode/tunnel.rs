//! GRE and VXLAN: the summary and details continue into the inner packet.
use super::{be16, Decoder};

const MAX_DEPTH: u8 = 4;

impl Decoder<'_> {
    pub(super) fn enter(&mut self) -> bool {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.warn("Too many nested tunnels");
        }
        self.depth <= MAX_DEPTH
    }

    pub(super) fn gre(&mut self, start: usize, end: usize) {
        let bytes = self.bytes;
        if start + 4 > end {
            self.warn("Truncated GRE header");
            return;
        }
        let flags = be16(bytes, start);
        // Optional checksum, key and sequence words; only version 0 is decoded.
        let length = 4 + [0x8000, 0x2000, 0x1000]
            .iter()
            .filter(|bit| flags & **bit != 0)
            .count()
            * 4;
        self.summary.info = format!("GRE · protocol 0x{:04x}", be16(bytes, start + 2));
        if flags & 7 != 0 || start + length > end {
            self.layer("GRE", start, end);
            return;
        }
        self.layer("GRE", start, start + length);
        self.field(start + 2, start + 4, || {
            format!("Protocol: 0x{:04x}", be16(bytes, start + 2))
        });
        if self.enter() {
            self.ethertype(be16(bytes, start + 2), start + length);
        }
    }

    pub(super) fn vxlan(&mut self, start: usize, end: usize) -> bool {
        let bytes = self.bytes;
        if end - start < 8 + 14 || bytes[start] & 0x08 == 0 {
            return false;
        }
        let vni = u32::from_be_bytes([0, bytes[start + 4], bytes[start + 5], bytes[start + 6]]);
        self.summary.info = format!("VXLAN · VNI {vni}");
        self.layer("VXLAN", start, start + 8);
        self.field(start + 4, start + 7, || format!("VNI: {vni}"));
        if self.enter() {
            self.ethernet(start + 8);
        }
        true
    }
}
