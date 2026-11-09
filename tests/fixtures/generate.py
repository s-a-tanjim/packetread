"""Regenerate tiny deterministic captures; all traffic uses documentation addresses."""
from pathlib import Path
import ipaddress
import struct

ROOT = Path(__file__).parent


def checksum(data):
    data += b"\0" * (len(data) % 2)
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def ethernet(payload, kind=0x0800):
    return bytes.fromhex("020000000002020000000001") + struct.pack("!H", kind) + payload


def ip4(payload, protocol, flags=0, reverse=False):
    src, dst = bytes([192, 0, 2, 10]), bytes([198, 51, 100, 8])
    if reverse:
        src, dst = dst, src
    if not flags and protocol in (6, 17):
        offset = 16 if protocol == 6 else 6
        pseudo = src + dst + struct.pack("!BBH", 0, protocol, len(payload))
        check = checksum(pseudo + payload) or 65535
        payload = payload[:offset] + struct.pack("!H", check) + payload[offset + 2:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, flags, 64, protocol, 0, src, dst)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp(flags):
    return struct.pack("!HHIIBBHHH", 51824, 443, 1000, 2000, 0x50, flags, 65535, 0, 0)


def udp(payload, src=53000, dst=53):
    return struct.pack("!HHHH", src, dst, 8 + len(payload), 0) + payload


query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\0\0\x01\0\x01"
response = query[:2] + b"\x81\x80" + query[4:]
arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("020000000001c000020a000000000000c6336408")
icmp = b"\x08\0\0\0\0\x01\0\x01ping"
icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
v6src, v6dst = (ipaddress.IPv6Address(s).packed for s in ("2001:db8::1", "2001:db8::2"))
v6udp = udp(b"hello", 12000, 12001)
pseudo = v6src + v6dst + struct.pack("!I3xB", len(v6udp), 17)
v6udp = v6udp[:6] + struct.pack("!H", checksum(pseudo + v6udp) or 65535) + v6udp[8:]
v6 = struct.pack("!IHBB16s16s", 6 << 28, len(v6udp), 17, 64, v6src, v6dst) + v6udp

frames = [
    ethernet(ip4(tcp(2), 6)),
    ethernet(ip4(tcp(0x10), 6)),
    ethernet(ip4(udp(query), 17)),
    ethernet(ip4(udp(response, 53, 53000), 17, reverse=True)),
    ethernet(ip4(udp(b"discovery", 5353, 5353), 17)),
    ethernet(arp, 0x0806),
    ethernet(ip4(icmp, 1)),
    ethernet(v6, 0x86DD),
    ethernet(struct.pack("!HH", 42, 0x0800) + ip4(tcp(0x18), 6), 0x8100),
    bytes.fromhex("0200000000020200"),
    ethernet(ip4(udp(b"fragment", 5000, 5001), 17, flags=0x2000)),
]

pcap = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
for index, frame in enumerate(frames):
    wire_len = 60 if index == 9 else len(frame)
    pcap += struct.pack("<IIII", 1700000000, index * 12500, len(frame), wire_len) + frame
(ROOT / "demo.pcap").write_bytes(pcap)


def block(kind, body):
    body += bytes((-len(body)) % 4)
    length = len(body) + 12
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


pcapng = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
pcapng += block(1, struct.pack("<HHI", 1, 0, 65535))
for index, frame in enumerate(frames):
    timestamp = 1700000000000000 + index * 12500
    wire_len = 60 if index == 9 else len(frame)
    pcapng += block(6, struct.pack("<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(frame), wire_len) + frame)
(ROOT / "demo.pcapng").write_bytes(pcapng)
print(f"Wrote {len(frames)} synthetic packets to demo.pcap and demo.pcapng")
