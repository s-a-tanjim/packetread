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


# --- protocols.pcap: application protocols, a TCP stream with problems, fragments ---

CLIENT, SERVER = bytes([192, 0, 2, 10]), bytes([198, 51, 100, 8])


def ip(src, dst, protocol, payload, ident=0, fragment=0):
    if not fragment and protocol in (6, 17):
        offset = 16 if protocol == 6 else 6
        pseudo = src + dst + struct.pack("!BBH", 0, protocol, len(payload))
        check = checksum(pseudo + payload) or 65535
        payload = payload[:offset] + struct.pack("!H", check) + payload[offset + 2:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, fragment, 64, protocol, 0, src, dst)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def segment(sport, dport, seq, ack, flags, payload=b"", window=65535):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, window, 0, 0) + payload


def from_client(sport, dport, seq, ack, flags, payload=b"", window=65535):
    return ethernet(ip(CLIENT, SERVER, 6, segment(sport, dport, seq, ack, flags, payload, window)))


def from_server(sport, dport, seq, ack, flags, payload=b"", window=65535):
    return ethernet(ip(SERVER, CLIENT, 6, segment(dport, sport, seq, ack, flags, payload, window)))


def handshake(sport, dport, client_isn, server_isn):
    return [
        from_client(sport, dport, client_isn, 0, 0x02),
        from_server(sport, dport, server_isn, client_isn + 1, 0x12),
        from_client(sport, dport, client_isn + 1, server_isn + 1, 0x10),
    ]


def write_pcap(name, packets):
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(packets):
        data += struct.pack("<IIII", 1700000000 + index // 100, index % 100 * 10000, len(frame), len(frame)) + frame
    (ROOT / name).write_bytes(data)


request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
head = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n"
c, s = 1001, 5001
packets = handshake(40000, 80, 1000, 5000) + [
    from_client(40000, 80, c, s, 0x18, request),
    from_server(40000, 80, s, c + len(request), 0x10),
    from_server(40000, 80, s, c + len(request), 0x18, head),
    from_server(40000, 80, s + len(head) + 6, c + len(request), 0x18, b"world!"),  # ahead of sequence
    from_client(40000, 80, c + len(request), s + len(head), 0x10),
    from_client(40000, 80, c + len(request), s + len(head), 0x10),  # duplicate ACK
    from_server(40000, 80, s + len(head), c + len(request), 0x18, b"hello "),
    from_server(40000, 80, s + len(head), c + len(request), 0x18, b"hello "),  # retransmission
    from_client(40000, 80, c + len(request), s + len(head) + 12, 0x10, window=0),  # zero window
]

answer = b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x06\x03www\xc0\x0c"
answer += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x07"
answered = query[:2] + struct.pack("!HHH", 0x8180, 1, 2) + query[8:] + answer
packets += [
    ethernet(ip(CLIENT, SERVER, 17, udp(query))),
    ethernet(ip(SERVER, CLIENT, 17, udp(answered, 53, 53000))),
]
packets += handshake(40001, 53, 2000, 6000)
packets.append(from_client(40001, 53, 2001, 6001, 0x18, struct.pack("!H", len(query)) + query))

dhcp = struct.pack("!BBBBIHH4s4s4s4s6s202x", 1, 1, 6, 0, 0xDEADBEEF, 0, 0, *[bytes(4)] * 4, bytes.fromhex("020000000001"))
dhcp += bytes.fromhex("63825363") + b"\x35\x01\x01" + b"\x0c\x06laptop" + b"\xff"
packets.append(ethernet(ip(bytes(4), bytes([255] * 4), 17, udp(dhcp, 68, 67))))

quic = b"\xc3" + struct.pack("!I", 1) + b"\x08" + bytes(range(1, 9)) + b"\x00" + bytes(40)
packets.append(ethernet(ip(CLIENT, SERVER, 17, udp(quic, 40002, 443))))

smb2 = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ16x", 64, 0, 0, 0, 1, 0, 0, 7, 0, 0, 0)
packets += handshake(40003, 445, 3000, 7000)
packets.append(from_client(40003, 445, 3001, 7001, 0x18, struct.pack("!I", len(smb2)) + smb2))

datagram = udp(b"fragmented-payload-0123456789abcdef", 5000, 5001)
packets += [
    ethernet(ip(CLIENT, SERVER, 17, datagram[:24], ident=0x4242, fragment=0x2000)),
    ethernet(ip(CLIENT, SERVER, 17, datagram[24:], ident=0x4242, fragment=3)),
]
v6datagram = udp(b"ipv6-fragmented-payload!", 6000, 6001)
for offset, more in ((0, 1), (16, 0)):
    part = v6datagram[offset:offset + 16] if more else v6datagram[offset:]
    extension = struct.pack("!BBHI", 17, 0, offset | more, 0x1234)
    packets.append(ethernet(struct.pack("!IHBB16s16s", 6 << 28, 8 + len(part), 44, 64, v6src, v6dst) + extension + part, 0x86DD))

telemetry = b"\x02\x01\x00" + struct.pack("<I", 5) + b"ab\0\0\xde\xad"
packets.append(ethernet(ip(CLIENT, SERVER, 17, udp(telemetry, 40004, 9999))))
write_pcap("protocols.pcap", packets)
print(f"Wrote {len(packets)} synthetic packets to protocols.pcap")


# --- more.pcap: messages spanning segments, more TCP conditions, more protocols, tunnels ---

big_request = b"GET /big HTTP/1.1\r\nHost: example.com\r\n\r\n"
big_head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\n"
c, s = 1001 + len(big_request), 5001 + len(big_head) + 30
more = handshake(40020, 80, 1000, 5000) + [
    from_client(40020, 80, 1001, 5001, 0x18, big_request),
    from_server(40020, 80, 5001, c, 0x18, big_head + b"0123456789"),
    from_server(40020, 80, s - 20, c, 0x18, b"abcdefghij"),
    from_server(40020, 80, s - 10, c, 0x18, b"ABCDEFGHIJ"),  # completes the body
    from_client(40020, 80, c - 1, s, 0x10),  # keep-alive
    from_server(40020, 80, s, c, 0x18, b"first"),
    from_server(40020, 80, s + 5, c, 0x18, b"second"),
    from_client(40020, 80, c, s, 0x10),  # duplicate ACKs ask for "first" again
    from_client(40020, 80, c, s, 0x10),
    from_server(40020, 80, s, c, 0x18, b"first"),  # fast retransmission
    from_server(40020, 80, s + 11, c, 0x14),  # reset
]
options = bytes.fromhex("020405b4") + b"\x04\x02" + b"\x08\x0a" + struct.pack("!II", 111, 0) + b"\x01" + b"\x03\x03\x07"
syn = struct.pack("!HHIIBBHHH", 40021, 22, 2000, 0, 0xA0, 0x02, 64240, 0, 0) + options
more += [
    ethernet(ip(CLIENT, SERVER, 6, syn)),
    from_server(40021, 22, 6001, 2001, 0x18, b"SSH-2.0-OpenSSH_9.6\r\n"),
    from_server(40023, 21, 1, 1, 0x18, b"220 Service ready\r\n"),
    from_client(40024, 25, 1, 1, 0x18, b"EHLO client.example\r\n"),
    ethernet(ip(CLIENT, SERVER, 17, udp(b"INVITE sip:bob@example.com SIP/2.0\r\nMax-Forwards: 70\r\n\r\n", 5060, 5060))),
    from_client(40025, 1883, 1, 1, 0x18, bytes.fromhex("100c00044d5154540402003c0000")),
    ethernet(ip(CLIENT, SERVER, 17, udp(b"\x23" + bytes(47), 40026, 123))),
    ethernet(ip(CLIENT, bytes([224, 0, 0, 251]), 2, bytes.fromhex("1600f904e00000fb"))),
    bytes.fromhex("0180c200000e020000000001") + struct.pack("!H", 0x88CC)
    + bytes.fromhex("020704020000000001") + bytes.fromhex("04020531") + bytes.fromhex("06020078")
    + b"\x0a\x07switch1" + b"\x00\x00",
    ethernet(ip(CLIENT, bytes([224, 0, 0, 251]), 17, udp(query, 5353, 5353))),
    ethernet(ip(CLIENT, SERVER, 47, struct.pack("!HH", 0, 0x0800) + ip(bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]), 1, icmp))),
    ethernet(ip(CLIENT, SERVER, 17, udp(
        struct.pack("!II", 0x08000000, 42 << 8)
        + ethernet(ip(bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]), 6, segment(40022, 80, 1, 0, 0x02))),
        40027, 4789))),
    ethernet(struct.pack("!IHBB16s16s", 6 << 28, 24, 58, 255, v6src, v6dst)
             + bytes.fromhex("87000000" "00000000") + v6dst, 0x86DD),
    ethernet(ip(CLIENT, SERVER, 17, udp(query, 53001, 5300))),
]
write_pcap("more.pcap", more)
print(f"Wrote {len(more)} synthetic packets to more.pcap")


# --- apps.pcap: the long tail of application, routing and tunnel protocols ---

def tlv(tag, *parts):
    body = b"".join(parts)
    length = bytes([len(body)]) if len(body) < 128 else b"\x82" + struct.pack("!H", len(body))
    return bytes([tag]) + length + body


def h2_frame(kind, flags, stream, body=b""):
    return struct.pack("!I", len(body))[1:] + bytes([kind, flags]) + struct.pack("!I", stream) + body


def stream_pair(port, dport, client_data, server_data):
    """A handshake, then alternating client and server segments."""
    out = handshake(port, dport, 1000, 5000)
    c, s = 1001, 5001
    for index in range(max(len(client_data), len(server_data))):
        if index < len(client_data):
            out.append(from_client(port, dport, c, s, 0x18, client_data[index]))
            c += len(client_data[index])
        if index < len(server_data):
            out.append(from_server(port, dport, s, c, 0x18, server_data[index]))
            s += len(server_data[index])
    return out


def datagram(payload, sport, dport, reverse=False):
    src, dst = (SERVER, CLIENT) if reverse else (CLIENT, SERVER)
    return ethernet(ip(src, dst, 17, udp(payload, sport, dport)))


h2_request = b"\x82\x86\x84\x41\x0bexample.com"
h2_response = b"\x88\x5f\x10application/grpc"
ws_key = b"\x01\x02\x03\x04"
ws_text = bytes(b ^ ws_key[i % 4] for i, b in enumerate(b"hello ws"))
oid = bytes.fromhex("2b06010201010100")
snmp = tlv(0x30, tlv(2, b"\x01"), tlv(4, b"public"), tlv(0xA0, tlv(2, b"\x00\x00\x00\x01"), tlv(2, b"\0"), tlv(2, b"\0"),
                                                         tlv(0x30, tlv(0x30, tlv(6, oid), tlv(5)))))
ldap = tlv(0x30, tlv(2, b"\x02"), tlv(0x63, tlv(4, b"dc=example,dc=com"), tlv(0x0A, b"\x02"), tlv(0x0A, b"\0"),
                                      tlv(2, b"\0"), tlv(2, b"\0"), tlv(1, b"\0"), tlv(0x87, b"objectClass"), tlv(0x30)))
principal = tlv(0x30, tlv(0xA0, tlv(2, b"\x01")), tlv(0xA1, tlv(0x30, tlv(0x1B, b"alice"))))
as_req = tlv(0x6A, tlv(0x30, tlv(0xA1, tlv(2, b"\x05")), tlv(0xA2, tlv(2, b"\x0a")),
                       tlv(0xA4, tlv(0x30, tlv(0xA0, tlv(3, bytes.fromhex("0040000000"))), tlv(0xA1, principal),
                                     tlv(0xA2, tlv(0x1B, b"EXAMPLE.COM"))))))
rdp_body = bytes.fromhex("e00000000000") + b"Cookie: mstshash=alice\r\n" + bytes.fromhex("0100080000000000")
rdp = b"\x03\x00" + struct.pack("!HB", 5 + len(rdp_body), len(rdp_body)) + rdp_body
rpc = struct.pack("!IIIIII", 0x1234ABCD, 0, 2, 100003, 3, 1) + bytes(16)
nfs = struct.pack("!I", 0x80000000 | len(rpc)) + rpc
mysql_greeting = b"\x0a8.0.36\0" + bytes(20)
mysql_query = b"\x03SELECT 1"
mysql = lambda seq, body: struct.pack("<I", len(body))[:3] + bytes([seq]) + body
pg_params = b"user\0alice\0database\0app\0\0"
pg_startup = struct.pack("!II", 8 + len(pg_params), 196608) + pg_params
pg = lambda kind, body: kind + struct.pack("!I", 4 + len(body)) + body
bgp = lambda kind, body=b"": b"\xff" * 16 + struct.pack("!HB", 19 + len(body), kind) + body
bgp_open = bgp(1, struct.pack("!BHH4sB", 4, 65001, 180, CLIENT, 0))
bgp_update = bgp(2, struct.pack("!HH", 0, 0) + bytes([24, 203, 0, 113]))
ospf = struct.pack("!BBH4s4sHH8s", 2, 1, 44, CLIENT, bytes(4), 0, 0, bytes(8)) + bytes(20)
rip = struct.pack("!BBH", 2, 2, 0) + struct.pack("!HH4s4s4sI", 2, 0, bytes([203, 0, 113, 0]), bytes([255, 255, 255, 0]), bytes(4), 1)
sdp = b"v=0\r\nc=IN IP4 192.0.2.10\r\nm=audio 40100 RTP/AVP 0\r\n"
invite = (b"INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: call-1@example.com\r\nFrom: <sip:alice@example.com>\r\n"
          b"To: <sip:bob@example.com>\r\nContent-Type: application/sdp\r\n\r\n" + sdp)
ok = b"SIP/2.0 200 OK\r\nCall-ID: call-1@example.com\r\nCSeq: 1 INVITE\r\n\r\n"
bye = b"BYE sip:bob@example.com SIP/2.0\r\nCall-ID: call-1@example.com\r\n\r\n"
rtp = lambda seq: struct.pack("!BBHII", 0x80, 0, seq, seq * 160, 0x1234ABCD) + bytes(160)
rtcp = struct.pack("!BBHI", 0x80, 200, 6, 0x1234ABCD) + bytes(20)
bpdu = struct.pack("!HBBBH6sIH6sHHHHH", 0, 0, 0, 0, 32768, bytes.fromhex("020000000001"), 4, 32768,
                   bytes.fromhex("020000000002"), 0x8001, 256, 5120, 512, 3840)
eapol_key = struct.pack("!BBHBHH8s32s", 2, 3, 95, 2, 0x008A, 16, bytes(7) + b"\x01", bytes(range(32))) + bytes(50)

apps = (
    stream_pair(40030, 8080,
                [b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2_frame(4, 0, 0) + h2_frame(1, 5, 1, h2_request)],
                [h2_frame(4, 0, 0, struct.pack("!HI", 3, 100)) + h2_frame(1, 4, 1, h2_response)
                 + h2_frame(0, 1, 1, b"\0" + struct.pack("!I", 5) + b"hello")])
    + stream_pair(40031, 8081,
                  [b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                   b"\x81\x88" + ws_key + ws_text],
                  [b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                   b"\x81\x07welcome"])
    + [
        datagram(snmp, 40032, 161),
        from_client(40033, 389, 1, 1, 0x18, ldap),
        datagram(as_req, 40034, 88),
        from_client(40035, 3389, 1, 1, 0x18, rdp),
        from_client(40036, 2049, 1, 1, 0x18, nfs),
        from_server(40037, 3306, 1, 1, 0x18, mysql(0, mysql_greeting)),
        from_client(40037, 3306, 1, 1, 0x18, mysql(0, mysql_query)),
        from_client(40038, 5432, 1, 1, 0x18, pg_startup),
        from_client(40038, 5432, 1 + len(pg_startup), 1, 0x18, pg(b"Q", b"SELECT 1\0")),
        from_server(40038, 5432, 1, 1, 0x18, pg(b"C", b"SELECT 1\0") + pg(b"Z", b"I")),
        from_client(40039, 179, 1, 1, 0x18, bgp_open + bgp(4)),
        from_client(40039, 179, 1 + len(bgp_open) + 19, 1, 0x18, bgp_update),
        ethernet(ip(CLIENT, bytes([224, 0, 0, 5]), 89, ospf)),
        datagram(rip, 520, 520),
        datagram(invite, 5060, 5060),
        datagram(ok, 5060, 5060, reverse=True),
        datagram(rtp(1), 40100, 40200),
        datagram(rtp(2), 40100, 40200),
        datagram(rtp(4), 40100, 40200),  # sequence 3 was lost
        datagram(rtcp, 40101, 40201),
        datagram(bye, 5060, 5060),
        ethernet(ip(CLIENT, SERVER, 50, struct.pack("!II", 0x2000, 1) + bytes(range(40)))),
        ethernet(ip(CLIENT, SERVER, 51, struct.pack("!BBHII", 1, 4, 0, 0x3000, 1) + bytes(12) + icmp)),
        bytes.fromhex("0180c2000000020000000001") + struct.pack("!H", 3 + len(bpdu)) + b"\x42\x42\x03" + bpdu,
        ethernet(struct.pack("!BBHHH", 0x11, 0, 0x0042, 2 + 20 + len(icmp), 0x0021) + ip(CLIENT, SERVER, 1, icmp), 0x8864),
        ethernet(struct.pack("!I", 100 << 12 | 0x100 | 64) + ip(CLIENT, SERVER, 1, icmp), 0x8847),
        ethernet(eapol_key, 0x888E),
    ]
)
write_pcap("apps.pcap", apps)
print(f"Wrote {len(apps)} synthetic packets to apps.pcap")

# --- links.pcapng: one interface per link type ---

beacon = (bytes.fromhex("80000000ffffffffffff") + bytes.fromhex("020000000001") * 2 + b"\0\0"
          + bytes(8) + bytes.fromhex("64001104") + b"\x00\x07example" + b"\x03\x01\x06")
radiotap = struct.pack("<BBHI", 0, 0, 15, 0x2E) + b"\x00\x0c" + struct.pack("<HH", 2412, 0x00A0) + b"\xd8"
usb = struct.pack("<QBBBBHBB", 1, ord("S"), 2, 0x80, 3, 1, 0, 0) + bytes(16) + struct.pack("<II", 18, 0)
usb += bytes.fromhex("8006000100001200")
link_frames = [
    (9, b"\xff\x03\x00\x21" + ip(CLIENT, SERVER, 1, icmp)),
    (9, b"\xc0\x21\x01\x01\x00\x04"),
    (0, struct.pack("<I", 2) + ip(CLIENT, SERVER, 1, icmp)),
    (105, beacon),
    (127, radiotap + beacon),
    (187, bytes.fromhex("040e0401030c00")),
    (187, bytes.fromhex("02010007000300040052")),
    (201, struct.pack("!I", 1) + bytes.fromhex("01030c00")),
    (189, usb),
    (227, struct.pack("!IB3x", 0x123, 2) + b"\xbe\xef"),
    (195, bytes.fromhex("6188" "07" "3412" "0000" "0100") + bytes.fromhex("0800" "0000" "0100" "1e" "05") + b"zb" + b"\0\0"),
    (147, b"unsupported link"),
]
links = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
kinds = sorted({kind for kind, _ in link_frames})
for kind in kinds:
    links += block(1, struct.pack("<HHI", kind, 0, 65535))
for index, (kind, frame) in enumerate(link_frames):
    timestamp = 1700000000000000 + index * 1000
    links += block(6, struct.pack("<IIIII", kinds.index(kind), timestamp >> 32, timestamp & 0xFFFFFFFF, len(frame), len(frame)) + frame)
(ROOT / "links.pcapng").write_bytes(links)
print(f"Wrote {len(link_frames)} synthetic packets to links.pcapng")


def crypto_fixtures():
    """Encrypted traffic with fixed throwaway keys: QUIC, IPsec ESP, WPA2 and Kerberos.

    Deterministic; needs the `cryptography` package. Keys live beside each capture.
    """
    import hashlib
    import hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM

    def ecb(key, data, decrypt=False):
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        op = cipher.decryptor() if decrypt else cipher.encryptor()
        return op.update(data) + op.finalize()

    def cbc(key, iv, data):
        op = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return op.update(data) + op.finalize()

    # QUIC (RFC 9001): Initial keys from the connection ID, then fixed traffic secrets.
    def expand_label(secret, label, length):
        label = b"tls13 " + label
        info = struct.pack("!HB", length, len(label)) + label + b"\0"
        return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]

    def quic_keys(secret):
        return [expand_label(secret, name, size) for name, size in ((b"quic key", 16), (b"quic iv", 12), (b"quic hp", 16))]

    def protect(keys, header, number, payload):
        key, iv, hp = keys
        pn = struct.pack("!I", number)
        nonce = iv[:4] + bytes(a ^ b for a, b in zip(iv[4:], struct.pack("!Q", number)))
        sealed = AESGCM(key).encrypt(nonce, payload, header + pn)
        mask = ecb(hp, sealed[:16])
        first = header[0] ^ (mask[0] & (0x0F if header[0] & 0x80 else 0x1F))
        return bytes([first]) + header[1:] + bytes(a ^ b for a, b in zip(pn, mask[1:5])) + sealed

    def long(kind, dcid, scid, number, keys, payload):
        header = bytes([0xC3 | kind << 4]) + struct.pack("!I", 1) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
        if kind == 0:
            header += b"\0"
        header += struct.pack("!H", 0x4000 | (4 + len(payload) + 16))
        return protect(keys, header, number, payload)

    def short(dcid, number, keys, payload):
        return protect(keys, b"\x43" + dcid, number, payload)

    def crypto_frame(message):
        return b"\x06\x00" + struct.pack("!H", 0x4000 | len(message)) + message

    def stream_frame(ident, data, fin=True):
        return bytes([0x0A | fin, ident]) + struct.pack("!H", 0x4000 | len(data)) + data

    def handshake_message(kind, body):
        return bytes([kind]) + struct.pack("!I", len(body))[1:] + body

    def extension(code, body):
        return struct.pack("!HH", code, len(body)) + body

    random = bytes(range(0x40, 0x60))
    sni = b"example.com"
    extensions = (extension(0, struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni)
                  + extension(16, b"\x00\x03\x02h3") + extension(43, b"\x02\x03\x04"))
    client_hello = handshake_message(1, b"\x03\x03" + random + b"\0" + b"\x00\x02\x13\x01" + b"\x01\0"
                                     + struct.pack("!H", len(extensions)) + extensions)
    server_extensions = extension(43, b"\x03\x04")
    server_hello = handshake_message(2, b"\x03\x03" + bytes(range(0x60, 0x80)) + b"\0" + b"\x13\x01" + b"\0"
                                     + struct.pack("!H", len(server_extensions)) + server_extensions)
    original, client_id, server_id = bytes.fromhex("8394c8f03e515708"), bytes.fromhex("c1c2c3c4"), bytes.fromhex("5152535455565758")
    salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    initial = hmac.new(salt, original, hashlib.sha256).digest()
    client_initial = quic_keys(expand_label(initial, b"client in", 32))
    server_initial = quic_keys(expand_label(initial, b"server in", 32))
    secrets = {name: hashlib.sha256(name.encode()).digest() for name in (
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0")}
    request = b"\x00\x00" + bytes([0xC0 | 17, 0xC0 | 23]) + b"\x51\x0b/index.html" + b"\x50\x0bexample.com"
    h3_response = b"\x00\x00" + bytes([0xC0 | 25])
    body = b"hello from h3"
    hello_payload = crypto_frame(client_hello)
    quic = [
        datagram(long(0, original, client_id, 0, client_initial, hello_payload + bytes(1100 - len(hello_payload))), 50000, 443),
        datagram(long(0, client_id, server_id, 0, server_initial, b"\x02\x00\x00\x00\x00" + crypto_frame(server_hello))
                 + long(2, client_id, server_id, 0, quic_keys(secrets["SERVER_HANDSHAKE_TRAFFIC_SECRET"]),
                        crypto_frame(handshake_message(8, b"\0\0"))), 443, 50000, reverse=True),
        datagram(short(server_id, 0, quic_keys(secrets["CLIENT_TRAFFIC_SECRET_0"]),
                       stream_frame(2, b"\x00\x04\x00", fin=False) + stream_frame(0, b"\x01" + bytes([len(request)]) + request)),
                 50000, 443),
        datagram(short(client_id, 0, quic_keys(secrets["SERVER_TRAFFIC_SECRET_0"]),
                       stream_frame(0, b"\x01" + bytes([len(h3_response)]) + h3_response + b"\x00" + bytes([len(body)]) + body)),
                 443, 50000, reverse=True),
    ]
    write_pcap("quic.pcap", quic)
    lines = ["# Fixed, made-up secrets for the synthetic quic.pcap; they protect no real traffic."]
    lines += [f"{name} {random.hex()} {secret.hex()}" for name, secret in secrets.items()]
    (ROOT / "quic.keys").write_text("\n".join(lines) + "\n")

    # IPsec ESP: AES-GCM in transport mode, AES-CBC in tunnel mode.
    def esp_trailer(payload, next_header, block):
        padding = (-(len(payload) + 2)) % block
        return payload + bytes(range(1, padding + 1)) + bytes([padding, next_header])

    gcm_key, gcm_salt, cbc_key = bytes(range(16)), bytes.fromhex("a1a2a3a4"), bytes(range(16, 32))
    header = struct.pack("!II", 0x1000, 1)
    iv = bytes(range(8))
    gcm = header + iv + AESGCM(gcm_key).encrypt(gcm_salt + iv, esp_trailer(udp(query), 17, 4), header)
    header = struct.pack("!II", 0x1001, 1)
    iv = bytes(range(16))
    inner = ip(bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]), 1, icmp)
    tunnel = header + iv + cbc(cbc_key, iv, esp_trailer(inner, 4, 16)) + bytes(12)
    write_pcap("ipsec.pcap", [
        ethernet(ip(CLIENT, SERVER, 50, gcm)),
        ethernet(ip(CLIENT, SERVER, 50, tunnel)),
        ethernet(ip(CLIENT, SERVER, 50, struct.pack("!II", 0x1000, 2) + bytes(40))),  # fails authentication
    ])

    # WPA2-PSK: a 4-way handshake, then CCMP data in both directions.
    ap, station = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")
    pmk = hashlib.pbkdf2_hmac("sha1", b"correct horse battery", b"example-net", 4096, 32)
    anonce, snonce = bytes(range(32)), bytes(range(100, 132))
    seed = b"Pairwise key expansion\0" + min(ap, station) + max(ap, station) + min(anonce, snonce) + max(anonce, snonce)
    ptk = b"".join(hmac.new(pmk, seed + bytes([i]), hashlib.sha1).digest() for i in range(3))
    kck, tk = ptk[:16], ptk[32:48]
    tap = struct.pack("<BBHI", 0, 0, 8, 0)
    snap = bytes.fromhex("aaaa03000000")

    def data_frame(from_ap, body, qos=False, protected=False):
        control = bytes([0x88 if qos else 0x08, (2 if from_ap else 1) | (0x40 if protected else 0)])
        addresses = (station + ap + ap) if from_ap else (ap + station + ap)
        return control + b"\0\0" + addresses + b"\x10\x00" + (b"\0\0" if qos else b""), body

    def eapol(from_ap, info, nonce, mic):
        frame = struct.pack("!BBHBHH8s32s", 2, 3, 95, 2, info, 16, bytes(7) + b"\x01", nonce) + bytes(32) + bytes(16) + b"\0\0"
        if mic:
            frame = frame[:81] + hmac.new(kck, frame, hashlib.sha1).digest()[:16] + frame[97:]
        head, body = data_frame(from_ap, snap + b"\x88\x8e" + frame)
        return tap + head + body

    def ccmp(from_ap, number, payload):
        head, _ = data_frame(from_ap, b"", qos=True, protected=True)
        pn = struct.pack("!Q", number)[2:]
        aad = bytes([head[0] & 0x8F, (head[1] & 0xC7) | 0x40]) + head[4:22] + bytes([head[22] & 0x0F, 0]) + b"\0\0"
        nonce = b"\0" + head[10:16] + pn
        sealed = AESCCM(tk, tag_length=8).encrypt(nonce, snap + payload, aad)
        return tap + head + bytes([pn[5], pn[4], 0, 0x20, pn[3], pn[2], pn[1], pn[0]]) + sealed

    wpa_beacon = (bytes.fromhex("80000000ffffffffffff") + ap * 2 + b"\0\0" + bytes(8) + bytes.fromhex("64001104")
                  + b"\x00\x0bexample-net")
    wpa = [
        tap + wpa_beacon,
        eapol(True, 0x008A, anonce, False),
        eapol(False, 0x010A, snonce, True),
        eapol(True, 0x13CA, anonce, True),
        eapol(False, 0x030A, bytes(32), True),
        ccmp(False, 1, b"\x08\x00" + ip(CLIENT, SERVER, 17, udp(query))),
        ccmp(True, 1, b"\x08\x00" + ip(SERVER, CLIENT, 17, udp(response, 53, 53000))),
        ccmp(False, 2, b"\x08\x06" + arp),
    ]
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    for index, frame in enumerate(wpa):
        data += struct.pack("<IIII", 1700000000, index * 1000, len(frame), len(frame)) + frame
    (ROOT / "wpa.pcap").write_bytes(data)

    # Kerberos AS-REP whose ticket and reply parts use AES128-CTS-HMAC-SHA1-96.
    def nfold(data, size):
        def rotate(value, bits):
            width = len(value) * 8
            number = int.from_bytes(value, "big")
            bits %= width
            return ((number >> bits) | (number << (width - bits)) & ((1 << width) - 1)).to_bytes(len(value), "big")
        from math import lcm
        total = lcm(len(data), size)
        joined = b"".join(rotate(data, 13 * i) for i in range(total // len(data)))
        value = 0
        for at in range(0, total, size):
            value += int.from_bytes(joined[at:at + size], "big")
        mask = (1 << size * 8) - 1
        while value >> size * 8:
            value = (value & mask) + (value >> size * 8)
        return value.to_bytes(size, "big")

    def derive(key, constant):
        block = nfold(constant, 16)
        out = b""
        while len(out) < len(key):
            block = ecb(key, block)
            out += block
        return out[:len(key)]

    def cts(key, data):
        padded = data + bytes((-len(data)) % 16)
        sealed = cbc(key, bytes(16), padded)
        if len(data) <= 16:
            return sealed
        return (sealed[:-32] + sealed[-16:] + sealed[-32:-16])[:len(data)]

    def krb_encrypt(key, usage, plain):
        plain = bytes(range(16)) + plain
        ke, ki = (derive(key, struct.pack("!IB", usage, kind)) for kind in (0xAA, 0x55))
        return cts(ke, plain) + hmac.new(ki, plain, hashlib.sha1).digest()[:12]

    assert nfold(b"012345", 8).hex() == "be072631276b1955"
    krb_key = bytes(range(0x30, 0x40))
    encrypted = lambda usage, plain: tlv(0x30, tlv(0xA0, tlv(2, b"\x11")), tlv(0xA2, tlv(4, krb_encrypt(krb_key, usage, plain))))
    realm = tlv(0x1B, b"EXAMPLE.COM")
    service = tlv(0x30, tlv(0xA0, tlv(2, b"\x02")), tlv(0xA1, tlv(0x30, tlv(0x1B, b"krbtgt"), realm)))
    ticket = tlv(0x61, tlv(0x30, tlv(0xA0, tlv(2, b"\x05")), tlv(0xA1, realm), tlv(0xA2, service),
                           tlv(0xA3, encrypted(2, b"ticket for alice@EXAMPLE.COM"))))
    as_rep = tlv(0x6B, tlv(0x30, tlv(0xA0, tlv(2, b"\x05")), tlv(0xA1, tlv(2, b"\x0b")), tlv(0xA3, realm),
                           tlv(0xA4, principal), tlv(0xA5, ticket),
                           tlv(0xA6, encrypted(3, b"session key for krbtgt/EXAMPLE.COM"))))
    write_pcap("kerberos.pcap", [datagram(as_req, 40034, 88), datagram(as_rep, 88, 40034, reverse=True)])
    entry = struct.pack("!H", 1) + struct.pack("!H", 11) + b"EXAMPLE.COM" + struct.pack("!H", 6) + b"krbtgt"
    entry += struct.pack("!IIBHH", 1, 1700000000, 1, 17, 16) + krb_key
    (ROOT / "kerberos.keytab").write_bytes(b"\x05\x02" + struct.pack("!i", len(entry)) + entry)
    print("Wrote quic.pcap, quic.keys, ipsec.pcap, wpa.pcap, kerberos.pcap and kerberos.keytab")




def tls_fixture(name="tls", key_type=("ec", "ec_paramgen_curve:prime256v1"), sessions=None, keep_key=False):
    """Real TLS handshakes between in-memory endpoints, replayed as TCP streams.

    Not deterministic (fresh keys each run): regenerates NAME.pcap and NAME.keys
    together, plus the throwaway server key NAME.key when `keep_key` is set.
    """
    import ssl
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        key, cert, log = (f"{directory}/{name}" for name in ("key.pem", "cert.pem", "keys.log"))
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", key_type[0], "-pkeyopt", key_type[1], "-nodes",
             "-keyout", key, "-out", cert, "-days", "3650", "-subj", "/CN=example.com"],
            check=True, capture_output=True,
        )
        out = []
        sessions = sessions or [
            (ssl.TLSVersion.TLSv1_3, None),
            (ssl.TLSVersion.TLSv1_2, "ECDHE-ECDSA-AES128-GCM-SHA256"),
            (ssl.TLSVersion.TLSv1_2, "ECDHE-ECDSA-CHACHA20-POLY1305"),
        ]
        for index, (version, cipher) in enumerate(sessions):
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            if keep_key:
                server_context.set_ciphers("ALL:@SECLEVEL=0")
            server_context.load_cert_chain(cert, key)
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.load_verify_locations(cert)
            client_context.keylog_filename = log
            client_context.maximum_version = version
            if cipher:
                client_context.set_ciphers(cipher)
            bios = [ssl.MemoryBIO() for _ in range(4)]
            client = client_context.wrap_bio(bios[0], bios[1], server_hostname="example.com")
            server = server_context.wrap_bio(bios[2], bios[3], server_side=True)
            port = 40010 + index
            out += handshake(port, 443, 1000, 5000)
            sequence = {True: 1001, False: 5001}

            def pump():
                moved = True
                while moved:
                    moved = False
                    for is_client, source, sink in ((True, bios[1], bios[2]), (False, bios[3], bios[0])):
                        data = source.read()
                        sink.write(data)
                        moved |= bool(data)
                        # A small MSS makes TLS records span TCP segments.
                        for at in range(0, len(data), 536):
                            part = data[at:at + 536]
                            send = from_client if is_client else from_server
                            out.append(send(port, 443, sequence[is_client], sequence[not is_client], 0x18, part))
                            sequence[is_client] += len(part)

            def step(action):
                try:
                    return action()
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    return None
                finally:
                    pump()

            for _ in range(6):
                step(client.do_handshake)
                step(server.do_handshake)
            assert not cipher or client.cipher()[0] == cipher.split(":")[0], client.cipher()
            client.write(b"GET /secret HTTP/1.1\r\nHost: example.com\r\n\r\n")
            pump()
            assert step(lambda: server.read(4096)).startswith(b"GET /secret")
            server.write(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\ndecrypted body")
            pump()
            assert step(lambda: client.read(4096)).endswith(b"decrypted body")
        write_pcap(f"{name}.pcap", out)
        note = f"# Session secrets for {name}.pcap: throwaway in-memory handshakes, no real traffic.\n"
        (ROOT / f"{name}.keys").write_text(note + Path(log).read_text())
        if keep_key:
            # A test-only key for a self-signed certificate that exists nowhere else.
            (ROOT / f"{name}.key").write_text(Path(key).read_text())
        print(f"Wrote {len(out)} packets to {name}.pcap and their secrets to {name}.keys")


if __name__ == "__main__" and "--tls" in __import__("sys").argv:
    tls_fixture()
if __name__ == "__main__" and "--tls-rsa" in __import__("sys").argv:
    import ssl as _ssl
    # RSA key exchange (decryptable with the server key) and AES-CBC suites.
    tls_fixture("tls-rsa", ("rsa", "rsa_keygen_bits:2048"), [
        (_ssl.TLSVersion.TLSv1_2, "AES128-SHA:@SECLEVEL=0"),
        (_ssl.TLSVersion.TLSv1_2, "ECDHE-RSA-AES256-SHA384:@SECLEVEL=0"),
        (_ssl.TLSVersion.TLSv1_2, "AES256-GCM-SHA384:@SECLEVEL=0"),
    ], keep_key=True)
if __name__ == "__main__" and "--crypto" in __import__("sys").argv:
    crypto_fixtures()
