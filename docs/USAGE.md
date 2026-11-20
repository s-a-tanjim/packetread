# Packetread usage reference

A Rust terminal packet inspector with a colorful, btop-inspired interface and mouse controls. Inspect saved captures or capture live traffic in a packet table, expandable protocol tree, and synchronized hex/ASCII view.

## Demo

![Packetread demo: browse packets, inspect protocol fields and bytes, apply DNS, TCP and field filters, view statistics and the flow diagram, and summarize a capture](assets/demo.gif)

Recorded with asciinema: launch `packetread`, open the included synthetic capture, and inspect its packets. [Download the recording](assets/demo.cast) or [regenerate the demo](DEMO.md).

```sh
asciinema play docs/assets/demo.cast
```

## Prebuilt downloads and releases

The GitHub Actions pipeline builds and tests Linux **x86-64** and **ARM64** packages. Branches and pull requests produce downloadable Actions artifacts; pushing a version tag such as `v0.1.0` publishes both archives and SHA-256 checksums to GitHub Releases after the checks pass.

Release binaries target Ubuntu 24.04 or compatible systems with glibc 2.39+ and the libpcap runtime. See [installation and release instructions](DISTRIBUTION.md) for architecture selection, runtime dependencies, capture permissions, and tagging a release.

## Build and run

Install a current stable Rust toolchain and the libpcap development package. On Ubuntu/Debian:

```sh
sudo apt-get install build-essential pkg-config libpcap-dev
cargo build --release
./target/release/packetread
```

The build also compiles a bundled Lua interpreter (for [Lua decoders](#custom-decoders)), which needs the C compiler from `build-essential`.

On macOS the system SDK already provides libpcap; install the Xcode command line tools and run `cargo build --release`. On Windows install [Npcap](https://npcap.com) and its SDK, and add the SDK's `Lib\x64` folder to the `LIB` environment variable before building. CI builds and tests both platforms, but release archives are produced for Linux only, and capture permissions differ: macOS needs read access to `/dev/bpf*`, Windows needs the Npcap driver.

If linking fails with `unable to find library -lpcap`, install `libpcap-dev` and `pkg-config`, then rerun `cargo build --release`. The runtime library installed with Wireshark is not sufficient: the linker also needs the development package's `libpcap.so` file.

The build produces two programs: `packetread`, the application, and `packetread-capture`, a small helper that the application starts for live capture. To run `packetread` from any directory, install both into the same directory. Make sure `~/.local/bin` is on your `PATH`:

```sh
mkdir -p "$HOME/.local/bin"
install -m755 target/release/packetread target/release/packetread-capture "$HOME/.local/bin/"
packetread --version
packetread
```

Repeat the install command after rebuilding to update the local copy. For live capture with this copy, apply the capability described below to `~/.local/bin/packetread-capture`.

Opening the application without a subcommand shows the interface with clickable **Open** and **Interfaces** controls. Try the included synthetic capture without capture privileges:

```sh
cargo run --release -- open tests/fixtures/demo.pcap
cargo run --release -- open tests/fixtures/demo.pcapng
cargo run --release -- summary tests/fixtures/demo.pcap
cargo run --release -- stats tests/fixtures/protocols.pcap
cargo run --release -- expert tests/fixtures/more.pcap
cargo run --release -- follow tests/fixtures/protocols.pcap --stream 0
cargo run --release -- --keylog tests/fixtures/tls.keys follow tests/fixtures/tls.pcap --stream 0
cargo run --release -- export tests/fixtures/protocols.pcap -o /tmp/http.json --filter 'proto=http'
cargo run --release -- interfaces
cargo run --release -- capture -i eth0 --capture-filter 'tcp port 443'
```

### Capture privileges

Live capture requires Linux capture permissions, and only the helper needs them. An administrator grants `packetread-capture` the `CAP_NET_RAW` capability once:

```sh
sudo setcap cap_net_raw=ep target/release/packetread-capture
./target/release/packetread capture -i eth0
```

`packetread` itself — the interface, every protocol decoder, file reading and file writing — runs with your normal privileges and does not link libpcap. The helper opens the capture devices, applies the BPF filter, and streams raw packets to the application over a pipe; it never decodes packets or touches files. The application treats that stream as untrusted input and bounds every frame. The helper is looked up next to the `packetread` executable; set `PACKETREAD_CAPTURE_HELPER` to use another location. The helper keeps its capability while it runs (it does not drop it after opening the devices).

If the TUI reports that capture permission is missing, run the `setcap` command shown in its help dialog and click **Start** again; no restart is needed. Verify the setting with `getcap target/release/packetread-capture`; it should show `cap_net_raw=ep`. Membership in the `wireshark` group does not grant capture permissions to this helper. Rebuilding replaces the helper and removes its capability, so reapply `setcap` after building. Running the whole application with `sudo` also works but is no longer necessary. Offline inspection requires no elevated privileges. Promiscuous mode is opt-in with `--promiscuous`.

### Capture controls

```sh
packetread capture -i eth0 -i wlan0                       # one session, several interfaces
packetread capture -i eth0 --write trace.pcapng           # save everything that is captured
packetread capture -i eth0 -w ring.pcap --rotate-mib 100 --rotate-files 5
packetread capture -i eth0 -w hourly.pcapng --rotate-seconds 3600
packetread capture -i eth0 --stop-after-seconds 60 --stop-after-packets 100000 --stop-after-mib 500
```

- Repeat `-i` (or tick several rows in the **Interfaces** dialog with Space or the mouse) to capture on several interfaces in one session. Each packet keeps its own link type.
- `--write` saves live traffic to a new `.pcap` or `.pcapng` file while you inspect it. Saving happens in the unprivileged application, before any display filter and independent of in-memory eviction. Existing files are never overwritten. A PCAP file holds a single link type; use `.pcapng` for mixed-link multi-interface sessions (other packets are counted as skipped).
- `--rotate-mib` and `--rotate-seconds` start a new numbered file (`trace_00001.pcapng`, `trace_00002.pcapng`, …) when the current one reaches the size or age. `--rotate-files N` keeps only the newest N files.
- `--headless` (with `--write`) captures to the file without the interface, until a stop limit or Ctrl+C; the file is completed either way.
- `--stop-after-seconds`, `--stop-after-packets` and `--stop-after-mib` end the capture automatically; whichever limit is reached first wins and the header shows **LIMIT REACHED**. Retained packets stay available.

### Remote capture

```sh
packetread capture --remote admin@gateway.example -i eth0 --capture-filter "not port 22"
```

`--remote [USER@]HOST` runs `tcpdump` on that host over SSH and reads its packet stream, so the host needs `tcpdump` with permission to capture and an SSH login that works without a prompt (a key or an agent; `ssh` runs in batch mode). One interface is captured. Add a capture filter such as `not port 22`, or the capture will record its own SSH session. Saving, rotation, `--headless` and the packet and size limits work as for a local capture; a time limit is only checked when a packet arrives. Set `PACKETREAD_SSH` to use another SSH client.

## Colorful and mouse accessible

The interface includes colored protocol labels, live packet/byte-rate graphs, capture status, separate drop counters, and memory usage. It uses three panes on wide terminals and clickable tabs on narrow terminals. Minimum size: 60 columns × 22 rows.

- Click toolbar controls to open files, choose interfaces, start/stop, toggle auto-scroll, move between file windows, find, save, open statistics or the selected stream, change themes, or open help.
- Click a packet to inspect it. Click a protocol heading to expand/collapse it or a field to highlight its bytes.
- Scroll the pane under the pointer. Drag scrollbars to navigate and dividers to resize panes.
- Click the display filter, type a query, and click **Apply**. File paths and capture filters also have mouse-accessible dialogs.

**Auto-scroll is ON by default** for each new capture session. Click **Auto-scroll ON/OFF** or press **Space** to toggle it. When ON, the packet list follows the newest matching packet. When OFF, incoming packets continue to be captured without moving the view to the latest packet. Selecting or scrolling through packets turns auto-scroll OFF so you can inspect them; turning it back ON jumps to the newest matching packet.

Use **Theme** to cycle vivid truecolor, 256-color, and high-contrast palettes, or choose at startup:

```sh
packetread --theme indexed open traffic.pcap
```

The terminal must support mouse reporting. Shift-selection is commonly available for normal terminal text selection while application mouse reporting is enabled.

| Keyboard | Action |
| --- | --- |
| `Tab`, `1` / `2` / `3` | Focus packets, protocol details, or bytes |
| Arrows, `j` / `k`, Page Up/Down | Navigate the focused pane |
| Home/End, `g` / `G` | First/last item |
| Enter, Left/Right in details | Expand/collapse a layer |
| `/`, Enter, Tab | Edit/apply the display filter, complete a field or protocol name |
| `F5`–`F12` | Apply a saved filter (also the buttons in the filter bar) |
| Space | Toggle auto-scroll ON/OFF (default ON); capture continues |
| `o`, `i`, `b` | Open file, interfaces, capture-filter dialog |
| `r`, `s` | Start a new session, stop capture |
| `n`, `p`, `:` | Next file window, previous file window, go to packet number |
| `f`, `F3` or `.`, `,` | Find text or `hex:` bytes, next match, previous match |
| `m`, `c` | Mark the selected packet, edit its comment |
| `w`, `W` | Save the displayed packets, save only the selected packet |
| `a` | Filter on the selected field (details pane) or conversation (packet list) |
| `S`, `E` | Statistics, expert information for the displayed packets |
| `T`, `N` | Cycle the time column format, show host names learned from DNS |
| `R` | Make the selected packet the time reference (again to clear) |
| `Y`, `D`, `V` | Graphs of the selected TCP stream, flow diagram of the displayed packets, VoIP calls |
| `F`, `K` | Follow the selected packet's stream, load a TLS key log |
| `P` | Save theme, filter and layout to the active profile |
| `t`, `?`, `q` | Theme, help, quit |
| Escape, Ctrl+C | Close editor/dialog, quit |

Starting or opening a new source clears the current in-memory session. Stopping leaves retained packets available for inspection.

## Filters

Capture filters use libpcap BPF, supplied through `--capture-filter` or the **BPF** dialog. Dialog changes take effect at the next **Start**.

Display filters combine predicates with `and` (or just whitespace), `or`, `not` and parentheses; `&&`, `||` and `!` work too. `and` binds tighter than `or`.

```text
proto=tcp port=443
(proto=dns or proto=http) and not src=192.0.2.1
addr=192.0.2.0/24 dst=2001:db8::/32
port=8000-8100 len>1000 ttl<5
tcp.flags=syn,ack tcp.window=0
tcp.analysis=retransmission or tcp.analysis=zero-window
info~"client hello.*example\.com"
bytes contains "password"        payload contains de:ad:be:ef
stream=3 and not marked
http.host == example.com and http.request.method == GET
ip.ttl < 10 or dns.qry.name contains "cdn"
```

| Field | Matches | Operators |
| --- | --- | --- |
| `proto` | `tcp`, `udp`, `icmp`, `arp`, `ipv4`, `ipv6`, `dns`, `http`, `tls`, `quic`, `dhcp`, `smb`, `ntp`, `ssh`, `ftp`, `smtp`, `pop3`, `imap`, `sip`, `mqtt`, `igmp`, `lldp`, `http2`, `grpc`, `http3`, `websocket`, `kerberos`, `ldap`, `snmp`, `rdp`, `nfs`, `mysql`, `pgsql`, `bgp`, `ospf`, `rip`, `stp`, `rtp`, `rtcp`, `esp`, `ah`, `wlan`, `eapol`, `ppp`, `mpls`, `bluetooth`, `usb`, `can`, `zigbee`, `ext` (custom decoder), `unknown`. Enclosing protocols match too: `proto=mpls`, `proto=esp` or `proto=wlan` find packets whose inner packet was decoded | `=` `!=` |
| `addr`, `src`, `dst` | IP address or CIDR subnet | `=` `!=` |
| `port`, `sport`, `dport` | Port number or range `low-high` | `=` `!=` `<` `<=` `>` `>=` |
| `len`, `ttl`, `vlan`, `stream`, `id`, `time` | Wire length, TTL/hop limit, VLAN ID, conversation number, packet number, capture time in whole Unix seconds | numeric, as above |
| `PROTOCOL.FIELD` | A field of the protocol details, named by its layer and label: `http.host`, `tcp.window`, `snmp.community`, `rtp.sequence`, `mpls.label`. Common Wireshark names are accepted (`ip.src`, `ip.ttl`, `tcp.srcport`, `dns.qry.name`, `http.request.method`, `http.request.uri`, `http.response.code`, `tls.handshake.extensions_server_name`). A bare name tests that the field exists | `==` `!=` (the whole value, one of its words, or equal numbers), `<` `<=` `>` `>=` (numbers, decimal or `0x` hex), `contains`, `~` |
| `tcp.seq`, `tcp.ack`, `tcp.window` | TCP header values | numeric |
| `tcp.flags` | All listed flags are set: `syn`, `ack`, `fin`, `rst`, `psh`, `urg`, `ece`, `cwr` | `=` `!=` |
| `tcp.analysis` | `retransmission`, `fast-retransmission`, `out-of-order`, `dup-ack`, `zero-window`, `keep-alive`, `reset`, `any` | `=` `!=` |
| `info`, `comment`, `warning` | Text, ignoring case | `contains "text"`, `~ "regex"` |
| `bytes`, `payload` | Packet bytes / transport payload | `contains "text"`, `contains de:ad` (hex), `~ "regex"` |
| `field` | The text of any layer or field in the protocol details, e.g. `field contains "server name: example.com"` or `field~"^TTL: [0-5]$"` | `contains "text"`, `~ "regex"` |
| `marked`, `comment`, `warning`, `reassembled` | Bare keywords: packet is marked, has a comment, has a decode warning, was rebuilt from IP fragments | — |

Named fields are typed by their value: numbers compare numerically, everything else as text ignoring case. Any label shown in the details pane can be used, with spaces written as `_` (`dhcp.host_name`, `ipv4.total_length`); like `field`, they decode each packet's details while filtering. In the filter bar, Tab completes field names, protocol names after `proto=`, and the values of `tcp.flags=` and `tcp.analysis=`.

Press `a` to build a filter from the selection: on a protocol field it produces `field contains "…"` for exactly that field, and in the packet list it produces `stream=N` for the packet's conversation. `field` gives access to everything the decoders show, at the cost of decoding each packet's details while filtering; the named fields above are faster.

`addr` and `port` match either endpoint. `proto=tcp` and `proto=udp` match every packet carried by that transport, including decoded application protocols; IP filters match packets carrying that IP version. `!=` is `not (… = …)`, so it also matches packets that lack the field. Regular expressions use the [regex crate syntax](https://docs.rs/regex/latest/regex/#syntax) and run in linear time; on `bytes`/`payload` they match raw bytes. Empty input shows all retained packets. Invalid input leaves the previous filter active. Filters are limited to 1,024 bytes. Wireshark display-filter syntax is not supported.

## Saving and exporting

```sh
packetread export traffic.pcapng -o dns.pcap --filter 'proto=dns'
packetread export traffic.pcap -o packets.json
packetread export traffic.pcap -o slow.csv -f 'tcp.analysis=any'
```

The non-interactive commands (`summary`, `stats`, `expert`, `export`, `follow`) accept `-` as the file to read a capture from standard input, for example `tcpdump -w - | packetread stats -`.

`export` reads the whole file with bounded memory and writes the packets matching `--filter`. In the interface, **Save** (`w`) writes the displayed packets — apply a filter such as `marked` or `stream=3` first — and `W` writes only the selected packet. The file extension picks the format:

- `.pcap` (nanosecond PCAP 2.4) and `.pcapng` keep the original captured bytes, timestamps and lengths. PCAPNG also stores packet comments and supports mixed link types.
- `.json` holds one object per packet: number, time, addresses, ports, protocol, lengths, stream, info, warning, comment, mark, and the decoded protocol layers with their fields.
- `.csv` holds the summary columns. Text taken from packets is escaped, and cells that would start a spreadsheet formula are prefixed with `'`.

Output files are always new: an existing path is refused rather than overwritten. Live traffic is saved with `capture --write` (see [Capture controls](#capture-controls)).

## Statistics

```sh
packetread stats traffic.pcap
packetread stats traffic.pcap --rank-by packets --direction received --top 10
packetread stats traffic.pcap --filter 'addr=192.0.2.10' --interval 0.1 --top 20 --bytes
```

**Stats** (`S`, or the **Stats** tab under the filter bar) replaces the packet panes with statistics for the displayed packets in the retained window. `S`, `Esc` or the **Inspect** tab returns to the packets; while Stats is open the toolbar's **Stats** button reads **Inspect** and does the same. The display filter above it still applies: applying a new filter on the Stats screen recounts them. While packets arrive, Stats updates by itself about once a second (less often when the window is large enough for counting to take a while), and the selection stays on its row as the ranking changes. `r` updates immediately.

The screen has five sections. Switch with `Tab` / `Shift+Tab`, `1`–`5`, or a click.

- **Overview** — a traffic chart, the five busiest addresses, the protocol mix and the TCP issues seen. Terminals narrower than 96 columns show the addresses and issues as one list.
- **IPs** — up to 50 addresses with their total, share, sent and received amounts. `u` switches between bytes and packets, and `d` cycles through sent plus received, sent, and received. Share is relative to all endpoint contributions for that metric and direction. A frame with both addresses contributes once to sent and once to received. If the address table fills, Stats shows the omitted amount.
- **Conversations** — the top 50 TCP/UDP conversations by wire bytes, for every address or for the one opened from Overview or IPs. `x` shows every address again.
- **Protocols** — packets and bytes per protocol, as named in the packet list. `u` switches the ranking.
- **Issues** — TCP retransmissions, out-of-order segments, duplicate ACKs, zero windows, keep-alives, fast retransmissions and resets, each with its count and first packet.

Move with the arrows, `j` / `k`, Page Up / Page Down, Home / End or the wheel. `Enter` or a click opens the selected row: an address opens its conversations, a conversation or protocol lists its packets, and an issue opens its first packet with the TCP sequence or window field highlighted. `p` lists the packets behind a row instead: all traffic of an address (including traffic outside its streams), or every packet with that issue. Backspace returns to the row a section was opened from.

Listing packets keeps the original display filter and excludes packets that arrived after Stats last updated, so the list matches the numbers you opened it from. Press `S` from the packet list to return to the same row and restore the original filter; Stats then catches up with any arrivals. Applying a filter of your own there ends the drill-down. Narrow terminals hide the less important columns first.

The CLI reads the whole file. `--rank-by bytes|packets` and `--direction both|sent|received` control the endpoint ranking. Defaults are `bytes` and `both`. The CLI and **Full report** (`f` in Stats) include:

- **Protocol hierarchy** — packets and bytes per network › transport › application path.
- **Conversations** — TCP and UDP conversations ranked by bytes, with per-direction packet/byte totals, duration, and TCP problem counts. The `#N` number is the `stream` filter value and the `follow --stream` argument.
- **Endpoints** — addresses ranked by the selected metric and direction, with sent and received counts.
- **TCP diagnostics** — totals of retransmissions, fast retransmissions, out-of-order segments, duplicate ACKs, zero windows, keep-alives and resets.
- **Response times** — minimum/average/maximum for DNS query→response, HTTP request→response and TCP SYN→SYN/ACK.
- **Traffic graph** — packets or bytes per interval. In the interface, `u` switches the unit and `+` / `-` change the interval (1 ms to 10 min); the same controls are clickable.

`packetread expert FILE` (and `E` in the interface) lists every anomaly by severity: malformed or truncated packets as errors, TCP retransmissions, gaps, zero windows and resets as warnings, duplicate ACKs, keep-alives and fast retransmissions as notes, each with its count and the first packet numbers.

All tables are bounded (50,000 conversations and endpoints, 10,000 graph intervals); anything beyond is counted as untracked.

## Streams, reassembly and TCP diagnostics

Packets are analyzed in capture order as they are read:

- **IP fragments** (IPv4 and IPv6) are collected, and the packet that completes a datagram is decoded from the rebuilt datagram: its Info starts with `[Reassembled N fragments]`, and its details and hex panes show the whole datagram. At most 256 incomplete datagrams of up to 65,535 bytes are kept.
- **Conversations** are numbered (`stream=N`). Up to 65,536 are tracked; beyond that, idle ones are forgotten and a resumed conversation gets a new number.
- **TCP diagnostics** flag, in the Info column and through `tcp.analysis`: `retransmission` (data at or below a sequence already seen), `fast-retransmission` (a retransmission that follows two or more duplicate ACKs for it), `out-of-order` (a segment ahead of the expected sequence, i.e. a gap or reordering; the late segment that fills the gap is not flagged), `dup-ack` (a repeated pure ACK while data is outstanding), `zero-window`, `keep-alive` (at most one byte, one below the next expected sequence) and `reset`.
- **Application messages that span TCP segments** — HTTP/1.x heads and `Content-Length` bodies, TLS records, DNS over TCP and SMB — are reassembled from in-order data. The packet that completes a message shows `[Reassembled N segments]` and the whole message in its details and hex panes. Messages over 60,000 bytes, chunked HTTP bodies, and data after a gap or retransmission are not reassembled; at most 64 MiB of incomplete messages are buffered across all conversations.

**Stream** (`F`) or `packetread follow FILE --stream N` reconstructs the selected conversation: TCP segments are ordered per direction, retransmitted bytes are dropped, and the result is shown as alternating client/server chunks, as text or a hex dump (`h` / `--hex`). Missing bytes are reported rather than guessed. UDP conversations show one chunk per datagram. This is separate from **Auto-scroll**, which only follows newly arriving packets. In the interface a followed stream is built from the retained packets (up to 4 MiB of payload).

### TLS decryption

```sh
SSLKEYLOGFILE=/tmp/keys.log curl https://example.com/      # browsers honor SSLKEYLOGFILE too
packetread --keylog /tmp/keys.log open traffic.pcap        # then F on a TLS packet
packetread --keylog /tmp/keys.log follow traffic.pcap --stream 0
```

With a key log (`--keylog`, the `K` dialog, or a profile), TLS is decrypted as packets are analyzed: the packet completing each record shows `[Decrypted TLS]` with the plaintext in its details and hex panes, decoded by the HTTP decoder when it is HTTP/1.x, so `proto=http`, `bytes contains` and the statistics see the cleartext. Following the stream shows the whole decrypted conversation. Loading a key log with `K` re-analyzes an open file; a live capture uses it from the next **Start**. Up to 4,096 TLS conversations are decrypted at a time. Supported: TLS 1.3 (including key updates) and TLS 1.2 with AES-GCM, ChaCha20-Poly1305 or AES-CBC suites (with or without encrypt-then-MAC). Decryption needs the session's secrets in the log and the handshake in the capture. Not supported: RC4 and 3DES suites, CBC before TLS 1.2, 0-RTT early data, and sessions whose handshake was not captured. Records that fail authentication are skipped and counted, never displayed. Key logs are secrets: keep them out of version control.

Sessions that used RSA key exchange (`TLS_RSA_…` suites) can instead be decrypted with the server's private key: `--tls-key server.pem` (unencrypted PEM, PKCS#8 or PKCS#1; repeatable). It does not help with Diffie-Hellman key exchange, which is what current servers negotiate; use a key log for those.

### Other decryption

All of these use keys you supply for your own traffic; without them the packets are shown as encrypted.

- **QUIC and HTTP/3.** Initial packets are protected only by keys derived from the connection ID, so the Client Hello (SNI, ALPN) and Server Hello are always shown. With a key log (`--keylog`, same file format as TLS) Handshake and 1-RTT packets are decrypted too and shown as `[Decrypted QUIC]` with their frames; HTTP/3 frames at the start of a stream are decoded, including QPACK header fields. Not handled: 0-RTT, key updates, connection migration to a different connection-ID length, and HTTP/3 messages that continue in later packets.
- **IPsec ESP.** `--esp-sa SPI:CIPHER:HEXKEY[:ICV]`, repeatable, e.g. `--esp-sa 0x1000:aes-gcm:<16 or 32 key bytes + 4 salt bytes>` or `--esp-sa 0x1001:aes-cbc:<key>:12` (the last number is the integrity value length in bytes, default 12; `null` is also accepted as a cipher). Tunnel and transport mode are decoded through to the inner packet, marked `[Decrypted ESP]`. AES-CBC integrity values are not verified; the padding is.
- **WPA2.** `--wpa-key "PASSPHRASE:SSID"`, repeatable, for 802.11 captures (with or without radiotap headers) that include the station's 4-way handshake. Unicast CCMP data frames are decrypted and shown as `[Decrypted WPA]`. Not handled: broadcast and multicast frames (group keys), TKIP, WPA3 and enterprise authentication.
- **Kerberos.** `--keytab FILE` loads the AES128 and AES256 keys of an MIT keytab; encrypted parts of Kerberos messages that one of them opens are listed in the details with the printable strings they contain.

## Investigation tools

- **Time column** (`T`): UTC time of day, seconds since the first retained packet, seconds since the previous displayed packet, or UTC date and time. `R` makes the selected packet the time reference: relative times then count from it (earlier packets are negative). `--time-shift SECONDS` (or `time_shift` in a profile) moves the displayed clock and date, for captures from a machine with a wrong clock.
- **Graphs** (`Y`, or `packetread graph FILE --stream N --kind sequence|throughput|window`): text charts of one TCP conversation, for the direction that carried more data: sequence number over time, payload bytes per second, and the advertised window.
- **Flow diagram** (`D`, or `packetread flow FILE [-f FILTER]`): one column per host (the first six) and one arrow per packet, with its ports, protocol and info.
- **VoIP** (`V`, or `packetread voip FILE`): SIP calls by Call-ID with their state, and RTP streams with packet loss and jitter. RTP is recognised on the ports that SIP session descriptions announce, or with `--decode-as udp:PORT=rtp`. Jitter assumes an 8 kHz media clock.
- **Host names** (`N`): shows names instead of addresses when a DNS answer in the capture resolved them. Packetread never performs lookups itself.
- **HTTP objects**: `packetread follow FILE --stream N --objects DIR` saves the message bodies of an HTTP/1.x stream (decrypted first when `--keylog` is given) as `streamN_object001.ext`, with the extension taken from the content type. File names never come from the traffic, existing files are not overwritten, and incomplete bodies are skipped.
- **Find** (`f`): search packet bytes for text (case-insensitive) or `hex:de:ad:be:ef`. `F3` / `.` and `,` jump to the next and previous match and wrap around. In a file, a forward search continues past the loaded window through the rest of the capture.
- **Mark** (`m`) and **comment** (`c`): marked packets show `*`, commented ones `#`; the comment appears at the top of the protocol details and is saved in PCAPNG exports (and loaded from PCAPNG files). Filter with `marked`, `comment`, or `comment~"text"`. Up to 10,000 annotations survive file-window changes; a new session clears them.
- **Profiles**: `P` saves the theme, display filter, pane layout, memory limits and key-log path to `~/.config/packetread/profiles/NAME.conf` (honoring `XDG_CONFIG_HOME`). `--profile NAME` loads one at startup; `default` is loaded automatically when it exists. Command-line options override the profile. Profiles are plain `key = value` files: `theme`, `filter`, `memory`, `max_packets`, `table_percent`, `details_percent`, `keylog`, `time_shift`, and the presentation lines below.
- **Coloring rules, columns and filter buttons** live in the profile, one per line:

  ```text
  color = red tcp.analysis=any          # red, green, yellow, cyan, purple or muted, then a display filter
  color = green proto=dns
  column = Host http.host               # a title and a named field, shown before INFO (up to 4)
  button = Web proto=http or proto=tls  # a label and a display filter (up to 8)
  ```

  The first coloring rule that matches colors a packet's row. Buttons appear in the filter bar and on `F5`–`F12`. Names are single words of up to 12 letters, digits, `-` or `_`.

## Navigating large files

A saved capture is loaded one bounded window at a time. **Next** (`n`) continues with the following window, **Prev** (`p`) returns to earlier ones, and `:` jumps to a packet number, reloading the window there. Find continues across windows. Moving backwards re-reads the file from the start (so reassembly and stream numbers stay exact) without keeping the skipped packets in memory, which takes time proportional to the file position.

## Custom decoders

A decoder file describes a fixed-layout protocol carried over UDP or TCP on a known port. It is offered every payload that no built-in decoder claimed:

```text
# telemetry.decoder
name = Telemetry
udp.port = 9999          # or tcp.port
field = Version u8
field = Flags u16 hex
field = Sequence u32le
field = Device str:8
field = Token bytes:4
```

```sh
packetread --decoder telemetry.decoder open traffic.pcap
```

Field types are `u8`, `u16`, `u32`, `u64` (big endian; append `le` for little endian, add `hex` to print hexadecimal), `bytes:N` and `str:N`. Matching packets show protocol `EXT` (`proto=ext`), the decoder name and first fields in Info, and every field with its byte range in the details pane. Payloads shorter than the declared fields are not claimed. `--decoder` may be repeated.

A decoder that needs logic can be a Lua script; `--decoder` treats files ending in `.lua` as scripts:

```lua
-- greeter.lua
name = "Greeter"
transport = "udp"        -- or "tcp"; leave out for both
ports = { 12001 }        -- leave out to be offered every undecoded payload
function decode(payload, src_port, dst_port)
  if #payload < 2 then return nil end           -- nil: not this protocol
  return {
    info = "greeting " .. payload,
    fields = { { label = "Length: " .. #payload, offset = 0, length = #payload } },
  }
end
```

A script is code you choose to run, so only load scripts you trust. It runs in a sandbox with Lua's string, table and math libraries: there is no access to files, processes, modules or the terminal. Each call is limited to about two million instructions and the interpreter to 16 MiB, so a runaway script produces no decode instead of freezing the program; long-running library calls on very large strings are not interrupted. Text a script returns is sanitized like any packet text.

Programs using the `packetread` library can also implement the `decode::Extension` trait and call `decode::register`.

## Supported captures and limits

- Standard PCAP 2.4 (both byte orders, microsecond or nanosecond timestamps), PCAPNG 1.0/1.2 packet blocks, and snoop (RFC 1761) Ethernet captures. Any of them may be gzip-compressed; decompression is streamed and bounded like other input. Zstandard and other compression, and older/modified PCAP dialects, are rejected. PCAPNG interface link types, timestamps and packet comments are retained; `summary` also prints the section's hardware, operating system and application, each interface's name and description, and the host names of name-resolution blocks.
- `packetread merge -o OUT.pcapng A.pcap B.pcapng …` writes up to 64 captures into one new file in time order (use `.pcapng` when link types differ). To cut a slice out of a capture, export with a filter: `export FILE -o part.pcap -f "id=1000-2000"` or `-f "time=1700000000-1700000060"`.
- Saved captures must be regular files. Named pipes, devices, and directories are rejected, including symlinks pointing to them. On Unix, the opened descriptor is checked without blocking on a pipe or reopening the path.
- Ethernet/VLAN (including 802.3 frames with LLC/SNAP), raw IP, BSD loopback, Linux cooked SLL/SLL2; ARP, IPv4/IPv6, TCP, UDP, ICMP. Unknown link types retain raw bytes.
- Other link layers: 802.11 with or without radiotap (frame types, addresses, SSID, rate, channel and signal; data frames are decoded when unencrypted or [decrypted](#other-decryption)), PPP and PPPoE, MPLS label stacks, Bluetooth HCI (commands, events, ACL data with L2CAP and attribute-protocol opcodes), USB (Linux usbmon and USBPcap headers, control requests), CAN (SocketCAN), and 802.15.4 with the Zigbee network header. These show headers and message names, not every field of the protocols above them.
- Spanning tree BPDUs, EAPOL (including the WPA handshake messages), IPsec ESP and AH headers, and OSPF headers.
- IPv4 header checksums and TCP/UDP checksums are verified in the details pane (an "incorrect" TCP/UDP checksum on locally captured traffic usually means the network card computes it). TCP options (MSS, window scale, SACK, timestamps) and ICMP/ICMPv6 message names, including neighbour discovery targets, are shown.
- GRE and VXLAN tunnels are decoded through to the inner packet (up to four levels); addresses, ports and the protocol are those of the inner packet.
- Application protocols: DNS over UDP and TCP (questions and answer records), mDNS and LLMNR, HTTP/1.x start line and headers, TLS records and cleartext handshake messages (version, SNI, ALPN, cipher suite), QUIC long headers (version, packet type, connection IDs; payloads stay encrypted), DHCPv4 (message type and common options), SMB (SMB2/3 header fields, SMB1 command), NTP, MQTT packet types, IGMP, LLDP, SSH banners, SIP, and the command/reply lines of FTP, SMTP, POP3 and IMAP. Also HTTP/2 frames with HPACK header fields (and gRPC messages on it), WebSocket frames, Kerberos message types with realms and principals, LDAP operations, SNMP v1/v2c requests with their object identifiers, RDP connection setup, ONC RPC with NFSv3, mount and portmap procedure names, MySQL and PostgreSQL messages with their SQL text, BGP messages with announced IPv4 prefixes, RIP, RTP and RTCP. HTTP/2 is recognised by its connection preface and then for the rest of that conversation; WebSocket after an HTTP upgrade; HPACK and QPACK entries that refer to the connection's dynamic table are shown as placeholders. HTTP, TLS, SMB, SSH banners and SIP are recognised by content; the others by port plus a successful parse. Guesses that cannot be validated (a QUIC short header on UDP 443, encrypted SSH on port 22) are labelled as assumed from the port.
- `--decode-as tcp:8025=smtp` (or `udp:5300=dns`, or a port number as the target) applies a port-bound decoder to another port; it may be repeated.
- Truncated and malformed packets are annotated.
- Default retention is 256 MiB and 100,000 packets, adjustable with `--memory` and `--max-packets`. Storage accounting is an estimate; process/library/allocator overhead is additional. Captured packet size is limited to 256 KiB.
- Both `open` and `summary` use a bounded Rust file reader: a fixed approximately 1 MiB input buffer, at most 1,024 interfaces per PCAPNG section, and at most 1 MiB per block. Oversized metadata or packets are rejected; these safety limits cannot be raised with `--memory`. Cancellation is checked between metadata blocks as well as packets. Libpcap is used only by the `packetread-capture` helper, for live capture and interface listing; `packetread` itself does not link it.
- Live sessions evict the oldest retained packets. Queue overload discards incoming batches and increments **app drops**. **OS drops** are libpcap-reported statistics, or `n/a` when unavailable. Evictions are a separate counter.
- Offline loading pauses when retention fills. **Next** discards the current window and continues reading; **Prev**, go-to and Find reload earlier or later windows (see [Navigating large files](#navigating-large-files)). `summary`, `stats`, `export` and `follow` process the whole file with bounded state (`follow` keeps up to 64 MiB of one conversation).
- Capture uses one worker thread (plus the helper process when live), while the main thread handles bounded ingestion, incremental filtering, and rendering at up to 30 FPS. Performance targets still require measurement.

## Development and tests

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
python3 -m unittest discover -s tests -p 'test_release.py'
python3 tests/fixtures/generate.py          # deterministic fixtures
python3 tests/fixtures/generate.py --tls    # also new TLS sessions (tls.pcap + tls.keys change)
python3 tests/fixtures/generate.py --tls-rsa  # RSA key exchange and CBC sessions (tls-rsa.*)
python3 tests/fixtures/generate.py --crypto   # QUIC, ESP, WPA and Kerberos (needs the cryptography package)
```

Tests cover protocol decoding (including the application protocols and custom decoder files), display-filter parsing and matching, fragment and message reassembly, TCP diagnostics, expert information, tunnels, checksums, Decode As, stream following, HTTP object extraction, headless capture, TLS 1.2/1.3 decryption against real handshakes, statistics, export formats, capture-file rotation and stop limits through a scripted capture helper, file-window navigation and search, truncated/random headers, DNS compression cycles, filtering, bounded retention, queue overload/cancellation, PCAP/PCAPNG ingestion, CLI summaries, and TUI mouse/layout behavior. Security regressions cover terminal control sequences in filenames, oversized packets/blocks, excessive interface metadata, and nonblocking rejection of pipes and devices. File-reader compatibility tests cover both byte orders, timestamp resolutions, empty captures, truncated inputs, and the original libpcap results. The later additions are covered too: the long tail of protocols and link layers, named-field filters, QUIC/HTTP/3, ESP, WPA2 and Kerberos decryption, TLS CBC suites and RSA key exchange, Lua decoders and their sandbox, gzip and snoop input, PCAPNG metadata, merging, remote capture through a stand-in for `ssh`, graphs, flow diagrams, VoIP statistics, and the presentation settings; one test truncates and corrupts every fixture packet to check that nothing panics. Fixtures contain only generated traffic using documentation addresses (`tls.keys`, `tls-rsa.keys`, `tls-rsa.key`, `quic.keys` and `kerberos.keytab` hold made-up keys for throwaway sessions that protect nothing); tests require no live capture privileges or network access after dependencies are installed.

`src/source.rs` owns the capture worker, `src/bin/packetread-capture.rs` is the privileged helper and `src/helper.rs` its frame protocol, `src/offline/` bounds and reads saved files, `src/decode/` parses packets (one file per protocol), `src/analysis.rs` reassembles fragments and tracks conversations, `src/follow.rs` and `src/tls.rs` reconstruct and decrypt streams, `src/crypto.rs` holds user-supplied keys and the ESP, WPA and Kerberos primitives, `src/stats.rs`, `src/graph.rs` and `src/export.rs` produce statistics, charts and files, `src/ingest.rs` moves packets from the worker into the session and decides live-versus-file retention, `src/session.rs` owns retention and selection, `src/filter.rs` handles predicates, and `src/tui/` owns rendering and input. CLI errors and interface listings sanitize terminal control characters, as does the TUI. Keep packet captures containing real traffic out of version control.
