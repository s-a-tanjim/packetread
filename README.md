# Packetread

A Rust terminal packet inspector with a colorful, btop-inspired interface and mouse controls. Inspect saved captures or capture live traffic in a packet table, expandable protocol tree, and synchronized hex/ASCII view.

## Prebuilt downloads and releases

The GitHub Actions pipeline builds and tests Linux **x86-64** and **ARM64** packages. Branches and pull requests produce downloadable Actions artifacts; pushing a version tag such as `v0.1.0` publishes both archives and SHA-256 checksums to GitHub Releases after the checks pass.

Release binaries target Ubuntu 24.04 or compatible systems with glibc 2.39+ and the libpcap runtime. See [installation and release instructions](docs/DISTRIBUTION.md) for architecture selection, runtime dependencies, capture permissions, and tagging a release.

## Build and run

Install a current stable Rust toolchain and the libpcap development package. On Ubuntu/Debian:

```sh
sudo apt-get install build-essential pkg-config libpcap-dev
cargo build --release
./target/release/packetread
```

If linking fails with `unable to find library -lpcap`, install `libpcap-dev` and `pkg-config`, then rerun `cargo build --release`. The runtime library installed with Wireshark is not sufficient: the linker also needs the development package's `libpcap.so` file.

Opening the application without a subcommand shows the interface with clickable **Open** and **Interfaces** controls. Try the included synthetic capture without capture privileges:

```sh
cargo run --release -- open tests/fixtures/demo.pcap
cargo run --release -- open tests/fixtures/demo.pcapng
cargo run --release -- summary tests/fixtures/demo.pcap
cargo run --release -- interfaces
cargo run --release -- capture -i eth0 --capture-filter 'tcp port 443'
```

Live capture requires Linux capture permissions. An administrator can grant the built binary `CAP_NET_RAW` when appropriate:

```sh
sudo setcap cap_net_raw=ep target/release/packetread
./target/release/packetread capture -i eth0
```

If the TUI reports `CAP_NET_RAW may be required`, quit it, run the `setcap` command above, and restart the same binary. Verify the setting with `getcap target/release/packetread`; it should show `cap_net_raw=ep`. Membership in the `wireshark` group does not automatically grant capture permissions to this executable.

Rebuilding replaces that binary and may remove its capabilities, so apply `setcap` after building and launch `./target/release/packetread` directly. An already-running process does not gain the new capability; it must be restarted. Offline inspection requires no elevated privileges. Promiscuous mode is opt-in with `--promiscuous`.

## Colorful and mouse accessible

The interface includes colored protocol labels, live packet/byte-rate graphs, capture status, separate drop counters, and memory usage. It uses three panes on wide terminals and clickable tabs on narrow terminals. Minimum size: 60 columns × 22 rows.

- Click toolbar controls to open files, choose interfaces, start/stop, toggle follow, advance file windows, change themes, or open help.
- Click a packet to inspect it. Click a protocol heading to expand/collapse it or a field to highlight its bytes.
- Scroll the pane under the pointer. Drag scrollbars to navigate and dividers to resize panes.
- Click the display filter, type a query, and click **Apply**. File paths and capture filters also have mouse-accessible dialogs.

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
| `/`, Enter | Edit/apply the display filter |
| Space | Toggle following new packets; capture continues |
| `o`, `i`, `b` | Open file, interfaces, capture-filter dialog |
| `r`, `s`, `n` | Start a new session, stop capture, next file window |
| `t`, `?`, `q` | Theme, help, quit |
| Escape, Ctrl+C | Close editor/dialog, quit |

Starting or opening a new source clears the current in-memory session. Stopping leaves retained packets available for inspection.

## Filters

Capture filters use libpcap BPF, supplied through `--capture-filter` or the **BPF** dialog. Dialog changes take effect at the next **Start**.

Display filters are a deliberately small language. Whitespace joins predicates with AND:

```text
proto=tcp port=443
proto=dns addr=192.0.2.10
src=2001:db8::1
dst=198.51.100.8 port=53
```

Supported fields: `proto`, `addr`, `src`, `dst`, `port`. `addr` and `port` match either endpoint. Protocols: `tcp`, `udp`, `dns`, `arp`, `icmp`, `ipv4`, `ipv6`, `unknown`. DNS over UDP also matches `proto=udp`; IP filters match packets carrying that IP version. Empty input shows all retained packets. Invalid input leaves the previous filter active. Wireshark display-filter syntax is not supported.

## Supported captures and limits

- Standard PCAP 2.4 (both byte orders, microsecond or nanosecond timestamps) and PCAPNG 1.0/1.2 packet blocks. Older/modified PCAP dialects are rejected. PCAPNG interface link types and timestamps are retained for decoding; other metadata is not retained.
- Saved captures must be regular files. Named pipes, devices, and directories are rejected, including symlinks pointing to them. On Unix, the opened descriptor is checked without blocking on a pipe or reopening the path.
- Ethernet/VLAN, raw IP, Linux cooked SLL/SLL2; ARP, IPv4/IPv6, TCP, UDP, ICMP, and basic DNS-over-UDP questions/header inspection. Unknown link types retain raw bytes.
- Truncated and malformed packets are annotated. Fragment reassembly, TCP stream reconstruction, decryption, and comprehensive application-protocol decoding are not implemented.
- Default retention is 256 MiB and 100,000 packets, adjustable with `--memory` and `--max-packets`. Storage accounting is an estimate; process/library/allocator overhead is additional. Captured packet size is limited to 256 KiB.
- Both `open` and `summary` use a bounded Rust file reader: a fixed approximately 1 MiB input buffer, at most 1,024 interfaces per PCAPNG section, and at most 1 MiB per block. Oversized metadata or packets are rejected; these safety limits cannot be raised with `--memory`. Cancellation is checked between metadata blocks as well as packets. Libpcap is used for live capture, not for reading saved files.
- Live sessions evict the oldest retained packets. Queue overload discards incoming batches and increments **app drops**. **OS drops** are libpcap-reported statistics, or `n/a` when unavailable. Evictions are a separate counter.
- Offline loading pauses when retention fills. **Next** discards the current window and continues reading. Full-file random access is not implemented. `summary` processes the whole file using bounded protocol counters.
- Capture uses one worker, while the main thread handles bounded ingestion, incremental filtering, and rendering at up to 30 FPS. Performance targets in [the plan](docs/PLAN.md) still require measurement.

## Development and tests

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
python3 -m unittest discover -s tests -p 'test_release.py'
python3 tests/fixtures/generate.py
```

Tests cover protocol decoding, truncated/random headers, DNS compression cycles, filtering, bounded retention, queue overload/cancellation, PCAP/PCAPNG ingestion, CLI summaries, and TUI mouse/layout behavior. Security regressions cover terminal control sequences in filenames, oversized packets/blocks, excessive interface metadata, and nonblocking rejection of pipes and devices. File-reader compatibility tests cover both byte orders, timestamp resolutions, empty captures, truncated inputs, and the original libpcap results. Fixtures contain only generated traffic using documentation addresses; tests require no live capture privileges or network access after dependencies are installed.

`src/source.rs` owns capture, `src/offline/` bounds and reads saved files, `src/decode/` parses packets, `src/session.rs` owns retention and selection, `src/filter.rs` handles predicates, and `src/tui/` owns rendering and input. CLI errors and interface listings sanitize terminal control characters, as does the TUI. Keep packet captures containing real traffic out of version control.
