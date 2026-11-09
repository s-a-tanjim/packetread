# Recording the README demo

The demo starts with `packetread`, then opens `tests/fixtures/demo.pcap` through
the application's Open dialog. The capture contains only synthetic traffic using
documentation addresses. It shows packet navigation,
protocol fields and their highlighted bytes, DNS and TCP display filters, keyboard
help, and a command-line summary. No network access or capture privileges are
needed to record it after the tools and Rust dependencies are installed.

## Prerequisites

- Linux or macOS with Python 3 and the project's Rust/libpcap build prerequisites.
- [asciinema 3](https://docs.asciinema.org/manual/cli/installation/) on `PATH`.
- [agg 1.9 or newer](https://docs.asciinema.org/manual/agg/installation/) on `PATH`.
- The DejaVu Sans Mono font (Ubuntu/Debian package `fonts-dejavu-core`).

The checked-in assets were generated with asciinema 3.2.1 and agg 1.9.0.

## Regenerate

From the repository root:

```sh
python3 scripts/record-demo.py
```

The script builds the release binary, drives the actual interface in a fixed
140 × 44 terminal, and overwrites `docs/assets/demo.cast` and
`docs/assets/demo.gif`. It uses an isolated asciinema configuration and records
only terminal output plus the `TERM` and `COLORTERM` environment values. It does
not upload the recording. The GIF is embedded directly in the README so it plays
on GitHub without an external hosting service.

Replay the original recording locally in a terminal at least 140 × 44:

```sh
asciinema play docs/assets/demo.cast
```

To render the GIF again without recording:

```sh
agg --font-family 'DejaVu Sans Mono' --font-size 14 --line-height 1.2 \
  --theme github-dark --fps-cap 12 --last-frame-duration 2 \
  docs/assets/demo.cast docs/assets/demo.gif
```
