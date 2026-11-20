# Packetread

A terminal packet inspector: packet table, protocol tree and hex view, with mouse support.

![Packetread demo](docs/assets/demo.gif)

## Download

On Linux (x86-64 or ARM64, Ubuntu 24.04 or compatible), install the latest [release](https://github.com/s-a-tanjim/packetread/releases) with one command:

```sh
curl -fsSL https://raw.githubusercontent.com/s-a-tanjim/packetread/master/scripts/install.sh | sh
```

It verifies the download, installs into `/usr/local/bin` and enables live capture; it asks for your `sudo` password.

Or build from source (needs Rust, `build-essential`, `pkg-config` and `libpcap-dev`):

```sh
git clone https://github.com/s-a-tanjim/packetread.git
cd packetread
cargo build --release
./target/release/packetread open tests/fixtures/demo.pcap
```

That opens a sample capture from the repository. The build is not on your `PATH`, so either keep the `./target/release/` prefix on the commands below or copy `packetread` and `packetread-capture` from `target/release/` into a directory that is. Live capture also needs a one-time `sudo setcap cap_net_raw=ep target/release/packetread-capture`, repeated after each rebuild.

## Use

```sh
packetread                          # open the interface, then click Open or Interfaces
packetread open traffic.pcap        # inspect a saved capture
packetread capture -i eth0          # capture live traffic
packetread summary traffic.pcap     # print a summary without the interface
packetread stats traffic.pcap --rank-by packets --direction received --top 10
```

Press `S` for the Stats tab: busiest addresses, conversations, protocols and TCP issues. Open an address to see its conversations, then a stream to inspect its packets; `S` brings you back.

Press `?` for help and `q` to quit. Run `packetread --help` for every command.

More: [full usage reference](docs/USAGE.md) · [installation and releases](docs/DISTRIBUTION.md)
