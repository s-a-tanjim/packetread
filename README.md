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
```

## Use

```sh
packetread                          # open the interface, then click Open or Interfaces
packetread open traffic.pcap        # inspect a saved capture
packetread capture -i eth0          # capture live traffic
packetread summary traffic.pcap     # print a summary without the interface
```

Press `?` for help and `q` to quit. Run `packetread --help` for every command.

More: [full usage reference](docs/USAGE.md) · [installation and releases](docs/DISTRIBUTION.md)
