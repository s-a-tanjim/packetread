# Packetread

A terminal packet inspector: packet table, protocol tree and hex view, with mouse support.

![Packetread demo](docs/assets/demo.gif)

## Download

Prebuilt Linux binaries (x86-64 and ARM64, Ubuntu 24.04 or compatible) are on the [GitHub Releases page](https://github.com/s-a-tanjim/packetread/releases). Download the archive for your CPU (`uname -m`), then:

```sh
tar -xzf packetread-*-x86_64-unknown-linux-gnu.tar.gz
sudo apt-get install libpcap0.8t64 libcap2-bin
sudo install -m755 packetread-*/packetread packetread-*/packetread-capture /usr/local/bin/
sudo setcap cap_net_raw=ep /usr/local/bin/packetread-capture   # only needed for live capture
```

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
