#!/bin/sh
# Install the latest Packetread release into /usr/local/bin and allow live capture.
set -eu

repo=s-a-tanjim/packetread
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) target=x86_64-unknown-linux-gnu ;;
  Linux-aarch64 | Linux-arm64) target=aarch64-unknown-linux-gnu ;;
  *) echo "No prebuilt Packetread for $(uname -sm); build from source instead." >&2; exit 1 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
cd "$work"

urls="$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" |
  sed -n 's/.*"browser_download_url": *"\([^"]*\)".*/\1/p')"
archive_url="$(printf '%s\n' "$urls" | grep -- "-$target.tar.gz\$")"
sums_url="$(printf '%s\n' "$urls" | grep '/SHA256SUMS$')"

curl -fsSLO "$archive_url"
curl -fsSLO "$sums_url"
sha256sum --check --ignore-missing --quiet SHA256SUMS
tar -xzf ./*.tar.gz

# The capture helper needs the libpcap runtime, and setcap comes from libcap2-bin.
if command -v apt-get >/dev/null; then
  sudo apt-get install -y libpcap0.8t64 libcap2-bin || sudo apt-get install -y libpcap0.8 libcap2-bin
fi
sudo install -m755 packetread-*/packetread packetread-*/packetread-capture /usr/local/bin/
sudo setcap cap_net_raw=ep /usr/local/bin/packetread-capture

/usr/local/bin/packetread --version
echo "Installed. Run: packetread"
