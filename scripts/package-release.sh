#!/usr/bin/env bash
# Package a native release build and verify the unpacked executable.
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
target="${1:?Usage: bash scripts/package-release.sh RUST_TARGET}"
case "$target" in
  x86_64-unknown-linux-gnu) expected_machine=x86_64 ;;
  aarch64-unknown-linux-gnu) expected_machine=aarch64 ;;
  *) printf 'Unsupported release target: %s\n' "$target" >&2; exit 1 ;;
esac
if [[ "$(uname -s)" != Linux || "$(uname -m)" != "$expected_machine" ]]; then
  printf 'Build and test %s on a native Linux %s runner.\n' "$target" "$expected_machine" >&2
  exit 1
fi

version="$(python3 scripts/release-version.py)"
binary="target/${target}/release/packetread"
helper="target/${target}/release/packetread-capture"
test -x "$binary"
test -x "$helper"
test "$("$binary" --version)" = "packetread ${version}"
stem="packetread-${version}-${target}"
stage_dir="$(mktemp -d)"
trap 'rm -rf -- "$stage_dir"' EXIT
mkdir -p "$stage_dir/$stem" dist
mkdir "$stage_dir/$stem/docs"
install -m755 "$binary" "$stage_dir/$stem/packetread"
install -m755 "$helper" "$stage_dir/$stem/packetread-capture"
install -m644 README.md Cargo.lock "$stage_dir/$stem/"
install -m644 docs/DISTRIBUTION.md "$stage_dir/$stem/INSTALL.md"
install -m644 docs/DISTRIBUTION.md "$stage_dir/$stem/docs/"
for license in LICENSE LICENSE.* NOTICE NOTICE.*; do
  if [[ -f "$license" ]]; then
    install -m644 "$license" "$stage_dir/$stem/"
  fi
done
{
  printf 'Package: packetread\nVersion: %s\nTarget: %s\n' "$version" "$target"
  printf 'Commit: %s\n' "${GITHUB_SHA:-local-build}"
  rustc --version
  cargo --version
  getconf GNU_LIBC_VERSION
  printf 'libpcap: %s\n' "$(pkg-config --modversion libpcap)"
} > "$stage_dir/$stem/BUILD-INFO.txt"

tar --sort=name --owner=0 --group=0 --numeric-owner \
  --mtime="@${SOURCE_DATE_EPOCH:-0}" \
  -czf "dist/${stem}.tar.gz" -C "$stage_dir" "$stem"
(
  cd dist
  sha256sum "${stem}.tar.gz" > "${stem}.tar.gz.sha256"
  sha256sum --check "${stem}.tar.gz.sha256"
)

# Test what users download, including executable permissions and dynamic linking.
mkdir "$stage_dir/unpacked"
tar -xzf "dist/${stem}.tar.gz" -C "$stage_dir/unpacked"
unpacked="$stage_dir/unpacked/$stem/packetread"
test -x "$unpacked"
test -x "$stage_dir/unpacked/$stem/packetread-capture"
test "$("$unpacked" --version)" = "packetread ${version}"
for fixture in tests/fixtures/demo.pcap tests/fixtures/demo.pcapng; do
  summary="$("$unpacked" summary "$fixture")"
  if [[ "${summary%%$'\n'*}" != 'Packets: 11' ]]; then
    printf 'Packaged binary failed capture smoke test: %s\n' "$fixture" >&2
    exit 1
  fi
done
printf 'Verified release archive: dist/%s.tar.gz\n' "$stem"
