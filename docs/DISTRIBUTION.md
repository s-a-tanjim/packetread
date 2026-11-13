# Distribution and releases

## Supported downloads

GitHub Releases provides separate Linux archives for these architectures:

| CPU | Rust target / archive suffix | Native CI runner |
| --- | --- | --- |
| Intel / AMD 64-bit | `x86_64-unknown-linux-gnu` | `ubuntu-24.04` |
| ARM 64-bit | `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |

Both builds run the test suite on their native CPU using [GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). This includes ARM64 Linux machines such as Raspberry Pi devices running a compatible 64-bit OS. 32-bit ARM, macOS, Windows, and Alpine/musl are not release targets yet. The `portability` CI job builds and tests macOS (Apple silicon) and Windows (with the Npcap SDK) without packaging them; build from source there (see `README.md`).

The release baseline is Ubuntu 24.04: glibc 2.39 or newer and the libpcap runtime (`libpcap.so.0.8`). Other distributions with compatible libraries may work, but the pipeline only tests the Ubuntu runner images. Build from source for older distributions. libpcap is dynamically linked and is not bundled in the archives.

## Install a prebuilt release

Run `uname -m` to choose the architecture. Download its `.tar.gz` archive and `SHA256SUMS` from the repository's **Releases** page. For version 0.1.0 on x86-64:

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf packetread-0.1.0-x86_64-unknown-linux-gnu.tar.gz
sudo apt-get install libpcap0.8t64 libcap2-bin
sudo install -m755 packetread-0.1.0-x86_64-unknown-linux-gnu/packetread /usr/local/bin/packetread
sudo install -m755 packetread-0.1.0-x86_64-unknown-linux-gnu/packetread-capture /usr/local/bin/packetread-capture
packetread --version
```

Replace `x86_64` with `aarch64` for ARM64. The `apt-get` packages above apply to Ubuntu 24.04; other distributions use their own libpcap package names. Prebuilt binaries need the runtime package, while building from source requires `libpcap-dev` and `pkg-config`. Building also needs a C compiler for the bundled Lua interpreter. Remote capture (`capture --remote`) uses the system `ssh` client.

Install both programs in the same directory. `packetread` is the application; `packetread-capture` is the small capture helper it starts for live traffic. For live capture, grant the capability to the **installed helper** only:

```sh
sudo setcap cap_net_raw=ep /usr/local/bin/packetread-capture
getcap /usr/local/bin/packetread-capture
packetread
```

The application itself never needs capture privileges and does not link libpcap; only the helper needs the libpcap runtime. Saved-file inspection requires no capture capability and no helper. File capabilities are not shipped in the archive: reapply them after replacing the installed binary during an upgrade. Each archive contains executable permissions, installation instructions, `Cargo.lock`, and `BUILD-INFO.txt` with the compiler, platform libraries, target, and source commit.

## CI and publishing

[The workflow](../.github/workflows/ci.yml) runs on branch pushes, pull requests, version-tag pushes, and manual dispatches. It:

1. Checks formatting, package/lockfile version consistency, and the release-version tests.
2. Installs libpcap development files, runs Clippy and Rust tests, and builds with `--locked` on each architecture.
3. Packages the application and capture helper, unpacks them, checks executable permissions/version, and reads both synthetic PCAP fixtures with the unpacked program.
4. Uploads archives and individual SHA-256 files as Actions artifacts, retained for 14 days.
5. On a pushed `v*` tag, verifies both downloads and publishes the two archives plus a combined `SHA256SUMS` to GitHub Releases.

Only the release job receives `contents: write`; branch and pull-request builds cannot publish. The built-in `GITHUB_TOKEN` is sufficient, with no personal access token needed. Third-party Actions are pinned to commits. The Rust compiler tracks the stable channel; `Cargo.lock` fixes dependency versions, but this is not a bit-for-bit reproducible-build guarantee.

To publish, first commit the project, including `.github/`, scripts, tests, fixtures, and `Cargo.lock`, to a GitHub repository with Actions enabled. For the current package version:

```sh
git tag -a v0.1.0 -m 'Release v0.1.0'
git push origin v0.1.0
```

For subsequent releases, update `package.version` in `Cargo.toml`, run `cargo check` to update the root package entry in `Cargo.lock`, and commit both before tagging. The tag must exactly equal `v` plus the manifest version; mismatches fail before building. A version such as `0.2.0-rc.1` produces a GitHub prerelease.

Manual dispatch builds downloadable artifacts without publishing. Existing published releases are not overwritten. If an upload fails after creating a draft, inspect/delete that incomplete draft before rerunning the release job. Automatically generated release notes accompany the assets. GitHub CLI documents the [release creation and upload behavior](https://cli.github.com/manual/gh_release_create).

## Reproduce packaging locally

On a native Linux machine with Rust, Python 3.11+, libpcap development files, and GNU tar/coreutils:

```sh
cargo build --locked --release --target x86_64-unknown-linux-gnu
bash scripts/package-release.sh x86_64-unknown-linux-gnu
python3 -m unittest discover -s tests -p 'test_release.py'
```

Use `aarch64-unknown-linux-gnu` on an ARM64 machine. The script rejects mismatched host/target architectures and stale manifest/lockfile versions. Files are written to the ignored `dist/` directory. Local packages use the local system's glibc/libpcap versions, recorded in `BUILD-INFO.txt`; the Ubuntu 24.04 baseline applies to GitHub runner builds.
