"""Validate release versions and package archives without local-only files."""
import importlib.util
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release-version.py"
SPEC = importlib.util.spec_from_file_location("release_version", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseVersionTests(unittest.TestCase):
    def inputs(self, version="0.1.0"):
        package = {"name": "packetread", "version": version}
        return {"package": package}, {"package": [dict(package)]}

    def test_matching_tag_can_publish(self):
        self.assertEqual(MODULE.release_version(*self.inputs(), "tag", "v0.1.0"), "0.1.0")

    def test_wrong_tag_cannot_publish(self):
        with self.assertRaisesRegex(ValueError, "must match"):
            MODULE.release_version(*self.inputs(), "tag", "v9.0.0")

    def test_stale_lockfile_cannot_publish(self):
        manifest, lock = self.inputs()
        lock["package"][0]["version"] = "0.0.9"
        with self.assertRaisesRegex(ValueError, "Cargo.lock"):
            MODULE.release_version(manifest, lock, "tag", "v0.1.0")

    def test_branch_and_prerelease_versions(self):
        self.assertEqual(MODULE.release_version(*self.inputs(), "branch", "feature/packages"), "0.1.0")
        self.assertEqual(MODULE.release_version(*self.inputs("0.2.0-rc.1"), "tag", "v0.2.0-rc.1"), "0.2.0-rc.1")


@unittest.skipUnless(
    platform.system() == "Linux" and platform.machine() in ("x86_64", "aarch64"),
    "Release archives require a supported native Linux host",
)
class ReleasePackagingTests(unittest.TestCase):
    def test_archive_builds_without_local_plan(self):
        target = f"{platform.machine()}-unknown-linux-gnu"
        version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
        with tempfile.TemporaryDirectory(prefix="packetread-package-test-") as directory:
            root = Path(directory)
            for name in (
                "Cargo.toml", "Cargo.lock", "README.md", "docs/DISTRIBUTION.md",
                "scripts/release-version.py", "scripts/package-release.sh",
                "tests/fixtures/demo.pcap", "tests/fixtures/demo.pcapng",
            ):
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, destination)

            # Exercise the real packaging script without compiling Rust or
            # requiring libpcap in the formatting/release-metadata CI job.
            binary = root / "target" / target / "release/packetread"
            binary.parent.mkdir(parents=True)
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "if sys.argv[1:] == ['--version']:\n"
                f"    print('packetread ' + {version!r})\n"
                "elif len(sys.argv) == 3 and sys.argv[1] == 'summary':\n"
                "    print('Packets: 11')\n"
                "else:\n"
                "    sys.exit(1)\n"
            )
            binary.chmod(0o755)
            helper = binary.with_name("packetread-capture")
            helper.write_text("#!/bin/sh\nexit 1\n")
            helper.chmod(0o755)
            metadata_tools = root / "metadata-tools"
            metadata_tools.mkdir()
            for tool in ("rustc", "cargo", "pkg-config"):
                executable = metadata_tools / tool
                executable.write_text("#!/bin/sh\nprintf '%s\\n' 'test-version'\n")
                executable.chmod(0o755)

            result = subprocess.run(
                ["bash", "scripts/package-release.sh", target],
                cwd=root,
                env={
                    **os.environ,
                    "PATH": f"{metadata_tools}{os.pathsep}{os.environ['PATH']}",
                    "GITHUB_REF_TYPE": "branch",
                    "GITHUB_REF_NAME": "packaging-test",
                    "SOURCE_DATE_EPOCH": "1700000000",
                },
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            stem = f"packetread-{version}-{target}"
            archive = root / "dist" / f"{stem}.tar.gz"
            with tarfile.open(archive) as package:
                self.assertIn(f"{stem}/docs/DISTRIBUTION.md", package.getnames())
                self.assertIn(f"{stem}/INSTALL.md", package.getnames())
                self.assertTrue(package.getmember(f"{stem}/packetread").mode & 0o111)
                self.assertTrue(package.getmember(f"{stem}/packetread-capture").mode & 0o111)
                self.assertTrue(all(item.mtime == 1700000000 for item in package.getmembers()))
            self.assertTrue(archive.with_suffix(".gz.sha256").is_file())


if __name__ == "__main__":
    unittest.main()
