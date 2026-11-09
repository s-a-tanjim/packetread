#!/usr/bin/env python3
"""Reject mismatched release tags before any binaries are published."""
import os
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parent.parent


def release_version(manifest, lock, ref_type="", ref_name=""):
    package = manifest["package"]
    version = package["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
        raise ValueError(f"Invalid package version: {version!r}")
    locked = [p for p in lock["package"] if p["name"] == package["name"] and "source" not in p]
    if len(locked) != 1 or locked[0]["version"] != version:
        raise ValueError("Cargo.toml and Cargo.lock versions differ; update and commit Cargo.lock")
    if ref_type == "tag" and ref_name != f"v{version}":
        raise ValueError(f"Tag {ref_name!r} must match Cargo.toml version: v{version}")
    return version


if __name__ == "__main__":
    try:
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
        lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
        print(release_version(manifest, lock, os.getenv("GITHUB_REF_TYPE", ""), os.getenv("GITHUB_REF_NAME", "")))
    except (ValueError, KeyError, OSError) as error:
        sys.exit(f"Release validation failed: {error}")
