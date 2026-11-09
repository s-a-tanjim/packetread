"""Release gates must reject publishing a binary under the wrong version."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release-version.py"
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


if __name__ == "__main__":
    unittest.main()
