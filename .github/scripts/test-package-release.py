#!/usr/bin/env python3
"""Exercise release manifest verification without running native build tools."""

import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location("package_release", Path(__file__).with_name("package-release.py"))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


class RuntimeManifestTests(unittest.TestCase):
    def fixture(self, root, target, binary=b"verified executable"):
        archive = root / "dist" / RELEASE.archive_name("0.1.0", target)
        prefix = f"beagle-0.1.0-{target}"
        name = "beagle.exe" if target.endswith("windows-gnu") else "beagle"
        metadata = {
            "schema_version": 1, "project": "beagle", "version": "0.1.0", "tag": "v0.1.0",
            "commit": "a" * 40, "tree": "b" * 40, "rust_toolchain": "1.94.1",
            "helper_protocol": 1, "cargo_lock_sha256": RELEASE.sha256(root / "Cargo.lock"),
            "target": target, "binary": {"name": name, "sha256": RELEASE.hashlib.sha256(b"verified executable").hexdigest()},
        }
        files = {f"{prefix}/{name}": binary, f"{prefix}/BUILD-PROVENANCE.json": json.dumps(metadata).encode()}
        if target.endswith("windows-gnu"):
            with zipfile.ZipFile(archive, "w") as bundle:
                for name, data in files.items():
                    bundle.writestr(name, data)
        else:
            with tarfile.open(archive, "w:gz") as bundle:
                for name, data in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    bundle.addfile(info, io.BytesIO(data))
        return archive

    def prepare(self, root):
        (root / "dist").mkdir()
        (root / "Cargo.lock").write_text("locked dependencies")
        (root / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.94.1"\n')
        for target in RELEASE.TARGETS:
            self.fixture(root, target)
        (root / "dist" / RELEASE.source_archive_name("0.1.0")).write_bytes(b"dependency sources")

    def test_manifest_binds_every_archive_to_one_release_and_checksums_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root)
            def git(*args):
                return "b" * 40 if args[-1] == "HEAD^{tree}" else "a" * 40
            with patch.object(RELEASE, "ROOT", root), patch.object(RELEASE, "command", side_effect=git):
                RELEASE.checksums("0.1.0")
            manifest = json.loads((root / "dist" / RELEASE.RUNTIME_MANIFEST).read_text())
            self.assertEqual(set(manifest["targets"]), set(RELEASE.TARGETS))
            self.assertIn(RELEASE.RUNTIME_MANIFEST, (root / "dist/SHA256SUMS").read_text())

    def test_rejects_modified_executable_in_tar_and_zip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root)
            for target in (RELEASE.TARGETS[0], RELEASE.TARGETS[-1]):
                archive = self.fixture(root, target, b"changed executable")
                with self.assertRaisesRegex(ValueError, "binary provenance mismatch"):
                    RELEASE.runtime_archive_record(archive, "0.1.0", target)

    def test_rejects_archives_from_another_source_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root)
            with patch.object(RELEASE, "ROOT", root), patch.object(RELEASE, "command", return_value="c" * 40):
                with self.assertRaisesRegex(ValueError, "source identity mismatch"):
                    RELEASE.checksums("0.1.0")


if __name__ == "__main__":
    unittest.main()
