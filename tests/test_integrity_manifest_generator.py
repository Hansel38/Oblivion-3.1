#!/usr/bin/env python3
"""Regression tests for the production file-integrity manifest generator."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = REPO_ROOT / "tools" / "generate_integrity_manifest.py"
REQUIRED = {
    "RRO.exe": "OBLIVION_FILE_HASH_RRO_EXE",
    "en.grf": "OBLIVION_FILE_HASH_EN_GRF",
    "DATA.ini": "OBLIVION_FILE_HASH_DATA_INI",
}


class IntegrityManifestGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="oblivion-manifest-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.game_dir = self.root / "game"
        self.game_dir.mkdir()
        self.output = self.root / "generated" / "file_integrity_manifest.generated.h"
        self.contents = {
            "RRO.exe": b"ragnarok-executable-fixture\x00",
            "en.grf": b"grf-fixture-data\x01\x02",
            "DATA.ini": b"[Data]\n0=grf-fixture\n",
        }
        for name, data in self.contents.items():
            (self.game_dir / name).write_bytes(data)

    def run_generator(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                str(self.game_dir),
                "--output",
                str(self.output),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_generates_deterministic_sha256_header(self) -> None:
        first = self.run_generator()
        self.assertEqual(first.returncode, 0, first.stderr)
        generated = self.output.read_text(encoding="ascii")
        for filename, macro in REQUIRED.items():
            digest = hashlib.sha256(self.contents[filename]).hexdigest()
            self.assertIn(f'#define {macro} "{digest}"', generated)

        second = self.run_generator()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(generated, self.output.read_text(encoding="ascii"))

    def test_missing_file_does_not_overwrite_existing_header(self) -> None:
        self.output.parent.mkdir(parents=True)
        self.output.write_text("KEEP_EXISTING_HEADER\n", encoding="ascii")
        (self.game_dir / "en.grf").unlink()

        result = self.run_generator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("en.grf: required production file is missing", result.stderr)
        self.assertEqual(
            "KEEP_EXISTING_HEADER\n",
            self.output.read_text(encoding="ascii"),
        )

    def test_rejects_symlinked_manifest_entry(self) -> None:
        linked = self.game_dir / "DATA.ini"
        linked.unlink()
        outside = self.root / "outside.ini"
        outside.write_bytes(b"not from the package directory")
        linked.symlink_to(outside)

        result = self.run_generator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DATA.ini: symlinks are not accepted", result.stderr)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
