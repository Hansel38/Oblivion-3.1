#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "tools" / "generate_unsigned_module_manifest.py"


class UnsignedModuleManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.game = self.root / "game"
        self.game.mkdir()
        self.source = self.root / "digital_signature_validator.cpp"
        self.output = self.root / "unsigned_module_manifest.generated.h"
        self.source.write_text(
            'const std::vector<std::wstring> DigitalSignatureValidator::m_allowedUnsignedDlls = { '
            'L"client.dll", L"granny2.dll", L"legacy.dll" };\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_generator(self, expect_success: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(GENERATOR), str(self.game),
             "--source", str(self.source), "--output", str(self.output)],
            capture_output=True, text=True, timeout=10,
        )
        if expect_success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def test_generates_exact_digests_for_present_allowlisted_files(self) -> None:
        contents_a = b"official client module\x00v1"
        contents_b = b"legacy module variant B"
        (self.game / "client.dll").write_bytes(contents_a)
        plugins = self.game / "plugins"
        plugins.mkdir()
        (plugins / "Granny2.DLL").write_bytes(contents_b)
        self.run_generator()
        header = self.output.read_text(encoding="ascii")
        self.assertIn('#define OBLIVION_UNSIGNED_MODULE_MANIFEST_READY 1', header)
        self.assertIn(f'"{hashlib.sha256(contents_a).hexdigest()}"', header)
        self.assertIn(f'"{hashlib.sha256(contents_b).hexdigest()}"', header)
        self.assertIn("kEntryCount = 2", header)
        self.assertNotIn("PLACEHOLDER", header)

    def test_symlink_in_package_is_rejected(self) -> None:
        target = self.game / "other.dll"
        target.write_bytes(b"other")
        link = self.game / "client.dll"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable in this environment")
        result = self.run_generator(expect_success=False)
        self.assertIn("symlinks are not accepted", result.stderr)

    def test_malformed_runtime_allowlist_is_rejected(self) -> None:
        self.source.write_text("no unsigned module list here\n", encoding="utf-8")
        result = self.run_generator(expect_success=False)
        self.assertIn("cannot locate m_allowedUnsignedDlls", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
