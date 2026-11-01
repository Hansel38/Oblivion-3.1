#!/usr/bin/env python3
"""Tests for the production release preflight checker."""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "tools" / "check_production_readiness.py"
REQUIRED = {
    "RRO.exe": "OBLIVION_FILE_HASH_RRO_EXE",
    "en.grf": "OBLIVION_FILE_HASH_EN_GRF",
    "DATA.ini": "OBLIVION_FILE_HASH_DATA_INI",
}
MAX_SIZE = 16 * 1024 * 1024


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL CLI required to create a local test certificate")
class ProductionReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="oblivion-production-preflight-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.game = self.root / "package"
        self.game.mkdir()
        self.manifest = self.root / "manifest.h"
        self.project = self.root / "client.vcxproj"
        self.runtime_source = self.root / "file_integrity_check.cpp"
        self.cert = self.root / "server-cert.pem"
        self.key = self.root / "server-key.pem"
        self.files = {
            "RRO.exe": b"release-fixture-executable",
            "en.grf": b"release-fixture-grf",
            "DATA.ini": b"[Data]\n0=fixture.grf\n",
        }
        for filename, data in self.files.items():
            (self.game / filename).write_bytes(data)
        self.write_manifest()
        self.write_project()
        self.runtime_source.write_text(
            "#if defined(OBLIVION_PRODUCTION_BUILD) && OBLIVION_ENFORCE_FILE_INTEGRITY != 1\n"
            "#define OBLIVION_MAX_HASH_FILE_SIZE_BYTES 16777216\n"
            "static constexpr unsigned long long kMaxHashFileSizeBytes = OBLIVION_MAX_HASH_FILE_SIZE_BYTES;\n",
            encoding="utf-8",
        )
        subprocess.run(
            [
                shutil.which("openssl") or "openssl",
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-days", "2", "-keyout", str(self.key), "-out", str(self.cert),
                "-subj", "/CN=shield.example.test",
                "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
                "-addext", "extendedKeyUsage=serverAuth",
                "-addext", "subjectAltName=DNS:shield.example.test",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.pin = self.leaf_pin()

    def leaf_pin(self) -> str:
        pem = self.cert.read_bytes()
        start = pem.index(b"-----BEGIN CERTIFICATE-----") + len(b"-----BEGIN CERTIFICATE-----")
        end = pem.index(b"-----END CERTIFICATE-----")
        der = base64.b64decode(b"".join(pem[start:end].split()))
        return hashlib.sha256(der).hexdigest()

    def write_manifest(self, override: dict[str, str] | None = None) -> None:
        override = override or {}
        lines = ["#pragma once"]
        for filename, macro in REQUIRED.items():
            digest = override.get(filename, hashlib.sha256(self.files[filename]).hexdigest())
            lines.append(f'#define {macro} "{digest}"')
        self.manifest.write_text("\n".join(lines) + "\n", encoding="ascii")

    def write_project(self, *, enforce: bool = True, max_size: int = MAX_SIZE) -> None:
        definitions = (
            f"OBLIVION_PRODUCTION_BUILD=1;OBLIVION_ENFORCE_FILE_INTEGRITY={1 if enforce else 0};"
            f"OBLIVION_MAX_HASH_FILE_SIZE_BYTES={max_size};%(PreprocessorDefinitions)"
        )
        xml = f'''<?xml version="1.0" encoding="utf-8"?>
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <ClCompile><PreprocessorDefinitions>{definitions}</PreprocessorDefinitions></ClCompile>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile><PreprocessorDefinitions>{definitions}</PreprocessorDefinitions></ClCompile>
  </ItemDefinitionGroup>
</Project>
'''
        self.project.write_text(xml, encoding="utf-8")

    def run_checker(self, *, host: str = "shield.example.test", pin: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable, str(CHECKER),
                "--game-dir", str(self.game),
                "--manifest", str(self.manifest),
                "--client-project", str(self.project),
                "--runtime-source", str(self.runtime_source),
                "--tls-cert", str(self.cert),
                "--tls-key", str(self.key),
                "--server-host", host,
                "--tls-pin-sha256", pin or self.pin,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_accepts_exact_package_release_flags_and_matching_tls_pin(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PRODUCTION PREFLIGHT PASSED", result.stdout)

    def test_rejects_placeholder_manifest(self) -> None:
        self.write_manifest({"en.grf": "PLACEHOLDER"})
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("en.grf: hash is missing/invalid", result.stderr)

    def test_rejects_package_hash_mismatch(self) -> None:
        self.write_manifest({"DATA.ini": "0" * 64})
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DATA.ini: package SHA-256 does not match", result.stderr)

    def test_rejects_mismatched_tls_private_key(self) -> None:
        other_key = self.root / "other-key.pem"
        other_cert = self.root / "other-cert.pem"
        subprocess.run(
            [
                shutil.which("openssl") or "openssl",
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-days", "2", "-keyout", str(other_key), "-out", str(other_cert),
                "-subj", "/CN=other.example.test",
                "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
                "-addext", "extendedKeyUsage=serverAuth",
                "-addext", "subjectAltName=DNS:shield.example.test",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.key.write_bytes(other_key.read_bytes())
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("certificate/private key pair is invalid or mismatched", result.stderr)

    def test_rejects_wrong_pin(self) -> None:
        wrong = ("0" if self.pin[0] != "0" else "1") + self.pin[1:]
        result = self.run_checker(pin=wrong)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absent from the configured pin list", result.stderr)

    def test_rejects_hostname_mismatch(self) -> None:
        result = self.run_checker(host="wrong.example.test")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SAN does not match", result.stderr)

    def test_rejects_missing_release_enforcement(self) -> None:
        self.write_project(enforce=False)
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("OBLIVION_ENFORCE_FILE_INTEGRITY=1", result.stderr)

    def test_rejects_package_above_runtime_hash_limit(self) -> None:
        self.write_project(max_size=8)
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exceeds the configured runtime limit", result.stderr)

    def test_rejects_certificate_without_san(self) -> None:
        subprocess.run(
            [
                shutil.which("openssl") or "openssl",
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-days", "2", "-keyout", str(self.key), "-out", str(self.cert),
                "-subj", "/CN=shield.example.test",
                "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
                "-addext", "extendedKeyUsage=serverAuth",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.pin = self.leaf_pin()
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no Subject Alternative Name", result.stderr)

    def test_rejects_certificate_without_server_auth_eku(self) -> None:
        subprocess.run(
            [
                shutil.which("openssl") or "openssl",
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-days", "2", "-keyout", str(self.key), "-out", str(self.cert),
                "-subj", "/CN=shield.example.test",
                "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
                "-addext", "extendedKeyUsage=clientAuth",
                "-addext", "subjectAltName=DNS:shield.example.test",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.pin = self.leaf_pin()
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Extended Key Usage must include serverAuth", result.stderr)

    def test_real_client_project_enables_production_enforcement(self) -> None:
        # Guard the actual repository configuration, not only the synthetic fixture.
        from importlib.util import module_from_spec, spec_from_file_location

        spec = spec_from_file_location("production_readiness", CHECKER)
        self.assertIsNotNone(spec)
        module = module_from_spec(spec)
        self.assertIsNotNone(spec.loader)
        spec.loader.exec_module(module)
        limit = module.release_limits(
            ROOT / "client" / "client.vcxproj",
            ROOT / "client" / "src" / "file_integrity_check.cpp",
        )
        self.assertEqual(limit, 512 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main(verbosity=2)
