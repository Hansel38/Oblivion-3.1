#!/usr/bin/env python3
"""Regression tests for the fail-closed production release preflight."""

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
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from production_network_config import parse_endpoint_list, parse_pin_list, render_header  # noqa: E402

CHECKER = TOOLS / "check_production_readiness.py"
REQUIRED = {
    "RRO.exe": "OBLIVION_FILE_HASH_RRO_EXE",
    "en.grf": "OBLIVION_FILE_HASH_EN_GRF",
    "DATA.ini": "OBLIVION_FILE_HASH_DATA_INI",
}
MAX_SIZE = 16 * 1024 * 1024
DEFAULT_HOST = "shield.example.test"


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL CLI required to create local test certificates")
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
        self.signature_source = self.root / "digital_signature_validator.cpp"
        self.network_config = self.root / "production_network_config.generated.h"
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
        self.generate_certificate(
            common_name=DEFAULT_HOST,
            san=f"DNS:{DEFAULT_HOST}",
            eku="serverAuth",
        )
        self.pin = self.leaf_pin()
        self.write_network_config()
        self.signature_source.write_text(
            "VerifyCatalogSignatureStatus CryptCATAdminEnumCatalogFromHash "
            "CryptCATAdminCalcHashFromFileHandle2 CMSG_SIGNER_CERT_INFO_PARAM "
            "PCERT_INFO WTD_CHOICE_CATALOG WTD_REVOKE_WHOLECHAIN "
            "WTD_DISABLE_MD2_MD4 ModuleTrustPolicy::Evaluate "
            "SameModuleFileStamp(initialStamp, finalStamp)\\n",
            encoding="utf-8",
        )

    def generate_certificate(
        self,
        *,
        common_name: str,
        san: str | None,
        eku: str | None,
        destination_cert: Path | None = None,
        destination_key: Path | None = None,
    ) -> None:
        cert = destination_cert or self.cert
        key = destination_key or self.key
        command = [
            shutil.which("openssl") or "openssl",
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
            "-days", "2", "-keyout", str(key), "-out", str(cert),
            "-subj", f"/CN={common_name}",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        ]
        if eku:
            command.extend(["-addext", f"extendedKeyUsage={eku}"])
        if san:
            command.extend(["-addext", f"subjectAltName={san}"])
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )

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

    def write_network_config(
        self,
        *,
        compiled_host: str = DEFAULT_HOST,
        compiled_port: int = 54321,
        compiled_pins: str | None = None,
    ) -> None:
        endpoints = parse_endpoint_list(f"{compiled_host}:{compiled_port}")
        pins = parse_pin_list(compiled_pins if compiled_pins is not None else self.pin)
        self.network_config.write_text(render_header(endpoints, pins), encoding="ascii")

    def run_checker(
        self,
        *,
        host: str = DEFAULT_HOST,
        pin: str | None = None,
        compiled_host: str = DEFAULT_HOST,
        compiled_pins: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.write_network_config(compiled_host=compiled_host, compiled_pins=compiled_pins)
        return subprocess.run(
            [
                sys.executable, str(CHECKER),
                "--game-dir", str(self.game),
                "--manifest", str(self.manifest),
                "--client-project", str(self.project),
                "--runtime-source", str(self.runtime_source),
                "--signature-source", str(self.signature_source),
                "--network-config", str(self.network_config),
                "--tls-cert", str(self.cert),
                "--tls-key", str(self.key),
                "--server-host", host,
                "--tls-pin-sha256", pin or self.pin,
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_signer_certificate_info_uses_cert_info_structure(self) -> None:
        source = (ROOT / "client" / "src" / "digital_signature_validator.cpp").read_text(encoding="utf-8")
        self.assertIn("CMSG_SIGNER_CERT_INFO_PARAM", source)
        self.assertIn("PCERT_INFO", source)
        self.assertNotIn("PCMSG_SIGNER_INFO", source)
        self.assertIn("SignaturePolicy::IsExpectedPublisherMatch", source)
        self.assertNotIn("lowerActual.find(lowerExpected)", source)

    def test_catalog_signature_fallback_is_present(self) -> None:
        source = (ROOT / "client" / "src" / "digital_signature_validator.cpp").read_text(encoding="utf-8")
        for token in (
            "VerifyCatalogSignatureStatus",
            "CryptCATAdminEnumCatalogFromHash",
            "CryptCATAdminCalcHashFromFileHandle2",
            "WTD_CHOICE_CATALOG",
            "CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)

    def test_accepts_exact_package_release_policy_and_matching_tls_identity(self) -> None:
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PRODUCTION PREFLIGHT PASSED", result.stdout)
        self.assertIn("compile-time endpoint", result.stdout)

    def test_rejects_module_verifier_missing_catalog_signature_checks(self) -> None:
        self.signature_source.write_text(
            "VerifyCatalogSignatureStatus CMSG_SIGNER_CERT_INFO_PARAM PCERT_INFO "
            "WTD_CHOICE_CATALOG WTD_REVOKE_WHOLECHAIN WTD_DISABLE_MD2_MD4 "
            "ModuleTrustPolicy::Evaluate SameModuleFileStamp(initialStamp, finalStamp)\\n",
            encoding="utf-8",
        )
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("module signature verifier is missing release security token", result.stderr)

    def test_rejects_unprovisioned_network_policy(self) -> None:
        self.network_config.write_text(
            '#define OBLIVION_PRODUCTION_NETWORK_CONFIG_READY 0\n'
            '#define OBLIVION_PRODUCTION_SERVER_ENDPOINTS "PRODUCTION_ENDPOINTS_NOT_CONFIGURED"\n'
            '#define OBLIVION_PRODUCTION_TLS_PIN_SHA256 "PLACEHOLDER"\n',
            encoding="ascii",
        )
        result = subprocess.run(
            [
                sys.executable, str(CHECKER),
                "--game-dir", str(self.game),
                "--manifest", str(self.manifest),
                "--client-project", str(self.project),
                "--runtime-source", str(self.runtime_source),
                "--network-config", str(self.network_config),
                "--tls-cert", str(self.cert),
                "--tls-key", str(self.key),
                "--server-host", DEFAULT_HOST,
                "--tls-pin-sha256", self.pin,
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("network config is not provisioned", result.stderr)

    def test_rejects_runtime_pin_not_equal_to_compiled_policy(self) -> None:
        wrong = ("0" if self.pin[0] != "0" else "1") + self.pin[1:]
        result = self.run_checker(pin=wrong)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the certificate pins compiled", result.stderr)

    def test_rejects_compiled_pin_not_matching_certificate(self) -> None:
        wrong = ("0" if self.pin[0] != "0" else "1") + self.pin[1:]
        result = self.run_checker(pin=wrong, compiled_pins=wrong)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absent from the compiled pin list", result.stderr)

    def test_rejects_endpoint_not_in_compiled_policy(self) -> None:
        result = self.run_checker(host="wrong.example.test")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must match an endpoint in the compiled production network policy", result.stderr)

    def test_rejects_certificate_san_mismatch_for_compiled_endpoint(self) -> None:
        result = self.run_checker(host="wrong.example.test", compiled_host="wrong.example.test")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SAN does not match compiled endpoint", result.stderr)

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
        self.generate_certificate(common_name=DEFAULT_HOST, san=None, eku="serverAuth")
        self.pin = self.leaf_pin()
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no Subject Alternative Name", result.stderr)

    def test_rejects_certificate_without_server_auth_eku(self) -> None:
        self.generate_certificate(
            common_name=DEFAULT_HOST,
            san=f"DNS:{DEFAULT_HOST}",
            eku="clientAuth",
        )
        self.pin = self.leaf_pin()
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Extended Key Usage must include serverAuth", result.stderr)

    def test_rejects_mismatched_tls_private_key(self) -> None:
        other_cert = self.root / "other-cert.pem"
        other_key = self.root / "other-key.pem"
        self.generate_certificate(
            common_name=DEFAULT_HOST,
            san=f"DNS:{DEFAULT_HOST}",
            eku="serverAuth",
            destination_cert=other_cert,
            destination_key=other_key,
        )
        self.key.write_bytes(other_key.read_bytes())
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("certificate/private key pair is invalid or mismatched", result.stderr)

    @unittest.skipIf(os.name == "nt", "POSIX mode bits do not represent Windows ACLs")
    def test_rejects_group_or_world_readable_tls_private_key(self) -> None:
        self.key.chmod(0o644)
        result = self.run_checker()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("permissions expose the key to group/other users", result.stderr)

    def test_real_network_reporter_source_enforces_pinned_release_policy(self) -> None:
        from importlib.util import module_from_spec, spec_from_file_location

        spec = spec_from_file_location("production_readiness", CHECKER)
        self.assertIsNotNone(spec)
        module = module_from_spec(spec)
        self.assertIsNotNone(spec.loader)
        spec.loader.exec_module(module)
        module.validate_network_policy_source(
            ROOT / "client" / "src" / "network_reporter.cpp"
        )

    def test_network_policy_source_missing_runtime_pin_override_is_rejected(self) -> None:
        from importlib.util import module_from_spec, spec_from_file_location

        spec = spec_from_file_location("production_readiness", CHECKER)
        self.assertIsNotNone(spec)
        module = module_from_spec(spec)
        self.assertIsNotNone(spec.loader)
        spec.loader.exec_module(module)
        source = self.root / "network_reporter.cpp"
        source.write_text(
            '#include "../include/production_network_config.generated.h"\\n'
            '#if defined(OBLIVION_PRODUCTION_BUILD) && OBLIVION_PRODUCTION_BUILD\\n'
            '#if OBLIVION_ALLOW_NETWORK_FAIL_OPEN\\n'
            'AppendEndpointList(cfg, OBLIVION_PRODUCTION_SERVER_ENDPOINTS);\\n'
            'cfg.endpointsFromLocalConfig = false;\\n'
            'cfg.failClosed = true;\\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(module.ReadinessError, "OBLIVION_PRODUCTION_NETWORK_CONFIG_READY"):
            module.validate_network_policy_source(source)

    def test_real_client_project_enables_production_enforcement(self) -> None:
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
