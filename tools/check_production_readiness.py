#!/usr/bin/env python3
"""Fail-closed preflight checks for an Oblivion production client release."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import re
import ssl
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "client" / "include" / "file_integrity_manifest.generated.h"
DEFAULT_CLIENT_PROJECT = ROOT / "client" / "client.vcxproj"
DEFAULT_RUNTIME_SOURCE = ROOT / "client" / "src" / "file_integrity_check.cpp"

REQUIRED_FILES = {
    "RRO.exe": "OBLIVION_FILE_HASH_RRO_EXE",
    "en.grf": "OBLIVION_FILE_HASH_EN_GRF",
    "DATA.ini": "OBLIVION_FILE_HASH_DATA_INI",
}
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
PEM_CERT_RE = re.compile(
    br"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
    re.DOTALL,
)
PROJECT_NS = {"msbuild": "http://schemas.microsoft.com/developer/msbuild/2003"}
RELEASE_CONFIGS = {
    "Release|Win32": "x86",
    "Release|x64": "x64",
}


class ReadinessError(Exception):
    """Raised when a required production invariant is not met."""


def parse_manifest(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="ascii")
    except OSError as exc:
        raise ReadinessError(f"cannot read manifest {path}: {exc}") from exc
    values: dict[str, str] = {}
    for filename, macro in REQUIRED_FILES.items():
        matches = re.findall(
            rf'^\s*#define\s+{re.escape(macro)}\s+"([^"]*)"\s*$',
            text,
            flags=re.MULTILINE,
        )
        if len(matches) != 1:
            raise ReadinessError(
                f"{macro}: expected exactly one macro definition for {filename}"
            )
        digest = matches[0]
        if not SHA256_RE.fullmatch(digest):
            raise ReadinessError(
                f"{filename}: hash is missing/invalid (placeholder values are not allowed)"
            )
        values[filename] = digest.lower()
    return values


def release_limits(project_path: Path, runtime_source_path: Path) -> int:
    try:
        tree = ET.parse(project_path)
    except (OSError, ET.ParseError) as exc:
        raise ReadinessError(f"cannot parse client project file {project_path}: {exc}") from exc

    definitions_by_config: dict[str, dict[str, str]] = {}
    root = tree.getroot()
    for group in root.findall("msbuild:ItemDefinitionGroup", PROJECT_NS):
        condition = group.get("Condition", "")
        for config in RELEASE_CONFIGS:
            if config in condition and "Release" in condition:
                node = group.find(
                    "msbuild:ClCompile/msbuild:PreprocessorDefinitions",
                    PROJECT_NS,
                )
                definitions: dict[str, str] = {}
                if node is not None and node.text:
                    for item in node.text.split(";"):
                        key, sep, value = item.partition("=")
                        if sep:
                            definitions[key.strip()] = value.strip()
                definitions_by_config[config] = definitions

    limits: list[int] = []
    for config, arch in RELEASE_CONFIGS.items():
        definitions = definitions_by_config.get(config)
        if definitions is None:
            raise ReadinessError(f"client project is missing the {config} compiler configuration")
        for name, expected in (
            ("OBLIVION_PRODUCTION_BUILD", "1"),
            ("OBLIVION_ENFORCE_FILE_INTEGRITY", "1"),
        ):
            if definitions.get(name) != expected:
                raise ReadinessError(
                    f"{arch} Release must define {name}={expected}; refusing production preflight"
                )
        raw_limit = definitions.get("OBLIVION_MAX_HASH_FILE_SIZE_BYTES")
        if raw_limit is None or not raw_limit.isdigit() or int(raw_limit) <= 0:
            raise ReadinessError(
                f"{arch} Release must define OBLIVION_MAX_HASH_FILE_SIZE_BYTES as a positive integer"
            )
        limits.append(int(raw_limit))

    if len(set(limits)) != 1:
        raise ReadinessError("x86 and x64 Release configurations use different file-hash size limits")

    try:
        source = runtime_source_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReadinessError(f"cannot read runtime integrity checker {runtime_source_path}: {exc}") from exc
    required_source_tokens = (
        "#if defined(OBLIVION_PRODUCTION_BUILD) && OBLIVION_ENFORCE_FILE_INTEGRITY != 1",
        "OBLIVION_MAX_HASH_FILE_SIZE_BYTES",
        "kMaxHashFileSizeBytes",
    )
    for token in required_source_tokens:
        if token not in source:
            raise ReadinessError(
                f"runtime integrity checker is missing the production guard token {token!r}"
            )
    return limits[0]


def hash_package(game_directory: Path, expected: dict[str, str], max_size: int) -> list[str]:
    if not game_directory.is_dir():
        raise ReadinessError(f"package directory does not exist: {game_directory}")
    results: list[str] = []
    for filename, macro in REQUIRED_FILES.items():
        file_path = game_directory / filename
        is_junction = bool(
            hasattr(file_path, "is_junction") and getattr(file_path, "is_junction")()
        )
        if file_path.is_symlink() or is_junction:
            raise ReadinessError(f"{filename}: symlinks/junctions are not allowed in a release package")
        if not file_path.is_file():
            raise ReadinessError(f"{filename}: required package file is missing or not a regular file")

        digest = hashlib.sha256()
        size = 0
        try:
            with file_path.open("rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    digest.update(chunk)
        except OSError as exc:
            raise ReadinessError(f"{filename}: cannot read package file: {exc}") from exc

        if size > max_size:
            raise ReadinessError(
                f"{filename}: {size} bytes exceeds the configured runtime limit {max_size}; "
                "raise the Release macro only after measuring startup impact"
            )
        actual = digest.hexdigest()
        if actual != expected[filename]:
            raise ReadinessError(
                f"{filename}: package SHA-256 does not match {macro} in the compiled manifest"
            )
        results.append(f"{filename}: SHA-256 verified ({size} bytes)")
    return results


def parse_pin_list(setting: str) -> list[str]:
    tokens = [token for token in re.split(r"[,;\s]+", setting.strip()) if token]
    if not tokens:
        raise ReadinessError("TLS SHA-256 pin list is empty")
    pins: list[str] = []
    for pin in tokens:
        if not SHA256_RE.fullmatch(pin):
            raise ReadinessError("each TLS SHA-256 pin must be exactly 64 hexadecimal characters")
        lowered = pin.lower()
        if lowered not in pins:
            pins.append(lowered)
    return pins


def read_leaf_certificate(cert_path: Path) -> tuple[bytes, dict]:
    try:
        pem = cert_path.read_bytes()
    except OSError as exc:
        raise ReadinessError(f"cannot read TLS certificate {cert_path}: {exc}") from exc
    match = PEM_CERT_RE.search(pem)
    if match is None:
        raise ReadinessError("TLS certificate must contain a PEM BEGIN/END CERTIFICATE block")
    try:
        der = base64.b64decode(re.sub(br"\s+", b"", match.group(1)), validate=True)
    except ValueError as exc:
        raise ReadinessError("TLS certificate PEM block is not valid Base64") from exc
    try:
        decoded = ssl._ssl._test_decode_cert(str(cert_path))
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise ReadinessError(f"cannot decode TLS certificate: {exc}") from exc
    return der, decoded


def _dns_san_matches(host: str, pattern: str) -> bool:
    host = host.rstrip(".").encode("idna").decode("ascii").lower()
    pattern = pattern.rstrip(".").lower()
    if pattern == host:
        return True
    if not pattern.startswith("*."):
        return False
    suffix = pattern[1:]  # leading dot plus base domain
    if not host.endswith(suffix):
        return False
    prefix = host[: -len(suffix)]
    return bool(prefix) and "." not in prefix


def validate_tls_certificate(cert_path: Path, host: str, pins_setting: str) -> str:
    pins = parse_pin_list(pins_setting)
    der, decoded = read_leaf_certificate(cert_path)
    actual_pin = hashlib.sha256(der).hexdigest()
    if actual_pin not in pins:
        raise ReadinessError(
            f"TLS leaf-certificate SHA-256 {actual_pin} is absent from the configured pin list"
        )

    extended_usage = decoded.get("extendedKeyUsage", ())
    if "TLS Web Server Authentication" not in extended_usage:
        raise ReadinessError(
            "TLS certificate Extended Key Usage must include serverAuth"
        )

    san = decoded.get("subjectAltName", ())
    if not san:
        raise ReadinessError("TLS certificate has no Subject Alternative Name (SAN); CN fallback is forbidden")

    try:
        ip_host = ipaddress.ip_address(host)
    except ValueError:
        ip_host = None
    if ip_host is not None:
        matched = any(
            kind == "IP Address"
            and _same_ip(value, ip_host)
            for kind, value in san
        )
    else:
        try:
            host_ascii = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ReadinessError("configured DNS hostname cannot be normalized with IDNA") from exc
        matched = any(
            kind == "DNS" and _dns_san_matches(host_ascii, value)
            for kind, value in san
        )
    if not matched:
        raise ReadinessError(
            "TLS certificate SAN does not match the configured server DNS name/IP"
        )

    now = time.time()
    not_before = ssl.cert_time_to_seconds(decoded["notBefore"])
    not_after = ssl.cert_time_to_seconds(decoded["notAfter"])
    if now < not_before or now >= not_after:
        raise ReadinessError("TLS certificate is not currently valid")
    return actual_pin


def _same_ip(value: str, expected: ipaddress._BaseAddress) -> bool:
    try:
        return ipaddress.ip_address(value) == expected
    except ValueError:
        return False


def run_preflight(
    game_directory: Path,
    manifest_path: Path,
    project_path: Path,
    runtime_source_path: Path,
    tls_cert_path: Path,
    server_host: str,
    tls_pins: str,
) -> list[str]:
    manifest = parse_manifest(manifest_path)
    max_size = release_limits(project_path, runtime_source_path)
    checks = hash_package(game_directory, manifest, max_size)
    pin = validate_tls_certificate(tls_cert_path, server_host, tls_pins)
    checks.append(f"TLS certificate: SAN, validity window, and pin verified ({pin})")
    checks.append(f"Release enforcement: x86/x64 enabled; maximum hashed file size {max_size} bytes")
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify manifest/package equality, Release enforcement flags, file-size policy, and TLS pin/identity before a production release."
    )
    parser.add_argument("--game-dir", type=Path, required=True, help="exact packaged Ragnarok client directory")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--client-project", type=Path, default=DEFAULT_CLIENT_PROJECT)
    parser.add_argument("--runtime-source", type=Path, default=DEFAULT_RUNTIME_SOURCE)
    parser.add_argument("--tls-cert", type=Path, required=True, help="PEM leaf certificate deployed by the server")
    parser.add_argument("--server-host", required=True, help="DNS name or IP address configured for clients")
    parser.add_argument("--tls-pin-sha256", required=True, help="real leaf certificate SHA-256 pin list")
    args = parser.parse_args()

    try:
        checks = run_preflight(
            args.game_dir,
            args.manifest,
            args.client_project,
            args.runtime_source,
            args.tls_cert,
            args.server_host,
            args.tls_pin_sha256,
        )
    except ReadinessError as exc:
        print(f"PRODUCTION PREFLIGHT FAILED: {exc}", file=sys.stderr)
        return 1

    print("PRODUCTION PREFLIGHT PASSED")
    for check in checks:
        print(f"  [OK] {check}")
    print("This check does not replace signed-binary verification, live-game smoke tests, or server load tests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
