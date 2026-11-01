"""Shared validation and rendering for the production client network policy.

This module deliberately keeps endpoints and certificate pins in a generated,
reviewable header. The client Release build must never accept runtime endpoint
or pin overrides from an editable local configuration file.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

DEFAULT_HEADER = (
    Path(__file__).resolve().parent.parent
    / "client"
    / "include"
    / "production_network_config.generated.h"
)


class NetworkConfigError(Exception):
    """Raised when production endpoint/pin configuration is invalid."""


def _normalize_host(host: str) -> tuple[str, bool]:
    value = host.rstrip(".")
    if not value or any(ch.isspace() or ord(ch) < 0x21 or ord(ch) > 0x7E for ch in value):
        raise NetworkConfigError(f"invalid endpoint host: {host!r}")

    try:
        address = ipaddress.ip_address(value)
        return str(address), address.version == 6
    except ValueError:
        pass

    try:
        dns_name = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise NetworkConfigError(f"endpoint DNS name cannot be normalized: {host!r}") from exc

    if len(dns_name) > 253:
        raise NetworkConfigError(f"endpoint DNS name exceeds 253 characters: {host!r}")
    labels = dns_name.split(".")
    if any(not DNS_LABEL_RE.fullmatch(label) for label in labels):
        raise NetworkConfigError(f"endpoint is not a valid DNS name or IP address: {host!r}")
    return dns_name, False


def parse_endpoint_token(token: str) -> tuple[str, int, str]:
    value = token.strip()
    if not value:
        raise NetworkConfigError("empty endpoint token")

    if value.startswith("["):
        close = value.find("]")
        if close < 0 or close == 1 or value[close + 1:close + 2] != ":":
            raise NetworkConfigError(
                f"IPv6 endpoints must use [address]:port syntax: {token!r}"
            )
        host_text = value[1:close]
        port_text = value[close + 2:]
        normalized_host, is_ipv6 = _normalize_host(host_text)
        if not is_ipv6:
            raise NetworkConfigError(f"bracketed endpoint host is not IPv6: {host_text!r}")
        endpoint_host = f"[{normalized_host}]"
    else:
        if value.count(":") != 1:
            raise NetworkConfigError(
                f"endpoint must include host:port (bracket IPv6 addresses): {token!r}"
            )
        host_text, port_text = value.rsplit(":", 1)
        normalized_host, is_ipv6 = _normalize_host(host_text)
        if is_ipv6:
            raise NetworkConfigError(
                f"IPv6 endpoint must be bracketed as [address]:port: {token!r}"
            )
        endpoint_host = normalized_host

    if not port_text.isdigit():
        raise NetworkConfigError(f"endpoint port must be an integer: {token!r}")
    port = int(port_text, 10)
    if not 1 <= port <= 65535:
        raise NetworkConfigError(f"endpoint port must be between 1 and 65535: {token!r}")

    return normalized_host, port, f"{endpoint_host}:{port}"


def parse_endpoint_list(setting: str) -> list[dict[str, object]]:
    tokens = [token for token in re.split(r"[,;\s]+", setting.strip()) if token]
    if not tokens:
        raise NetworkConfigError("production endpoint list is empty")

    endpoints: list[dict[str, object]] = []
    seen: set[str] = set()
    for token in tokens:
        host, port, normalized = parse_endpoint_token(token)
        if normalized not in seen:
            endpoints.append({"host": host, "port": port, "spec": normalized})
            seen.add(normalized)
    if not endpoints:
        raise NetworkConfigError("production endpoint list does not contain a valid endpoint")
    return endpoints


def validate_deployable_endpoints(
    endpoints: list[dict[str, object]],
    *,
    allow_test_endpoints: bool = False,
) -> None:
    """Reject obvious examples/reserved targets from a production trust policy.

    The explicit override is intended only for compile-only CI fixtures. The
    production preflight always calls this with the default (strict) setting.
    """
    reserved_dns_suffixes = (".invalid", ".test", ".example", ".localhost")
    reserved_dns_names = {
        "localhost",
        "example.com", "example.net", "example.org",
    }
    # Python's ipaddress.is_reserved does not mark all RFC 5737 documentation
    # prefixes as reserved on every supported Python version. Deny them
    # explicitly so sample addresses cannot pass production preflight.
    reserved_ip_networks = tuple(
        ipaddress.ip_network(network)
        for network in (
            "192.0.2.0/24",       # TEST-NET-1
            "198.51.100.0/24",    # TEST-NET-2
            "203.0.113.0/24",     # TEST-NET-3
            "2001:db8::/32",      # IPv6 documentation prefix
        )
    )

    for endpoint in endpoints:
        host = str(endpoint["host"]).lower().rstrip(".")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if not allow_test_endpoints and (
                host in reserved_dns_names
                or any(host == suffix[1:] or host.endswith(suffix) for suffix in reserved_dns_suffixes)
                or host.endswith(".example.com")
                or host.endswith(".example.net")
                or host.endswith(".example.org")
            ):
                raise NetworkConfigError(
                    f"reserved/test hostname {host!r} cannot be used in a production network policy"
                )
            continue

        if not allow_test_endpoints and (
            address.is_loopback
            or address.is_unspecified
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or any(address.version == network.version and address in network
                   for network in reserved_ip_networks)
        ):
            raise NetworkConfigError(
                f"reserved/test IP address {host!r} cannot be used in a production network policy"
            )


def parse_pin_list(setting: str) -> list[str]:
    tokens = [token for token in re.split(r"[,;\s]+", setting.strip()) if token]
    if not tokens:
        raise NetworkConfigError("production TLS certificate pin list is empty")

    pins: list[str] = []
    for token in tokens:
        if not SHA256_RE.fullmatch(token):
            raise NetworkConfigError(
                "each production TLS pin must be exactly 64 hexadecimal characters"
            )
        normalized = token.lower()
        if normalized not in pins:
            pins.append(normalized)
    return pins


def render_header(endpoints: list[dict[str, object]], pins: list[str]) -> str:
    endpoint_value = ",".join(str(item["spec"]) for item in endpoints)
    pin_value = ",".join(pins)
    # The parsers restrict both values to a small safe ASCII alphabet, so these
    # strings cannot inject quotes or C/C++ escapes into the generated header.
    return (
        "#pragma once\n\n"
        "// Generated by tools/generate_production_network_config.py.\n"
        "// Production Release must never use editable oblivion.cfg/environment endpoints or pins.\n"
        "// Regenerate and review this file for the deployment being built.\n"
        "#define OBLIVION_PRODUCTION_NETWORK_CONFIG_READY 1\n"
        f'#define OBLIVION_PRODUCTION_SERVER_ENDPOINTS "{endpoint_value}"\n'
        f'#define OBLIVION_PRODUCTION_TLS_PIN_SHA256 "{pin_value}"\n'
    )


def read_network_config(path: Path) -> dict[str, object]:
    try:
        source = path.read_text(encoding="ascii")
    except OSError as exc:
        raise NetworkConfigError(f"cannot read production network config {path}: {exc}") from exc

    ready = re.findall(
        r"^\s*#define\s+OBLIVION_PRODUCTION_NETWORK_CONFIG_READY\s+([0-9]+)\s*$",
        source,
        re.MULTILINE,
    )
    endpoint_values = re.findall(
        r'^\s*#define\s+OBLIVION_PRODUCTION_SERVER_ENDPOINTS\s+"([^"]*)"\s*$',
        source,
        re.MULTILINE,
    )
    pin_values = re.findall(
        r'^\s*#define\s+OBLIVION_PRODUCTION_TLS_PIN_SHA256\s+"([^"]*)"\s*$',
        source,
        re.MULTILINE,
    )
    if len(ready) != 1 or len(endpoint_values) != 1 or len(pin_values) != 1:
        raise NetworkConfigError("generated production network header is missing/ambiguous macros")
    if ready[0] != "1":
        raise NetworkConfigError(
            "production network config is not provisioned; generate real endpoints and TLS pins first"
        )

    endpoints = parse_endpoint_list(endpoint_values[0])
    pins = parse_pin_list(pin_values[0])
    validate_deployable_endpoints(endpoints)
    return {
        "endpoints": endpoints,
        "pins": pins,
        "endpoint_spec": endpoint_values[0],
        "pin_spec": pin_values[0],
    }
