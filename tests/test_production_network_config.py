#!/usr/bin/env python3
"""Regression tests for compile-time production endpoint and TLS pin policy."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from production_network_config import (  # noqa: E402
    NetworkConfigError,
    parse_endpoint_list,
    parse_pin_list,
    read_network_config,
    render_header,
    validate_deployable_endpoints,
)

PIN_A = "a" * 64
PIN_B = "b" * 64


class ProductionNetworkConfigTests(unittest.TestCase):
    def test_normalizes_dns_ipv4_and_bracketed_ipv6_endpoints(self) -> None:
        endpoints = parse_endpoint_list(
            "SHIELD.Example.test:54321, 192.0.2.10:443;[2001:db8::1]:54321"
        )
        self.assertEqual(
            [entry["spec"] for entry in endpoints],
            [
                "shield.example.test:54321",
                "192.0.2.10:443",
                "[2001:db8::1]:54321",
            ],
        )

    def test_deduplicates_repeated_endpoints(self) -> None:
        endpoints = parse_endpoint_list(
            "shield.example.test:54321,SHIELD.EXAMPLE.TEST:54321"
        )
        self.assertEqual(len(endpoints), 1)

    def test_requires_explicit_valid_ports(self) -> None:
        for setting in (
            "shield.example.test",
            "shield.example.test:0",
            "shield.example.test:65536",
            "shield.example.test:notaport",
            "2001:db8::1:54321",
            "[not-ipv6]:54321",
        ):
            with self.subTest(setting=setting):
                with self.assertRaises(NetworkConfigError):
                    parse_endpoint_list(setting)

    def test_rejects_empty_or_invalid_pins(self) -> None:
        for setting in ("", "PLACEHOLDER", "a" * 63, "g" * 64):
            with self.subTest(setting=setting):
                with self.assertRaises(NetworkConfigError):
                    parse_pin_list(setting)

    def test_normalizes_and_deduplicates_pins(self) -> None:
        pins = parse_pin_list(f"{PIN_A.upper()}, {PIN_A}; {PIN_B}")
        self.assertEqual(pins, [PIN_A, PIN_B])

    def test_unprovisioned_header_is_rejected(self) -> None:
        header = (
            "#pragma once\n"
            "#define OBLIVION_PRODUCTION_NETWORK_CONFIG_READY 0\n"
            '#define OBLIVION_PRODUCTION_SERVER_ENDPOINTS "PRODUCTION_ENDPOINTS_NOT_CONFIGURED"\n'
            '#define OBLIVION_PRODUCTION_TLS_PIN_SHA256 "PLACEHOLDER"\n'
        )
        with tempfile.TemporaryDirectory(prefix="oblivion-network-policy-") as directory:
            path = Path(directory) / "network.h"
            path.write_text(header, encoding="ascii")
            with self.assertRaisesRegex(NetworkConfigError, "not provisioned"):
                read_network_config(path)

    def test_rendered_header_round_trips_through_reader(self) -> None:
        endpoints = parse_endpoint_list("192.168.56.20:54321,192.168.56.21:54321")
        pins = parse_pin_list(f"{PIN_A},{PIN_B}")
        header = render_header(endpoints, pins)
        with tempfile.TemporaryDirectory(prefix="oblivion-network-policy-") as directory:
            path = Path(directory) / "network.h"
            path.write_text(header, encoding="ascii")
            parsed = read_network_config(path)
        self.assertEqual(
            [entry["spec"] for entry in parsed["endpoints"]],
            ["192.168.56.20:54321", "192.168.56.21:54321"],
        )
        self.assertEqual(parsed["pins"], [PIN_A, PIN_B])

    def test_reserved_test_endpoints_are_rejected_for_production(self) -> None:
        for endpoint in (
            "ci.invalid:54321",
            "shield.example.test:54321",
            "localhost:54321",
            "127.0.0.1:54321",
            "0.0.0.0:54321",
            "192.0.2.10:54321",
        ):
            with self.subTest(endpoint=endpoint):
                parsed = parse_endpoint_list(endpoint)
                with self.assertRaises(NetworkConfigError):
                    validate_deployable_endpoints(parsed)

    def test_reserved_test_endpoints_require_explicit_ci_override(self) -> None:
        validate_deployable_endpoints(
            parse_endpoint_list("ci.invalid:54321"),
            allow_test_endpoints=True,
        )

    def test_network_config_reader_rejects_reserved_endpoint(self) -> None:
        header = render_header(
            [{"host": "ci.invalid", "port": 54321, "spec": "ci.invalid:54321"}],
            [PIN_A],
        )
        with tempfile.TemporaryDirectory(prefix="oblivion-network-policy-") as directory:
            path = Path(directory) / "network.h"
            path.write_text(header, encoding="ascii")
            with self.assertRaisesRegex(NetworkConfigError, "reserved/test hostname"):
                read_network_config(path)

    def test_reader_rejects_malformed_endpoint_or_pin_macros(self) -> None:
        bad_endpoint = render_header(
            [{"host": "shield.example.test", "port": 54321, "spec": "shield.example.test"}],
            [PIN_A],
        )
        with tempfile.TemporaryDirectory(prefix="oblivion-network-policy-") as directory:
            path = Path(directory) / "network.h"
            path.write_text(bad_endpoint, encoding="ascii")
            with self.assertRaisesRegex(NetworkConfigError, "host:port"):
                read_network_config(path)

            bad_pin = render_header(
                [{"host": "shield.example.test", "port": 54321, "spec": "shield.example.test:54321"}],
                ["PLACEHOLDER"],
            )
            path.write_text(bad_pin, encoding="ascii")
            with self.assertRaises(NetworkConfigError):
                read_network_config(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
