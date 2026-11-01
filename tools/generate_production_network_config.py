#!/usr/bin/env python3
"""Generate the compile-time production endpoint and certificate-pin header."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from production_network_config import (
    DEFAULT_HEADER,
    NetworkConfigError,
    parse_endpoint_list,
    parse_pin_list,
    render_header,
)


def write_atomically(destination: Path, contents: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="ascii",
            newline="\n",
            dir=destination.parent,
            prefix=destination.name + ".",
            suffix=".tmp",
            delete=False,
        ) as output:
            temp_name = output.name
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, destination)
        temp_name = None
    except OSError as exc:
        raise NetworkConfigError(f"cannot write production network header {destination}: {exc}") from exc
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate the compile-time Release network policy. Endpoint and pin values are public, "
            "but changing them changes the server trust policy and requires rebuilding the client."
        )
    )
    parser.add_argument(
        "--server-endpoints",
        required=True,
        help="comma/semicolon/space-separated host:port endpoints; IPv6 must use [address]:port",
    )
    parser.add_argument(
        "--tls-pin-sha256",
        required=True,
        help="one or more real 64-hex SHA-256 leaf certificate pins, comma/semicolon/space-separated",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_HEADER,
        help=f"generated header path (default: {DEFAULT_HEADER})",
    )
    args = parser.parse_args()

    try:
        endpoints = parse_endpoint_list(args.server_endpoints)
        pins = parse_pin_list(args.tls_pin_sha256)
        rendered = render_header(endpoints, pins)
        write_atomically(args.output, rendered)
    except NetworkConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Generated production network policy: {args.output}")
    print("Endpoints: " + ", ".join(str(endpoint["spec"]) for endpoint in endpoints))
    print(f"TLS pins configured: {len(pins)}")
    print("Release client must be rebuilt; runtime endpoint/TLS-pin overrides will be ignored.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
