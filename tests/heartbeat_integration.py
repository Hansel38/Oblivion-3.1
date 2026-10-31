#!/usr/bin/env python3
"""Local TCP integration test for the Oblivion heartbeat protocol.

The test launches an isolated server process, verifies valid authenticated
heartbeats, then proves a status-bit modification invalidates the PONG HMAC.
No production secrets or external services are used.
"""

import hashlib
import hmac
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HOST = "127.0.0.1"
PORT = 54321
TEST_SECRET = "oblivion-integration-secret-at-least-32-bytes"
MAX_FRAME_BYTES = 4096


def recv_frame(sock: socket.socket, buffered: bytes) -> tuple[str, bytes]:
    while b";" not in buffered:
        chunk = sock.recv(2048)
        if not chunk:
            raise RuntimeError("server closed the connection before a complete frame")
        buffered += chunk
        if len(buffered) > MAX_FRAME_BYTES:
            raise RuntimeError("server frame exceeded the integration-test limit")
    frame, buffered = buffered.split(b";", 1)
    return frame.decode("ascii"), buffered


def recv_ping(sock: socket.socket, buffered: bytes) -> tuple[tuple[int, int, int], bytes]:
    frame, buffered = recv_frame(sock, buffered)
    fields = frame.split(":")
    if len(fields) != 4 or fields[0] != "PING":
        raise RuntimeError(f"expected PING frame, received {frame!r}")
    try:
        sequence, server_timestamp, nonce = (int(value, 10) for value in fields[1:])
    except ValueError as exc:
        raise RuntimeError("PING contained a non-numeric field") from exc
    if sequence <= 0 or server_timestamp <= 0 or nonce <= 0:
        raise RuntimeError("PING contained a zero or negative security field")
    return (sequence, server_timestamp, nonce), buffered


def authenticate(sock: socket.socket, hwid: str) -> tuple[str, bytes]:
    sock.sendall(f"CHECKIN::{hwid}:{TEST_SECRET};".encode("ascii"))
    first, buffered = recv_frame(sock, b"")
    if first != "OK":
        raise RuntimeError(f"check-in rejected: {first!r}")
    second, buffered = recv_frame(sock, buffered)
    prefix = "SESSION_NONCE:"
    if not second.startswith(prefix):
        raise RuntimeError(f"missing session nonce: {second!r}")
    session_nonce_text = second[len(prefix):]
    if not session_nonce_text.isdigit() or int(session_nonce_text) == 0:
        raise RuntimeError("server returned an invalid session nonce")
    session_key = hmac.new(
        TEST_SECRET.encode("ascii"),
        f"{hwid}:{session_nonce_text}".encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return session_key, buffered


def send_pong(
    sock: socket.socket,
    hwid: str,
    session_key: str,
    ping: tuple[int, int, int],
    *,
    wire_status: str = "1|1",
    signed_status: str = "1|1",
) -> None:
    sequence, server_timestamp, nonce = ping
    client_timestamp = max(1, int(time.monotonic() * 1000))
    # This is the canonical wire contract used by client and both servers.
    signed_payload = (
        f"{sequence}:{client_timestamp}:{server_timestamp}:"
        f"{nonce}:{signed_status}:{hwid}"
    )
    digest = hmac.new(
        session_key.encode("ascii"),
        signed_payload.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    frame = (
        f"PONG:{sequence}:{client_timestamp}:{nonce}:"
        f"{wire_status}:{hwid}:{digest};"
    )
    sock.sendall(frame.encode("ascii"))


def run_integration(server_binary: Path) -> None:
    env = os.environ.copy()
    env["OBLIVION_SECRET"] = TEST_SECRET
    env["OBLV_HB_INTERVAL_MS"] = "250"
    env["OBLV_HB_TIMEOUT_MS"] = "1000"
    env["OBLV_HB_MAX_MISS"] = "2"
    env["OBLV_HB_RTT_WARN_MS"] = "60000"

    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as server_log:
        process = subprocess.Popen(
            [str(server_binary)],
            cwd=str(server_binary.parent),
            env=env,
            stdout=server_log,
            stderr=subprocess.STDOUT,
        )
        sockets: list[socket.socket] = []
        try:
            # First connection also acts as readiness probe; do not leave idle
            # probe sockets behind to consume a worker slot.
            good = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            good.settimeout(4)
            deadline = time.monotonic() + 12
            while True:
                try:
                    good.connect((HOST, PORT))
                    break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError("server exited before accepting a connection")
                    if time.monotonic() >= deadline:
                        raise RuntimeError("server did not start listening on port 54321")
                    time.sleep(0.1)
            sockets.append(good)

            good_hwid = f"TEST-GOOD-{os.urandom(8).hex()}"
            good_key, buffered = authenticate(good, good_hwid)
            for _ in range(2):
                ping, buffered = recv_ping(good, buffered)
                send_pong(good, good_hwid, good_key, ping)

            # With the configured miss threshold of two, receiving sequence 3
            # proves both earlier PONG HMACs were accepted, not merely tolerated.
            third_ping, buffered = recv_ping(good, buffered)
            if third_ping[0] != 3:
                raise RuntimeError(f"expected third valid heartbeat, got sequence {third_ping[0]}")
            good.close()
            sockets.remove(good)

            bad = socket.create_connection((HOST, PORT), timeout=3)
            bad.settimeout(3)
            sockets.append(bad)
            bad_hwid = f"TEST-TAMPER-{os.urandom(8).hex()}"
            bad_key, buffered = authenticate(bad, bad_hwid)

            for _ in range(2):
                ping, buffered = recv_ping(bad, buffered)
                # Sign status 1|1, then alter it in transit to 0|1. The server
                # must reject this response because status is covered by HMAC.
                send_pong(
                    bad, bad_hwid, bad_key, ping,
                    wire_status="0|1",
                    signed_status="1|1",
                )

            try:
                unexpected = bad.recv(512)
            except socket.timeout as exc:
                raise RuntimeError("server did not close after repeated tampered PONGs") from exc
            if unexpected:
                raise RuntimeError(
                    "server accepted tampered status HMAC and continued sending frames"
                )

        finally:
            for sock in sockets:
                try:
                    sock.close()
                except OSError:
                    pass
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        if process.returncode not in (0, -signal.SIGTERM, 128 + signal.SIGTERM):
            server_log.seek(0)
            log_tail = server_log.read()[-5000:]
            raise RuntimeError(
                f"server exited unexpectedly with code {process.returncode}\n{log_tail}"
            )


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: heartbeat_integration.py PATH_TO_SERVER", file=sys.stderr)
        return 2
    server_binary = Path(sys.argv[1]).resolve()
    if not server_binary.is_file():
        print(f"Server binary not found: {server_binary}", file=sys.stderr)
        return 2
    try:
        run_integration(server_binary)
    except Exception as exc:
        print(f"Heartbeat TCP integration test: FAIL: {exc}", file=sys.stderr)
        return 1
    print("Heartbeat TCP integration test: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
