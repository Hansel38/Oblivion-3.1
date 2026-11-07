#!/usr/bin/env python3
"""Local TLS socket integration test for the Oblivion heartbeat protocol.

The test launches an isolated server process, verifies valid authenticated
heartbeats, then proves a status-bit modification invalidates the PONG HMAC.
No production secrets or external services are used.
"""

import hashlib
import hmac
import os
import signal
import shutil
import ssl
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HOST = "127.0.0.1"
PORT = 54321
TEST_SECRET = "oblivion-integration-secret-at-least-32-bytes"
TEST_HEARTBEAT_INTERVAL_MS = 250
TEST_HEARTBEAT_JITTER_MS = 20
TEST_HEARTBEAT_TIMEOUT_MS = 1000
MAX_FRAME_BYTES = 4096
TLS_CONTEXT: ssl.SSLContext | None = None


def connect_tls(timeout: float = 3) -> ssl.SSLSocket:
    if TLS_CONTEXT is None:
        raise RuntimeError("TLS test context was not initialized")
    raw = socket.create_connection((HOST, PORT), timeout=timeout)
    raw.settimeout(timeout)
    try:
        return TLS_CONTEXT.wrap_socket(raw, server_hostname=HOST)
    except Exception:
        raw.close()
        raise


def recv_closed(sock: socket.socket, size: int = 1) -> bytes:
    try:
        return sock.recv(size)
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
        # A missing TLS close_notify is still treated as transport EOF here.
        return b""


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
    heartbeat_frame, buffered = recv_frame(sock, buffered)
    heartbeat_fields = heartbeat_frame.split(":")
    if len(heartbeat_fields) != 4 or heartbeat_fields[0] != "HEARTBEAT":
        raise RuntimeError(f"missing heartbeat timing policy: {heartbeat_frame!r}")
    try:
        heartbeat_timing = tuple(int(value, 10) for value in heartbeat_fields[1:])
    except ValueError as exc:
        raise RuntimeError("heartbeat timing policy contains a non-numeric field") from exc
    expected_timing = (
        TEST_HEARTBEAT_INTERVAL_MS,
        TEST_HEARTBEAT_JITTER_MS,
        TEST_HEARTBEAT_TIMEOUT_MS,
    )
    if heartbeat_timing != expected_timing:
        raise RuntimeError(
            f"server advertised heartbeat timing {heartbeat_timing!r}, "
            f"expected {expected_timing!r}"
        )

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


def verify_trailing_data_is_rejected() -> None:
    sock = connect_tls(timeout=3)
    sock.settimeout(3)
    try:
        hwid = os.urandom(32).hex()
        sock.sendall(
            f"CHECKIN::{hwid}:{TEST_SECRET};EXTRA_FRAME;".encode("ascii")
        )
        frame, _ = recv_frame(sock, b"")
        if frame != "ERROR:INVALID_FORMAT":
            raise RuntimeError(
                f"server accepted bytes after the check-in terminator: {frame!r}"
            )
    finally:
        sock.close()


def verify_malformed_request_does_not_log_secret(server_binary: Path) -> None:
    sock = connect_tls(timeout=3)
    sock.settimeout(3)
    log_path = server_binary.parent / "violations.log"
    previous_log = log_path.read_bytes() if log_path.exists() else b""
    secret_marker = "SECRET_LEAK_SENTINEL_91C2"
    try:
        # A malformed TYPE forces the parser error path; the SECRET field must
        # not be copied into the server's persistent violation log.
        hwid = os.urandom(32).hex()
        sock.sendall(f"!::{hwid}:{secret_marker};".encode("ascii"))
        frame, _ = recv_frame(sock, b"")
        if frame != "ERROR:INVALID_FORMAT":
            raise RuntimeError(f"malformed request was not rejected: {frame!r}")
        if recv_closed(sock, 1) != b"":
            raise RuntimeError("server kept the malformed-request connection open")
    finally:
        sock.close()

    current_log = log_path.read_bytes() if log_path.exists() else b""
    if not current_log.startswith(previous_log):
        appended = current_log
    else:
        appended = current_log[len(previous_log):]
    if secret_marker.encode("ascii") in appended:
        raise RuntimeError("server logged the SECRET field from a malformed request")


def verify_incomplete_initial_frame_is_rejected() -> None:
    sock = connect_tls(timeout=3)
    sock.settimeout(8)
    hwid = os.urandom(32).hex()
    try:
        # Omit the final semicolon. The server must enforce its frame deadline
        # and must not answer with INVALID_FORMAT for a request never completed.
        sock.sendall(f"CHECKIN::{hwid}:".encode("ascii"))
        response = recv_closed(sock, 512)
        if response:
            raise RuntimeError(
                f"server replied to an incomplete initial frame: {response!r}"
            )
    except socket.timeout as exc:
        raise RuntimeError("server kept an incomplete initial frame open past its deadline") from exc
    finally:
        sock.close()


def verify_short_hwid_is_rejected() -> None:
    sock = connect_tls(timeout=3)
    sock.settimeout(3)
    try:
        # Production HWIDs are SHA-256 digests, never arbitrary short tokens.
        sock.sendall(f"CHECKIN::A:{TEST_SECRET};".encode("ascii"))
        frame, _ = recv_frame(sock, b"")
        if frame != "ERROR:INVALID_FORMAT":
            raise RuntimeError(f"server accepted a short HWID: {frame!r}")
    finally:
        sock.close()



def verify_missing_ban_list_is_rejected(ban_list_path: Path) -> None:
    # A missing ban list must not silently become an empty list.
    backup_path = ban_list_path.with_name(ban_list_path.name + ".integration-backup")
    if backup_path.exists():
        raise RuntimeError(f"stale ban-list backup exists: {backup_path}")
    ban_list_path.rename(backup_path)
    try:
        sock = connect_tls(timeout=3)
        sock.settimeout(3)
        try:
            hwid = os.urandom(32).hex()
            sock.sendall(f"CHECKIN::{hwid}:{TEST_SECRET};".encode("ascii"))
            frame, _ = recv_frame(sock, b"")
            if frame != "ERROR:BANLIST":
                raise RuntimeError(
                    f"server allowed check-in with an unreadable ban list: {frame!r}"
                )
            if recv_closed(sock, 1) != b"":
                raise RuntimeError("server kept the connection open after ban-list error")
        finally:
            sock.close()
    finally:
        backup_path.rename(ban_list_path)



def verify_weak_secret_is_rejected(server_binary: Path) -> None:
    env = os.environ.copy()
    env["OBLIVION_SECRET"] = "weak"
    result = subprocess.run(
        [str(server_binary)],
        cwd=str(server_binary.parent),
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
    )
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode == 0 or "32 dan 128 byte" not in output:
        raise RuntimeError(
            "server did not reject a short production secret before listening"
        )


def verify_overlong_secret_is_rejected(server_binary: Path) -> None:
    env = os.environ.copy()
    env["OBLIVION_SECRET"] = "x" * 129
    result = subprocess.run(
        [str(server_binary)],
        cwd=str(server_binary.parent),
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
    )
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode == 0 or "32 dan 128 byte" not in output:
        raise RuntimeError(
            "server did not reject a secret longer than the protocol's 128-byte limit"
        )



def verify_secret_delimiters_are_rejected(server_binary: Path) -> None:
    for delimiter in (":", ";"):
        env = os.environ.copy()
        env["OBLIVION_SECRET"] = TEST_SECRET + delimiter
        result = subprocess.run(
            [str(server_binary)],
            cwd=str(server_binary.parent),
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0 or "secret tidak boleh mengandung ':' atau ';'" not in output:
            raise RuntimeError(
                f"server did not reject a protocol delimiter in the secret: {delimiter!r}"
            )


def encode_protocol_details(details: str) -> str:
    # Percent must be encoded first so literal "%3A" remains literal after decoding.
    return "!OBLV1!" + details[:2048].replace("%", "%25").replace(":", "%3A").replace(";", "%3B")


def verify_violation_ack(server_binary: Path) -> None:
    sock = connect_tls(timeout=3)
    sock.settimeout(3)
    try:
        hwid = os.urandom(32).hex()
        raw_details = r"path=C:\Games\Ragnarok; marker=%3A; token=OBV-DETAIL-ROUNDTRIP-9173"
        report = f"TEST_VIOLATION:{encode_protocol_details(raw_details)}:{hwid}:{TEST_SECRET};"
        sock.sendall(report.encode("ascii"))
        frame, _ = recv_frame(sock, b"")
        if frame != "ACK":
            raise RuntimeError(
                f"server did not acknowledge an unbanned violation report: {frame!r}"
            )
        if recv_closed(sock, 1) != b"":
            raise RuntimeError("server did not close the violation-report connection")
        log_path = server_binary.parent / "violations.log"
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        if raw_details not in log_text:
            raise RuntimeError(f"server did not preserve escaped details in the log: {raw_details!r}")
    finally:
        sock.close()


def verify_plaintext_protocol_is_rejected() -> None:
    sock = socket.create_connection((HOST, PORT), timeout=3)
    sock.settimeout(3)
    try:
        hwid = os.urandom(32).hex()
        sock.sendall(f"CHECKIN::{hwid}:{TEST_SECRET};".encode("ascii"))
        try:
            response = sock.recv(512)
        except (ConnectionResetError, socket.timeout):
            response = b""
        if response.startswith((b"OK;", b"KICK;", b"ERROR:")):
            raise RuntimeError(
                f"server processed a plaintext protocol frame instead of requiring TLS: {response!r}"
            )
    finally:
        sock.close()


def verify_tls_handshake_deadline() -> None:
    sock = socket.create_connection((HOST, PORT), timeout=3)
    sock.settimeout(8)
    started = time.monotonic()
    try:
        # A peer that opens TCP but never sends a TLS ClientHello must be closed
        # by the server's bounded TLS-handshake timeout.
        try:
            sock.recv(512)
        except (ConnectionResetError, socket.timeout):
            pass
        elapsed = time.monotonic() - started
        if elapsed > 7.0:
            raise RuntimeError(f"TLS handshake deadline exceeded: {elapsed:.2f}s")
    finally:
        sock.close()


def verify_tls_client_pin_checks(
    probe_binary: Path,
    server_certificate: Path,
    server_ca_certificate: Path,
    tls_directory: Path,
) -> None:
    certificate_der = subprocess.run(
        ["openssl", "x509", "-in", str(server_certificate), "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    certificate_pin = hashlib.sha256(certificate_der).hexdigest()
    wrong_pin = ("0" if certificate_pin[0] != "0" else "1") + certificate_pin[1:]
    cases = [
        (HOST, certificate_pin, "accept", "valid certificate pin and IP SAN"),
        (HOST, wrong_pin, "reject", "wrong certificate pin"),
        ("wrong.invalid", certificate_pin, "reject", "hostname mismatch"),
    ]
    trusted_probe_env = os.environ.copy()
    trusted_probe_env["SSL_CERT_FILE"] = str(server_ca_certificate)
    trusted_probe_env["SSL_CERT_DIR"] = str(tls_directory / "empty-system-ca-dir")
    (tls_directory / "empty-system-ca-dir").mkdir(exist_ok=True)

    for expected_host, pin, expected_result, description in cases:
        result = subprocess.run(
            [str(probe_binary), HOST, expected_host, str(PORT), pin, expected_result],
            capture_output=True, text=True, timeout=8, env=trusted_probe_env,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"TLS client verification case failed ({description}): "
                f"exit={result.returncode}, stdout={result.stdout}, stderr={result.stderr}"
            )

    # Private deployments may pin a self-signed leaf as the explicit trust anchor.
    self_signed_key = tls_directory / "self-signed-valid.key"
    self_signed_cert = tls_directory / "self-signed-valid.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "2", "-keyout", str(self_signed_key), "-out", str(self_signed_cert),
        "-subj", "/CN=127.0.0.1",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
        "-addext", "subjectAltName=IP:127.0.0.1",
    ], check=True, capture_output=True, text=True)
    self_signed_der = subprocess.run(
        ["openssl", "x509", "-in", str(self_signed_cert), "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    self_signed_pin = hashlib.sha256(self_signed_der).hexdigest()
    self_signed_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    self_signed_context.load_cert_chain(
        certfile=str(self_signed_cert), keyfile=str(self_signed_key)
    )

    self_signed_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self_signed_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self_signed_listener.bind((HOST, 0))
    self_signed_listener.listen(1)
    self_signed_port = self_signed_listener.getsockname()[1]
    self_signed_errors: list[str] = []

    def serve_self_signed() -> None:
        try:
            connection, _ = self_signed_listener.accept()
            with connection:
                try:
                    with self_signed_context.wrap_socket(connection, server_side=True) as tls_socket:
                        tls_socket.settimeout(2)
                        try:
                            tls_socket.recv(1)
                        except (ssl.SSLError, OSError, socket.timeout):
                            pass
                except (ssl.SSLError, OSError):
                    pass
        except OSError as exc:
            self_signed_errors.append(str(exc))
        finally:
            self_signed_listener.close()

    self_signed_thread = threading.Thread(target=serve_self_signed, daemon=True)
    self_signed_thread.start()
    try:
        self_signed_env = os.environ.copy()
        # Remove the temporary test CA: the leaf is accepted only by its exact pin.
        self_signed_env["SSL_CERT_FILE"] = str(tls_directory / "empty-ca-file.pem")
        self_signed_env["SSL_CERT_DIR"] = str(tls_directory / "empty-ca-dir")
        (tls_directory / "empty-ca-file.pem").write_text("", encoding="ascii")
        (tls_directory / "empty-ca-dir").mkdir(exist_ok=True)
        result = subprocess.run(
            [str(probe_binary), HOST, HOST, str(self_signed_port), self_signed_pin, "accept"],
            capture_output=True, text=True, timeout=8, env=self_signed_env,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "TLS client rejected a valid pinned self-signed leaf: "
                f"exit={result.returncode}, stdout={result.stdout}, stderr={result.stderr}"
            )
    finally:
        self_signed_listener.close()
        self_signed_thread.join(timeout=3)
    if self_signed_thread.is_alive():
        raise RuntimeError("self-signed TLS test server thread did not stop")
    if self_signed_errors:
        raise RuntimeError("self-signed TLS test server failed: " + "; ".join(self_signed_errors))

    # X509_check_host() otherwise accepts the legacy Subject CN when the
    # certificate has no subjectAltName. Require DNS SAN explicitly.
    cn_key = tls_directory / "cn-only.key"
    cn_cert = tls_directory / "cn-only.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "2", "-keyout", str(cn_key), "-out", str(cn_cert),
        "-subj", "/CN=localhost",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
    ], check=True, capture_output=True, text=True)
    cn_der = subprocess.run(
        ["openssl", "x509", "-in", str(cn_cert), "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    cn_pin = hashlib.sha256(cn_der).hexdigest()
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile=str(cn_cert), keyfile=str(cn_key))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, 0))
    listener.listen(1)
    cn_only_port = listener.getsockname()[1]
    server_errors: list[str] = []

    def serve_cn_only_certificate() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                try:
                    with server_context.wrap_socket(connection, server_side=True) as tls_socket:
                        tls_socket.settimeout(2)
                        try:
                            tls_socket.recv(1)
                        except (ssl.SSLError, OSError, socket.timeout):
                            pass
                except (ssl.SSLError, OSError):
                    pass
        except OSError as exc:
            server_errors.append(str(exc))
        finally:
            listener.close()

    server_thread = threading.Thread(target=serve_cn_only_certificate, daemon=True)
    server_thread.start()
    try:
        result = subprocess.run(
            [str(probe_binary), HOST, "localhost", str(cn_only_port), cn_pin, "reject"],
            capture_output=True, text=True, timeout=8,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "TLS client accepted or failed to test a CN-only certificate without DNS SAN: "
                f"exit={result.returncode}, stdout={result.stdout}, stderr={result.stderr}"
            )
    finally:
        listener.close()
        server_thread.join(timeout=3)
    if server_thread.is_alive():
        raise RuntimeError("CN-only TLS test server thread did not stop")
    if server_errors:
        raise RuntimeError("CN-only TLS test server failed: " + "; ".join(server_errors))


    # CA-issued peers must chain to a trusted root in SSL_CERT_FILE/SSL_CERT_DIR.
    ca_key = tls_directory / "test-root-ca.key"
    ca_cert = tls_directory / "test-root-ca.pem"
    leaf_key = tls_directory / "ca-issued-leaf.key"
    leaf_csr = tls_directory / "ca-issued-leaf.csr"
    leaf_cert = tls_directory / "ca-issued-leaf.pem"
    leaf_extensions = tls_directory / "ca-issued-leaf.ext"
    rogue_ca_key = tls_directory / "rogue-root-ca.key"
    rogue_ca_cert = tls_directory / "rogue-root-ca.pem"
    empty_ca_directory = tls_directory / "empty-ca-directory"
    empty_ca_directory.mkdir(exist_ok=True)

    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "2", "-keyout", str(ca_key), "-out", str(ca_cert),
        "-subj", "/CN=Oblivion Integration Test Root CA",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
    ], check=True, capture_output=True, text=True)
    subprocess.run([
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-keyout", str(leaf_key), "-out", str(leaf_csr), "-subj", "/CN=localhost",
    ], check=True, capture_output=True, text=True)
    leaf_extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=IP:127.0.0.1,DNS:localhost\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n",
        encoding="ascii",
    )
    subprocess.run([
        "openssl", "x509", "-req", "-in", str(leaf_csr),
        "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
        "-days", "2", "-sha256", "-extfile", str(leaf_extensions),
        "-out", str(leaf_cert),
    ], check=True, capture_output=True, text=True)
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "2", "-keyout", str(rogue_ca_key), "-out", str(rogue_ca_cert),
        "-subj", "/CN=Unrelated Integration Root CA",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
    ], check=True, capture_output=True, text=True)

    leaf_der = subprocess.run(
        ["openssl", "x509", "-in", str(leaf_cert), "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    leaf_pin = hashlib.sha256(leaf_der).hexdigest()
    ca_server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca_server_context.load_cert_chain(certfile=str(leaf_cert), keyfile=str(leaf_key))

    def run_ca_certificate_case(trust_root: Path, expected: str, description: str) -> None:
        ca_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ca_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ca_listener.bind((HOST, 0))
        ca_listener.listen(1)
        ca_port = ca_listener.getsockname()[1]
        ca_server_errors: list[str] = []

        def serve_ca_certificate() -> None:
            try:
                connection, _ = ca_listener.accept()
                with connection:
                    try:
                        with ca_server_context.wrap_socket(connection, server_side=True) as tls_socket:
                            tls_socket.settimeout(2)
                            try:
                                tls_socket.recv(1)
                            except (ssl.SSLError, OSError, socket.timeout):
                                pass
                    except (ssl.SSLError, OSError):
                        pass
            except OSError as exc:
                ca_server_errors.append(str(exc))
            finally:
                ca_listener.close()

        ca_thread = threading.Thread(target=serve_ca_certificate, daemon=True)
        ca_thread.start()
        try:
            probe_env = os.environ.copy()
            probe_env["SSL_CERT_FILE"] = str(trust_root)
            probe_env["SSL_CERT_DIR"] = str(empty_ca_directory)
            result = subprocess.run(
                [str(probe_binary), HOST, HOST, str(ca_port), leaf_pin, expected],
                capture_output=True, text=True, timeout=8, env=probe_env,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"CA chain verification failed ({description}): "
                    f"exit={result.returncode}, stdout={result.stdout}, stderr={result.stderr}"
                )
        finally:
            ca_listener.close()
            ca_thread.join(timeout=3)
        if ca_thread.is_alive():
            raise RuntimeError(f"CA test server thread did not stop ({description})")
        if ca_server_errors:
            raise RuntimeError(
                f"CA test server failed ({description}): " + "; ".join(ca_server_errors)
            )

    run_ca_certificate_case(ca_cert, "accept", "leaf chains to configured trusted root")
    run_ca_certificate_case(rogue_ca_cert, "reject", "leaf issuer is not in configured trust store")


def verify_missing_tls_certificate_is_rejected(server_binary: Path) -> None:
    # Startup must fail before listening if no server certificate/key can be loaded.
    with tempfile.TemporaryDirectory(prefix="oblivion-no-tls-cert-") as directory:
        env = os.environ.copy()
        env["OBLIVION_SECRET"] = TEST_SECRET
        env["OBLIVION_TLS_CERT_FILE"] = str(Path(directory) / "missing-cert.pem")
        env["OBLIVION_TLS_KEY_FILE"] = str(Path(directory) / "missing-key.pem")
        result = subprocess.run(
            [str(server_binary)],
            cwd=directory,
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0:
            raise RuntimeError("server started successfully without a TLS certificate/key pair")
        if (
            "TLS initialization failed" not in output
            and "Cannot resolve TLS certificate/key paths" not in output
            and "Cannot inspect TLS private key permissions" not in output
        ):
            raise RuntimeError(
                "server failed without a TLS certificate/key pair for an unexpected reason: "
                f"exit={result.returncode}, output={output!r}"
            )

def verify_insecure_tls_private_key_is_rejected(
    server_binary: Path, server_certificate: Path, server_key: Path
) -> None:
    # Runtime policy must agree with production-check: group/world-accessible key
    # material is a deployment error, not something to warn about and continue.
    original_mode = stat.S_IMODE(server_key.stat().st_mode)
    try:
        server_key.chmod((original_mode & ~0o077) | 0o640)
        env = os.environ.copy()
        env["OBLIVION_SECRET"] = TEST_SECRET
        env["OBLIVION_TLS_CERT_FILE"] = str(server_certificate)
        env["OBLIVION_TLS_KEY_FILE"] = str(server_key)
        result = subprocess.run(
            [str(server_binary)],
            cwd=str(server_key.parent),
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0:
            raise RuntimeError("server accepted a TLS private key readable by the group")
        if "TLS private key permissions expose the key to group/other users" not in output:
            raise RuntimeError(
                "server rejected an insecure TLS key for an unexpected reason: "
                f"exit={result.returncode}, output={output!r}"
            )
    finally:
        server_key.chmod(original_mode)


def run_integration(server_binary: Path, tls_probe_binary: Path) -> None:
    global TLS_CONTEXT
    verify_weak_secret_is_rejected(server_binary)
    verify_overlong_secret_is_rejected(server_binary)
    verify_secret_delimiters_are_rejected(server_binary)
    verify_missing_tls_certificate_is_rejected(server_binary)

    tls_temporary = tempfile.TemporaryDirectory(prefix="oblivion-tls-test-")
    tls_directory = Path(tls_temporary.name)
    ca_key = tls_directory / "test-ca.key"
    ca_cert = tls_directory / "test-ca.pem"
    server_key = tls_directory / "server.key"
    server_csr = tls_directory / "server.csr"
    server_cert = tls_directory / "server.pem"
    extensions = tls_directory / "server-ext.cnf"

    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "2", "-keyout", str(ca_key), "-out", str(ca_cert),
        "-subj", "/CN=Oblivion Integration Test CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    ], check=True, capture_output=True, text=True)
    subprocess.run([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-keyout", str(server_key), "-out", str(server_csr),
        "-subj", "/CN=127.0.0.1",
    ], check=True, capture_output=True, text=True)
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=IP:127.0.0.1,DNS:localhost\n",
        encoding="ascii",
    )
    subprocess.run([
        "openssl", "x509", "-req", "-in", str(server_csr),
        "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(server_cert), "-days", "2", "-sha256",
        "-extfile", str(extensions),
    ], check=True, capture_output=True, text=True)

    TLS_CONTEXT = ssl.create_default_context(cafile=str(ca_cert))
    TLS_CONTEXT.check_hostname = True

    verify_insecure_tls_private_key_is_rejected(server_binary, server_cert, server_key)

    ban_list_path = server_binary.parent / "bans.txt"
    original_ban_list = ban_list_path.read_bytes() if ban_list_path.exists() else None
    # Use a deterministic empty list for the integration test; restore any local
    # file after the server has exited.
    ban_list_path.write_text("# isolated integration-test ban list\n", encoding="ascii")

    env = os.environ.copy()
    env["OBLIVION_SECRET"] = TEST_SECRET
    env["OBLIVION_TLS_CERT_FILE"] = str(server_cert)
    env["OBLIVION_TLS_KEY_FILE"] = str(server_key)
    env["OBLV_HB_INTERVAL_MS"] = str(TEST_HEARTBEAT_INTERVAL_MS)
    env["OBLV_HB_JITTER_MS"] = str(TEST_HEARTBEAT_JITTER_MS)
    env["OBLV_HB_TIMEOUT_MS"] = str(TEST_HEARTBEAT_TIMEOUT_MS)
    env["OBLV_HB_MAX_MISS"] = "2"
    env["OBLV_HB_RTT_WARN_MS"] = "60000"

    # Start outside the executable directory and place a decoy ban list in the
    # working directory. The server must always use the executable-adjacent file.
    working_directory = Path(tempfile.mkdtemp(prefix="oblivion-working-dir-"))
    (working_directory / "bans.txt").write_text(
        "# decoy: must never be used as the server ban list\n", encoding="ascii"
    )

    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as server_log:
        process = subprocess.Popen(
            [str(server_binary)],
            cwd=str(working_directory),
            env=env,
            stdout=server_log,
            stderr=subprocess.STDOUT,
        )
        sockets: list[socket.socket] = []
        try:
            # Readiness probe is closed immediately; otherwise its 5-second
            # handshake deadline would expire while the other test cases run.
            ready = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ready.settimeout(4)
            deadline = time.monotonic() + 12
            while True:
                try:
                    ready.connect((HOST, PORT))
                    break
                except OSError:
                    if process.poll() is not None:
                        raise RuntimeError("server exited before accepting a connection")
                    if time.monotonic() >= deadline:
                        raise RuntimeError("server did not start listening on port 54321")
                    time.sleep(0.1)
            ready.close()

            verify_trailing_data_is_rejected()
            verify_plaintext_protocol_is_rejected()
            verify_tls_handshake_deadline()
            verify_tls_client_pin_checks(tls_probe_binary, server_cert, ca_cert, tls_directory)
            verify_malformed_request_does_not_log_secret(server_binary)
            verify_incomplete_initial_frame_is_rejected()
            verify_short_hwid_is_rejected()
            verify_missing_ban_list_is_rejected(ban_list_path)
            verify_violation_ack(server_binary)

            good = connect_tls(timeout=4)
            good.settimeout(4)
            sockets.append(good)
            good_hwid = os.urandom(32).hex()  # HWID protocol accepts exactly 64 hexadecimal SHA-256 characters
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

            bad = connect_tls(timeout=3)
            bad.settimeout(3)
            sockets.append(bad)
            bad_hwid = os.urandom(32).hex()  # HWID protocol accepts hex characters and dashes only
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

            # SIGTERM must stop accepting, wake the active heartbeat socket,
            # wait for its worker to exit, and release server resources cleanly.
            shutdown_client = connect_tls(timeout=3)
            shutdown_client.settimeout(8)
            sockets.append(shutdown_client)
            shutdown_hwid = os.urandom(32).hex()
            _, shutdown_buffer = authenticate(shutdown_client, shutdown_hwid)
            _, shutdown_buffer = recv_ping(shutdown_client, shutdown_buffer)
            process.send_signal(signal.SIGTERM)
            shutdown_response = recv_closed(shutdown_client, 1)
            if shutdown_response:
                raise RuntimeError(
                    f"server sent unexpected data during graceful shutdown: {shutdown_response!r}"
                )
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("server did not finish graceful shutdown within 8 seconds") from exc
            if process.returncode != 0:
                raise RuntimeError(
                    f"server returned {process.returncode} instead of clean exit code 0 on SIGTERM"
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

            if original_ban_list is None:
                try:
                    ban_list_path.unlink()
                except FileNotFoundError:
                    pass
            else:
                ban_list_path.write_bytes(original_ban_list)
            shutil.rmtree(working_directory, ignore_errors=True)
        tls_temporary.cleanup()
        TLS_CONTEXT = None

        if process.returncode not in (0, -signal.SIGTERM, 128 + signal.SIGTERM):
            server_log.seek(0)
            log_tail = server_log.read()[-5000:]
            raise RuntimeError(
                f"server exited unexpectedly with code {process.returncode}\n{log_tail}"
            )


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: heartbeat_integration.py PATH_TO_SERVER PATH_TO_TLS_PROBE", file=sys.stderr)
        return 2
    server_binary = Path(sys.argv[1]).resolve()
    tls_probe_binary = Path(sys.argv[2]).resolve()
    if not server_binary.is_file():
        print(f"Server binary not found: {server_binary}", file=sys.stderr)
        return 2
    if not tls_probe_binary.is_file():
        print(f"TLS probe binary not found: {tls_probe_binary}", file=sys.stderr)
        return 2
    try:
        run_integration(server_binary, tls_probe_binary)
    except Exception as exc:
        print(f"Heartbeat TLS integration test: FAIL: {exc}", file=sys.stderr)
        return 1
    print("Heartbeat TLS integration test: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
