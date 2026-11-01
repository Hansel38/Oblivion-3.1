# Oblivion Server - Linux Build Guide

> **Transport security:** this build requires TLS 1.2 or newer for every client connection.
> Plaintext protocol frames are not accepted. The client verifies the certificate validity period,
> server-auth certificate purpose, endpoint hostname/IP SAN, and a configured SHA-256 pin of
> the leaf certificate before sending check-in/report data. Keep the private key secret, distribute
> the certificate pin through a trusted deployment channel, and do not treat a writable local
> oblivion.cfg as tamper-proof policy. The shared secret is still embedded/loaded by the client
> and can be recovered by local reverse engineering; TLS protects it in transit, not at rest or
> against a compromised client. Load-test and validate false-positive behavior with the actual
> Ragnarok client/server setup before declaring a deployment production-ready.


## Requirements

### Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev
```

### Dependencies
- g++ (C++17 compiler)
- OpenSSL development libraries (libssl-dev)
- pthread (usually included with g++)

### Windows client/server TLS dependency

The Windows Visual Studio projects now link OpenSSL through vcpkg. Install vcpkg and OpenSSL using the same triplet used by the project, then set the VCPKG_ROOT environment variable before opening/building the solution:

~~~powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg.exe install openssl:x64-windows-static-md
$env:VCPKG_ROOT = 'C:\vcpkg'
msbuild Oblivion.sln /m /p:Configuration=Release /p:Platform=x64
~~~

The current CI builds Release x64 and installs this OpenSSL triplet automatically. Production clients must also be provisioned with the matching certificate pin described below; successfully compiling TLS support does not establish trust by itself.
## Build Instructions

### 1. Navigate to server directory
```bash
cd server
```

### 2. Build the server
```bash
make
```

### 3. Make management script executable and fix line endings
```bash
# Install dos2unix (if not already installed)
sudo apt-get install -y dos2unix

# Fix Windows line endings (if transferred from Windows)
dos2unix oblivion-start

# Make executable
chmod +x oblivion-start

# Test the script
./oblivion-start
```

**Note:** If you get "bad interpreter" error, it means the file has Windows line endings (CRLF). Run `dos2unix oblivion-start` to fix it.

### 4. Run the server

**Option A: Using management script (recommended)**
```bash
# Interactive mode (shows usage and prompts for input)
./oblivion-start

# Or with command directly
./oblivion-start start
```

**Option B: Run directly**
```bash
./oblivion-server
```

## Configuration

### Environment Variables
You can configure heartbeat settings via environment variables:

```bash
export OBLV_HB_INTERVAL_MS=3000
export OBLV_HB_JITTER_MS=250
export OBLV_HB_TIMEOUT_MS=4000
export OBLV_HB_MAX_MISS=3
export OBLV_HB_RTT_WARN_MS=1500
./oblivion-server
```

### TLS certificate and client pin (required)

The server fails to start if it cannot load a matching TLS certificate and private key. By default it looks for these files next to the server executable:

- **server-cert.pem** — server certificate in PEM format.
- **server-key.pem** — private key in PEM format; restrict file permissions (on Linux, use **chmod 600 server-key.pem**).

The installer now refuses a fresh install if it cannot find a certificate/key pair. If the pair is beside the Makefile, run `make install` and it is copied beside the installed binary (private key mode 0600). To copy a pair from another location, use `make install TLS_CERT_FILE=/secure/path/server-cert.pem TLS_KEY_FILE=/secure/path/server-key.pem`. Existing installed cert/key files are preserved when no source pair is supplied. If the service uses external paths instead, configure both `OBLIVION_TLS_CERT_FILE` and `OBLIVION_TLS_KEY_FILE` in the service environment before installing and starting the server.

For a DNS endpoint such as shield.example.com, the certificate Subject Alternative Name (SAN) must include that DNS name. For a fixed IP endpoint, the certificate needs an IP SAN for the configured IP address. The server prints the leaf-certificate SHA-256 fingerprint at startup.

Example for a DNS endpoint (use your real server name):

~~~bash
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
  -keyout server-key.pem -out server-cert.pem \
  -subj "/CN=shield.example.com" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=DNS:shield.example.com"

chmod 600 server-key.pem
openssl x509 -in server-cert.pem -outform DER | openssl dgst -sha256
~~~

Configure the client to pin the SHA-256 fingerprint shown by the server / calculated above. The value is 64 hexadecimal characters (without the SHA2-256(stdin)= prefix). Copy the pin to the client through a trusted deployment channel.

Example oblivion.cfg:

~~~ini
server=shield.example.com:54321
tls_pin_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
~~~

Alternatively set **OBLIVION_TLS_PIN_SHA256**. It overrides the file setting. Multiple SHA-256 leaf pins may be listed, separated by comma, semicolon, or whitespace, to permit certificate rotation. Each pin must be exactly 64 hex characters; an invalid or missing pin prevents a production client from connecting.

The server accepts these optional variables to select certificate and key files:
- **OBLIVION_TLS_CERT_FILE**
- **OBLIVION_TLS_KEY_FILE**

A relative certificate/key path is resolved relative to the server executable directory; absolute paths are also accepted. The client checks hostname/IP SAN and certificate validity in addition to the pin. During certificate renewal, install a new certificate and distribute its pin before removing the old pin from clients.

### Server Secret
Server harus memakai secret yang sama dengan client. Atur secret produksi melalui salah satu cara berikut:
Buat nilai acak yang kuat dengan panjang 32 sampai 128 byte dan tanpa karakter ':' atau ';'. Server dan client menolak secret
kosong, development fallback, terlalu pendek, melebihi batas protokol, atau mengandung delimiter protokol. Gunakan nilai yang sama
pada kedua sisi:

```bash
openssl rand -hex 32
```

1. **Environment variable** (recommended):
   ```bash
   export OBLIVION_SECRET="PASTE_THE_SAME_RANDOM_SECRET_HERE"
   ./oblivion-server
   ```

2. **File-based** (secret.dat):
   **PENTING:** Jika environment variable dan `secret.dat` tidak tersedia, kode memakai
   secret development `DEV_SECRET_NOT_SET`; server sekarang menolak startup dengan nilai ini.
   Jangan pernah memakai nilai development tersebut di produksi.
   - Create a file named `secret.dat` in the same directory as the server executable
   - The file should contain XOR-encoded secret (same format as Windows version)

### Production release preflight (required)

The Visual Studio Release configurations for both Win32/x86 and x64 now define
`OBLIVION_PRODUCTION_BUILD=1` and `OBLIVION_ENFORCE_FILE_INTEGRITY=1`.
They will fail closed at startup when any integrity hash is a placeholder. Debug
builds remain report-only for development. Do not distribute a Release client
until its manifest is generated from the exact package and the preflight below
passes.

1. Generate the manifest from the exact folder that will be shipped. Run from the repository root:

   ```powershell
   python tools/generate_integrity_manifest.py "D:\\Builds\\Ragnarok-Package"
   ```

2. If `RRO.exe`, `en.grf`, or `DATA.ini` is larger than 512 MiB, review performance and raise
   `OBLIVION_MAX_HASH_FILE_SIZE_BYTES` in both Release configurations to a measured, acceptable
   value. The runtime refuses to enforce files over that limit.

3. Run the release preflight. The certificate must be a PEM leaf certificate whose SAN matches
   the configured DNS name/IP, is currently valid, and whose SHA-256 fingerprint appears in the
   pin list distributed to the client:

   ```bash
   make -C server production-check \\
     OBLIVION_PRODUCTION_GAME_DIR="/absolute/path/to/the/exact/game-package" \\
     OBLIVION_SERVER_HOST="shield.example.com" \\
     OBLIVION_TLS_PIN_SHA256="paste-the-real-64-hex-leaf-pin" \\
     TLS_CERT_FILE="/absolute/path/to/server-cert.pem"
   ```

The preflight refuses placeholders, malformed digests, package/hash mismatches, file sizes above
the configured runtime cap, missing Release enforcement flags, invalid or mismatched TLS pins,
expired/not-yet-valid certificates, and missing or mismatched hostname/IP SANs. It does not
replace a live Windows smoke test, production server load test, or Authenticode code signing.

## Client Protection Status (Heartbeat PONG)

Setiap PONG dari client membawa bit status lapisan pengaman:

```
PONG:<seq>:<ts_client>:<nonce>:<antiSuspendOk>|<integrityOk>:<hwid>:<hmac>;
```

- `1|1` — anti-suspend guard dan self-integrity guard client berjalan normal
- selain `1|1` — ada lapisan pengaman client yang tidak berjalan

Server hanya **mencatat** kondisi ini (tidak langsung kick) supaya gangguan lokal tidak
menghukum pemain sah:

- console: `[HB] PROTECTION DEGRADED for HWID [<hwid>] status=0|1`
- `violations.log`: entri `HB_PROTECTION_DEGRADED`
- status heartbeat ditandai `WARNING` selama kondisi berlangsung, dan kembali `HEALTHY`
  setelah client melaporkan `1|1` lagi (`[HB] PROTECTION RECOVERED`)

Pelanggaran yang benar-benar terdeteksi tetap diverifikasi server dan dijawab `KICK;`.

### Client-side configuration (oblivion.cfg / environment)

Client Oblivion dapat diarahkan ke VPS tanpa recompile. Urutan prioritas:
environment variable → `oblivion.cfg` (folder executable) → default di kode.

```ini
# oblivion.cfg
server=your-vps.example.com:54321
server=103.150.1.10:54321     # endpoint cadangan (opsional, dicoba berurutan)
port=54321                    # port default bila spec tidak memuat port
fail_mode=closed              # build produksi selalu fail-closed
connect_timeout_ms=3000
retry_count=3
handshake_timeout_ms=4000
```

| Environment variable | Arti |
| --- | --- |
| `OBLIVION_SERVER` / `OBLIVION_SERVERS` | daftar `host:port` dipisah koma |
| `OBLIVION_PORT` | port default untuk spec tanpa port |
| `OBLIVION_FAIL_MODE` | konfigurasi fail-mode; build produksi memaksa `closed` |
| `OBLIVION_CONNECT_TIMEOUT_MS` | timeout connect per endpoint (500–30000 ms) |
| `OBLIVION_RETRY_COUNT` | jumlah putaran percobaan seluruh endpoint (1–10) |
| `OBLIVION_HANDSHAKE_TIMEOUT_MS` | timeout menunggu respons check-in (500–30000 ms) |
| `OBLIVION_TLS_PIN_SHA256` | daftar pin SHA-256 sertifikat server (wajib pada client produksi) |

Catatan kebijakan produksi:
- Build Release memaksa `fail_mode=closed`; konfigurasi `open` tidak dapat menonaktifkan pemeriksaan ban.
- Fail-open hanya tersedia bila developer secara eksplisit mengompilasi build development dengan
  `OBLIVION_ALLOW_NETWORK_FAIL_OPEN=1`. Jangan aktifkan macro ini pada build produksi.
- Kegagalan jaringan dicatat lokal di `oblivion_client_errors.log`; client produksi berhenti
  bila check-in atau heartbeat tidak dapat diverifikasi.

## Files

- `bans.txt` - Ban list (one HWID per line, comments with #)
- `violations.log` - Log of all violations detected
- `secret.dat` - Optional: XOR-encoded server secret

**Ban-list availability is required for check-in.** If `bans.txt` is missing or unreadable,
the server now refuses check-in with `ERROR:BANLIST;` instead of treating every HWID as
not banned. Keep the file next to the server executable and make it readable by the server
process. An empty list can contain only comments. `make install` installs the initial list
to `/usr/local/bin/bans.txt` only when no list already exists; updates preserve the
administrator's existing ban list.

## Server Management Script

The `oblivion-start` script provides easy server management with interactive mode:

### Interactive Mode
```bash
# Run without arguments to enter interactive mode
./oblivion-start
# Output:
# Usage: ./oblivion-start { start | stop | restart | status | watch | help | log }
# Enter a valid option: 
```

### Direct Commands
```bash
# Start server
./oblivion-start start

# Stop server
./oblivion-start stop

# Restart server
./oblivion-start restart

# Check status
./oblivion-start status

# View log (last 50 lines)
./oblivion-start log

# View live log (follow mode)
./oblivion-start watch
# or
./oblivion-start log tail

# Show help
./oblivion-start help
```

### Status Output
The status command shows:
- Server running status (RUNNING/STOPPED)
- Process ID (PID)
- Port listening status
- Recent log entries
- Process information

## Running as a Service

### Using systemd (recommended)

Create `/etc/systemd/system/oblivion-server.service`:

```ini
[Unit]
Description=Oblivion Hack Shield Server
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/server
ExecStart=/path/to/server/oblivion-server
Restart=always
RestartSec=10
Environment="OBLIVION_SECRET=your-secret-key"

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable oblivion-server
sudo systemctl start oblivion-server
sudo systemctl status oblivion-server
```

## Troubleshooting

### Port already in use
If port 54321 is already in use, you can change it by modifying `DEFAULT_PORT` in `server_linux.cpp` or use a port forwarder.

### Permission denied
Make sure the server executable has execute permissions:
```bash
chmod +x oblivion-server
```

### SSL library not found
Install OpenSSL development package:
```bash
sudo apt-get install libssl-dev
```

## Clean Build

To clean build artifacts:
```bash
make clean
```

## Notes

- The server listens on port 54321 by default
- All logs and ban files are created in the same directory as the executable
- The server supports multiple concurrent client connections
- Heartbeat monitoring is enabled by default

