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
sudo apt-get install -y build-essential libssl-dev libyaml-cpp-dev
```

### Dependencies
- g++ (C++17 compiler)
- OpenSSL development libraries (libssl-dev)
- yaml-cpp YAML parser (libyaml-cpp-dev)
- pthread (usually included with g++)

### Windows client/server TLS dependency

The Windows Visual Studio projects link OpenSSL and yaml-cpp through vcpkg. Install both packages using the same triplet used by the project, then set the VCPKG_ROOT environment variable before opening/building the solution:

~~~powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg.exe install openssl:x64-windows-static-md yaml-cpp:x64-windows-static-md
$env:VCPKG_ROOT = 'C:\vcpkg'
msbuild Oblivion.sln /m /p:Configuration=Release /p:Platform=x64
~~~

The current CI builds Release x86 and x64 and installs the OpenSSL and yaml-cpp triplets automatically. Production clients must also be provisioned with the matching certificate pin described below; successfully compiling TLS support does not establish trust by itself.
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

### YAML runtime configuration

The server reads `oblivion-server.yaml` beside the executable. A default, editable file is included at `server/oblivion-server.yaml`; `make install` copies it next to the installed binary only when no existing config is present. Existing operator edits are preserved during subsequent installs.

The supported sections are:
- `server.bind_address`: IPv4 address to bind to; `0.0.0.0` listens on all local IPv4 interfaces.
- `server.listen_port`: TCP listener port from 1 to 65535 (default `54321`).
- `tls.certificate_file` and `tls.private_key_file`: relative paths beside the server executable or absolute paths.
- `heartbeat.*`: bounded heartbeat interval, jitter, timeout, miss threshold, and RTT warning threshold.

Example:

```yaml
version: 1
server:
  bind_address: "0.0.0.0"
  listen_port: "54321"
tls:
  certificate_file: "server-cert.pem"
  private_key_file: "server-key.pem"
heartbeat:
  interval_ms: 3000
  jitter_ms: 250
  timeout_ms: 4000
  max_consecutive_misses: 3
  rtt_warn_ms: 1500
```

Malformed YAML, unsupported keys, out-of-range values, and files larger than 64 KiB cause startup/configuration failure rather than silently using an unsafe value. Environment variables remain available to override supported fields. **Never put the shared secret or TLS private key contents in YAML**; keep `OBLIVION_SECRET` in the environment or the protected `secret.dat`, and keep the TLS private key as a separate file with mode `0600`.

### Client YAML configuration

Copy `client/oblivion.yaml.example` to `oblivion.yaml` in the directory containing the Ragnarok executable. Then edit only the server endpoint and connection parameters:

```yaml
version: 1
server:
  default_port: 54321
  # Configure real DNS/IP endpoints for the deployment.
  endpoints: []
connection:
  connect_timeout_ms: 3000
  retry_count: 3
  handshake_timeout_ms: 4000
policy:
  fail_closed: true
```

The client can read multiple entries in `server.endpoints` and tries them in order. Prefer a stable DNS hostname pointing to the VPS instead of hard-coding a changing public IP.

**Release trust boundary:** `oblivion.yaml` can select the hostname and port, but it cannot change the TLS certificate pin. Release builds always use the pin compiled into the client and verify the certificate validity, server-auth purpose, and hostname/IP SAN. An endpoint that does not present the pinned leaf certificate with a matching SAN is rejected. The `tls.pin_sha256` field is for Debug/development builds only; Release ignores it. When rotating the server certificate, provision the new pin into the client build before removing the old pin.

If no YAML file exists, development builds may use the legacy INI/environment configuration. Release uses the provisioned compiled endpoint only when no valid runtime YAML endpoint is configured; every runtime endpoint still must match the compiled certificate pin and certificate SAN. A malformed YAML file is logged and does not weaken TLS verification. There is no implicit localhost/public-IP fallback in the client.

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

For a DNS endpoint, the certificate Subject Alternative Name (SAN) must include the exact DNS name configured by the operator. For a fixed IP endpoint, the certificate needs an IP SAN for the configured IP address. The server prints the leaf-certificate SHA-256 fingerprint at startup.

### VPS listen address, TCP port, and client endpoint

The server binds to the local wildcard address (not to a hard-coded public IP), so a VPS public IP does not need to be entered on the server itself. The default listener is TCP port `54321`. You can override the port without editing the source:

```bash
export OBLIVION_LISTEN_PORT=54321
./oblivion-server
```

Set `OBLIVION_LISTEN_PORT` in your systemd service environment when running the server as a service. The value must be a decimal TCP port from 1 to 65535. The client endpoint must use the same port.

Allow the port through **both** the VPS provider's network/security firewall and the operating-system firewall. On Ubuntu/Debian with UFW, for example:

```bash
sudo ufw allow 54321/tcp
sudo ufw status
sudo ss -lntp | grep ':54321'
```

In the client Release build, configure the reachable public DNS name (recommended) or public IP and the matching TLS leaf-certificate SHA-256 pin in the generated production header. For example, run from the repository root after the server certificate is installed:

```bash
openssl x509 -in server/server-cert.pem -outform DER | sha256sum
: "${OBLIVION_PRODUCTION_SERVER_ENDPOINTS:?set real DNS/IP endpoints before building Release}"
: "${OBLIVION_TLS_PIN_SHA256:?set real SHA-256 leaf-certificate pin(s) before building Release}"
python3 tools/generate_production_network_config.py \
  --server-endpoints "$OBLIVION_PRODUCTION_SERVER_ENDPOINTS" \
  --tls-pin-sha256 "$OBLIVION_TLS_PIN_SHA256"
```

Provide the real endpoint list and matching leaf-certificate pin list through the required environment variables before generating the header. The certificate SAN must match every endpoint in the generated policy. Rebuild the Windows client after changing the compiled fallback endpoint or pins. Release ignores endpoint and pin overrides in `oblivion.cfg`; runtime YAML endpoints are still constrained by the compiled pin and SAN validation.

Changing the port requires updating the VPS firewall and regenerating/rebuilding the client endpoint configuration with the same port. The anti-cheat listener uses TCP, not UDP.

Create a self-signed certificate for the configured DNS hostname (for production, use a certificate issued by your chosen CA):

~~~bash
: "${OBLIVION_SERVER_HOST:?set the actual DNS hostname used by clients}"
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
  -keyout server-key.pem -out server-cert.pem \
  -subj "/CN=$OBLIVION_SERVER_HOST" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=DNS:$OBLIVION_SERVER_HOST"

chmod 600 server-key.pem
openssl x509 -in server-cert.pem -outform DER | openssl dgst -sha256
~~~

Configure the client to pin the SHA-256 fingerprint shown by the server / calculated above. The value is 64 hexadecimal characters (without the SHA2-256(stdin)= prefix). Copy the pin to the client through a trusted deployment channel.

In the local development-only `oblivion.cfg`, set `server=` entries to actual endpoint values. Do not commit deployment-specific endpoints or TLS pin values.

In Debug/development builds, **OBLIVION_TLS_PIN_SHA256** can override the local pin setting. Release ignores file/environment pin values and always uses the generated, compiled trust policy. Multiple SHA-256 leaf pins may be listed, separated by comma, semicolon, or whitespace, to permit certificate rotation. Each pin must be exactly 64 hex characters; an invalid or missing pin prevents a production client from connecting.

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
   read -rsp "OBLIVION_SECRET: " OBLIVION_SECRET
   echo
   export OBLIVION_SECRET
   ./oblivion-server
   ```

2. **File-based** (secret.dat):
   **PENTING:** Jika environment variable dan `secret.dat` tidak tersedia, kode memakai
   secret development `DEV_SECRET_NOT_SET`; server sekarang menolak startup dengan nilai ini.
   Jangan pernah memakai nilai development tersebut di produksi.
   - Create a file named `secret.dat` in the same directory as the server executable
   - The file should contain XOR-encoded secret (same format as Windows version)

### Production release preflight (required)

The Visual Studio Release configurations for both Win32/x86 and x64 define
`OBLIVION_PRODUCTION_BUILD=1` and `OBLIVION_ENFORCE_FILE_INTEGRITY=1`.
Release builds require both a provisioned compile-time network policy and a
real compile-time integrity manifest. The client fails to compile when
`production_network_config.generated.h` has `OBLIVION_PRODUCTION_NETWORK_CONFIG_READY 0`
or any integrity hash is not exactly 64 hexadecimal digits. The unprovisioned templates
are deliberate. Never ship them or the disposable `ci.invalid` endpoint/hash manifest
used by compile-only CI. Validly formatted hashes can still refer to a different package;
the production preflight compares them with the exact shipped files, and the runtime
enforcement detects mismatches after launch.

1. Generate the production endpoint/pin header from the real deployment. Include every
   endpoint the client will be allowed to contact; each endpoint must have a valid TLS
   certificate SAN and the corresponding leaf-certificate pin must be in the pin list.
   Run from the repository root:

   ```powershell
   $env:OBLIVION_PRODUCTION_SERVER_ENDPOINTS = Read-Host "Actual DNS/IP endpoint(s), comma-separated"
   $env:OBLIVION_TLS_PIN_SHA256 = Read-Host "Actual SHA-256 leaf-certificate pin(s), comma-separated"
   if ([string]::IsNullOrWhiteSpace($env:OBLIVION_PRODUCTION_SERVER_ENDPOINTS) -or
       [string]::IsNullOrWhiteSpace($env:OBLIVION_TLS_PIN_SHA256)) { throw "Endpoint and TLS pin values are required" }
   python tools/generate_production_network_config.py \\
     --server-endpoints $env:OBLIVION_PRODUCTION_SERVER_ENDPOINTS \\
     --tls-pin-sha256 $env:OBLIVION_TLS_PIN_SHA256
   ```

   Enter actual DNS/IP endpoints and the certificate pin list for the deployed service.
   Changes to production endpoints or pins require regenerating the header and rebuilding
   Release x86/x64. Release ignores endpoint and TLS-pin overrides in `oblivion.cfg` and
   environment variables; Debug builds retain these overrides for development.

2. Generate the integrity manifest from the exact folder that will be distributed:

   ```powershell
   python tools/generate_integrity_manifest.py "D:\\Builds\\Ragnarok-Package"
   ```

   Do not edit the generated SHA-256 values manually. A Release build with a placeholder,
   malformed, or missing digest fails at compile time. The release preflight additionally
   hashes the exact packaged files and refuses any mismatch. If `RRO.exe`, `en.grf`, or
   `DATA.ini` is larger than 512 MiB, review startup performance and raise
   `OBLIVION_MAX_HASH_FILE_SIZE_BYTES` in both Release configurations only after measuring
   a suitable cap. The runtime refuses to enforce a monitored file over that limit and
   checks that the file stayed stable while it was hashed.

3. Run the release preflight with the same endpoint, TLS pin, and certificate/private-key pair
   that will be deployed. The certificate must have serverAuth EKU, a SAN matching every compiled
   endpoint, a current validity window, and a leaf fingerprint present in the compiled pin list.
   On POSIX, the private key must not be readable by group/other users (`chmod 600`).

   ```bash
   make -C server production-check \\
     OBLIVION_PRODUCTION_GAME_DIR="$OBLIVION_PRODUCTION_GAME_DIR" \\
     OBLIVION_SERVER_HOST="$OBLIVION_SERVER_HOST" \\
     OBLIVION_TLS_PIN_SHA256="$OBLIVION_TLS_PIN_SHA256" \\
     TLS_CERT_FILE="$TLS_CERT_FILE" \\
     TLS_KEY_FILE="$TLS_KEY_FILE"
   ```

The preflight rejects placeholder/malformed hashes, package/hash mismatches, missing or
unprovisioned network policy, endpoints not in the compiled list, mismatched pins, oversized
files, missing Release enforcement, an invalid/mismatched or overly permissive TLS private key,
a certificate without serverAuth EKU, expired/not-yet-valid certificates, or missing/mismatched
DNS/IP SANs. A passing preflight still does not replace a live Windows smoke test, packet-loss/
reconnect tests, a production server load test, or Authenticode code signing.

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

Debug/development clients can be pointed at a test VPS without recompiling. Release builds
use the compile-time endpoint and TLS-pin policy generated above; `server`, `servers`,
`host`, `OBLIVION_SERVER`, `OBLIVION_SERVERS`, `OBLIVION_PORT`, and
`OBLIVION_TLS_PIN_SHA256` cannot redirect production check-in or replace the production pin.
Runtime YAML may select a different endpoint only when the endpoint certificate passes the compiled pin and SAN checks. To change the compiled fallback endpoint or pin list, regenerate the network header and rebuild/distribute a new client.

```ini
# oblivion.cfg
# Deployment-specific server endpoints are intentionally not included in this example.
port=54321                    # default port when an endpoint omits the port
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
| `OBLIVION_TLS_PIN_SHA256` | Debug/dev override; Release memakai pin yang dikompilasi dari generated header |

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
EnvironmentFile=/etc/oblivion/oblivion.env

[Install]
WantedBy=multi-user.target
```

Create **/etc/oblivion/oblivion.env** with the generated **OBLIVION_SECRET** value and restrict it to the service administrator (for example, owner **root**, mode **0600**). Do not put the secret value in this unit file or in YAML.

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable oblivion-server
sudo systemctl start oblivion-server
sudo systemctl status oblivion-server
```

## Troubleshooting

### Port already in use
If port 54321 is already in use, set `OBLIVION_LISTEN_PORT` to an available TCP port and allow that same port in the VPS/provider firewall and operating-system firewall.

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

