# Oblivion Server - Linux Build Guide

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

### Server Secret
Server harus memakai secret yang sama dengan client. Atur secret produksi melalui salah satu cara berikut:
Buat nilai acak yang kuat (minimal 32 byte) dan gunakan nilai yang sama pada server dan client:

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

### Client Protection Status (Heartbeat PONG)

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

