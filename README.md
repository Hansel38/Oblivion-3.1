# Oblivion Anti-Cheat — Process & Thread Watcher

## Overview
Oblivion is a modular anti-cheat system for games, featuring a client DLL (for injection into the game process) and a server (for receiving detection reports).
This module implements the **Process & Thread Watcher**: it scans for blacklisted/suspicious processes and threads, reports detections to the server, notifies the user, and closes the game if necessary.

---

## Digital Signature Validator

Fitur ini memeriksa apakah modul (file exe/dll) yang berjalan memiliki digital signature yang valid.
Jika Anda ingin **mengecualikan** file tertentu agar tidak diperiksa signature-nya (misal `REP.exe`), gunakan konfigurasi berikut.

### Cara Skip Signature Check untuk Exe Tertentu

Tambahkan atau edit bagian berikut pada file `client_config.json`:

```
"signature_skip_names": "REP.exe"
```

- Untuk lebih dari satu file, pisahkan dengan tanda `;`:
```
"signature_skip_names": "REP.exe;launcher.exe"
```

Fitur ini akan otomatis melewati signature check untuk file yang namanya sesuai daftar di atas (case-insensitive).

### Contoh Konfigurasi Lengkap

```
{
  ...
  "enable_signature_validator": true,
  "signature_threshold": 2,
  "signature_skip_names": "REP.exe;launcher.exe",
  ...
}
```

### Catatan

- Anda tidak perlu mengubah kode untuk menambah/mengganti file yang di-skip, cukup edit config.
- Jika ingin menonaktifkan signature validator sepenuhnya, set:
```
"enable_signature_validator": false
```

---

**Fitur lain dan penjelasan konfigurasi dapat dilihat di bagian ClientConfig pada dokumentasi atau file `client/include/ConfigLoader.h`.**

---

## Folder Structure
```
/OblivionClient
  /include
    ProcessThreadWatcher.h
    NetworkClient.h
    JsonBuilder.h
    blacklist_process.h
  /src
    ProcessThreadWatcher.cpp
    NetworkClient.cpp
    JsonBuilder.cpp
  dllmain.cpp
  client_config.json

/OblivionServer
  /include
  /src
  server.cpp
  server_config.json
```

---

## Prerequisites
- **Visual Studio 2022** (Community/Pro/Enterprise)
- **Windows 10/11 x86** (32-bit target)
- **C++17** (set in project properties)
- **WinSock2**, **Psapi**, **Advapi32** (all are standard Windows SDK libraries)

---

## Build Instructions

### 1. Create Solution and Projects
- Open Visual Studio 2022.
- Create a new **Blank Solution** (e.g., `Oblivion`).
- Add two projects:
  - **OblivionClient**: Dynamic-Link Library (DLL), C++, x86, C++17
  - **OblivionServer**: Console Application, C++, x86, C++17

### 2. Add Source Files
- Place all provided `.h` files in `OblivionClient/include/` and `.cpp` files in `OblivionClient/src/`.
- Place `dllmain.cpp` in `OblivionClient/`.
- Place `server.cpp` in `OblivionServer/`.
- Add all files to their respective projects in Visual Studio (right-click project > Add > Existing Item).

### 3. Project Settings
#### OblivionClient (DLL)
- **Configuration**: Debug/Release, **Platform**: x86
- **C++ Language Standard**: C++17
- **Precompiled Header**: Use `pch.h`
- **Additional Include Directories**: Add `include`
- **Linker > Input > Additional Dependencies**:
  Add: `ws2_32.lib; psapi.lib; advapi32.lib; user32.lib;`

#### OblivionServer (Console)
- **Configuration**: Debug/Release, **Platform**: x86
- **C++ Language Standard**: C++17
- **Linker > Input > Additional Dependencies**:
  Add: `ws2_32.lib;`

### 4. Configuration Files
- Place `client_config.json` in the same directory as the DLL.
- Place `server_config.json` in the same directory as the server executable.

---

## Running & Testing

### 1. Build Both Projects
- Build `OblivionServer` (should produce `server.exe`).
- Build `OblivionClient` (should produce `OblivionClient.dll`).

### 2. Start the Server
- Run `server.exe` from the `OblivionServer` output directory.
- The server will listen for detection reports and print them to the console/log.

### 3. Inject the Client DLL
- Use **Stud_PE** or any compatible DLL injector to inject `OblivionClient.dll` into `RRO.exe` (the game client).
- Ensure `client_config.json` is present and configured as needed.

### 4. Test Detection
- Start a process with a name matching an entry in `blacklist_process.h` (e.g., `cheatengine.exe`).
- The client will:
  - Show a MessageBox with the detection message.
  - Send a JSON report to the server.
  - Attempt to close `RRO.exe` if the detection threshold is met.

### 5. Review Server Output
- The server console/log will display the detection report in JSON format.

---

## Customization
- **Blacklist**: Edit `blacklist_process.h` to add/remove process names.
- **Config**: Edit `client_config.json` and `server_config.json` for server IP/port, detection message, thresholds, etc.

---

## Notes
- **False Positive Mitigation**: The client only closes the game if at least 2 independent indicators are found (e.g., blacklist match or multiple heuristics).
- **Performance**: Scans are optimized for minimal CPU/memory usage.
- **No Sensitive Logging**: Only minimal, non-sensitive info is logged.
- **No Hard-Coded IP/Port**: All network settings are in config files.

---

## Required Libraries
- `ws2_32.lib` (networking)
- `psapi.lib` (process info)
- `advapi32.lib` (advanced Windows API)
- `user32.lib` (MessageBox)

---

## Example Test Plan
1. Build and run the server.
2. Build the client DLL.
3. Inject the DLL into a test process or `RRO.exe`.
4. Launch a fake cheat process (e.g., rename `notepad.exe` to `cheatengine.exe` and run it).
5. Observe:
   - MessageBox appears.
   - Server receives and logs the detection.
   - `RRO.exe` is closed if running.

---

## Integration with Stud_PE
- The DLL exports `Garuda_Entry` for compatibility with Stud_PE import workflow.
- See: [Stud_PE DLL Import Guide](https://docs.herc.ws/client/dll-import)

---

## Troubleshooting
- If the client does not detect, check process names and config.
- If the server does not receive reports, check firewall and IP/port settings.
- For build errors, ensure all dependencies and include paths are set.

---

FEATURE COMPLETE — Process & Thread Watcher
