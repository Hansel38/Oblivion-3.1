# Logger System Documentation

## Overview
Sistem logging untuk Oblivion Anti-Cheat Client DLL yang mencatat semua error, warning, dan event penting ke dalam satu file log.

## File Log
- **Nama File**: `oblivion_client.log`
- **Lokasi**: Berada di folder yang sama dengan file `client.dll`
- **Format**: Text file dengan timestamp, level, dan pesan

## Format Log Entry
```
[YYYY-MM-DD HH:MM:SS.mmm] [LEVEL] Message
```

### Contoh:
```
[2025-11-03 14:30:45.123] [INFO] Oblivion Anti-Cheat Client Initializing
[2025-11-03 14:30:45.456] [ERROR] Failed to initialize ML Anomaly Detector
[2025-11-03 14:30:46.789] [WARNING] Detection sent - Type: ce_behavior, Process: cheatengine.exe
```

## Log Levels
- **INFO**: Informasi normal (inisialisasi, konfigurasi)
- **WARNING**: Peringatan (deteksi cheat, kondisi tidak normal)
- **ERROR**: Error yang dapat dipulihkan (gagal inisialisasi module tertentu)
- **CRITICAL**: Error kritis yang mempengaruhi operasi DLL

## Cara Menggunakan di Kode

### Basic Logging
```cpp
#include "Logger.h"

// Simple message
LOG_INFO("Module initialized successfully");
LOG_WARNING("Suspicious activity detected");
LOG_ERROR("Failed to connect to server");
LOG_CRITICAL("Critical system error");
```

### Formatted Logging
```cpp
// Dengan format string
LOG_INFO_FMT("Connected to server %s:%d", serverIP, port);
LOG_ERROR_FMT("Failed to load file: %s (error code: %d)", filename, errorCode);
LOG_WARNING_FMT("Detection: %s in process %d", detectionType, pid);
```

### Advanced Logging dengan Function Info
```cpp
// Mencatat nama function dan line number
LOG_EX(Logger::LogLevel::ERROR, "Detailed error information");
```

## Lifecycle

### Inisialisasi
Logger diinisialisasi otomatis saat DLL dimuat (DLL_PROCESS_ATTACH):
```cpp
Logger::GetInstance().Initialize(g_hModule);
```

### Shutdown
Logger di-shutdown otomatis saat DLL unload (DLL_PROCESS_DETACH):
```cpp
Logger::GetInstance().Shutdown();
```

## Thread Safety
Logger menggunakan mutex internal untuk memastikan thread-safe operation. Aman digunakan dari multiple threads.

## Performance
- Log file dibuka dalam append mode
- Setiap log entry di-flush immediately untuk memastikan error tercatat meskipun terjadi crash
- Minimal overhead karena hanya menulis ke file saat diperlukan

## Troubleshooting

### File Log Tidak Terbuat
1. Periksa permission folder tempat DLL berada
2. Pastikan DLL berhasil dimuat (cek dengan Process Explorer)
3. Periksa apakah ada antivirus yang memblokir

### File Log Kosong
1. Logger mungkin belum diinisialisasi - cek DllMain
2. Periksa apakah ada crash sebelum log ditulis

### File Log Terlalu Besar
File log akan terus bertambah. Untuk production:
1. Implementasi log rotation (belum ada di versi ini)
2. Atau manual delete file log secara berkala
3. Atau tambahkan feature untuk limit ukuran file

## Lokasi Logging di Kode

Logger sudah ditambahkan di:
1. **InitThreadProc**: Mencatat inisialisasi semua module
2. **CleanupGlobals**: Mencatat cleanup semua module
3. **SendDetectionJson**: Mencatat setiap deteksi yang dikirim
4. **Network initialization**: Mencatat koneksi ke server
5. **Error conditions**: Mencatat semua exception dan error

## Best Practices

1. **Gunakan level yang tepat**:
   - INFO: Operasi normal
   - WARNING: Hal mencurigakan tapi tidak fatal
   - ERROR: Error yang dapat dipulihkan
   - CRITICAL: Error fatal

2. **Berikan context yang cukup**:
   ```cpp
   // BAD
   LOG_ERROR("Failed");
   
   // GOOD
   LOG_ERROR_FMT("Failed to initialize %s: error code %d", moduleName, errorCode);
   ```

3. **Hindari logging di hot path**:
   - Jangan log di loop yang dijalankan berkali-kali per detik
   - Gunakan hanya untuk event penting

4. **Sensitive Information**:
   - Jangan log password, keys, atau data sensitif lainnya
   - Hati-hati dengan PII (Personally Identifiable Information)

## Contoh Output Log File

```
========================================
Logger initialized at 2025-11-03 14:30:45.000
DLL Path: H:\Oblivion\Debug\client.dll
========================================
[2025-11-03 14:30:45.100] [INFO] === Oblivion Anti-Cheat Client Initializing ===
[2025-11-03 14:30:45.150] [INFO] Configuration loaded and clamped
[2025-11-03 14:30:45.200] [INFO] Telemetry collector started successfully
[2025-11-03 14:30:45.250] [INFO] ML Feature Extractor initialized successfully
[2025-11-03 14:30:45.300] [INFO] ML Anomaly Detector initialized successfully
[2025-11-03 14:30:45.350] [INFO] Adaptive Threshold Manager initialized successfully
[2025-11-03 14:30:45.400] [INFO] Network client initialized - Connected to 127.0.0.1:8888
[2025-11-03 14:30:45.450] [INFO] HMAC authentication enabled
[2025-11-03 14:30:45.500] [INFO] Heartbeat started with interval 30000ms
[2025-11-03 14:30:45.550] [INFO] Signature database loaded: 150 total, 145 enabled
[2025-11-03 14:31:20.000] [WARNING] Detection sent - Type: ce_behavior, Process: cheatengine.exe (PID: 1234)
[2025-11-03 14:35:00.000] [INFO] === Starting cleanup process ===
[2025-11-03 14:35:00.050] [INFO] ProcessThreadWatcher cleaned up
[2025-11-03 14:35:00.100] [INFO] PeriodicScanner cleaned up
[2025-11-03 14:35:00.500] [INFO] === Cleanup process completed ===
[2025-11-03 14:35:00.550] Logger shutting down
========================================
```
