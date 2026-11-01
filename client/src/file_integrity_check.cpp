#include "pch.h"
#include "file_integrity_check.h"
#include "file_integrity_manifest.generated.h"
#include "win_path_utils.h"
#include <windows.h>
#include <bcrypt.h> // Header untuk CNG API
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cctype>

// Definisi NTSTATUS jika ntstatus.h tidak tersedia
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

// Forward declaration
extern void ReportViolationAndExit(const std::wstring& message, const std::string& type, const std::string& details);

// Pelaporan NON-fatal (hanya kirim laporan + log lokal, client tetap berjalan).
// Dipakai untuk temuan yang tidak boleh men-kick pemain (lihat kebijakan di bawah).
extern void ReportViolationSoft(const std::string& type, const std::string& details);

#pragma comment(lib, "bcrypt.lib") // Linker library untuk CNG

// ============================================================================
//  KEBIJAKAN INTEGRITAS FILE
//
//  OBLIVION_ENFORCE_FILE_INTEGRITY = 0 (default)
//      Temuan integritas file HANYA dilaporkan (ke server + log lokal), client
//      tetap berjalan. Dipakai selama hash di bawah belum diverifikasi.
//  OBLIVION_ENFORCE_FILE_INTEGRITY = 1
//      Temuan integritas file menutup client (ReportViolationAndExit).
//      Aktifkan HANYA setelah SEMUA hash di m_filesToCheck adalah hash produksi
//      yang sudah diuji pada build game yang sebenarnya.
//
//  PERINGATAN: daftar hash placeholder (belum digenerate) akan dilewati secara
//  otomatis, sehingga tidak bisa men-kick pemain sah. Jangan pernah menaruh hash
//  karangan di sini sambil mengaktifkan enforcement.
// ============================================================================
#ifndef OBLIVION_ENFORCE_FILE_INTEGRITY
#define OBLIVION_ENFORCE_FILE_INTEGRITY 0
#endif

#if defined(OBLIVION_PRODUCTION_BUILD) && OBLIVION_ENFORCE_FILE_INTEGRITY != 1
#error Production builds must enable OBLIVION_ENFORCE_FILE_INTEGRITY=1
#endif

#ifndef OBLIVION_MAX_HASH_FILE_SIZE_BYTES
#define OBLIVION_MAX_HASH_FILE_SIZE_BYTES (512ULL * 1024ULL * 1024ULL)
#endif

// Batas ukuran file yang di-hash saat start. File lebih besar dari ini dilewati
// (dengan catatan lokal) supaya startup tidak memblokir puluhan detik; hash-nya
// bisa dihitung oleh tool external dan ditaruh pada daftar terpisah.
static constexpr unsigned long long kMaxHashFileSizeBytes =
    static_cast<unsigned long long>(OBLIVION_MAX_HASH_FILE_SIZE_BYTES);

// Hash placeholder (belum digenerate) ditandai dengan marker ini supaya bisa
// dilewati tanpa risiko false positive.
static const char* const kPlaceholderHashMarker = "PLACEHOLDER";

// Validasi format hash SHA-256: 64 karakter hex. Selain itu dianggap belum valid.
static bool IsPlaceholderHash(const std::string& hash) {
    if (hash.empty()) {
        return true;
    }
    if (hash.find(kPlaceholderHashMarker) != std::string::npos) {
        return true;
    }
    if (hash.size() != 64) {
        return true;
    }
    for (char c : hash) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return true;
        }
    }
    return false;
}

static std::string ToUtf8(const std::wstring& text) {
    if (text.empty()) {
        return std::string();
    }
    const int size_needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), NULL, 0, NULL, NULL);
    if (size_needed <= 0) {
        return std::string();
    }
    std::string out(size_needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), &out[0], size_needed, NULL, NULL);
    return out;
}

// Catat temuan integritas file ke log lokal (oblivion_client_errors.log).
// NON-fatal: hanya jejak audit, tidak menutup client dan tidak memblokir pemain.
static void LogFileIntegrityIssue(const std::string& type, const std::string& details) {
    std::cerr << "[FileIntegrity] " << type << " - " << details << std::endl;

    const std::wstring executablePath = Oblivion::WinPath::GetModulePath(nullptr);
    if (executablePath.empty()) {
        return;
    }
    const size_t lastSlash = executablePath.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos) {
        return;
    }

    const std::wstring logPath =
        executablePath.substr(0, lastSlash + 1) + L"oblivion_client_errors.log";
    std::ofstream logFile(logPath, std::ios::app);
    if (!logFile.is_open()) {
        return;
    }
    SYSTEMTIME st;
    GetLocalTime(&st);
    logFile << st.wYear << '-' << st.wMonth << '-' << st.wDay << ' '
            << st.wHour << ':' << st.wMinute << ':' << st.wSecond
            << " [" << type << "] " << details << std::endl;
}

// DAFTAR FILE DAN HASH YANG DIHARAPKAN
//
// Cara mengisi hash produksi:
//   PowerShell:  Get-FileHash -Algorithm SHA256 .\RRO.exe
//   Linux:       sha256sum RRO.exe
// Setelah SEMUA entri berisi hash 64-hex yang benar, definisikan
// OBLIVION_ENFORCE_FILE_INTEGRITY=1 bila ingin temuan bersifat menutup client.
//
// Entri dengan hash placeholder akan DILEWATI (tidak dibandingkan).
const std::vector<Oblivion::FileIntegrityChecker::FileHashPair> Oblivion::FileIntegrityChecker::m_filesToCheck = {
    { L"RRO.exe", OBLIVION_FILE_HASH_RRO_EXE },
    { L"en.grf", OBLIVION_FILE_HASH_EN_GRF },
    { L"DATA.ini", OBLIVION_FILE_HASH_DATA_INI }
};

namespace Oblivion {
    bool FileIntegrityChecker::IsEnforcementEnabled() {
        return OBLIVION_ENFORCE_FILE_INTEGRITY != 0;
    }

    void FileIntegrityChecker::PerformCheck() {
        // Resolve the complete executable path without MAX_PATH truncation.
        const std::wstring executablePath = Oblivion::WinPath::GetModulePath(nullptr);
        const size_t lastSlash = executablePath.find_last_of(L"\\/");
        if (executablePath.empty() || lastSlash == std::wstring::npos) {
            LogFileIntegrityIssue(
                "FILE_INTEGRITY_CONFIG",
                "Unable to resolve a complete executable path");
            if (OBLIVION_ENFORCE_FILE_INTEGRITY) {
                MessageBoxW(
                    nullptr,
                    L"File-integrity enforcement could not resolve the game executable path. Verify the installation path and restart the client.",
                    L"Oblivion Hack Shield - Configuration Error",
                    MB_OK | MB_ICONERROR | MB_TOPMOST);
                ExitProcess(ERROR_INSUFFICIENT_BUFFER);
                return;
            }
            return;
        }
        const std::wstring exeDir = executablePath.substr(0, lastSlash + 1);

        // Report missing/invalid hashes once per check, and fail closed only when
        // enforcement is explicitly enabled. Never misclassify this as player cheating.
        std::string missingHashFiles;
        for (const auto& filePair : m_filesToCheck) {
            if (!IsPlaceholderHash(filePair.expectedHash)) {
                continue;
            }
            if (!missingHashFiles.empty()) {
                missingHashFiles += ", ";
            }
            missingHashFiles += ToUtf8(filePair.relativePath);
        }
        if (!missingHashFiles.empty()) {
            const std::string configDetails =
                "Missing/invalid SHA-256 manifest entries: " + missingHashFiles;
            LogFileIntegrityIssue("FILE_INTEGRITY_CONFIG", configDetails);
            if (OBLIVION_ENFORCE_FILE_INTEGRITY) {
                MessageBoxW(
                    nullptr,
                    L"File-integrity enforcement is enabled, but one or more expected hashes are missing or invalid. Configure every monitored file hash before starting the client.",
                    L"Oblivion Hack Shield - Configuration Error",
                    MB_OK | MB_ICONERROR | MB_TOPMOST);
                ExitProcess(ERROR_INVALID_DATA);
                return;
            }
        }

        for (const auto& filePair : m_filesToCheck) {
            // Hash placeholder (belum digenerate) TIDAK boleh dipakai untuk men-kick
            // pemain: lewati sambil mencatat supaya terlihat di log lokal.
            if (IsPlaceholderHash(filePair.expectedHash)) {
                std::cerr << "[FileIntegrity] Entri dilewati (hash belum digenerate): ";
                std::wcerr << filePair.relativePath << std::endl;
                continue;
            }

            std::wstring fullFilePath = exeDir + filePair.relativePath;

            // Batas ukuran: hashing file raksasa (mis. GRF ratusan MB) saat start
            // memblokir thread inisialisasi. Lewati dengan catatan lokal.
            WIN32_FILE_ATTRIBUTE_DATA fileInfo = { 0 };
            if (GetFileAttributesExW(fullFilePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
                const unsigned long long fileSize =
                    (static_cast<unsigned long long>(fileInfo.nFileSizeHigh) << 32) | fileInfo.nFileSizeLow;
                if (fileSize > kMaxHashFileSizeBytes) {
                    const std::string details = ToUtf8(filePair.relativePath) +
                        " exceeds the configured file-hash size limit (verification skipped)";
                    if (OBLIVION_ENFORCE_FILE_INTEGRITY) {
                        LogFileIntegrityIssue("FILE_TOO_LARGE_CONFIG", details);
                        MessageBoxW(
                            nullptr,
                            L"File-integrity enforcement cannot verify a monitored file because it exceeds the configured hash-size limit. Raise the limit or remove the file from the manifest only after reviewing the security impact.",
                            L"Oblivion Hack Shield - Configuration Error",
                            MB_OK | MB_ICONERROR | MB_TOPMOST);
                        ExitProcess(ERROR_FILE_TOO_LARGE);
                        return;
                    }
                    LogFileIntegrityIssue("FILE_TOO_LARGE", details);
                    continue;
                }
            }
            std::string calculatedHash = CalculateSHA256(fullFilePath);

            if (calculatedHash.empty()) {
                // Hash tidak dapat dihitung. Penyebabnya dibedakan supaya kegagalan
                // infrastruktur tidak dianggap pelanggaran (false positive):
                //  - File tidak ada         -> instalasi client tidak lengkap / file dihapus
                //  - File ada tapi terkunci -> antivirus atau patcher sedang memakai file
                //    (mis. antivirus memindai DATA.ini / en.grf). Kasus ini sangat umum
                //    pada pemain sah dan sebelumnya membuat mereka di-kick sebagai cheater.
                const DWORD attributes = GetFileAttributesW(fullFilePath.c_str());
                if (attributes != INVALID_FILE_ATTRIBUTES) {
                    const std::string details = ToUtf8(filePair.relativePath) +
                        " exists but could not be hashed (access denied, sharing conflict, or unsupported file type)";
                    std::cerr << "[FileIntegrity] File ada tetapi tidak dapat diverifikasi: ";
                    std::wcerr << filePair.relativePath << std::endl;
                    if (OBLIVION_ENFORCE_FILE_INTEGRITY) {
                        LogFileIntegrityIssue("FILE_UNREADABLE_CONFIG", details);
                        MessageBoxW(
                            nullptr,
                            L"File-integrity enforcement could not read a monitored file. Close the patcher or application that is locking the file, verify file permissions, and restart the client.",
                            L"Oblivion Hack Shield - Integrity Check Error",
                            MB_OK | MB_ICONERROR | MB_TOPMOST);
                        ExitProcess(ERROR_ACCESS_DENIED);
                        return;
                    }
                    LogFileIntegrityIssue("FILE_UNREADABLE", details);
                    continue;
                }

                // GetFileAttributesW can fail for reasons other than a missing file.
                // Do not turn access/IO failures into a cheating report in report-only mode.
                const DWORD attributesError = GetLastError();
                if (attributesError != ERROR_FILE_NOT_FOUND &&
                    attributesError != ERROR_PATH_NOT_FOUND) {
                    const std::string details = ToUtf8(filePair.relativePath) +
                        " could not be inspected (Win32 error " +
                        std::to_string(attributesError) + ")";
                    LogFileIntegrityIssue("FILE_ACCESS_ERROR", details);
                    if (OBLIVION_ENFORCE_FILE_INTEGRITY) {
                        MessageBoxW(
                            nullptr,
                            L"File-integrity enforcement could not determine whether a monitored file exists. Verify the installation and file permissions, then restart the client.",
                            L"Oblivion Hack Shield - Integrity Check Error",
                            MB_OK | MB_ICONERROR | MB_TOPMOST);
                        ExitProcess(attributesError ? attributesError : ERROR_ACCESS_DENIED);
                        return;
                    }
                    continue;
                }

                // Konversi file path ke UTF-8 untuk details
                std::string details_utf8;
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, &filePair.relativePath[0], (int)filePair.relativePath.size(), NULL, 0, NULL, NULL);
                if (size_needed > 0) {
                    details_utf8.assign(size_needed, 0);
                    WideCharToMultiByte(CP_UTF8, 0, &filePair.relativePath[0], (int)filePair.relativePath.size(), &details_utf8[0], size_needed, NULL, NULL);
                }
                details_utf8 += " - File not found";
                
                if (OBLIVION_ENFORCE_FILE_INTEGRITY) {
                    ReportViolationAndExit(L"", "FILE_INTEGRITY_FAILED", details_utf8);
                } else {
                    // Report-only: kirim laporan (best-effort) + log lokal, tanpa kick.
                    LogFileIntegrityIssue("FILE_INTEGRITY_FAILED", details_utf8);
                    ReportViolationSoft("FILE_INTEGRITY_FAILED", details_utf8);
                }
                continue;
            }

            // Bandingkan hash (case-insensitive)
            if (_stricmp(calculatedHash.c_str(), filePair.expectedHash.c_str()) != 0) {
                // Hash tidak cocok, file telah dimodifikasi
                // Konversi file path ke UTF-8 untuk details
                std::string details_utf8;
                int size_needed = WideCharToMultiByte(CP_UTF8, 0, &filePair.relativePath[0], (int)filePair.relativePath.size(), NULL, 0, NULL, NULL);
                if (size_needed > 0) {
                    details_utf8.assign(size_needed, 0);
                    WideCharToMultiByte(CP_UTF8, 0, &filePair.relativePath[0], (int)filePair.relativePath.size(), &details_utf8[0], size_needed, NULL, NULL);
                }
                details_utf8 += " - Hash mismatch. Expected: " + filePair.expectedHash + ", Got: " + calculatedHash;
                
                if (OBLIVION_ENFORCE_FILE_INTEGRITY) {
                    ReportViolationAndExit(L"", "FILE_MODIFIED", details_utf8);
                } else {
                    // Hash tidak cocok: selama hash produksi belum terverifikasi,
                    // ini HANYA dilaporkan (soft) agar pemain sah tidak di-kick.
                    LogFileIntegrityIssue("FILE_MODIFIED", details_utf8);
                    ReportViolationSoft("FILE_MODIFIED", details_utf8);
                }
            }
        }
        // Jika semua lolos, tidak ada yang perlu dilakukan
    }

    std::string FileIntegrityChecker::CalculateSHA256(const std::wstring& filePath) {
        // Gunakan CreateFile dengan share mode untuk membaca file yang sedang dieksekusi
        // Ini penting karena std::ifstream tidak bisa membaca file yang sedang dieksekusi dengan benar
        HANDLE hFile = CreateFileW(
            filePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, // Penting: allow sharing untuk file yang sedang dieksekusi
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, // Optimize untuk sequential read
            NULL
        );
        
        if (hFile == INVALID_HANDLE_VALUE) {
            return ""; // File tidak bisa dibuka
        }

        // Snapshot the opened file identity and mutation metadata before hashing.
        // FILE_SHARE_WRITE/DELETE is retained for compatibility with patchers/AV,
        // so the read must prove the file stayed stable throughout the operation.
        BY_HANDLE_FILE_INFORMATION initialFileInfo{};
        FILE_BASIC_INFO initialBasicInfo{};
        if (!GetFileInformationByHandle(hFile, &initialFileInfo) ||
            !GetFileInformationByHandleEx(
                hFile, FileBasicInfo, &initialBasicInfo, sizeof(initialBasicInfo)) ||
            (initialFileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            (initialFileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            CloseHandle(hFile);
            return "";
        }

        const unsigned long long initialFileSize =
            (static_cast<unsigned long long>(initialFileInfo.nFileSizeHigh) << 32) |
            initialFileInfo.nFileSizeLow;
        if (initialFileSize > kMaxHashFileSizeBytes) {
            CloseHandle(hFile);
            SetLastError(ERROR_FILE_TOO_LARGE);
            return "";
        }

        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
        PBYTE pbHashObject = NULL;
        PBYTE pbHash = NULL;
        std::string result = "";
        const DWORD BUFFER_SIZE = 4096;

        // Buka algoritma SHA-256
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            CloseHandle(hFile);
            return ""; 
        }

        // Hitung ukuran buffer yang diperlukan
        cbData = 0;
        status = BCryptGetProperty(
            hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&cbHashObject),
            sizeof(cbHashObject), &cbData, 0);
        if (!BCRYPT_SUCCESS(status) || cbData != sizeof(cbHashObject) ||
            cbHashObject == 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return "";
        }

        cbData = 0;
        status = BCryptGetProperty(
            hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PBYTE>(&cbHash),
            sizeof(cbHash), &cbData, 0);
        // SHA-256 must always produce exactly 32 bytes; reject inconsistent
        // provider metadata instead of trusting an unexpected digest length.
        if (!BCRYPT_SUCCESS(status) || cbData != sizeof(cbHash) || cbHash != 32) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return "";
        }

        // Alokasikan buffer
        pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
        pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
        if (!pbHashObject || !pbHash) { 
            if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
            if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return ""; 
        }

        // Buat handle hash
        status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            HeapFree(GetProcessHeap(), 0, pbHashObject);
            HeapFree(GetProcessHeap(), 0, pbHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return ""; 
        }

        // Baca file dan hashkan kontennya menggunakan ReadFile
        BYTE buffer[BUFFER_SIZE];
        DWORD bytesRead = 0;
        bool readFailed = false;
        DWORD readError = ERROR_SUCCESS;
        unsigned long long totalBytesHashed = 0;
        for (;;) {
            if (!ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL)) {
                readError = GetLastError();
                // EOF dari ReadFile dilaporkan sebagai ERROR_HANDLE_EOF (bukan kegagalan).
                if (readError != ERROR_HANDLE_EOF) {
                    readFailed = true;
                }
                break;
            }
            if (bytesRead == 0) {
                break; // EOF normal
            }

            // Enforce the byte cap during the read too; the path's size may have
            // changed after PerformCheck inspected it but before/during this loop.
            if (totalBytesHashed > kMaxHashFileSizeBytes ||
                static_cast<unsigned long long>(bytesRead) >
                    kMaxHashFileSizeBytes - totalBytesHashed) {
                readFailed = true;
                readError = ERROR_FILE_TOO_LARGE;
                break;
            }
            totalBytesHashed += bytesRead;

            status = BCryptHashData(hHash, buffer, bytesRead, 0);
            if (!BCRYPT_SUCCESS(status)) { 
                BCryptDestroyHash(hHash);
                HeapFree(GetProcessHeap(), 0, pbHashObject);
                HeapFree(GetProcessHeap(), 0, pbHash);
                BCryptCloseAlgorithmProvider(hAlg, 0);
                CloseHandle(hFile);
                return ""; 
            }
        }
        
        // Periksa error dari ReadFile (bukan EOF)
        if (readFailed) {
            std::cerr << "[FileIntegrity] Gagal membaca file (kode " << readError << ")" << std::endl;
            BCryptDestroyHash(hHash);
            HeapFree(GetProcessHeap(), 0, pbHashObject);
            HeapFree(GetProcessHeap(), 0, pbHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return "";
        }

        // A file could be modified while ReadFile was running because sharing is
        // allowed for compatibility. Refuse a hash if identity, length, last-write,
        // or NTFS ChangeTime changed during the operation. ChangeTime also catches
        // ordinary writes that restore the visible last-write timestamp.
        BY_HANDLE_FILE_INFORMATION finalFileInfo{};
        FILE_BASIC_INFO finalBasicInfo{};
        const bool metadataReadable =
            GetFileInformationByHandle(hFile, &finalFileInfo) != FALSE &&
            GetFileInformationByHandleEx(
                hFile, FileBasicInfo, &finalBasicInfo, sizeof(finalBasicInfo)) != FALSE;
        const bool fileStable = metadataReadable &&
            initialFileInfo.dwVolumeSerialNumber == finalFileInfo.dwVolumeSerialNumber &&
            initialFileInfo.nFileIndexHigh == finalFileInfo.nFileIndexHigh &&
            initialFileInfo.nFileIndexLow == finalFileInfo.nFileIndexLow &&
            initialFileInfo.nFileSizeHigh == finalFileInfo.nFileSizeHigh &&
            initialFileInfo.nFileSizeLow == finalFileInfo.nFileSizeLow &&
            CompareFileTime(
                &initialFileInfo.ftLastWriteTime, &finalFileInfo.ftLastWriteTime) == 0 &&
            initialBasicInfo.ChangeTime.QuadPart == finalBasicInfo.ChangeTime.QuadPart;

        if (!fileStable) {
            std::cerr << "[FileIntegrity] File changed during SHA-256 verification; refusing the unstable result" << std::endl;
            BCryptDestroyHash(hHash);
            HeapFree(GetProcessHeap(), 0, pbHashObject);
            HeapFree(GetProcessHeap(), 0, pbHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return "";
        }

        // Selesaikan perhitungan hash
        status = BCryptFinishHash(hHash, pbHash, cbHash, 0);
        if (!BCRYPT_SUCCESS(status)) { 
            BCryptDestroyHash(hHash);
            HeapFree(GetProcessHeap(), 0, pbHashObject);
            HeapFree(GetProcessHeap(), 0, pbHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            CloseHandle(hFile);
            return ""; 
        }

        // Konversi hash byte ke string hex
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < cbHash; i++) {
            ss << std::setw(2) << static_cast<unsigned int>(pbHash[i]);
        }
        result = ss.str();

        // Cleanup
        BCryptDestroyHash(hHash);
        HeapFree(GetProcessHeap(), 0, pbHashObject);
        HeapFree(GetProcessHeap(), 0, pbHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);

        return result;
    }
}