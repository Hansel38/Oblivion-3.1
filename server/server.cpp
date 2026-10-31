#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <atomic>
#include <mutex>
#include <windows.h>
#include "secret_obf.h"
#include "include/heartbeat_protocol.h"
#include "../common/heartbeat_auth.h"
#include <bcrypt.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

// Fallback define for older SDKs where BCRYPT_ALG_HANDLE_HMAC is missing
#ifndef BCRYPT_ALG_HANDLE_HMAC
#define BCRYPT_ALG_HANDLE_HMAC 0x00000008
#endif

#define DEFAULT_PORT "54321"
#define BUFFER_LEN 4096
#define MAX_TYPE_LEN 64
#define MAX_DETAILS_LEN 2048
#define MAX_HWID_LEN 128
#define MAX_SECRET_LEN 128
// Ambil secret yang di-obfuscate agar tidak muncul sebagai literal.
static std::string SERVER_SECRET = OblivionServer::GetServerSecret();
#define BAN_LIST_FILE "bans.txt"
#define VIOLATION_LOG_FILE "violations.log"

// Resolve the executable directory with a growable buffer so long paths never
// fall back silently to the process working directory.
std::string GetExecutableDirectory() {
    std::vector<char> exePath(MAX_PATH, '\0');
    constexpr size_t kMaxPathCapacity = 32768;
    while (exePath.size() <= kMaxPathCapacity) {
        const DWORD pathLength = GetModuleFileNameA(
            NULL, exePath.data(), static_cast<DWORD>(exePath.size()));
        if (pathLength == 0) {
            return "";
        }
        if (static_cast<size_t>(pathLength) < exePath.size()) {
            const std::string path(exePath.data(), pathLength);
            const size_t lastSlash = path.find_last_of("\\/");
            return lastSlash == std::string::npos
                ? std::string()
                : path.substr(0, lastSlash + 1);
        }
        if (exePath.size() == kMaxPathCapacity) {
            break;
        }
        exePath.resize((std::min)(exePath.size() * 2, kMaxPathCapacity), '\0');
    }
    return "";
}

// Fungsi untuk mendapatkan path lengkap file (relatif terhadap executable)
std::string GetFilePath(const std::string& filename) {
    std::string exeDir = GetExecutableDirectory();
    return exeDir + filename;
}

// Fungsi helper untuk mendapatkan timestamp saat ini
std::string GetCurrentTimestamp() {
    auto now = std::time(nullptr);
    struct tm tm;
    localtime_s(&tm, &now);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// A ban-list read failure is a configuration/infrastructure error, not evidence
// that a client is clean. Never convert it to "not banned".
enum class BanLookupResult {
    Banned,
    NotBanned,
    Error
};

static std::mutex g_banListMutex;

static BanLookupResult LookupHWIDBanStatusUnlocked(const std::string& hwid) {
    const std::string banFilePath = GetFilePath(BAN_LIST_FILE);
    std::ifstream banFile(banFilePath);
    if (!banFile.is_open()) {
        std::cerr << "[ERROR] Ban list is missing or unreadable: " << banFilePath << std::endl;
        return BanLookupResult::Error;
    }

    std::string line;
    while (std::getline(banFile, line)) {
        const size_t first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) {
            continue;
        }
        const size_t last = line.find_last_not_of(" \t\r\n");
        line = line.substr(first, last - first + 1);
        if (line[0] == '#') {
            continue;
        }
        if (_stricmp(line.c_str(), hwid.c_str()) == 0) {
            return BanLookupResult::Banned;
        }
    }

    if (banFile.bad()) {
        std::cerr << "[ERROR] I/O error while reading ban list: " << banFilePath << std::endl;
        return BanLookupResult::Error;
    }
    return BanLookupResult::NotBanned;
}

static BanLookupResult LookupHWIDBanStatus(const std::string& hwid) {
    std::lock_guard<std::mutex> lock(g_banListMutex);
    return LookupHWIDBanStatusUnlocked(hwid);
}

void AddToBanList(const std::string& hwid) {
    // Keep the lookup + append atomic against other connection workers.
    std::lock_guard<std::mutex> lock(g_banListMutex);
    const BanLookupResult status = LookupHWIDBanStatusUnlocked(hwid);
    if (status == BanLookupResult::Banned) {
        return;
    }
    if (status == BanLookupResult::Error) {
        std::cerr << "[ERROR] Refusing to update ban list because it cannot be read." << std::endl;
        return;
    }

    const std::string banFilePath = GetFilePath(BAN_LIST_FILE);
    std::ofstream banFile(banFilePath, std::ios::app);
    if (!banFile.is_open()) {
        std::cerr << "[ERROR] Gagal membuka file ban list untuk menulis." << std::endl;
        return;
    }

    banFile << hwid << std::endl;
    if (!banFile.good()) {
        std::cerr << "[ERROR] Gagal menulis HWID ke ban list." << std::endl;
        return;
    }
    std::cout << "[BAN] HWID [" << hwid << "] ditambahkan ke ban list." << std::endl;
}

// Helper function untuk extract file/software name dari details
std::string ExtractDetectedFile(const std::string& type, const std::string& details) {
    std::string detectedFile = "UNKNOWN";
    
    // Untuk PROCESS_DETECTED, details biasanya berisi nama process
    if (type == "PROCESS_DETECTED") {
        // Details biasanya berisi nama file .exe
        size_t dotExe = details.find(".exe");
        if (dotExe != std::string::npos) {
            size_t start = details.rfind(' ', dotExe);
            if (start == std::string::npos) start = 0;
            else start++;
            detectedFile = details.substr(start, dotExe - start + 4);
        } else {
            detectedFile = details; // Ambil seluruh details jika tidak ada .exe
        }
    }
    // Untuk INJECTION_DETECTED, details berisi nama DLL
    else if (type == "INJECTION_DETECTED") {
        size_t dotDll = details.find(".dll");
        if (dotDll != std::string::npos) {
            size_t start = details.rfind(' ', dotDll);
            if (start == std::string::npos) start = 0;
            else start++;
            detectedFile = details.substr(start, dotDll - start + 4);
        } else {
            detectedFile = details;
        }
    }
    // Untuk UNTRUSTED_MODULE, extract nama modul dari details
    else if (type == "UNTRUSTED_MODULE") {
        // Format: "Module: WpeSpy.dll | Path: H:\..."
        size_t modulePos = details.find("Module: ");
        if (modulePos != std::string::npos) {
            size_t start = modulePos + 8; // len("Module: ")
            size_t end = details.find(" | ", start);
            if (end != std::string::npos) {
                detectedFile = details.substr(start, end - start);
            } else {
                detectedFile = details.substr(start);
                // Truncate jika terlalu panjang
                if (detectedFile.length() > 100) {
                    detectedFile = detectedFile.substr(0, 100);
                }
            }
        } else {
            // Fallback: cari .dll dalam details
            size_t dotDll = details.find(".dll");
            if (dotDll != std::string::npos) {
                size_t start = details.rfind(' ', dotDll);
                if (start == std::string::npos) start = 0;
                else start++;
                detectedFile = details.substr(start, dotDll - start + 4);
            } else {
                detectedFile = details.length() > 100 ? details.substr(0, 100) + "..." : details;
            }
        }
    }
    // Untuk FILE_MODIFIED atau FILE_INTEGRITY_FAILED, extract nama file
    else if (type == "FILE_MODIFIED" || type == "FILE_INTEGRITY_FAILED") {
        // Format biasanya: "filename.ext - Hash mismatch..." atau "filename.ext - File not found"
        size_t dash = details.find(" - ");
        if (dash != std::string::npos) {
            detectedFile = details.substr(0, dash);
        } else {
            detectedFile = details;
        }
    }
    // Untuk ADV_HEURISTIC_DETECTED, extract process name
    else if (type == "ADV_HEURISTIC_DETECTED") {
        // Format: "[DETECTION_TYPE] processName.exe (PID:123) => indicator"
        size_t bracket = details.find(']');
        if (bracket != std::string::npos) {
            size_t spaceAfter = details.find(' ', bracket + 1);
            if (spaceAfter != std::string::npos) {
                size_t spaceBeforePid = details.find(" (PID:", spaceAfter);
                if (spaceBeforePid != std::string::npos) {
                    detectedFile = details.substr(spaceAfter + 1, spaceBeforePid - spaceAfter - 1);
                } else {
                    // Fallback: ambil setelah bracket sampai spasi berikutnya
                    detectedFile = details.substr(spaceAfter + 1);
                    size_t nextSpace = detectedFile.find(' ');
                    if (nextSpace != std::string::npos) {
                        detectedFile = detectedFile.substr(0, nextSpace);
                    }
                }
            }
        }
        // Fallback: cari .exe dalam details
        if (detectedFile == "UNKNOWN") {
            size_t dotExe = details.find(".exe");
            if (dotExe != std::string::npos) {
                size_t start = details.rfind(' ', dotExe);
                if (start == std::string::npos) start = 0;
                else start++;
                detectedFile = details.substr(start, dotExe - start + 4);
            }
        }
    }
    // Untuk OVERLAY_DETECTED, details berisi window class name
    else if (type == "OVERLAY_DETECTED") {
        detectedFile = "Overlay Window: " + details;
    }
    // Untuk SIGNATURE_SPOOFING, extract process name dari details
    else if (type == "SIGNATURE_SPOOFING") {
        // Format: "Process: processName.exe (PID:123) | Path: ... | Expected: ... | Actual: ..."
        size_t processPos = details.find("Process: ");
        if (processPos != std::string::npos) {
            size_t start = processPos + 9; // len("Process: ")
            size_t end = details.find(" (PID:", start);
            if (end != std::string::npos) {
                detectedFile = details.substr(start, end - start);
            } else {
                size_t spaceAfter = details.find(' ', start);
                if (spaceAfter != std::string::npos) {
                    detectedFile = details.substr(start, spaceAfter - start);
                } else {
                    detectedFile = details.substr(start);
                }
            }
        } else {
            // Fallback: cari .exe dalam details
            size_t dotExe = details.find(".exe");
            if (dotExe != std::string::npos) {
                size_t start = details.rfind(' ', dotExe);
                if (start == std::string::npos) start = 0;
                else start++;
                detectedFile = details.substr(start, dotExe - start + 4);
            } else {
                detectedFile = details.length() > 100 ? details.substr(0, 100) + "..." : details;
            }
        }
    }
    // Untuk CODE_MODIFICATION, EARLY_INJECTION, CODE_CAVE_DETECTED, SUSPICIOUS_MEMORY
    else if (type == "CODE_MODIFICATION" || type == "EARLY_INJECTION" || 
             type == "CODE_CAVE_DETECTED" || type == "SUSPICIOUS_MEMORY") {
        // Format: "File: filename.exe | Section: ... | ..." atau "File: filename.exe | ..."
        size_t filePos = details.find("File: ");
        if (filePos != std::string::npos) {
            size_t start = filePos + 6; // len("File: ")
            size_t end = details.find(" | ", start);
            if (end != std::string::npos) {
                detectedFile = details.substr(start, end - start);
            } else {
                // Jika tidak ada " | ", ambil sampai akhir string atau sampai karakter tertentu
                size_t spaceAfter = details.find(' ', start);
                if (spaceAfter != std::string::npos && spaceAfter < start + 200) {
                    detectedFile = details.substr(start, spaceAfter - start);
                } else {
                    detectedFile = details.substr(start);
                    if (detectedFile.length() > 100) {
                        detectedFile = detectedFile.substr(0, 100);
                    }
                }
            }
        } else {
            // Fallback untuk format lama
            size_t dotExe = details.find(".exe");
            if (dotExe != std::string::npos) {
                size_t start = details.rfind(' ', dotExe);
                if (start == std::string::npos) start = 0;
                else start++;
                detectedFile = details.substr(start, dotExe - start + 4);
            } else {
                detectedFile = details.length() > 100 ? details.substr(0, 100) + "..." : details;
            }
        }
    }
    // Untuk deteksi lain, coba extract dari details
    else {
        // Coba cari .exe atau .dll dalam details
        size_t dotExe = details.find(".exe");
        size_t dotDll = details.find(".dll");
        
        if (dotExe != std::string::npos && (dotDll == std::string::npos || dotExe < dotDll)) {
            size_t start = details.rfind(' ', dotExe);
            if (start == std::string::npos) start = 0;
            else start++;
            detectedFile = details.substr(start, dotExe - start + 4);
        } else if (dotDll != std::string::npos) {
            size_t start = details.rfind(' ', dotDll);
            if (start == std::string::npos) start = 0;
            else start++;
            detectedFile = details.substr(start, dotDll - start + 4);
        } else {
            // Jika tidak ada, gunakan detail lengkap (mungkin sudah jelas)
            detectedFile = details.length() > 100 ? details.substr(0, 100) + "..." : details;
        }
    }
    
    return detectedFile;
}

// Fungsi untuk mencatat pelanggaran ke log file
static std::mutex g_violationLogMutex;

// Defense in depth: also sanitize at the logging boundary. Malformed frames can
// reach LogViolation before ParseProtocol has sanitized any user-controlled data.
std::string SanitizeInput(const std::string& input, size_t maxLen);

void LogViolation(const std::string& type, const std::string& details, const std::string& hwid) {
    // Multiple client workers may report at the same time; serialize complete
    // log records so concurrent file streams cannot interleave their fields.
    std::lock_guard<std::mutex> logGuard(g_violationLogMutex);
    const std::string safeType = SanitizeInput(type, MAX_TYPE_LEN);
    const std::string safeDetails = SanitizeInput(details, MAX_DETAILS_LEN);
    const std::string safeHwid = SanitizeInput(hwid, MAX_HWID_LEN);
    std::string logFilePath = GetFilePath(VIOLATION_LOG_FILE);
    std::ofstream logFile(logFilePath, std::ios::app);
    if (logFile.is_open()) {
        // Extract only from sanitized details so log records cannot be forged.
        std::string detectedFile = ExtractDetectedFile(safeType, safeDetails);
        
        logFile << "[" << GetCurrentTimestamp() << "] TYPE: " << safeType
                << " | HWID: " << safeHwid
                << " | DETECTED_FILE/SOFTWARE: " << SanitizeInput(detectedFile, 256)
                << " | DETAILS: " << safeDetails << std::endl;
        logFile.close();
        
        std::cout << "[VIOLATION] TYPE: " << safeType
                  << " | HWID: " << safeHwid
                  << " | FILE/SOFTWARE: " << SanitizeInput(detectedFile, 256) << std::endl;
    } else {
        std::cerr << "[ERROR] Gagal membuka file log untuk menulis." << std::endl;
    }
}

// Fungsi untuk menentukan apakah pelanggaran serius dan perlu di-ban
bool IsSeriousViolation(const std::string& type) {
    // Daftar tipe pelanggaran yang dianggap serius dan langsung di-ban
    std::vector<std::string> seriousViolations = {
        "MEMORY_VIOLATION",
        "INJECTION_DETECTED",
        "FILE_MODIFIED",
        "FILE_INTEGRITY_FAILED",
        "SIGNATURE_SPOOFING",      // Spoofing process name dengan fake signature
        "ADV_HEURISTIC_DETECTED",  // Advanced heuristics detection (CE, WPE, dll)
        "PROCESS_DETECTED"         // Blacklisted process detected
    };
    
    for (const auto& serious : seriousViolations) {
        if (_stricmp(type.c_str(), serious.c_str()) == 0) {
            return true;
        }
    }
    
    return false;
}

// Fungsi untuk mencoba extract HWID dari raw data (best effort)
std::string ExtractHWIDFromRawData(const std::string& rawData) {
    // Format yang diharapkan: TYPE:DETAILS:HWID:SECRET;
    // Kita akan coba extract HWID bahkan jika format tidak sempurna
    
    size_t firstColon = rawData.find(':');
    if (firstColon == std::string::npos) return "UNKNOWN";
    
    size_t secondColon = rawData.find(':', firstColon + 1);
    if (secondColon == std::string::npos) return "UNKNOWN";
    
    size_t thirdColon = rawData.find(':', secondColon + 1);
    if (thirdColon == std::string::npos) return "UNKNOWN";
    
    // Extract HWID (antara colon ke-2 dan ke-3)
    std::string hwid = rawData.substr(secondColon + 1, thirdColon - secondColon - 1);
    
    // Validasi panjang minimal dan maksimal
    if (hwid.empty() || hwid.length() > MAX_HWID_LEN) return "UNKNOWN";
    
    // Sanitasi: hanya izinkan alphanumeric dan dash (untuk SHA256 hash: 0-9a-f dan dash)
    // Tidak perlu filter ketat, cukup buang karakter berbahaya
    std::string sanitizedHwid;
    for (char c : hwid) {
        // Izinkan: alphanumeric (0-9, a-z, A-Z) dan dash
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-') {
            sanitizedHwid += c;
        }
    }
    
    return sanitizedHwid.empty() ? "UNKNOWN" : sanitizedHwid;
}

// Fungsi untuk sanitasi string input (menghapus karakter berbahaya)
std::string SanitizeInput(const std::string& input, size_t maxLen) {
    std::string sanitized;
    const size_t reserveSize = input.length() < maxLen ? input.length() : maxLen;
    sanitized.reserve(reserveSize);

    for (unsigned char uc : input) {
        if (sanitized.length() >= maxLen) {
            break;
        }
        // Newlines and tabs from clients must not create forged log records.
        if (uc == '\n' || uc == '\r' || uc == '\t') {
            sanitized.push_back(' ');
            continue;
        }
        if (uc >= 0x20 && uc <= 0x7E &&
            uc != '<' && uc != '>' && uc != '&' && uc != '"' && uc != '\'') {
            sanitized.push_back(static_cast<char>(uc));
        }
    }
    return sanitized;
}

// Struktur untuk hasil parsing protokol
struct ParsedReport {
    bool valid = false;
    std::string type = "";
    std::string details = "";
    std::string hwid = "";
    std::string secret = "";
    std::string errorMessage = "";
};

// Fungsi untuk validasi format protokol dan parsing yang aman
ParsedReport ParseProtocol(const std::string& report) {
    ParsedReport result;
    result.valid = false;
    
    // Validasi panjang minimum
    if (report.length() < 10) { // Minimal TYPE::HWID:SECRET;
        result.errorMessage = "Report too short (minimum 10 characters required)";
        return result;
    }
    
    // Validasi panjang maksimum
    if (report.length() > BUFFER_LEN - 1) {
        result.errorMessage = "Report exceeds maximum length";
        return result;
    }
    
    // Validasi format: harus diakhiri dengan semicolon
    // Accept exactly one complete frame. Extra bytes after ';' could otherwise
    // be silently ignored when TCP coalesces multiple frames into one recv().
    const size_t terminator = report.find(';');
    if (terminator != report.size() - 1 ||
        std::count(report.begin(), report.end(), ';') != 1) {
        result.errorMessage = "Report contains trailing data or multiple frames";
        return result;
    }
    
    // Hitung jumlah delimiter
    size_t colonCount = std::count(report.begin(), report.end(), ':');
    if (colonCount != 3) {
        result.errorMessage = "Invalid format: expected 3 colons, found " + std::to_string(colonCount);
        return result;
    }
    
    // Parse dengan validasi posisi
    size_t pos1 = report.find(':');
    if (pos1 == std::string::npos || pos1 == 0) {
        result.errorMessage = "Invalid TYPE field position";
        return result;
    }
    
    size_t pos2 = report.find(':', pos1 + 1);
    if (pos2 == std::string::npos) {
        result.errorMessage = "Invalid DETAILS field position";
        return result;
    }
    
    size_t pos3 = report.find(':', pos2 + 1);
    if (pos3 == std::string::npos) {
        result.errorMessage = "Invalid HWID field position";
        return result;
    }
    
    size_t pos4 = report.find(';', pos3 + 1);
    if (pos4 == std::string::npos || pos4 == pos3 + 1) {
        result.errorMessage = "Invalid SECRET field position";
        return result;
    }
    
    // Extract fields dengan boundary checking
    try {
        result.type = report.substr(0, pos1);
        result.details = report.substr(pos1 + 1, pos2 - pos1 - 1);
        result.hwid = report.substr(pos2 + 1, pos3 - pos2 - 1);
        result.secret = report.substr(pos3 + 1, pos4 - pos3 - 1);
    } catch (const std::out_of_range& e) {
        result.errorMessage = std::string("Parsing error: ") + e.what();
        return result;
    }
    
    // Validasi panjang setiap field
    if (result.type.length() > MAX_TYPE_LEN) {
        result.errorMessage = "TYPE field exceeds maximum length (" + std::to_string(MAX_TYPE_LEN) + ")";
        return result;
    }
    
    if (result.details.length() > MAX_DETAILS_LEN) {
        result.errorMessage = "DETAILS field exceeds maximum length (" + std::to_string(MAX_DETAILS_LEN) + ")";
        return result;
    }
    
    if (result.hwid.length() > MAX_HWID_LEN) {
        result.errorMessage = "HWID field exceeds maximum length (" + std::to_string(MAX_HWID_LEN) + ")";
        return result;
    }
    
    if (result.secret.length() > MAX_SECRET_LEN) {
        result.errorMessage = "SECRET field exceeds maximum length (" + std::to_string(MAX_SECRET_LEN) + ")";
        return result;
    }
    
    // Validasi TYPE tidak kosong dan hanya berisi karakter alphanumeric + underscore
    if (result.type.empty()) {
        result.errorMessage = "TYPE field cannot be empty";
        return result;
    }
    
    for (char c : result.type) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') {
            result.errorMessage = "TYPE field contains invalid characters";
            return result;
        }
    }
    
    // The client derives HWID as a SHA-256 digest: accept exactly 64 hex characters.
    if (result.hwid.size() != 64) {
        result.errorMessage = "HWID must be a 64-character SHA-256 hex digest";
        return result;
    }

    for (unsigned char c : result.hwid) {
        if (!std::isxdigit(c)) {
            result.errorMessage = "HWID field contains invalid characters (expected 64 hex characters)";
            return result;
        }
    }

    // Validasi SECRET tidak kosong
    if (result.secret.empty()) {
        result.errorMessage = "SECRET field cannot be empty";
        return result;
    }
    
    // Sanitasi DETAILS (bisa kosong untuk CHECKIN)
    result.details = SanitizeInput(result.details, MAX_DETAILS_LEN);
    
    result.valid = true;
    return result;
}

// Batas koneksi client yang diproses bersamaan. Satu thread per koneksi TANPA batas
// bisa dihabiskan oleh flood koneksi (thread + handle menumpuk) sehingga anti-cheat
// tidak bisa lagi melayani pemain sah (DoS).
static const int kMaxConcurrentClients = 256;
static std::atomic<int> g_activeClients{ 0 };
static Oblivion::HeartbeatConfig g_heartbeatConfig;

static bool TryAcquireClientSlot() {
    int current = g_activeClients.load(std::memory_order_relaxed);
    while (current < kMaxConcurrentClients) {
        if (g_activeClients.compare_exchange_weak(
                current, current + 1,
                std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

// Generate nonces only with the operating system cryptographic random generator.
// Failure returns zero and aborts the secure session rather than using weak entropy.

uint64_t MonotonicMilliseconds() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

void SleepHeartbeat(uint32_t milliseconds) {
#ifdef _WIN32
    Sleep(milliseconds);
#else
    usleep(static_cast<useconds_t>(milliseconds) * 1000U);
#endif
}

bool SendAllBytes(SOCKET socket, const std::string& payload) {
    size_t sent = 0;
    while (sent < payload.size()) {
        const size_t remaining = payload.size() - sent;
        const int chunk = static_cast<int>((std::min)(remaining, static_cast<size_t>(0x7fffffff)));
#ifdef _WIN32
        const int result = send(socket, payload.data() + sent, chunk, 0);
#else
        const ssize_t result = send(socket, payload.data() + sent, static_cast<size_t>(chunk), SEND_FLAGS);
#endif
        if (result <= 0) return false;
        sent += static_cast<size_t>(result);
    }
    return true;
}

bool ReceiveSemicolonFrame(SOCKET socket, std::string& buffered, uint32_t timeoutMs, size_t maxBytes) {
    const uint64_t started = MonotonicMilliseconds();
    while (buffered.find(';') == std::string::npos) {
        if (buffered.size() >= maxBytes) return false;
        const uint64_t elapsed = MonotonicMilliseconds() - started;
        if (elapsed >= timeoutMs) return false;
        const uint32_t remainingMs = timeoutMs - static_cast<uint32_t>(elapsed);
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(socket, &readSet);
        struct timeval timeout{};
        timeout.tv_sec = remainingMs / 1000;
        timeout.tv_usec = (remainingMs % 1000) * 1000;
#ifdef _WIN32
        const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
#else
        const int ready = select(socket + 1, &readSet, nullptr, nullptr, &timeout);
#endif
        if (ready <= 0) return false;
        char chunk[512] = {};
#ifdef _WIN32
        const int received = recv(socket, chunk, static_cast<int>(sizeof(chunk)), 0);
#else
        const ssize_t received = recv(socket, chunk, sizeof(chunk), 0);
#endif
        if (received <= 0 || buffered.size() + static_cast<size_t>(received) > maxBytes) return false;
        buffered.append(chunk, static_cast<size_t>(received));
    }
    return true;
}

bool ParseUnsignedDecimal(const std::string& text, uint64_t& value) {
    if (text.empty()) return false;
    uint64_t parsed = 0;
    for (unsigned char c : text) {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (parsed > (UINT64_MAX - digit) / 10ULL) return false;
        parsed = parsed * 10ULL + digit;
    }
    value = parsed;
    return true;
}

bool IsSha256HexDigest(const std::string& digest) {
    if (digest.size() != 64) return false;
    for (unsigned char c : digest) if (!std::isxdigit(c)) return false;
    return true;
}

bool ConstantTimeEquals(const std::string& lhs, const std::string& rhs) {
    if (lhs.size() != rhs.size()) return false;
    unsigned char difference = 0;
    for (size_t i = 0; i < lhs.size(); ++i) {
        difference |= static_cast<unsigned char>(lhs[i] ^ rhs[i]);
    }
    return difference == 0;
}

uint64_t GenerateSecureNonce() {
    uint64_t value = 0;
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&value),
                        static_cast<ULONG>(sizeof(value)),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        std::cerr << "[ERROR] BCryptGenRandom gagal; nonce tidak dapat dibuat." << std::endl;
        return 0;
    }
    return value;
}

// Fungsi untuk menangani setiap client yang terhubung
void HandleClient(SOCKET clientSocket) {
    int bytesReceived = 0;
    std::string extractedHwid = "UNKNOWN"; // Untuk logging jika parsing gagal

    try {
        // Use a single wall-clock deadline for the initial frame. A per-recv
        // timeout alone permits slow clients to hold a worker indefinitely by
        // sending one byte just before each timeout expires.
        std::string report;
        (void)ReceiveSemicolonFrame(
            clientSocket, report, 5000, static_cast<size_t>(BUFFER_LEN - 1));
        bytesReceived = static_cast<int>(report.size());
        if (bytesReceived > 0) {
            // Null-terminate untuk keamanan
            
            // (Pesan sudah dirakit utuh pada loop framing di atas.)
            
            // Extract HWID untuk logging (best effort, sebelum parsing)
            extractedHwid = ExtractHWIDFromRawData(report);
            
            std::cout << "[DEBUG] Received raw data (" << bytesReceived << " bytes) from HWID: " << extractedHwid << std::endl;
            
            // --- PARSING DENGAN VALIDASI ROBUST ---
            ParsedReport parsed = ParseProtocol(report);
            
            if (!parsed.valid) {
                std::cout << "[ERROR] Invalid protocol format: " << parsed.errorMessage << std::endl;
                std::cout << "[DEBUG] Expected format: TYPE:DETAILS:HWID:SECRET;" << std::endl;
                
                // Log attempt dengan data mentah (truncated untuk keamanan)
                std::string truncatedReport = report.length() > 100 ? report.substr(0, 100) + "..." : report;
                LogViolation("MALFORMED_REQUEST", parsed.errorMessage + " | Data: " + truncatedReport, extractedHwid);
                
                // Kirim error response dan tutup koneksi
                const char* errorResponse = "ERROR:INVALID_FORMAT;";
                SendAllBytes(clientSocket, errorResponse);
                closesocket(clientSocket);
                return;
            }
            
            std::string type = parsed.type;
            std::string details = parsed.details;
            std::string hwid = parsed.hwid;
            std::string secret = parsed.secret;
            
            std::cout << "[PARSE] TYPE: " << type << " | HWID: " << hwid << " | DETAILS_LEN: " << details.length() << std::endl;

            // --- CEK SECRET KEY TERLEBIH DAHULU ---
            if (!ConstantTimeEquals(secret, SERVER_SECRET)) {
                // PENTING: ini kegagalan KONFIGURASI, bukan bukti pemain di-ban.
                // Versi sebelumnya mengirim "KICK;" sehingga client menampilkan
                // "HWID Anda telah di-ban" kepada SEMUA pemain hanya karena secret
                // server/client tidak sinkron. Sekarang dikirim kode khusus
                // "ERROR:AUTH;" yang dipahami client sebagai masalah autentikasi.
                std::cout << "[AUTH] Secret key tidak valid dari HWID [" << hwid << "]" << std::endl;
                // Jangan pernah mencetak nilai secret (bocor ke stdout / file log).
                std::cout << "[AUTH] Panjang secret diterima: " << secret.length()
                          << " | diharapkan: " << SERVER_SECRET.length() << std::endl;

                LogViolation("AUTH_FAILED", "Invalid secret key (config mismatch, bukan ban)", hwid);

                const char* authError = "ERROR:AUTH;";
                SendAllBytes(clientSocket, authError);
                std::cout << "[INFO] ERROR:AUTH dikirim. Periksa secret.dat / OBLIVION_SECRET di kedua sisi." << std::endl;
            }
            else if (type == "CHECKIN") {
                // Ini adalah check-in dari client saat pertama kali start
                std::cout << "[CHECKIN] Client check-in dari HWID [" << hwid << "]" << std::endl;
                
                // Cek apakah HWID sudah di-ban (file dibaca fresh setiap kali, tidak ada cache)
                const BanLookupResult banStatus = LookupHWIDBanStatus(hwid);
                
                if (banStatus == BanLookupResult::Error) {
                    LogViolation("BAN_LIST_UNAVAILABLE", "Cannot read ban list; refusing check-in", hwid);
                    SendAllBytes(clientSocket, "ERROR:BANLIST;");
                } else if (banStatus == BanLookupResult::Banned) {
                    // HWID di-ban, kirim KICK
                    const char* kickCommand = "KICK;";
                    SendAllBytes(clientSocket, kickCommand);
                    std::cout << "[BAN] HWID [" << hwid << "] terdeteksi di ban list. Perintah KICK dikirim." << std::endl;
                    std::cout << "[INFO] Untuk unban, hapus HWID dari bans.txt dan restart client." << std::endl;
                } else {
                    // HWID tidak di-ban, kirim OK dan mulai heartbeat ping
                    // HWID tidak di-ban, kirim OK dan session nonce dalam satu pesan
                    uint64_t sessionNonce = GenerateSecureNonce();
                    std::string response = sessionNonce == 0 ? "ERROR:CRYPTO;" : ("OK;SESSION_NONCE:" + std::to_string(sessionNonce) + ";");
                    SendAllBytes(clientSocket, response);
                    std::cout << "[OK] HWID [" << hwid << "] diizinkan. Memulai heartbeat ping." << std::endl;

                    // Basic ping scheduler over the same socket (line-based)
                    Oblivion::HeartbeatConfig cfg = g_heartbeatConfig; 
                    uint32_t seq = 1;
                    uint32_t consecutiveMiss = 0;
                    uint64_t rttSum = 0; uint32_t rttCount = 0; 
                    // Cumulative metrics across the connection
                    uint64_t rttSumCumulative = 0; uint64_t rttCountCumulative = 0; 
                    uint32_t totalMisses = 0;
                    // Bit status proteksi client dari PONG terakhir ("antiSuspend|integrity").
                    // false = lapisan pengaman client dilaporkan tidak berjalan penuh.
                    bool protectionDegraded = false;

                    // derive session key: key' = HMAC_SHA256(SERVER_SECRET, hwid|nonce)
                    auto hmacSha256 = [](const std::string& key, const std::string& data){
                        BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_HASH_HANDLE hHash = NULL;
                        NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC);
                        if (st != 0) return std::string(); DWORD objLen=0, dlen=0;
                        (void)BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(DWORD), &dlen, 0);
                        std::vector<UCHAR> obj(objLen);
                        st = BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, (PUCHAR)key.data(), (ULONG)key.size(), 0);
                        if (st != 0) { BCryptCloseAlgorithmProvider(hAlg,0); return std::string(); }
                        st = BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
                        if (st != 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0); return std::string(); }
                        UCHAR hash[32]; st = BCryptFinishHash(hHash, hash, sizeof(hash), 0);
                        BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0);
                        if (st != 0) return std::string(); static const char* hex = "0123456789abcdef";
                        std::string out; out.reserve(64); for(int i=0;i<32;++i){ out.push_back(hex[(hash[i]>>4)&0xF]); out.push_back(hex[hash[i]&0xF]); }
                        return out;
                    };
                    std::string sessionKey = hmacSha256(SERVER_SECRET, hwid + ":" + std::to_string(sessionNonce));
                    if (sessionNonce == 0 || sessionKey.empty()) {
                        LogViolation("HB_INIT_FAILED", "Cryptographic session initialization failed", hwid);
                    } else {
                        std::cout << "[HEARTBEAT] Started for HWID [" << hwid << "]" << std::endl;
                        bool warningLogged = false;
                        std::string heartbeatBuffer;
                        const uint32_t missLimit = (std::max)(1U, cfg.max_consecutive_miss);

                        auto registerMiss = [&](const std::string& reason) {
                            ++consecutiveMiss;
                            ++totalMisses;
                            if (!warningLogged) {
                                warningLogged = true;
                                LogViolation("HB_WARNING", reason + " | consecutive=" +
                                    std::to_string(consecutiveMiss), hwid);
                            }
                            if (consecutiveMiss >= missLimit) {
                                LogViolation("HB_FLAGGED", reason + " | misses=" +
                                    std::to_string(totalMisses), hwid);
                                return false;
                            }
                            return true;
                        };

                        while (true) {
                            const uint64_t pingTimestamp = MonotonicMilliseconds();
                            const uint64_t pingNonce = GenerateSecureNonce();
                            if (pingNonce == 0) {
                                LogViolation("HB_CRYPTO_FAILED", "Secure nonce generation failed", hwid);
                                break;
                            }
                            const std::string ping = "PING:" + std::to_string(seq) + ":" +
                                std::to_string(pingTimestamp) + ":" + std::to_string(pingNonce) + ";";
                            if (!SendAllBytes(clientSocket, ping)) {
                                std::cout << "[HEARTBEAT] Failed to send PING for HWID [" << hwid << "]" << std::endl;
                                break;
                            }

                            if (!ReceiveSemicolonFrame(clientSocket, heartbeatBuffer, cfg.timeout_ms, 1024)) {
                                if (!registerMiss("Heartbeat PONG timeout or incomplete frame")) break;
                                ++seq;
                                SleepHeartbeat(cfg.interval_ms);
                                continue;
                            }

                            const size_t frameEnd = heartbeatBuffer.find(';');
                            const std::string response = heartbeatBuffer.substr(0, frameEnd);
                            heartbeatBuffer.erase(0, frameEnd + 1);
                            if (response.rfind("PONG:", 0) != 0) {
                                if (!registerMiss("Unexpected heartbeat response")) break;
                                ++seq;
                                SleepHeartbeat(cfg.interval_ms);
                                continue;
                            }

                            std::vector<size_t> colons;
                            for (size_t pos = 0; (pos = response.find(':', pos)) != std::string::npos; ++pos) {
                                colons.push_back(pos);
                            }
                            if (colons.size() != 6) {
                                if (!registerMiss("Malformed PONG field count")) break;
                                ++seq;
                                SleepHeartbeat(cfg.interval_ms);
                                continue;
                            }

                            uint64_t pongSeq = 0;
                            uint64_t clientTimestamp = 0;
                            uint64_t pongNonce = 0;
                            const std::string status = response.substr(colons[3] + 1, colons[4] - colons[3] - 1);
                            const std::string pongHwid = response.substr(colons[4] + 1, colons[5] - colons[4] - 1);
                            const std::string hmac = response.substr(colons[5] + 1);
                            const bool fieldsValid =
                                ParseUnsignedDecimal(response.substr(colons[0] + 1, colons[1] - colons[0] - 1), pongSeq) &&
                                ParseUnsignedDecimal(response.substr(colons[1] + 1, colons[2] - colons[1] - 1), clientTimestamp) &&
                                ParseUnsignedDecimal(response.substr(colons[2] + 1, colons[3] - colons[2] - 1), pongNonce) &&
                                pongSeq == seq && pongNonce == pingNonce && clientTimestamp != 0 &&
                                pongHwid == hwid &&
                                (status == "1|1" || status == "1|0" || status == "0|1" || status == "0|0") &&
                                IsSha256HexDigest(hmac);
                            if (!fieldsValid) {
                                if (!registerMiss("PONG fields, identity, sequence, or nonce validation failed")) break;
                                ++seq;
                                SleepHeartbeat(cfg.interval_ms);
                                continue;
                            }

                            const std::string signedData = Oblivion::Protocol::BuildPongAuthPayload(
                                pongSeq, clientTimestamp, pingTimestamp, pongNonce, status, pongHwid);
                            const std::string expectedHmac = hmacSha256(sessionKey, signedData);
                            if (expectedHmac.empty() || !ConstantTimeEquals(expectedHmac, hmac)) {
                                if (!registerMiss("PONG HMAC verification failed")) break;
                                ++seq;
                                SleepHeartbeat(cfg.interval_ms);
                                continue;
                            }

                            const uint64_t rtt = MonotonicMilliseconds() - pingTimestamp;
                            rttSum += rtt;
                            ++rttCount;
                            rttSumCumulative += rtt;
                            ++rttCountCumulative;
                            consecutiveMiss = 0;
                            warningLogged = false;

                            const bool protectionOk = status == "1|1";
                            if (!protectionOk && !protectionDegraded) {
                                protectionDegraded = true;
                                LogViolation("HB_PROTECTION_DEGRADED",
                                    "Client protection degraded | status=" + status, hwid);
                            } else if (protectionOk && protectionDegraded) {
                                protectionDegraded = false;
                                std::cout << "[HB] PROTECTION RECOVERED for HWID [" << hwid << "]" << std::endl;
                            }

                            if (rttCount >= 5) {
                                const uint64_t averageRtt = rttSum / rttCount;
                                if (averageRtt > cfg.rtt_warn_ms) {
                                    const double cumulativeAverage = rttCountCumulative
                                        ? static_cast<double>(rttSumCumulative) / rttCountCumulative : 0.0;
                                    LogViolation("HB_WARNING",
                                        "High average RTT " + std::to_string(averageRtt) +
                                        "ms | average cumulative RTT=" +
                                        std::to_string(static_cast<int>(cumulativeAverage)) + "ms", hwid);
                                }
                                rttSum = 0;
                                rttCount = 0;
                            }
                            ++seq;
                            SleepHeartbeat(cfg.interval_ms);
                        }
                    }
                }
            } else {
                // Handler untuk violation reports lainnya
                std::cout << "[INFO] Laporan diterima dari HWID [" << hwid << "]: " << type << " - " << details << std::endl;
                
                // --- LOGIKA SERVER: CEK BAN LIST DAN LOG PELANGGARAN ---
                
                // 1. Catat semua pelanggaran ke log file
                LogViolation(type, details, hwid);
                
                // 2. Cek apakah HWID sudah di-ban (hanya cek, tidak auto-ban)
                const BanLookupResult reportBanStatus = LookupHWIDBanStatus(hwid);
                
                // 3. AUTO-BAN DISABLED - Admin melakukan ban manual via bans.txt
                // bool isSerious = IsSeriousViolation(type);
                // if (isSerious && !isBanned) {
                //     AddToBanList(hwid);
                //     isBanned = true;
                //     std::cout << "[BAN] Pelanggaran serius terdeteksi! HWID [" << hwid << "] di-ban otomatis." << std::endl;
                // }
                
                // 4. Kirim perintah KICK hanya jika sudah di-ban secara manual
                if (reportBanStatus == BanLookupResult::Error) {
                    LogViolation("BAN_LIST_UNAVAILABLE", "Cannot read ban list while processing a violation report", hwid);
                    SendAllBytes(clientSocket, "ERROR:BANLIST;");
                } else if (reportBanStatus == BanLookupResult::Banned) {
                    const char* kickCommand = "KICK;";
                    SendAllBytes(clientSocket, kickCommand);
                    std::cout << "[INFO] Perintah KICK dikirim ke client (HWID: " << hwid << ") - sudah ada di ban list." << std::endl;
                } else {
                    // Pelanggaran hanya dicatat ke log, tidak langsung di-ban atau di-kick
                    std::cout << "[WARNING] Pelanggaran terdeteksi dari HWID [" << hwid << "], dicatat ke log (menunggu review manual)." << std::endl;
                    // Client yang melaporkan pelanggaran sah perlu ACK agar tidak timeout.
                    const char* acknowledgement = "ACK;";
                    SendAllBytes(clientSocket, acknowledgement);
                }
            }
        } else if (bytesReceived == 0) {
            std::cout << "[INFO] Client closed connection gracefully" << std::endl;
        } else {
            int errorCode = WSAGetLastError();
            std::cout << "[ERROR] recv() failed with error code: " << errorCode << std::endl;
            LogViolation("RECV_ERROR", "Error code: " + std::to_string(errorCode), extractedHwid);
        }
    } catch (const std::exception& e) {
        std::cerr << "[EXCEPTION] Error handling client: " << e.what() << std::endl;
        LogViolation("EXCEPTION", std::string("Exception: ") + e.what(), extractedHwid);
    } catch (...) {
        std::cerr << "[EXCEPTION] Unknown error handling client" << std::endl;
        LogViolation("EXCEPTION", "Unknown exception occurred", extractedHwid);
    }

    closesocket(clientSocket);
}

int main() {
    if (SERVER_SECRET.empty() ||
        SERVER_SECRET == "DEV_SECRET_NOT_SET" ||
        SERVER_SECRET.size() < 32 ||
        SERVER_SECRET.size() > MAX_SECRET_LEN) {
        std::cerr << "[FATAL] OBLIVION_SECRET/secret.dat wajib dikonfigurasi "
                  << "dengan panjang secret antara 32 dan " << MAX_SECRET_LEN
                  << " byte. Server menolak secret kosong, development, terlalu pendek, "
                  << "atau melebihi batas protokol." << std::endl;
        return 1;
    }

    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    // Inisialisasi Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup gagal dengan error: " << iResult << std::endl;
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE; // Untuk bind()

    // Resolve alamat server dan port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo gagal dengan error: " << iResult << std::endl;
        WSACleanup();
        return 1;
    }

    // Buat socket untuk mendengarkan koneksi client
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        std::cerr << "Socket gagal dibuat dengan error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // SO_REUSEADDR: tanpa ini, restart server sering gagal dengan WSAEADDRINUSE
    // (socket dalam status TIME_WAIT) sehingga anti-cheat tidak bisa dijalankan ulang.
    {
        int reuseOpt = 1;
        if (setsockopt(ListenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuseOpt, sizeof(reuseOpt)) == SOCKET_ERROR) {
            std::cerr << "[WARN] setsockopt(SO_REUSEADDR) gagal dengan error: " << WSAGetLastError() << std::endl;
        }
    }

    // Bind socket ke alamat dan port
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "Bind gagal dengan error: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    // Mulai mendengarkan koneksi
    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "Listen gagal dengan error: " << WSAGetLastError() << std::endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "==================================================" << std::endl;
    std::cout << "  OBLIVION HACK SHIELD - Server Component" << std::endl;
    std::cout << "  Version 1.0 - Ragnarok Online Protection" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << "[INFO] Server berjalan dan mendengarkan di port " << DEFAULT_PORT << std::endl;
    std::cout << "[INFO] Ban list file: " << GetFilePath(BAN_LIST_FILE) << std::endl;
    std::cout << "[INFO] Violation log file: " << GetFilePath(VIOLATION_LOG_FILE) << std::endl;
    std::cout << "[INFO] Menunggu koneksi dari client..." << std::endl;
    std::cout << "==================================================" << std::endl;

    // Optional: read heartbeat config overrides from environment
    auto readEnvUint = [](const char* name, uint32_t defVal){
        char buf[64]; DWORD n = GetEnvironmentVariableA(name, buf, sizeof(buf));
        if (n == 0 || n >= sizeof(buf)) return defVal; 
        try { return (uint32_t)std::stoul(std::string(buf)); } catch (...) { return defVal; }
    };
    Oblivion::HeartbeatConfig globalHbCfg;
    globalHbCfg.interval_ms = readEnvUint("OBLV_HB_INTERVAL_MS", globalHbCfg.interval_ms);
    globalHbCfg.jitter_ms = readEnvUint("OBLV_HB_JITTER_MS", globalHbCfg.jitter_ms);
    globalHbCfg.timeout_ms = readEnvUint("OBLV_HB_TIMEOUT_MS", globalHbCfg.timeout_ms);
    globalHbCfg.max_consecutive_miss = readEnvUint("OBLV_HB_MAX_MISS", globalHbCfg.max_consecutive_miss);
    globalHbCfg.rtt_warn_ms = readEnvUint("OBLV_HB_RTT_WARN_MS", globalHbCfg.rtt_warn_ms);
    // Bound externally supplied timing values to avoid zero intervals and overflow.
    if (globalHbCfg.interval_ms < 250 || globalHbCfg.interval_ms > 60000) globalHbCfg.interval_ms = 3000;
    if (globalHbCfg.timeout_ms < 250 || globalHbCfg.timeout_ms > 60000) globalHbCfg.timeout_ms = 4000;
    if (globalHbCfg.max_consecutive_miss < 1 || globalHbCfg.max_consecutive_miss > 10) globalHbCfg.max_consecutive_miss = 3;
    if (globalHbCfg.rtt_warn_ms > 60000) globalHbCfg.rtt_warn_ms = 1500;
    g_heartbeatConfig = globalHbCfg;
    std::cout << "[HB CFG] interval=" << globalHbCfg.interval_ms << "ms jitter=" << globalHbCfg.jitter_ms
              << "ms timeout=" << globalHbCfg.timeout_ms << "ms maxMiss=" << globalHbCfg.max_consecutive_miss
              << " rttWarn=" << globalHbCfg.rtt_warn_ms << "ms" << std::endl;

    // Loop utama untuk menerima koneksi
    while (true) {
        // Terima koneksi dari client
        ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) {
            std::cerr << "[ERROR] Accept gagal dengan error: " << WSAGetLastError() << std::endl;
            continue; // Jangan shutdown server, coba accept lagi
        }

        std::cout << "\n[CONNECTION] New client connected" << std::endl;

        // Reserve a slot atomically; load()+fetch_add() allowed concurrent
        // accepts to exceed the configured worker limit under connection floods.
        if (!TryAcquireClientSlot()) {
            std::cerr << "[WARN] Batas koneksi bersamaan tercapai (" << kMaxConcurrentClients << "), koneksi baru ditolak" << std::endl;
            const char* busyResponse = "ERROR:BUSY;";
            SendAllBytes(ClientSocket, busyResponse);
            closesocket(ClientSocket);
            continue;
        }

        const SOCKET acceptedSocket = ClientSocket;
        std::thread clientThread;
        try {
            clientThread = std::thread([acceptedSocket]() {
                HandleClient(acceptedSocket);
                g_activeClients.fetch_sub(1, std::memory_order_release);
            });
        } catch (const std::exception& e) {
            g_activeClients.fetch_sub(1, std::memory_order_release);
            std::cerr << "[ERROR] Tidak dapat membuat worker client: " << e.what() << std::endl;
            closesocket(acceptedSocket);
            continue;
        }

        // If detach fails, keep ownership and join rather than destructing a
        // joinable std::thread (which would call std::terminate).
        try {
            clientThread.detach();
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Tidak dapat detach worker; menunggu worker selesai: " << e.what() << std::endl;
            if (clientThread.joinable()) {
                clientThread.join();
            }
        }
    }

    // Cleanup (tidak akan pernah tercapai dalam loop tak terbatas ini)
    closesocket(ListenSocket);
    WSACleanup();

    return 0;
}
