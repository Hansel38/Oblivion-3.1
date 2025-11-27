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
#include <algorithm>
#include <windows.h>

#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_PORT "54321"
#define BUFFER_LEN 512
#define BAN_LIST_FILE "bans.txt"
#define VIOLATION_LOG_FILE "violations.log"

// Fungsi untuk mendapatkan path folder tempat executable berada
std::string GetExecutableDirectory() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string path(exePath);
    size_t lastSlash = path.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        return path.substr(0, lastSlash + 1);
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

// Fungsi untuk mengecek apakah HWID sudah di-ban
// PENTING: File bans.txt dibaca fresh setiap kali fungsi ini dipanggil (tidak ada caching)
// Untuk unban HWID, cukup hapus baris HWID dari bans.txt dan restart client
bool IsHWIDBanned(const std::string& hwid) {
    std::string banFilePath = GetFilePath(BAN_LIST_FILE);
    std::ifstream banFile(banFilePath);
    if (!banFile.is_open()) {
        return false; // File tidak ada, berarti belum ada yang di-ban
    }
    
    std::string line;
    while (std::getline(banFile, line)) {
        // Hapus whitespace dari awal dan akhir
        line.erase(0, line.find_first_not_of(" \t\n\r"));
        line.erase(line.find_last_not_of(" \t\n\r") + 1);
        
        // Jika line kosong atau komentar (dimulai dengan #), skip
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Bandingkan HWID (case-insensitive)
        if (_stricmp(line.c_str(), hwid.c_str()) == 0) {
            banFile.close();
            return true;
        }
    }
    
    banFile.close();
    return false;
}

// Fungsi untuk menambahkan HWID ke ban list
void AddToBanList(const std::string& hwid) {
    // Cek dulu apakah sudah di-ban
    if (IsHWIDBanned(hwid)) {
        return; // Sudah di-ban, tidak perlu ditambahkan lagi
    }
    
    std::string banFilePath = GetFilePath(BAN_LIST_FILE);
    std::ofstream banFile(banFilePath, std::ios::app);
    if (banFile.is_open()) {
        banFile << hwid << std::endl;
        banFile.close();
        std::cout << "[BAN] HWID [" << hwid << "] ditambahkan ke ban list." << std::endl;
    } else {
        std::cerr << "[ERROR] Gagal membuka file ban list untuk menulis." << std::endl;
    }
}

// Fungsi untuk mencatat pelanggaran ke log file
void LogViolation(const std::string& type, const std::string& details, const std::string& hwid) {
    std::string logFilePath = GetFilePath(VIOLATION_LOG_FILE);
    std::ofstream logFile(logFilePath, std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << GetCurrentTimestamp() << "] TYPE: " << type 
                << " | HWID: " << hwid 
                << " | DETAILS: " << details << std::endl;
        logFile.close();
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
        "FILE_INTEGRITY_FAILED"
    };
    
    for (const auto& serious : seriousViolations) {
        if (_stricmp(type.c_str(), serious.c_str()) == 0) {
            return true;
        }
    }
    
    return false;
}

// Fungsi untuk menangani setiap client yang terhubung
void HandleClient(SOCKET clientSocket) {
    char buffer[BUFFER_LEN] = {0};
    int bytesReceived;

    try {
        bytesReceived = recv(clientSocket, buffer, BUFFER_LEN, 0);
        if (bytesReceived > 0) {
            std::string report(buffer, bytesReceived);
            
            std::cout << "[DEBUG] Received raw data (" << bytesReceived << " bytes): " << report << std::endl;
            
            // --- PARSING FORMAT BARU: TYPE:DETAILS:HWID; ---
            size_t pos1 = report.find(':');
            size_t pos2 = report.find(':', pos1 + 1);
            size_t pos3 = report.find(';', pos2 + 1);

            if (pos1 != std::string::npos && pos2 != std::string::npos && pos3 != std::string::npos) {
                std::string type = report.substr(0, pos1);
                std::string details = report.substr(pos1 + 1, pos2 - pos1 - 1);
                std::string hwid = report.substr(pos2 + 1, pos3 - pos2 - 1);

                std::cout << "[PARSE] TYPE: " << type << " | DETAILS: " << details << " | HWID: " << hwid << std::endl;

            // --- CEK JIKA INI CHECK-IN (bukan pelanggaran) ---
            if (type == "CHECKIN") {
                // Ini adalah check-in dari client saat pertama kali start
                std::cout << "[CHECKIN] Client check-in dari HWID [" << hwid << "]" << std::endl;
                
                // Cek apakah HWID sudah di-ban (file dibaca fresh setiap kali, tidak ada cache)
                bool isBanned = IsHWIDBanned(hwid);
                
                if (isBanned) {
                    // HWID di-ban, kirim KICK
                    const char* kickCommand = "KICK;";
                    send(clientSocket, kickCommand, (int)strlen(kickCommand), 0);
                    std::cout << "[BAN] HWID [" << hwid << "] terdeteksi di ban list. Perintah KICK dikirim." << std::endl;
                    std::cout << "[INFO] Untuk unban, hapus HWID dari bans.txt dan restart client." << std::endl;
                } else {
                    // HWID tidak di-ban, kirim OK
                    const char* okCommand = "OK;";
                    send(clientSocket, okCommand, (int)strlen(okCommand), 0);
                    std::cout << "[OK] HWID [" << hwid << "] diizinkan untuk melanjutkan (tidak ada di ban list)." << std::endl;
                }
            } else {
                // Ini adalah laporan pelanggaran
                std::cout << "[INFO] Laporan diterima dari HWID [" << hwid << "]: " << type << " - " << details << std::endl;
                
                // --- LOGIKA SERVER: CEK BAN LIST DAN LOG PELANGGARAN ---
                
                // 1. Catat semua pelanggaran ke log file
                LogViolation(type, details, hwid);
                
                // 2. Cek apakah HWID sudah di-ban
                bool isBanned = IsHWIDBanned(hwid);
                
                // 3. Jika pelanggaran serius, tambahkan ke ban list
                bool isSerious = IsSeriousViolation(type);
                if (isSerious && !isBanned) {
                    AddToBanList(hwid);
                    isBanned = true; // Setelah ditambahkan, anggap sudah di-ban
                    std::cout << "[BAN] Pelanggaran serius terdeteksi! HWID [" << hwid << "] di-ban otomatis." << std::endl;
                }
                
                // 4. Kirim perintah KICK jika sudah di-ban atau pelanggaran serius
                if (isBanned || isSerious) {
                    const char* kickCommand = "KICK;";
                    send(clientSocket, kickCommand, (int)strlen(kickCommand), 0);
                    std::cout << "[INFO] Perintah KICK dikirim ke client (HWID: " << hwid << ")." << std::endl;
                } else {
                    // Untuk pelanggaran ringan, hanya log saja (tidak langsung di-ban)
                    std::cout << "[WARNING] Pelanggaran ringan terdeteksi dari HWID [" << hwid << "], hanya dicatat ke log." << std::endl;
                    // Tetap kirim KICK untuk pelanggaran ringan juga (opsional, bisa diubah)
                    const char* kickCommand = "KICK;";
                    send(clientSocket, kickCommand, (int)strlen(kickCommand), 0);
                }
            }

        } else {
            std::cout << "[ERROR] Laporan tidak valid diterima (malformed format): " << report << std::endl;
            std::cout << "[DEBUG] Expected format: TYPE:DETAILS:HWID;" << std::endl;
        }
    } else if (bytesReceived == 0) {
        std::cout << "[INFO] Client closed connection gracefully" << std::endl;
    } else {
        std::cout << "[ERROR] recv() failed with error code: " << WSAGetLastError() << std::endl;
    }
    } catch (const std::exception& e) {
        std::cerr << "[EXCEPTION] Error handling client: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[EXCEPTION] Unknown error handling client" << std::endl;
    }

    closesocket(clientSocket);
}

int main() {
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

    // Loop utama untuk menerima koneksi
    while (true) {
        // Terima koneksi dari client
        ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) {
            std::cerr << "[ERROR] Accept gagal dengan error: " << WSAGetLastError() << std::endl;
            continue; // Jangan shutdown server, coba accept lagi
        }

        std::cout << "\n[CONNECTION] New client connected" << std::endl;
        
        // Buat thread baru untuk menangani client agar server bisa menerima client lain
        std::thread clientThread(HandleClient, ClientSocket);
        clientThread.detach(); // Lepaskan thread agar bisa berjalan mandiri
    }

    // Cleanup (tidak akan pernah tercapai dalam loop tak terbatas ini)
    closesocket(ListenSocket);
    WSACleanup();

    return 0;
}