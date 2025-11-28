#include "pch.h"
#include "network_reporter.h"
#include "hwid_generator.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <chrono>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "Ws2_32.lib")

namespace Oblivion {
    NetworkReporter::NetworkReporter(const std::string& serverIP, int serverPort, const std::string& secretKey)
        : m_serverIP(serverIP), m_serverPort(serverPort), m_secretKey(secretKey) {
        // Inisialisasi Winsock sekali saja untuk seluruh aplikasi
        // Catatan: WSAStartup bisa dipanggil beberapa kali, setiap panggilan harus diikuti WSACleanup
        WSADATA wsaData;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        // Jika WSAStartup gagal, gunakan fallback (jangan tutup aplikasi di constructor)
        if (iResult != 0) {
            m_hwid = "UNKNOWN";
            return;
        }
        
        // --- GENERATE HWID SAAT PEMBUATAN OBJEK ---
        // Gunakan try-catch untuk menangani error dari WMI atau hashing
        try {
            m_hwid = HWIDGenerator::Generate();
            // Jika Generate() mengembalikan string kosong, gunakan fallback
            if (m_hwid.empty()) {
                m_hwid = "UNKNOWN";
            }
        } catch (...) {
            // Jika ada exception (misalnya dari WMI), gunakan fallback
            m_hwid = "UNKNOWN";
        }
    }

    NetworkReporter::~NetworkReporter() {
        // Cleanup Winsock saat DLL dibongkar
        WSACleanup();
    }

    bool NetworkReporter::CheckBanStatus() {
        // Fungsi untuk check-in ke server dan mengecek apakah HWID di-ban
        SOCKET connectSocket = INVALID_SOCKET;
        struct addrinfo* result = NULL, * ptr = NULL, hints;

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        // Resolve server address and port
        std::string portStr = std::to_string(m_serverPort);
        int iResult = getaddrinfo(m_serverIP.c_str(), portStr.c_str(), &hints, &result);
        if (iResult != 0) {
            // Gagal resolve alamat server - Fail-Closed
            MessageBoxW(NULL, L"Gagal menyelesaikan alamat server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
        }

        // Attempt to connect to an address until one succeeds
        for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
            connectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (connectSocket == INVALID_SOCKET) {
                continue;
            }

            // Connect to server.
            if (connect(connectSocket, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
                closesocket(connectSocket);
                connectSocket = INVALID_SOCKET;
                continue;
            }
            break; // Connected
        }

        freeaddrinfo(result);

        if (connectSocket == INVALID_SOCKET) {
            // Gagal terhubung - Fail-Closed
            MessageBoxW(NULL, L"Tidak dapat terhubung ke server keamanan.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
        }

        // Kirim check-in dengan secret: "CHECKIN::HWID:SECRET;"
        std::string checkin = "CHECKIN::" + m_hwid + ":" + m_secretKey + ";";
        int bytesSent = send(connectSocket, checkin.c_str(), (int)checkin.length(), 0);
        if (bytesSent == SOCKET_ERROR || bytesSent == 0) {
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Gagal mengirim check-in ke server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
        }

        // Tunggu respons dari server dengan timeout
        char recvbuf[512] = { 0 };
        int recvbuflen = 512;
        fd_set fdset;
        struct timeval tv;
        tv.tv_sec = 3; // Timeout 3 detik
        tv.tv_usec = 0;
        FD_ZERO(&fdset);
        FD_SET(connectSocket, &fdset);

        int selectResult = select(0, &fdset, NULL, NULL, &tv);
        bool isBanned = false;
        if (selectResult > 0) {
            int bytesReceived = recv(connectSocket, recvbuf, recvbuflen, 0);
            if (bytesReceived > 0) {
                // Parse response - lebih robust
                std::string response(recvbuf, bytesReceived);
                
                // Hapus semua null terminator dan whitespace
                response.erase(std::remove(response.begin(), response.end(), '\0'), response.end());
                
                // Trim whitespace dari awal dan akhir
                size_t start = response.find_first_not_of(" \t\n\r");
                if (start != std::string::npos) {
                    response = response.substr(start);
                }
                size_t end = response.find_last_not_of(" \t\n\r");
                if (end != std::string::npos) {
                    response = response.substr(0, end + 1);
                }
                
                // Cek apakah response mengandung "KICK" (case-insensitive untuk lebih aman)
                std::string responseUpper = response;
                std::transform(responseUpper.begin(), responseUpper.end(), responseUpper.begin(), ::toupper);
                
                if (responseUpper.find("KICK") != std::string::npos || response == "KICK;") {
                    isBanned = true;
                }
            }
        } else {
            // Timeout - Fail-Closed
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Timeout menunggu respons server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            // Paksa tutup segera
            Sleep(100); // Beri waktu untuk MessageBox ditutup
            ExitProcess(0);
            TerminateProcess(GetCurrentProcess(), 0);
            return false;
        }

        closesocket(connectSocket);
        
        if (isBanned) {
            // HWID di-ban, tampilkan pesan dan tutup
            MessageBoxW(NULL, L"HWID Anda telah di-ban dari server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Banned", MB_OK | MB_ICONERROR | MB_TOPMOST);
            
            // Beri waktu singkat untuk MessageBox ditutup, lalu paksa tutup proses
            Sleep(100);
            
            // Paksa tutup proses dengan beberapa metode untuk memastikan
            ExitProcess(0);
            
            // Fallback jika ExitProcess tidak bekerja
            TerminateProcess(GetCurrentProcess(), 0);
            
            // Tidak akan sampai di sini
            return false;
        }
        
        return true; // Tidak di-ban, boleh lanjut
    }

    void NetworkReporter::ReportViolation(const std::string& type, const std::string& details) {
        // BLOCKING: Menunggu respons dari server sebelum kembali
        // Ini diperlukan agar client menunggu respons KICK dari server
        SOCKET connectSocket = INVALID_SOCKET;
        struct addrinfo* result = NULL, * ptr = NULL, hints;

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        // Resolve server address and port
        std::string portStr = std::to_string(m_serverPort);
        int iResult = getaddrinfo(m_serverIP.c_str(), portStr.c_str(), &hints, &result);
        if (iResult != 0) {
            // Gagal resolve alamat server - Fail-Closed
            MessageBoxW(NULL, L"Gagal menyelesaikan alamat server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
        }

        // Attempt to connect to an address until one succeeds
        for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
            connectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (connectSocket == INVALID_SOCKET) {
                continue;
            }

            // Connect to server.
            if (connect(connectSocket, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
                closesocket(connectSocket);
                connectSocket = INVALID_SOCKET;
                continue;
            }
            break; // Connected
        }

        freeaddrinfo(result);

        if (connectSocket == INVALID_SOCKET) {
            // --- GAGAL TERHUBUNG ---
            // Kebijakan "Fail-Closed": Jika tidak bisa hubungi server, anggap sebagai pelanggaran.
            MessageBoxW(NULL, L"Tidak dapat terhubung ke server keamanan.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
            return;
        }

        // --- FORMAT LAPORAN BARU MENGGUNAKAN HWID ---
        // Sanitasi details: replace colon dengan pipe untuk menghindari konflik parsing
        std::string sanitizedDetails = details;
        for (char& c : sanitizedDetails) {
            if (c == ':') c = '|';  // Replace colon dengan pipe
            if (c == ';') c = ',';  // Replace semicolon dengan comma (delimiter utama)
        }
        
        std::string report = type + ":" + sanitizedDetails + ":" + m_hwid + ":" + m_secretKey + ";";
        int bytesSent = send(connectSocket, report.c_str(), (int)report.length(), 0);
        if (bytesSent == SOCKET_ERROR || bytesSent == 0) {
            // Gagal mengirim laporan - Fail-Closed
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Gagal mengirim laporan ke server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(1);
        }

        // Tunggu respons dari server dengan timeout
        char recvbuf[512] = { 0 };
        int recvbuflen = 512;
        fd_set fdset;
        struct timeval tv;
        tv.tv_sec = 3; // Timeout 3 detik
        tv.tv_usec = 0;
        FD_ZERO(&fdset);
        FD_SET(connectSocket, &fdset);

            int selectResult = select(0, &fdset, NULL, NULL, &tv);
            if (selectResult > 0) {
                int bytesReceived = recv(connectSocket, recvbuf, recvbuflen, 0);
                if (bytesReceived > 0) {
                    // Parse response (hilangkan null terminator dan whitespace)
                    std::string response(recvbuf, bytesReceived);
                    // Trim whitespace dan null characters dari awal
                    size_t start = response.find_first_not_of(" \t\n\r\0");
                    if (start != std::string::npos) {
                        response = response.substr(start);
                    }
                    // Trim dari akhir
                    size_t end = response.find_last_not_of(" \t\n\r\0");
                    if (end != std::string::npos) {
                        response = response.substr(0, end + 1);
                    }
                    
                    // Cleanup socket sebelum ExitProcess
                    closesocket(connectSocket);
                    
                    // Cek apakah response adalah "KICK;" (case-sensitive sesuai server)
                    if (response == "KICK;") {
                        // Server mengirim perintah KICK - tampilkan message dan tutup
                        MessageBoxW(NULL, L"Server mendeteksi pelanggaran.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Violation", MB_OK | MB_ICONERROR | MB_TOPMOST);
                        ExitProcess(0);
                    }
                }
            }
        else {
            // Timeout atau error, juga dianggap pelanggaran (Fail-Closed)
            closesocket(connectSocket);
            MessageBoxW(NULL, L"Timeout menunggu respons server.\n\nClient akan ditutup.", L"Oblivion Hack Shield - Error", MB_OK | MB_ICONERROR | MB_TOPMOST);
            ExitProcess(0);
        }

        // Cleanup socket (jika masih terbuka)
        closesocket(connectSocket);
    }
}