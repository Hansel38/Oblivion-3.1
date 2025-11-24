#include "pch.h"
#include "network_reporter.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <chrono>

#pragma comment(lib, "Ws2_32.lib")

namespace Oblivion {
    NetworkReporter::NetworkReporter(const std::string& serverIP, int serverPort)
        : m_serverIP(serverIP), m_serverPort(serverPort) {
        // Inisialisasi Winsock sekali saja untuk seluruh aplikasi
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    NetworkReporter::~NetworkReporter() {
        // Cleanup Winsock saat DLL dibongkar
        WSACleanup();
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
        getaddrinfo(m_serverIP.c_str(), portStr.c_str(), &hints, &result);

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

        // Format dan kirim laporan
        std::string report = type + ":" + details + ";";
        send(connectSocket, report.c_str(), (int)report.length(), 0);

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