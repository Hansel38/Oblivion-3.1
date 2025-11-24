#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_PORT "54321"
#define BUFFER_LEN 512

// Fungsi untuk menangani setiap client yang terhubung
void HandleClient(SOCKET clientSocket) {
    char buffer[BUFFER_LEN] = { 0 };
    int bytesReceived;

    // Terima data dari client
    bytesReceived = recv(clientSocket, buffer, BUFFER_LEN, 0);
    if (bytesReceived > 0) {
        std::string report(buffer, bytesReceived);
        std::cout << "[INFO] Laporan diterima: " << report << std::endl;

        // --- LOGIKA SERVER DI SINI ---
        // Di masa depan, Anda bisa menambahkan logika lebih lanjut:
        // - Parsing laporan (misal: PROCESS_DETECTED:cheatengine.exe)
        // - Memeriksa database pemain
        // - Mencatat ke file log atau database SQL
        // - Memberikan ban sementara atau permanen

        // Untuk saat ini, kita akan selalu memerintahkan client untuk keluar
        const char* kickCommand = "KICK;";
        send(clientSocket, kickCommand, (int)strlen(kickCommand), 0);
        std::cout << "[INFO] Perintah KICK dikirim ke client." << std::endl;
    }
    else {
        std::cout << "[ERROR] Gagal menerima data dari client atau client memutuskan koneksi." << std::endl;
    }

    // Tutup koneksi dengan client
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

    std::cout << "Oblivion Hack Shield Server berjalan dan mendengarkan di port " << DEFAULT_PORT << "..." << std::endl;

    // Loop utama untuk menerima koneksi
    while (true) {
        // Terima koneksi dari client
        ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) {
            std::cerr << "Accept gagal dengan error: " << WSAGetLastError() << std::endl;
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }

        // Buat thread baru untuk menangani client agar server bisa menerima client lain
        std::thread clientThread(HandleClient, ClientSocket);
        clientThread.detach(); // Lepaskan thread agar bisa berjalan mandiri
    }

    // Cleanup (tidak akan pernah tercapai dalam loop tak terbatas ini)
    closesocket(ListenSocket);
    WSACleanup();

    return 0;
}