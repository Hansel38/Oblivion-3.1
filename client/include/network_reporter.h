#pragma once

#include <string>

namespace Oblivion {
    class NetworkReporter {
    public:
        NetworkReporter(const std::string& serverIP, int serverPort);
        ~NetworkReporter();

        // Fungsi untuk check-in ke server (cek apakah di-ban)
        // Mengembalikan true jika diizinkan, false jika di-ban
        bool CheckBanStatus();

        // Fungsi utama untuk melaporkan pelanggaran
        void ReportViolation(const std::string& type, const std::string& details);

    private:
        std::string m_serverIP;
        int m_serverPort;
        std::string m_hwid;  // Hardware ID yang di-generate saat konstruktor
    };
}