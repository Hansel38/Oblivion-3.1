#pragma once

#include <string>

namespace Oblivion {
    class NetworkReporter {
    public:
        NetworkReporter(const std::string& serverIP, int serverPort);
        ~NetworkReporter();

        // Fungsi utama untuk melaporkan pelanggaran
        void ReportViolation(const std::string& type, const std::string& details);

    private:
        std::string m_serverIP;
        int m_serverPort;
    };
}