#pragma once
#include <windows.h>
#include <string>
#include <vector>

// ===== PRIORITY 2.3: Network Artifact Detection =====
// Detects CE server listening ports and network-based speedhack

struct NetworkArtifactFinding {
    DWORD localPort = 0;
    DWORD remotePort = 0;
    std::wstring localAddress;
    std::wstring remoteAddress;
    std::wstring processName;
    DWORD processId = 0;
    int indicators = 0;
    std::wstring reason;
    bool isCEServer = false;
    bool isSpeedhackPattern = false;
};

class NetworkArtifactScanner
{
public:
    NetworkArtifactScanner();
    ~NetworkArtifactScanner();

    void SetThreshold(int t) { m_threshold = t; }

    // ===== PRIORITY 2.3.1: CE Server Port Detection =====
    // Detect CE server listening on default port 52736 or range 52000-53000
    bool ScanForCEServerPort(NetworkArtifactFinding& outFinding);

    // Scan all listening TCP ports for suspicious patterns
    bool ScanListeningPorts(NetworkArtifactFinding& outFinding);

    // Scan active TCP connections for CE signature
    bool ScanActiveTCPConnections(NetworkArtifactFinding& outFinding);

private:
    int m_threshold = 2;

    // CE default server port
    static constexpr DWORD CE_DEFAULT_PORT = 52736;
    static constexpr DWORD CE_PORT_RANGE_START = 52000;
    static constexpr DWORD CE_PORT_RANGE_END = 53000;

    bool IsCESuspiciousPort(DWORD port);
    bool GetProcessNameByPid(DWORD pid, std::wstring& outName);
    bool EnumerateTCPConnections(std::vector<NetworkArtifactFinding>& outConnections);
    bool EnumerateTCPListeners(std::vector<NetworkArtifactFinding>& outListeners);
};
