#include "../pch.h"
#include "NetworkArtifactScanner.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

NetworkArtifactScanner::NetworkArtifactScanner()
{
}

NetworkArtifactScanner::~NetworkArtifactScanner()
{
}

bool NetworkArtifactScanner::IsCESuspiciousPort(DWORD port)
{
    return (port == CE_DEFAULT_PORT) || 
           (port >= CE_PORT_RANGE_START && port <= CE_PORT_RANGE_END);
}

bool NetworkArtifactScanner::GetProcessNameByPid(DWORD pid, std::wstring& outName)
{
    outName.clear();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                outName = pe.szExeFile;
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return false;
}

bool NetworkArtifactScanner::EnumerateTCPListeners(std::vector<NetworkArtifactFinding>& outListeners)
{
    outListeners.clear();

    // Get TCP table with owning process
    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    
    if (result != ERROR_INSUFFICIENT_BUFFER) return false;

    std::vector<BYTE> buffer(size);
    auto pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

    result = GetExtendedTcpTable(pTcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (result != NO_ERROR) return false;

    for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
        auto& row = pTcpTable->table[i];

        NetworkArtifactFinding finding;
        finding.localPort = ntohs((WORD)row.dwLocalPort);
        finding.processId = row.dwOwningPid;

        // Convert IP address
        IN_ADDR addr;
        addr.S_un.S_addr = row.dwLocalAddr;
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
        
        wchar_t wideIp[INET_ADDRSTRLEN];
        MultiByteToWideChar(CP_ACP, 0, ipStr, -1, wideIp, INET_ADDRSTRLEN);
        finding.localAddress = wideIp;

        GetProcessNameByPid(finding.processId, finding.processName);

        outListeners.push_back(finding);
    }

    return !outListeners.empty();
}

bool NetworkArtifactScanner::EnumerateTCPConnections(std::vector<NetworkArtifactFinding>& outConnections)
{
    outConnections.clear();

    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    
    if (result != ERROR_INSUFFICIENT_BUFFER) return false;

    std::vector<BYTE> buffer(size);
    auto pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

    result = GetExtendedTcpTable(pTcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR) return false;

    for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
        auto& row = pTcpTable->table[i];

        // Only interested in established connections
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue;

        NetworkArtifactFinding finding;
        finding.localPort = ntohs((WORD)row.dwLocalPort);
        finding.remotePort = ntohs((WORD)row.dwRemotePort);
        finding.processId = row.dwOwningPid;

        // Local address
        IN_ADDR localAddr;
        localAddr.S_un.S_addr = row.dwLocalAddr;
        char localIpStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &localAddr, localIpStr, sizeof(localIpStr));
        
        wchar_t wideLocalIp[INET_ADDRSTRLEN];
        MultiByteToWideChar(CP_ACP, 0, localIpStr, -1, wideLocalIp, INET_ADDRSTRLEN);
        finding.localAddress = wideLocalIp;

        // Remote address
        IN_ADDR remoteAddr;
        remoteAddr.S_un.S_addr = row.dwRemoteAddr;
        char remoteIpStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &remoteAddr, remoteIpStr, sizeof(remoteIpStr));
        
        wchar_t wideRemoteIp[INET_ADDRSTRLEN];
        MultiByteToWideChar(CP_ACP, 0, remoteIpStr, -1, wideRemoteIp, INET_ADDRSTRLEN);
        finding.remoteAddress = wideRemoteIp;

        GetProcessNameByPid(finding.processId, finding.processName);

        outConnections.push_back(finding);
    }

    return !outConnections.empty();
}

bool NetworkArtifactScanner::ScanListeningPorts(NetworkArtifactFinding& outFinding)
{
    outFinding = NetworkArtifactFinding{};

    std::vector<NetworkArtifactFinding> listeners;
    if (!EnumerateTCPListeners(listeners)) return false;

    for (const auto& listener : listeners) {
        if (IsCESuspiciousPort(listener.localPort)) {
            int score = 0;

            // Exact CE default port
            if (listener.localPort == CE_DEFAULT_PORT) {
                score += 5;
                outFinding.reason = L"CE default server port detected (52736)";
            } else {
                score += 3;
                wchar_t buf[128];
                swprintf_s(buf, L"Suspicious port in CE range (%u)", listener.localPort);
                outFinding.reason = buf;
            }

            // Check process name
            std::wstring procLower = listener.processName;
            std::transform(procLower.begin(), procLower.end(), procLower.begin(), ::towlower);

            if (procLower.find(L"cheatengine") != std::wstring::npos ||
                procLower.find(L"ce.exe") != std::wstring::npos ||
                procLower.find(L"ce-x64") != std::wstring::npos) {
                score += 5;
                outFinding.reason += L" [CheatEngine process]";
            }

            outFinding = listener;
            outFinding.indicators = score;
            outFinding.isCEServer = true;

            if (score >= m_threshold) {
                return true;
            }
        }
    }

    return false;
}

bool NetworkArtifactScanner::ScanActiveTCPConnections(NetworkArtifactFinding& outFinding)
{
    outFinding = NetworkArtifactFinding{};

    std::vector<NetworkArtifactFinding> connections;
    if (!EnumerateTCPConnections(connections)) return false;

    DWORD currentPid = GetCurrentProcessId();

    for (const auto& conn : connections) {
        // Check if this process is connected to a CE server port
        if (conn.processId == currentPid || conn.remotePort == 0) continue;

        if (IsCESuspiciousPort(conn.remotePort)) {
            int score = 3; // Connection to CE port range

            if (conn.remotePort == CE_DEFAULT_PORT) {
                score += 3;
                outFinding.reason = L"Active connection to CE server port (52736)";
            } else {
                wchar_t buf[128];
                swprintf_s(buf, L"Connection to suspicious CE port (%u)", conn.remotePort);
                outFinding.reason = buf;
            }

            outFinding = conn;
            outFinding.indicators = score;
            outFinding.isCEServer = true;

            if (score >= m_threshold) {
                return true;
            }
        }

        // Also check local port (if we're the server)
        if (conn.processId == currentPid && IsCESuspiciousPort(conn.localPort)) {
            int score = 5;
            
            wchar_t buf[128];
            swprintf_s(buf, L"Game process bound to CE server port (%u)", conn.localPort);
            outFinding.reason = buf;

            outFinding = conn;
            outFinding.indicators = score;
            outFinding.isCEServer = true;

            if (score >= m_threshold) {
                return true;
            }
        }
    }

    return false;
}

bool NetworkArtifactScanner::ScanForCEServerPort(NetworkArtifactFinding& outFinding)
{
    // Try all detection methods
    if (ScanListeningPorts(outFinding)) return true;
    if (ScanActiveTCPConnections(outFinding)) return true;

    return false;
}
