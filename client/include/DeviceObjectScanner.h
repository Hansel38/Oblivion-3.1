#pragma once
#include <windows.h>
#include <string>
#include <vector>

// ===== PRIORITY 2.2: Enhanced Driver Detection =====
// Detects CE/DBK drivers by device object names and IOCTL codes

struct DeviceObjectFinding {
    std::wstring deviceName;        // e.g., \Device\DBK64, \Device\CEDRIVER
    std::wstring symbolicLink;      // e.g., \DosDevices\DBK64
    std::wstring driverName;        // Associated driver name if available
    DWORD suspiciousIoctlCode = 0;  // Detected DBK IOCTL code
    int indicators = 0;
    std::wstring reason;
};

class DeviceObjectScanner
{
public:
    DeviceObjectScanner();
    ~DeviceObjectScanner();

    void SetThreshold(int t) { m_threshold = t; }

    // ===== PRIORITY 2.2.2: Device Object Detection =====
    // Scan for suspicious device objects (\Device\DBK*, \Device\CEDRIVER*)
    bool ScanDeviceObjects(DeviceObjectFinding& outFinding);

    // ===== PRIORITY 2.2.1: DBK Driver IOCTL Detection =====
    // Detect DBK-characteristic IOCTL codes (0x9C402000-0x9C402FFF)
    bool DetectDBKIoctlPattern(DeviceObjectFinding& outFinding);

    // Scan symbolic links in \\DosDevices\\ directory
    bool ScanSymbolicLinks(DeviceObjectFinding& outFinding);

    // Try to communicate with known CE device paths
    bool ProbeKnownCEDevices(DeviceObjectFinding& outFinding);

private:
    int m_threshold = 2;

    // Known CE/DBK device patterns
    static constexpr const wchar_t* KNOWN_PATTERNS[] = {
        L"\\Device\\DBK",
        L"\\Device\\CEDRIVER",
        L"\\Device\\speedhack",
        L"\\Device\\kernelcheatengine",
        L"\\DosDevices\\DBK",
        L"\\DosDevices\\CEDRIVER"
    };

    // DBK IOCTL range: 0x9C402000 - 0x9C402FFF
    static constexpr DWORD DBK_IOCTL_BASE = 0x9C402000;
    static constexpr DWORD DBK_IOCTL_END = 0x9C402FFF;

    // Known DBK IOCTL codes
    static constexpr DWORD DBK_IOCTL_READMSR = 0x9C402000;
    static constexpr DWORD DBK_IOCTL_WRITEMSR = 0x9C402004;
    static constexpr DWORD DBK_IOCTL_READMEM = 0x9C402008;
    static constexpr DWORD DBK_IOCTL_WRITEMEM = 0x9C40200C;
    static constexpr DWORD DBK_IOCTL_READPCI = 0x9C402010;

    bool IsDBKIoctlCode(DWORD ioctl);
    bool QueryObjectDirectory(const wchar_t* directory, std::vector<std::wstring>& outObjects);
    bool TestDeviceCommunication(const wchar_t* devicePath, DWORD& outIoctlDetected);
};
