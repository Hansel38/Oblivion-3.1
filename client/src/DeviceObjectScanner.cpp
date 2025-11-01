#include "../pch.h"
#include "DeviceObjectScanner.h"
#include <winternl.h>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")

// NT Native API declarations
typedef NTSTATUS (NTAPI* pfnNtQueryDirectoryObject)(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI* pfnNtOpenDirectoryObject)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

#define DIRECTORY_QUERY 0x0001
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)

DeviceObjectScanner::DeviceObjectScanner()
{
}

DeviceObjectScanner::~DeviceObjectScanner()
{
}

bool DeviceObjectScanner::IsDBKIoctlCode(DWORD ioctl)
{
    return (ioctl >= DBK_IOCTL_BASE && ioctl <= DBK_IOCTL_END);
}

bool DeviceObjectScanner::QueryObjectDirectory(const wchar_t* directory, std::vector<std::wstring>& outObjects)
{
    outObjects.clear();

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    auto NtOpenDirectoryObject = reinterpret_cast<pfnNtOpenDirectoryObject>(
        GetProcAddress(ntdll, "NtOpenDirectoryObject"));
    auto NtQueryDirectoryObject = reinterpret_cast<pfnNtQueryDirectoryObject>(
        GetProcAddress(ntdll, "NtQueryDirectoryObject"));

    if (!NtOpenDirectoryObject || !NtQueryDirectoryObject) return false;

    UNICODE_STRING usDirName;
    RtlInitUnicodeString(&usDirName, directory);

    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    oa.ObjectName = &usDirName;
    oa.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE hDir = nullptr;
    NTSTATUS status = NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa);
    if (status != STATUS_SUCCESS || !hDir) return false;

    // Buffer for directory entries
    BYTE buffer[4096];
    ULONG context = 0;
    ULONG returnLength = 0;
    bool foundAny = false;

    while (true) {
        status = NtQueryDirectoryObject(hDir, buffer, sizeof(buffer), FALSE, FALSE, &context, &returnLength);
        
        if (status == STATUS_NO_MORE_ENTRIES) break;
        if (status != STATUS_SUCCESS) break;

        auto info = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(buffer);
        
        while (info->Name.Length > 0) {
            std::wstring name(info->Name.Buffer, info->Name.Length / sizeof(WCHAR));
            outObjects.push_back(name);
            foundAny = true;
            info++;
        }
    }

    CloseHandle(hDir);
    return foundAny;
}

bool DeviceObjectScanner::TestDeviceCommunication(const wchar_t* devicePath, DWORD& outIoctlDetected)
{
    outIoctlDetected = 0;

    // Try to open the device
    HANDLE hDevice = CreateFileW(
        devicePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        return false; // Device doesn't exist or access denied
    }

    // Device exists! This is already suspicious for DBK/CE patterns
    // Try common DBK IOCTL codes to verify it's actually a DBK driver
    DWORD testIoctls[] = {
        DBK_IOCTL_READMSR,
        DBK_IOCTL_WRITEMSR,
        DBK_IOCTL_READMEM,
        DBK_IOCTL_WRITEMEM,
        DBK_IOCTL_READPCI
    };

    BYTE inBuf[16] = { 0 };
    BYTE outBuf[256] = { 0 };
    DWORD bytesReturned = 0;

    for (DWORD ioctl : testIoctls) {
        // Don't actually execute potentially harmful operations
        // Just check if the IOCTL is recognized (may return error but not invalid function)
        BOOL result = DeviceIoControl(
            hDevice,
            ioctl,
            inBuf,
            sizeof(inBuf),
            outBuf,
            sizeof(outBuf),
            &bytesReturned,
            nullptr
        );

        DWORD error = GetLastError();
        
        // If error is NOT ERROR_INVALID_FUNCTION, the IOCTL is recognized
        if (error != ERROR_INVALID_FUNCTION && error != ERROR_NOT_SUPPORTED) {
            outIoctlDetected = ioctl;
            CloseHandle(hDevice);
            return true; // DBK IOCTL confirmed!
        }
    }

    CloseHandle(hDevice);
    return false; // Device exists but doesn't respond to DBK IOCTLs
}

bool DeviceObjectScanner::ScanDeviceObjects(DeviceObjectFinding& outFinding)
{
    outFinding = DeviceObjectFinding{};

    // Query \Device\ directory for suspicious objects
    std::vector<std::wstring> deviceObjects;
    if (QueryObjectDirectory(L"\\Device", deviceObjects)) {
        for (const auto& obj : deviceObjects) {
            std::wstring objLower = obj;
            std::transform(objLower.begin(), objLower.end(), objLower.begin(), ::towlower);

            // Check against known patterns
            if (objLower.find(L"dbk") != std::wstring::npos ||
                objLower.find(L"cedriver") != std::wstring::npos ||
                objLower.find(L"speedhack") != std::wstring::npos ||
                objLower.find(L"kernelcheatengine") != std::wstring::npos) {
                
                int score = 5; // Direct match to known CE pattern
                
                outFinding.deviceName = L"\\Device\\" + obj;
                outFinding.reason = L"Detected CE/DBK device object: " + obj;
                outFinding.indicators = score;

                // Try to get more info about the driver
                DWORD ioctlCode = 0;
                std::wstring dosDevicePath = L"\\\\.\\" + obj;
                if (TestDeviceCommunication(dosDevicePath.c_str(), ioctlCode)) {
                    outFinding.suspiciousIoctlCode = ioctlCode;
                    outFinding.indicators += 3;
                    outFinding.reason += L" [DBK IOCTL confirmed]";
                }

                if (outFinding.indicators >= m_threshold) {
                    return true;
                }
            }
        }
    }

    return false;
}

bool DeviceObjectScanner::ScanSymbolicLinks(DeviceObjectFinding& outFinding)
{
    outFinding = DeviceObjectFinding{};

    // Query \DosDevices\ (or \??\) directory
    std::vector<std::wstring> dosDevices;
    if (QueryObjectDirectory(L"\\DosDevices", dosDevices)) {
        for (const auto& link : dosDevices) {
            std::wstring linkLower = link;
            std::transform(linkLower.begin(), linkLower.end(), linkLower.begin(), ::towlower);

            // Check for DBK/CE symbolic links
            if (linkLower.find(L"dbk") != std::wstring::npos ||
                linkLower.find(L"cedriver") != std::wstring::npos) {
                
                int score = 5;
                
                outFinding.symbolicLink = L"\\DosDevices\\" + link;
                outFinding.reason = L"Detected CE/DBK symbolic link: " + link;
                outFinding.indicators = score;

                // Try to communicate with the device
                DWORD ioctlCode = 0;
                std::wstring devicePath = L"\\\\.\\" + link;
                if (TestDeviceCommunication(devicePath.c_str(), ioctlCode)) {
                    outFinding.suspiciousIoctlCode = ioctlCode;
                    outFinding.indicators += 3;
                    outFinding.reason += L" [Active DBK driver]";
                }

                if (outFinding.indicators >= m_threshold) {
                    return true;
                }
            }
        }
    }

    return false;
}

bool DeviceObjectScanner::ProbeKnownCEDevices(DeviceObjectFinding& outFinding)
{
    outFinding = DeviceObjectFinding{};

    // List of known CE/DBK device paths to probe
    const wchar_t* knownPaths[] = {
        L"\\\\.\\DBK32",
        L"\\\\.\\DBK64",
        L"\\\\.\\CEDRIVER",
        L"\\\\.\\CEDRIVER32",
        L"\\\\.\\CEDRIVER64",
        L"\\\\.\\speedhack",
        L"\\\\.\\kernelcheatengine"
    };

    for (const wchar_t* path : knownPaths) {
        DWORD ioctlCode = 0;
        if (TestDeviceCommunication(path, ioctlCode)) {
            int score = 5; // Device exists

            outFinding.deviceName = path;
            outFinding.reason = L"Known CE device path active: ";
            outFinding.reason += path;
            outFinding.indicators = score;

            if (ioctlCode > 0) {
                outFinding.suspiciousIoctlCode = ioctlCode;
                outFinding.indicators += 3;
                outFinding.reason += L" [DBK IOCTL confirmed]";
            }

            if (outFinding.indicators >= m_threshold) {
                return true;
            }
        }
    }

    return false;
}

bool DeviceObjectScanner::DetectDBKIoctlPattern(DeviceObjectFinding& outFinding)
{
    // This method combines all scanning techniques
    if (ProbeKnownCEDevices(outFinding)) return true;
    if (ScanDeviceObjects(outFinding)) return true;
    if (ScanSymbolicLinks(outFinding)) return true;

    return false;
}
