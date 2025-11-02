#pragma once
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <unordered_set>

// Extended structures for PEB walking
typedef struct _PEB_LDR_DATA_EXTENDED {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_EXTENDED, * PPEB_LDR_DATA_EXTENDED;

typedef struct _LDR_DATA_TABLE_ENTRY_EXTENDED {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_EXTENDED, * PLDR_DATA_TABLE_ENTRY_EXTENDED;

// Hidden module detection result
struct HiddenModuleInfo {
    std::wstring moduleName;
    PVOID baseAddress;
    SIZE_T size;
    std::string detectionMethod;  // "PEB_UNLINK", "MEMORY_SCAN", "TOOLHELP_MISMATCH"
    DWORD timestamp;
};

class PEBManipulationDetector {
public:
    PEBManipulationDetector();
    ~PEBManipulationDetector();

    // Main scanning function
    bool ScanForPEBManipulation();

    // Get detected hidden modules
    std::vector<HiddenModuleInfo> GetHiddenModules() const { return m_hiddenModules; }

    // Clear previous results
    void ClearResults();

    // Configuration
    void SetTargetProcess(HANDLE hProcess, DWORD pid);
    void SetEnableMemoryScan(bool enable) { m_enableMemoryScan = enable; }
    void SetEnableToolHelpValidation(bool enable) { m_enableToolHelpValidation = enable; }

private:
    // PEB enumeration methods
    bool EnumeratePEBModules(std::unordered_set<PVOID>& pebModules);
    bool EnumerateToolHelpModules(std::unordered_set<PVOID>& toolhelpModules);
    bool EnumerateMemoryRegions(std::vector<MEMORY_BASIC_INFORMATION>& regions);

    // Detection methods
    void DetectUnlinkedModules(
        const std::unordered_set<PVOID>& pebModules,
        const std::unordered_set<PVOID>& toolhelpModules
    );
    void DetectHiddenModulesInMemory(
        const std::unordered_set<PVOID>& pebModules
    );
    
    // Helper functions
    bool IsPEHeader(PVOID address);
    bool ReadRemoteMemory(PVOID address, PVOID buffer, SIZE_T size);
    std::wstring GetModuleNameFromPE(PVOID baseAddress);
    PPEB GetRemotePEB();
    
    // Validation
    bool ValidatePEBIntegrity();
    bool CheckForListManipulation(PLIST_ENTRY listHead);

private:
    HANDLE m_hProcess;
    DWORD m_targetPid;
    std::vector<HiddenModuleInfo> m_hiddenModules;
    
    // Configuration flags
    bool m_enableMemoryScan;
    bool m_enableToolHelpValidation;
    bool m_isInitialized;

    // Function pointers for undocumented APIs
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    pNtQueryInformationProcess NtQueryInformationProcess;
};
