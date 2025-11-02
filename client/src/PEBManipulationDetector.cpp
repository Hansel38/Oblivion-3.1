#include "../pch.h"
#include "../include/PEBManipulationDetector.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "ntdll.lib")

PEBManipulationDetector::PEBManipulationDetector()
    : m_hProcess(nullptr)
    , m_targetPid(0)
    , m_enableMemoryScan(true)
    , m_enableToolHelpValidation(true)
    , m_isInitialized(false)
    , NtQueryInformationProcess(nullptr)
{
    // Load NtQueryInformationProcess
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(
            hNtdll, "NtQueryInformationProcess");
    }
}

PEBManipulationDetector::~PEBManipulationDetector()
{
    if (m_hProcess && m_hProcess != GetCurrentProcess()) {
        CloseHandle(m_hProcess);
    }
}

void PEBManipulationDetector::SetTargetProcess(HANDLE hProcess, DWORD pid)
{
    if (m_hProcess && m_hProcess != GetCurrentProcess()) {
        CloseHandle(m_hProcess);
    }
    
    m_hProcess = hProcess;
    m_targetPid = pid;
    m_isInitialized = (hProcess != nullptr && NtQueryInformationProcess != nullptr);
}

void PEBManipulationDetector::ClearResults()
{
    m_hiddenModules.clear();
}

bool PEBManipulationDetector::ScanForPEBManipulation()
{
    if (!m_isInitialized) {
        return false;
    }

    ClearResults();

    // Step 1: Enumerate modules from PEB
    std::unordered_set<PVOID> pebModules;
    if (!EnumeratePEBModules(pebModules)) {
        return false;
    }

    // Step 2: Enumerate modules using ToolHelp32 (if enabled)
    if (m_enableToolHelpValidation) {
        std::unordered_set<PVOID> toolhelpModules;
        if (EnumerateToolHelpModules(toolhelpModules)) {
            DetectUnlinkedModules(pebModules, toolhelpModules);
        }
    }

    // Step 3: Scan memory for hidden PE headers (if enabled)
    if (m_enableMemoryScan) {
        DetectHiddenModulesInMemory(pebModules);
    }

    // Step 4: Validate PEB integrity
    ValidatePEBIntegrity();

    return true;
}

PPEB PEBManipulationDetector::GetRemotePEB()
{
    if (!NtQueryInformationProcess) {
        return nullptr;
    }

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;

    NTSTATUS status = NtQueryInformationProcess(
        m_hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status != 0) {
        return nullptr;
    }

    return pbi.PebBaseAddress;
}

bool PEBManipulationDetector::ReadRemoteMemory(PVOID address, PVOID buffer, SIZE_T size)
{
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(m_hProcess, address, buffer, size, &bytesRead) && (bytesRead == size);
}

bool PEBManipulationDetector::EnumeratePEBModules(std::unordered_set<PVOID>& pebModules)
{
    PPEB peb = GetRemotePEB();
    if (!peb) {
        return false;
    }

    // Read PEB from target process
    PEB pebData = { 0 };
    if (!ReadRemoteMemory(peb, &pebData, sizeof(PEB))) {
        return false;
    }

    if (!pebData.Ldr) {
        return false;
    }

    // Read PEB_LDR_DATA
    PEB_LDR_DATA_EXTENDED ldrData = { 0 };
    if (!ReadRemoteMemory(pebData.Ldr, &ldrData, sizeof(PEB_LDR_DATA_EXTENDED))) {
        return false;
    }

    // Walk InLoadOrderModuleList
    PLIST_ENTRY head = &ldrData.InLoadOrderModuleList;
    PLIST_ENTRY current = ldrData.InLoadOrderModuleList.Flink;

    // Prevent infinite loop
    int maxIterations = 1000;
    int iterations = 0;

    while (current != head && iterations++ < maxIterations) {
        // Read LDR_DATA_TABLE_ENTRY
        LDR_DATA_TABLE_ENTRY_EXTENDED entry = { 0 };
        PLDR_DATA_TABLE_ENTRY_EXTENDED pEntry = CONTAINING_RECORD(
            current, LDR_DATA_TABLE_ENTRY_EXTENDED, InLoadOrderLinks);

        if (!ReadRemoteMemory(pEntry, &entry, sizeof(LDR_DATA_TABLE_ENTRY_EXTENDED))) {
            break;
        }

        // Add to set
        if (entry.DllBase) {
            pebModules.insert(entry.DllBase);
        }

        current = entry.InLoadOrderLinks.Flink;

        // Sanity check
        if (!current || current == (PLIST_ENTRY)head) {
            break;
        }
    }

    return !pebModules.empty();
}

bool PEBManipulationDetector::EnumerateToolHelpModules(std::unordered_set<PVOID>& toolhelpModules)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_targetPid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32W me32 = { 0 };
    me32.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            toolhelpModules.insert(me32.modBaseAddr);
        } while (Module32NextW(hSnapshot, &me32));
    }

    CloseHandle(hSnapshot);
    return !toolhelpModules.empty();
}

bool PEBManipulationDetector::EnumerateMemoryRegions(std::vector<MEMORY_BASIC_INFORMATION>& regions)
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    PVOID address = nullptr;

    while (VirtualQueryEx(m_hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Look for committed executable memory
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            regions.push_back(mbi);
        }

        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    return !regions.empty();
}

void PEBManipulationDetector::DetectUnlinkedModules(
    const std::unordered_set<PVOID>& pebModules,
    const std::unordered_set<PVOID>& toolhelpModules)
{
    // Find modules in ToolHelp but not in PEB (unlinked from PEB)
    for (PVOID moduleBase : toolhelpModules) {
        if (pebModules.find(moduleBase) == pebModules.end()) {
            HiddenModuleInfo info;
            info.baseAddress = moduleBase;
            info.moduleName = GetModuleNameFromPE(moduleBase);
            info.detectionMethod = "PEB_UNLINK";
            info.timestamp = GetTickCount();
            info.size = 0; // Will be filled if needed

            m_hiddenModules.push_back(info);
        }
    }
}

void PEBManipulationDetector::DetectHiddenModulesInMemory(
    const std::unordered_set<PVOID>& pebModules)
{
    std::vector<MEMORY_BASIC_INFORMATION> regions;
    if (!EnumerateMemoryRegions(regions)) {
        return;
    }

    for (const auto& mbi : regions) {
        PVOID baseAddr = mbi.BaseAddress;

        // Skip if already in PEB
        if (pebModules.find(baseAddr) != pebModules.end()) {
            continue;
        }

        // Check if it's a PE header
        if (IsPEHeader(baseAddr)) {
            HiddenModuleInfo info;
            info.baseAddress = baseAddr;
            info.moduleName = GetModuleNameFromPE(baseAddr);
            info.detectionMethod = "MEMORY_SCAN";
            info.timestamp = GetTickCount();
            info.size = mbi.RegionSize;

            m_hiddenModules.push_back(info);
        }
    }
}

bool PEBManipulationDetector::IsPEHeader(PVOID address)
{
    IMAGE_DOS_HEADER dosHeader = { 0 };
    if (!ReadRemoteMemory(address, &dosHeader, sizeof(IMAGE_DOS_HEADER))) {
        return false;
    }

    // Check DOS signature
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    // Validate e_lfanew range
    if (dosHeader.e_lfanew < sizeof(IMAGE_DOS_HEADER) || dosHeader.e_lfanew > 0x1000) {
        return false;
    }

    // Read NT headers
    IMAGE_NT_HEADERS ntHeaders = { 0 };
    PVOID ntHeaderAddr = (PVOID)((ULONG_PTR)address + dosHeader.e_lfanew);
    
    if (!ReadRemoteMemory(ntHeaderAddr, &ntHeaders, sizeof(IMAGE_NT_HEADERS))) {
        return false;
    }

    // Check PE signature
    return (ntHeaders.Signature == IMAGE_NT_SIGNATURE);
}

std::wstring PEBManipulationDetector::GetModuleNameFromPE(PVOID baseAddress)
{
    // Try to get module name from export directory
    IMAGE_DOS_HEADER dosHeader = { 0 };
    if (!ReadRemoteMemory(baseAddress, &dosHeader, sizeof(IMAGE_DOS_HEADER))) {
        return L"<Unknown>";
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return L"<Invalid PE>";
    }

    IMAGE_NT_HEADERS ntHeaders = { 0 };
    PVOID ntHeaderAddr = (PVOID)((ULONG_PTR)baseAddress + dosHeader.e_lfanew);
    
    if (!ReadRemoteMemory(ntHeaderAddr, &ntHeaders, sizeof(IMAGE_NT_HEADERS))) {
        return L"<Unknown>";
    }

    // Get export directory
    DWORD exportDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) {
        std::wstringstream ss;
        ss << L"<NoName_0x" << std::hex << std::setw(8) << std::setfill(L'0') 
           << (ULONG_PTR)baseAddress << L">";
        return ss.str();
    }

    IMAGE_EXPORT_DIRECTORY exportDir = { 0 };
    PVOID exportDirAddr = (PVOID)((ULONG_PTR)baseAddress + exportDirRVA);
    
    if (!ReadRemoteMemory(exportDirAddr, &exportDir, sizeof(IMAGE_EXPORT_DIRECTORY))) {
        return L"<Unknown>";
    }

    if (exportDir.Name == 0) {
        std::wstringstream ss;
        ss << L"<NoName_0x" << std::hex << std::setw(8) << std::setfill(L'0') 
           << (ULONG_PTR)baseAddress << L">";
        return ss.str();
    }

    // Read module name
    char moduleName[MAX_PATH] = { 0 };
    PVOID nameAddr = (PVOID)((ULONG_PTR)baseAddress + exportDir.Name);
    
    if (!ReadRemoteMemory(nameAddr, moduleName, sizeof(moduleName))) {
        return L"<Unknown>";
    }

    moduleName[MAX_PATH - 1] = '\0';

    // Convert to wstring
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, moduleName, -1, nullptr, 0);
    if (wideLen == 0) {
        return L"<ConversionError>";
    }

    std::wstring result(wideLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, moduleName, -1, &result[0], wideLen);
    
    // Remove null terminator
    if (!result.empty() && result.back() == L'\0') {
        result.pop_back();
    }

    return result;
}

bool PEBManipulationDetector::ValidatePEBIntegrity()
{
    PPEB peb = GetRemotePEB();
    if (!peb) {
        return false;
    }

    PEB pebData = { 0 };
    if (!ReadRemoteMemory(peb, &pebData, sizeof(PEB))) {
        return false;
    }

    // Check if Ldr is null (major manipulation)
    if (!pebData.Ldr) {
        HiddenModuleInfo info;
        info.baseAddress = nullptr;
        info.moduleName = L"<PEB.Ldr is NULL>";
        info.detectionMethod = "PEB_INTEGRITY_CHECK";
        info.timestamp = GetTickCount();
        info.size = 0;
        m_hiddenModules.push_back(info);
        return false;
    }

    // Read LDR data
    PEB_LDR_DATA_EXTENDED ldrData = { 0 };
    if (!ReadRemoteMemory(pebData.Ldr, &ldrData, sizeof(PEB_LDR_DATA_EXTENDED))) {
        return false;
    }

    // Check if module lists are circular
    if (!CheckForListManipulation(&ldrData.InLoadOrderModuleList)) {
        HiddenModuleInfo info;
        info.baseAddress = nullptr;
        info.moduleName = L"<InLoadOrderModuleList Corrupted>";
        info.detectionMethod = "PEB_LIST_MANIPULATION";
        info.timestamp = GetTickCount();
        info.size = 0;
        m_hiddenModules.push_back(info);
    }

    return true;
}

bool PEBManipulationDetector::CheckForListManipulation(PLIST_ENTRY listHead)
{
    // This is a simplified check - in reality, we'd need to walk the list
    // and verify that Flink->Blink == current for each entry
    
    // For now, just check if the list is empty or has invalid pointers
    if (!listHead || !listHead->Flink || !listHead->Blink) {
        return false;
    }

    // List should be circular: if list has only header, Flink should point to itself
    // We can't do deep validation here without reading remote memory extensively
    
    return true;
}
