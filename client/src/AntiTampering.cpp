#include "../pch.h"
#include "AntiTampering.h"
#include "../include/JsonBuilder.h"
#include "../include/PEBManipulationDetector.h"
#include "Logger.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <winternl.h>

#pragma comment(lib, "psapi.lib")

// ===== GLOBAL API RESOLVER =====
ApiResolver* g_pApiResolver = nullptr;

// ===== API RESOLVER IMPLEMENTATION =====

ApiResolver::ApiResolver() {
    LOG_INFO("ApiResolver initialized");
}

ApiResolver::~ApiResolver() {
    m_apiCache.clear();
}

DWORD ApiResolver::CalculateHash(const char* str) {
    if (!str) return 0;
    
    DWORD hash = 0x811C9DC5; // FNV-1a offset basis
    while (*str) {
        hash ^= static_cast<unsigned char>(*str++);
        hash *= 0x01000193; // FNV-1a prime
    }
    return hash;
}

HMODULE ApiResolver::ManualGetModuleHandle(const char* moduleName) {
    // Walk PEB to find module (avoid using GetModuleHandle from IAT)
    
    #ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    #else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    #endif
    
    if (!pPeb) return nullptr;
    
    PPEB_LDR_DATA_EXTENDED pLdr = reinterpret_cast<PPEB_LDR_DATA_EXTENDED>(pPeb->Ldr);
    if (!pLdr) return nullptr;
    
    // Iterate through InMemoryOrderModuleList
    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;
    
    while (pListEntry != pListHead) {
    PLDR_DATA_TABLE_ENTRY_EXTENDED pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY_EXTENDED, InMemoryOrderLinks);
    if (pEntry->BaseDllName.Buffer) {
        // Convert to lowercase for comparison
        std::wstring dllName(pEntry->BaseDllName.Buffer, pEntry->BaseDllName.Length / sizeof(WCHAR));
        std::string dllNameA = WToUtf8(dllName);
        // Simple case-insensitive comparison
        bool match = true;
        size_t len = strlen(moduleName);
        if (dllNameA.length() >= len) {
            for (size_t i = 0; i < len; ++i) {
                char c1 = tolower(dllNameA[i]);
                char c2 = tolower(moduleName[i]);
                if (c1 != c2) {
                    match = false;
                    break;
                }
            }
        } else {
            match = false;
        }
        if (match) {
            return (HMODULE)pEntry->DllBase;
        }
    }
        
        pListEntry = pListEntry->Flink;
    }
    
    return nullptr;
}

FARPROC ApiResolver::ManualGetProcAddress(HMODULE hModule, const char* functionName) {
    if (!hModule || !functionName) return nullptr;
    
    __try {
        // Parse PE headers
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        
        // Get export directory
        IMAGE_DATA_DIRECTORY* exportDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir->VirtualAddress == 0) return nullptr;
        
        IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule + exportDir->VirtualAddress);
        
        DWORD* functions = (DWORD*)((BYTE*)hModule + exports->AddressOfFunctions);
        DWORD* names = (DWORD*)((BYTE*)hModule + exports->AddressOfNames);
        WORD* ordinals = (WORD*)((BYTE*)hModule + exports->AddressOfNameOrdinals);
        
        // Search for function by name
        for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
            const char* name = (const char*)((BYTE*)hModule + names[i]);
            if (strcmp(name, functionName) == 0) {
                WORD ordinal = ordinals[i];
                DWORD functionRva = functions[ordinal];
                return (FARPROC)((BYTE*)hModule + functionRva);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    
    return nullptr;
}

FARPROC ApiResolver::GetAPI(const char* moduleName, const char* functionName) {
    if (!moduleName || !functionName) return nullptr;
    
    // Calculate hash for caching
    DWORD hash = CalculateHash(moduleName) ^ CalculateHash(functionName);
    
    // Check cache
    auto it = m_apiCache.find(hash);
    if (it != m_apiCache.end()) {
        return it->second;
    }
    
    // Resolve manually
    HMODULE hModule = ManualGetModuleHandle(moduleName);
    if (!hModule) {
        // Fallback to LoadLibrary if module not loaded
        hModule = LoadLibraryA(moduleName);
        if (!hModule) return nullptr;
    }
    
    FARPROC proc = ManualGetProcAddress(hModule, functionName);
    
    // Cache result
    if (proc) {
        m_apiCache[hash] = proc;
    }
    
    return proc;
}

FARPROC ApiResolver::GetAPIByHash(DWORD moduleHash, DWORD functionHash) {
    DWORD hash = moduleHash ^ functionHash;
    
    auto it = m_apiCache.find(hash);
    if (it != m_apiCache.end()) {
        return it->second;
    }
    
    // For hash-based lookup, we need a reverse mapping (not implemented here for brevity)
    // In production, you'd maintain a hash->name mapping
    return nullptr;
}

// ===== CODE INTEGRITY SELF-CHECK IMPLEMENTATION =====

CodeIntegritySelfCheck::CodeIntegritySelfCheck()
    : m_hModule(nullptr)
    , m_textBase(nullptr)
    , m_textSize(0)
    , m_expectedTextChecksum(0)
{
}

CodeIntegritySelfCheck::~CodeIntegritySelfCheck() {
}

bool CodeIntegritySelfCheck::Initialize(HMODULE hModule) {
    m_hModule = hModule;
    
    if (!ParsePEHeaders()) {
        LOG_ERROR("CodeIntegritySelfCheck: Failed to parse PE headers");
        return false;
    }
    
    // Calculate initial checksum of .text section
    m_expectedTextChecksum = CalculateChecksum(m_textBase, m_textSize);
    
    LOG_INFO_FMT("CodeIntegritySelfCheck: Initialized with .text at 0x%p, size=%zu, checksum=0x%X",
                 m_textBase, m_textSize, m_expectedTextChecksum);
    
    return true;
}

bool CodeIntegritySelfCheck::ParsePEHeaders() {
    if (!m_hModule) return false;
    
    __try {
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)m_hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)m_hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
        
        // Find .text section
        IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
            if (memcmp(section->Name, ".text", 5) == 0) {
                m_textBase = (BYTE*)m_hModule + section->VirtualAddress;
                m_textSize = section->Misc.VirtualSize;
                return true;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    
    return false;
}

DWORD CodeIntegritySelfCheck::CalculateChecksum(const void* data, size_t size) {
    if (!data || size == 0) return 0;
    
    DWORD checksum = 0;
    const BYTE* bytes = static_cast<const BYTE*>(data);
    
    __try {
        for (size_t i = 0; i < size; ++i) {
            checksum = (checksum << 5) + checksum + bytes[i]; // hash * 33 + c
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    
    return checksum;
}

bool CodeIntegritySelfCheck::VerifyIntegrity(IntegrityCheckResult& result) {
    result.isValid = true;
    
    // Check .text section
    if (!VerifyTextSection(result)) {
        return false;
    }
    
    // Check critical functions
    for (const auto& func : m_criticalFunctions) {
        DWORD currentChecksum = CalculateChecksum(func.address, func.size);
        if (currentChecksum != func.expectedChecksum) {
            result.isValid = false;
            result.reason = "Critical function tampered: " + func.name;
            result.expectedChecksum = func.expectedChecksum;
            result.actualChecksum = currentChecksum;
            result.tamperedAddress = func.address;
            
            LOG_WARNING_FMT("CodeIntegritySelfCheck: Function '%s' tampered (expected: 0x%X, actual: 0x%X)",
                           func.name.c_str(), func.expectedChecksum, currentChecksum);
            return false;
        }
    }
    
    // Check IAT
    if (!VerifyIAT(result)) {
        return false;
    }
    
    return true;
}

bool CodeIntegritySelfCheck::VerifyTextSection(IntegrityCheckResult& result) {
    if (!m_textBase || m_textSize == 0) {
        result.isValid = false;
        result.reason = "Invalid .text section";
        return false;
    }
    
    DWORD currentChecksum = CalculateChecksum(m_textBase, m_textSize);
    
    if (currentChecksum != m_expectedTextChecksum) {
        result.isValid = false;
        result.reason = ".text section modified";
        result.expectedChecksum = m_expectedTextChecksum;
        result.actualChecksum = currentChecksum;
        result.tamperedAddress = m_textBase;
        
        LOG_WARNING_FMT("CodeIntegritySelfCheck: .text section tampered (expected: 0x%X, actual: 0x%X)",
                       m_expectedTextChecksum, currentChecksum);
        return false;
    }
    
    return true;
}

bool CodeIntegritySelfCheck::VerifyIAT(IntegrityCheckResult& result) {
    // Simple IAT verification (check if imports point to expected modules)
    // Full implementation would validate each import entry
    
    __try {
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)m_hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return true; // Skip if invalid
        
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)m_hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return true;
        
        IMAGE_DATA_DIRECTORY* importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir->VirtualAddress == 0) return true; // No imports
        
        // In production, iterate through imports and verify they point to legitimate modules
        // For now, just a placeholder
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
    
    return true;
}

void CodeIntegritySelfCheck::RegisterCriticalFunction(void* functionPtr, size_t size, const char* name) {
    if (!functionPtr || size == 0 || !name) return;
    
    DWORD checksum = CalculateChecksum(functionPtr, size);
    
    CriticalFunction func = {};
    func.address = functionPtr;
    func.size = size;
    func.name = name;
    func.expectedChecksum = checksum;
    
    m_criticalFunctions.push_back(func);
    
    LOG_INFO_FMT("CodeIntegritySelfCheck: Registered function '%s' at 0x%p, size=%zu, checksum=0x%X",
                 name, functionPtr, size, checksum);
}

DWORD CodeIntegritySelfCheck::CalculateFunctionChecksum(void* functionPtr, size_t estimatedSize) {
    return CalculateChecksum(functionPtr, estimatedSize);
}

// ===== ANTI-DUMPING IMPLEMENTATION =====

const char* AntiDumping::DUMPING_TOOLS[] = {
    "procdump.exe",
    "procdump64.exe",
    "processhacker.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "dumper.exe",
    "megadumper.exe"
};

const size_t AntiDumping::DUMPING_TOOLS_COUNT = sizeof(DUMPING_TOOLS) / sizeof(DUMPING_TOOLS[0]);

AntiDumping::AntiDumping()
    : m_hModule(nullptr)
    , m_useDebugRegisters(false)
    , m_usePageGuards(false)
    , m_useWriteWatch(false)
    , m_monitorHandles(true)
{
}

AntiDumping::~AntiDumping() {
}

bool AntiDumping::Initialize(HMODULE hModule) {
    m_hModule = hModule;
    LOG_INFO("AntiDumping initialized");
    return true;
}

bool AntiDumping::DetectDumpingAttempt(DumpAttempt& result) {
    // Check process handles
    if (m_monitorHandles && DetectViaProcessHandles(result)) {
        return true;
    }
    
    // Check for dumping tools
    if (DetectDumpingTools()) {
    result.method = DumpDetectionMethod::PROCESS_HANDLE;
        result.description = "Dumping tool detected";
        result.timestamp = GetTickCount64();
        return true;
    }
    
    return false;
}

bool AntiDumping::DetectViaProcessHandles(DumpAttempt& result) {
    // Check for PROCESS_VM_READ handles from suspicious processes
    // Similar to handle detection in dllmain.cpp
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    
    DWORD selfPid = GetCurrentProcessId();
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == selfPid) continue;
            
            // Check if process name matches dumping tools
            std::wstring procName = pe.szExeFile;
            std::string procNameA = WToUtf8(procName);
            
            // Convert to lowercase
            for (char& c : procNameA) c = tolower(c);
            
            for (size_t i = 0; i < DUMPING_TOOLS_COUNT; ++i) {
                if (procNameA.find(DUMPING_TOOLS[i]) != std::string::npos) {
                    result.method = DumpDetectionMethod::PROCESS_HANDLE;
                    result.description = "Dumping tool process detected: " + procNameA;
                    result.suspiciousPid = pe.th32ProcessID;
                    result.suspiciousProcess = procNameA;
                    result.timestamp = GetTickCount64();
                    
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return false;
}

bool AntiDumping::DetectDumpingTools() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            std::wstring procName = pe.szExeFile;
            std::string procNameA = WToUtf8(procName);
            
            for (char& c : procNameA) c = tolower(c);
            
            for (size_t i = 0; i < DUMPING_TOOLS_COUNT; ++i) {
                if (procNameA == DUMPING_TOOLS[i]) {
                    CloseHandle(hSnapshot);
                    LOG_WARNING_FMT("AntiDumping: Detected dumping tool: %s", DUMPING_TOOLS[i]);
                    return true;
                }
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return false;
}

bool AntiDumping::DetectViaDebugRegisters(DumpAttempt& result) {
    // Check if debug registers are set (possible memory access breakpoint)
    // This would require checking DR0-DR7 which is already done in HardwareBreakpointMonitor
    return false;
}

bool AntiDumping::DetectViaPageGuards(DumpAttempt& result) {
    // Set guard pages and detect access violations
    // Not implemented in this version
    return false;
}

bool AntiDumping::DetectViaWriteWatch(DumpAttempt& result) {
    // Use GetWriteWatch to detect memory reads
    // Not implemented in this version
    return false;
}

// ===== ANTI-TAMPERING ORCHESTRATOR =====

AntiTampering::AntiTampering()
    : m_pApiResolver(nullptr)
    , m_pCodeIntegrity(nullptr)
    , m_pAntiDumping(nullptr)
    , m_enableCodeIntegrity(true)
    , m_enableAntiDumping(true)
    , m_checkIntervalMs(5000)
    , m_tamperingDetectionCount(0)
    , m_dumpingAttemptCount(0)
{
}

AntiTampering::~AntiTampering() {
    if (m_pApiResolver) {
        delete m_pApiResolver;
        m_pApiResolver = nullptr;
    }
    
    if (m_pCodeIntegrity) {
        delete m_pCodeIntegrity;
        m_pCodeIntegrity = nullptr;
    }
    
    if (m_pAntiDumping) {
        delete m_pAntiDumping;
        m_pAntiDumping = nullptr;
    }
}

bool AntiTampering::Initialize(HMODULE hModule) {
    LOG_INFO("AntiTampering: Initializing...");
    
    // Initialize API Resolver
    m_pApiResolver = new ApiResolver();
    g_pApiResolver = m_pApiResolver;
    
    // Initialize Code Integrity Self-Check
    if (m_enableCodeIntegrity) {
        m_pCodeIntegrity = new CodeIntegritySelfCheck();
        if (!m_pCodeIntegrity->Initialize(hModule)) {
            LOG_ERROR("AntiTampering: Failed to initialize CodeIntegritySelfCheck");
            delete m_pCodeIntegrity;
            m_pCodeIntegrity = nullptr;
        }
    }
    
    // Initialize Anti-Dumping
    if (m_enableAntiDumping) {
        m_pAntiDumping = new AntiDumping();
        if (!m_pAntiDumping->Initialize(hModule)) {
            LOG_ERROR("AntiTampering: Failed to initialize AntiDumping");
            delete m_pAntiDumping;
            m_pAntiDumping = nullptr;
        }
    }
    
    LOG_INFO("AntiTampering: Initialization complete");
    return true;
}

bool AntiTampering::RunPeriodicChecks() {
    bool detectionTriggered = false;
    
    // Code integrity check
    if (m_enableCodeIntegrity && m_pCodeIntegrity) {
        IntegrityCheckResult result;
        if (!m_pCodeIntegrity->VerifyIntegrity(result)) {
            m_tamperingDetectionCount++;
            detectionTriggered = true;
            
            LOG_CRITICAL_FMT("AntiTampering: Code integrity violation - %s", result.reason.c_str());
        }
    }
    
    // Anti-dumping check
    if (m_enableAntiDumping && m_pAntiDumping) {
        DumpAttempt attempt;
        if (m_pAntiDumping->DetectDumpingAttempt(attempt)) {
            m_dumpingAttemptCount++;
            detectionTriggered = true;
            
            LOG_WARNING_FMT("AntiTampering: Dumping attempt detected - %s", attempt.description.c_str());
        }
    }
    
    return detectionTriggered;
}

// ===== OBFUSCATED API WRAPPERS =====

namespace ObfuscatedAPI {
    HANDLE ObfCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                           LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
                           DWORD dwCreationFlags, LPDWORD lpThreadId) {
        if (!g_pApiResolver) return nullptr;
        
    using PFN_CreateThread = HANDLE (WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    auto pCreateThread = g_pApiResolver->GetAPITyped<PFN_CreateThread>(OBFUSCATE("kernel32.dll").c_str(), OBFUSCATE("CreateThread").c_str());
        
        if (pCreateThread) {
            return pCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
        }
        
        return nullptr;
    }
    
    BOOL ObfVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
        if (!g_pApiResolver) return FALSE;
        
    using PFN_VirtualProtect = BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
    auto pVirtualProtect = g_pApiResolver->GetAPITyped<PFN_VirtualProtect>(OBFUSCATE("kernel32.dll").c_str(), OBFUSCATE("VirtualProtect").c_str());
        
        if (pVirtualProtect) {
            return pVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
        }
        
        return FALSE;
    }
    
    HMODULE ObfLoadLibraryA(LPCSTR lpLibFileName) {
        if (!g_pApiResolver) return nullptr;
        
    using PFN_LoadLibraryA = HMODULE (WINAPI*)(LPCSTR);
    auto pLoadLibraryA = g_pApiResolver->GetAPITyped<PFN_LoadLibraryA>(OBFUSCATE("kernel32.dll").c_str(), OBFUSCATE("LoadLibraryA").c_str());
        
        if (pLoadLibraryA) {
            return pLoadLibraryA(lpLibFileName);
        }
        
        return nullptr;
    }
    
    FARPROC ObfGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
        if (!g_pApiResolver) return nullptr;
        
        // Use ApiResolver's manual implementation
        return g_pApiResolver->GetAPI("kernel32.dll", lpProcName);
    }
    
    PFN_NtQuerySystemInformation ObfNtQuerySystemInformation() {
        if (!g_pApiResolver) return nullptr;
        
    return g_pApiResolver->GetAPITyped<PFN_NtQuerySystemInformation>(OBFUSCATE("ntdll.dll").c_str(), OBFUSCATE("NtQuerySystemInformation").c_str());
    }
    
    PFN_NtQueryInformationProcess ObfNtQueryInformationProcess() {
        if (!g_pApiResolver) return nullptr;
        
    return g_pApiResolver->GetAPITyped<PFN_NtQueryInformationProcess>(OBFUSCATE("ntdll.dll").c_str(), OBFUSCATE("NtQueryInformationProcess").c_str());
    }
    
    BOOL ObfEnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam) {
        if (!g_pApiResolver) return FALSE;
        
    using PFN_EnumWindows = BOOL (WINAPI*)(WNDENUMPROC, LPARAM);
    auto pEnumWindows = g_pApiResolver->GetAPITyped<PFN_EnumWindows>(OBFUSCATE("user32.dll").c_str(), OBFUSCATE("EnumWindows").c_str());
        
        if (pEnumWindows) {
            return pEnumWindows(lpEnumFunc, lParam);
        }
        
        return FALSE;
    }
    
    HWND ObfFindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName) {
        if (!g_pApiResolver) return nullptr;
        
    using PFN_FindWindowW = HWND (WINAPI*)(LPCWSTR, LPCWSTR);
    auto pFindWindowW = g_pApiResolver->GetAPITyped<PFN_FindWindowW>(OBFUSCATE("user32.dll").c_str(), OBFUSCATE("FindWindowW").c_str());
        
        if (pFindWindowW) {
            return pFindWindowW(lpClassName, lpWindowName);
        }
        
        return nullptr;
    }
}

// ===== UTILITIES =====
namespace AntiTamperingUtils {
    bool PatchCodeOnce(void* target, const void* data, size_t size) {
        if (!target || !data || size == 0) return false;

        SYSTEM_INFO si{}; GetSystemInfo(&si);
        const size_t pageSize = si.dwPageSize ? si.dwPageSize : 0x1000;

        BYTE* start = static_cast<BYTE*>(target);
        BYTE* pageBase = reinterpret_cast<BYTE*>(reinterpret_cast<uintptr_t>(start) & ~(pageSize - 1));
        size_t offset = static_cast<size_t>(start - pageBase);
        size_t total = offset + size;
        size_t protectSize = ((total + pageSize - 1) / pageSize) * pageSize;

        DWORD oldProt = 0;
        if (!ObfuscatedAPI::ObfVirtualProtect(pageBase, protectSize, PAGE_EXECUTE_READWRITE, &oldProt)) {
            return false;
        }

        // Single, atomic write
        memcpy(start, data, size);

        // Flush instruction cache via obfuscated resolver if available; fallback to direct API
        using PFN_FlushInstructionCache = BOOL (WINAPI*)(HANDLE, LPCVOID, SIZE_T);
        BOOL flushed = FALSE;
        if (g_pApiResolver) {
            auto pFlush = g_pApiResolver->GetAPITyped<PFN_FlushInstructionCache>("kernel32.dll", "FlushInstructionCache");
            if (pFlush) flushed = pFlush(GetCurrentProcess(), start, size);
        }
        if (!flushed) {
            flushed = FlushInstructionCache(GetCurrentProcess(), start, size);
        }

        DWORD dummy = 0;
        ObfuscatedAPI::ObfVirtualProtect(pageBase, protectSize, oldProt, &dummy);
        return TRUE == flushed;
    }
}

// ===== ENCRYPTED SIGNATURES DEFINITIONS =====

// (EncryptedSignatures removed; use OBFUSCATE inline where needed)
