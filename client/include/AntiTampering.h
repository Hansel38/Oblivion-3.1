#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>

// ===== STRING ENCRYPTION =====
// Compile-time XOR string encryption
// Usage: OBFUSCATE("my secret string")

namespace Obfuscation {
    // XOR key generator (compile-time)
    constexpr char RandomKey(size_t index) {
        return static_cast<char>((index * 0x45d9f3b + 0x11) ^ 0xAB);
    }

    // Compile-time string encryption
    template<size_t N>
    struct EncryptedString {
        char data[N];
        
        constexpr EncryptedString(const char(&str)[N]) : data{} {
            for (size_t i = 0; i < N; ++i) {
                data[i] = str[i] ^ RandomKey(i);
            }
        }
        
        // Runtime decryption
        std::string Decrypt() const {
            std::string result;
            result.resize(N - 1); // Exclude null terminator
            for (size_t i = 0; i < N - 1; ++i) {
                result[i] = data[i] ^ RandomKey(i);
            }
            return result;
        }
        
        std::wstring DecryptW() const {
            std::string temp = Decrypt();
            return std::wstring(temp.begin(), temp.end());
        }
    };
}

// Macro untuk easy usage
#define OBFUSCATE(str) (Obfuscation::EncryptedString<sizeof(str)>(str).Decrypt())
#define OBFUSCATE_W(str) (Obfuscation::EncryptedString<sizeof(str)>(str).DecryptW())

// ===== API OBFUSCATION =====
// Dynamic API resolution to hide imports from IAT

class ApiResolver {
public:
    ApiResolver();
    ~ApiResolver();

    // Get API address dynamically (not in IAT)
    FARPROC GetAPI(const char* moduleName, const char* functionName);
    
    // Get API with hash-based lookup (more obfuscated)
    FARPROC GetAPIByHash(DWORD moduleHash, DWORD functionHash);
    
    // Template wrapper for type safety
    template<typename T>
    T GetAPITyped(const char* moduleName, const char* functionName) {
        return reinterpret_cast<T>(GetAPI(moduleName, functionName));
    }

private:
    // API cache to avoid repeated resolution
    std::unordered_map<DWORD, FARPROC> m_apiCache;
    
    // Hash function for obfuscation
    static DWORD CalculateHash(const char* str);
    
    // Manual GetProcAddress (don't use IAT)
    FARPROC ManualGetProcAddress(HMODULE hModule, const char* functionName);
    
    // Manual GetModuleHandle (don't use IAT)
    HMODULE ManualGetModuleHandle(const char* moduleName);
};

// Global API resolver instance
extern ApiResolver* g_pApiResolver;

// ===== CODE INTEGRITY SELF-CHECK =====
// Verify anti-cheat DLL hasn't been tampered with

struct IntegrityCheckResult {
    bool isValid = true;
    std::string reason;
    DWORD expectedChecksum = 0;
    DWORD actualChecksum = 0;
    void* tamperedAddress = nullptr;
};

class CodeIntegritySelfCheck {
public:
    CodeIntegritySelfCheck();
    ~CodeIntegritySelfCheck();

    // Initialize integrity checking for anti-cheat DLL
    bool Initialize(HMODULE hModule);
    
    // Verify anti-cheat code hasn't been modified
    bool VerifyIntegrity(IntegrityCheckResult& result);
    
    // Calculate checksum of critical functions
    DWORD CalculateFunctionChecksum(void* functionPtr, size_t estimatedSize);
    
    // Verify IAT hasn't been hooked
    bool VerifyIAT(IntegrityCheckResult& result);
    
    // Verify .text section integrity
    bool VerifyTextSection(IntegrityCheckResult& result);
    
    // Register critical function for monitoring
    void RegisterCriticalFunction(void* functionPtr, size_t size, const char* name);

private:
    HMODULE m_hModule;
    void* m_textBase;
    size_t m_textSize;
    DWORD m_expectedTextChecksum;
    
    struct CriticalFunction {
        void* address;
        size_t size;
        std::string name;
        DWORD expectedChecksum;
    };
    
    std::vector<CriticalFunction> m_criticalFunctions;
    
    bool ParsePEHeaders();
    DWORD CalculateChecksum(const void* data, size_t size);
};

// ===== ANTI-DUMPING =====
// Detect memory dumping attempts

enum class DumpDetectionMethod {
    DEBUG_REGS,           // DR0-DR7 set on critical memory
    PAGE_GUARD_HIT,       // Guard pages triggering
    WRITE_WATCH_ACTIVITY, // WriteWatch API monitoring
    PROCESS_HANDLE,       // Suspicious PROCESS_VM_READ handles
    MINIDUMP_CB           // MiniDumpWriteDump hook detection
};

struct DumpAttempt {
    DumpDetectionMethod method;
    std::string description;
    DWORD suspiciousPid = 0;
    std::string suspiciousProcess;
    ULONGLONG timestamp = 0;
};

class AntiDumping {
public:
    AntiDumping();
    ~AntiDumping();

    // Initialize anti-dumping protections
    bool Initialize(HMODULE hModule);
    
    // Detect active dumping attempts
    bool DetectDumpingAttempt(DumpAttempt& result);
    
    // Enable/disable specific detection methods
    void EnableDebugRegisterProtection(bool enable) { m_useDebugRegisters = enable; }
    void EnablePageGuardProtection(bool enable) { m_usePageGuards = enable; }
    void EnableWriteWatchProtection(bool enable) { m_useWriteWatch = enable; }
    void EnableProcessHandleMonitoring(bool enable) { m_monitorHandles = enable; }
    
    // Check if dumping tools are running
    bool DetectDumpingTools();

private:
    HMODULE m_hModule;
    bool m_useDebugRegisters;
    bool m_usePageGuards;
    bool m_useWriteWatch;
    bool m_monitorHandles;
    
    // Detection implementations
    bool DetectViaDebugRegisters(DumpAttempt& result);
    bool DetectViaPageGuards(DumpAttempt& result);
    bool DetectViaWriteWatch(DumpAttempt& result);
    bool DetectViaProcessHandles(DumpAttempt& result);
    
    // Known dumping tools
    static const char* DUMPING_TOOLS[];
    static const size_t DUMPING_TOOLS_COUNT;
};

// ===== ANTI-TAMPERING ORCHESTRATOR =====
// Coordinates all anti-tampering features

class AntiTampering {
public:
    AntiTampering();
    ~AntiTampering();

    // Initialize all anti-tampering features
    bool Initialize(HMODULE hModule);
    
    // Run periodic integrity checks
    bool RunPeriodicChecks();
    
    // Get individual components
    ApiResolver* GetApiResolver() { return m_pApiResolver; }
    CodeIntegritySelfCheck* GetCodeIntegrity() { return m_pCodeIntegrity; }
    AntiDumping* GetAntiDumping() { return m_pAntiDumping; }
    
    // Configuration
    void SetEnableCodeIntegrity(bool enable) { m_enableCodeIntegrity = enable; }
    void SetEnableAntiDumping(bool enable) { m_enableAntiDumping = enable; }
    void SetCheckInterval(DWORD intervalMs) { m_checkIntervalMs = intervalMs; }
    
    // Statistics
    int GetTamperingDetectionCount() const { return m_tamperingDetectionCount; }
    int GetDumpingAttemptCount() const { return m_dumpingAttemptCount; }

private:
    ApiResolver* m_pApiResolver;
    CodeIntegritySelfCheck* m_pCodeIntegrity;
    AntiDumping* m_pAntiDumping;
    
    bool m_enableCodeIntegrity;
    bool m_enableAntiDumping;
    DWORD m_checkIntervalMs;
    
    int m_tamperingDetectionCount;
    int m_dumpingAttemptCount;
};

// ===== OBFUSCATED API WRAPPERS =====
// Common APIs with obfuscation

namespace ObfuscatedAPI {
    // Kernel32
    HANDLE ObfCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, 
                           LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, 
                           DWORD dwCreationFlags, LPDWORD lpThreadId);
    
    BOOL ObfVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    
    HMODULE ObfLoadLibraryA(LPCSTR lpLibFileName);
    
    FARPROC ObfGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
    
    // Ntdll
    using PFN_NtQuerySystemInformation = LONG (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    PFN_NtQuerySystemInformation ObfNtQuerySystemInformation();
    
    using PFN_NtQueryInformationProcess = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    PFN_NtQueryInformationProcess ObfNtQueryInformationProcess();
    
    // User32
    BOOL ObfEnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam);
    
    HWND ObfFindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName);
}

// (EncryptedSignatures removed; prefer using OBFUSCATE/OBFUSCATE_W inline)
