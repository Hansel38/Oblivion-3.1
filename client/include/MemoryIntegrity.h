#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

// CRC32 table for fast hashing
namespace CRC32 {
    void InitializeTable();
    DWORD Calculate(const void* data, size_t size);
}

// SHA256 hashing
namespace SHA256 {
    struct Hash {
        BYTE data[32];
        bool operator==(const Hash& other) const;
        bool operator!=(const Hash& other) const;
        std::string ToString() const;
    };
    Hash Calculate(const void* data, size_t size);
}

// Critical region information
struct CriticalRegion {
    void* baseAddress;
    size_t size;
    std::string name;
    DWORD expectedCRC32;
    SHA256::Hash expectedSHA256;
    DWORD originalProtection;
    DWORD currentProtection;
    bool usesSHA256;  // true = SHA256, false = CRC32
    ULONGLONG lastCheckTime;
    int violationCount;
};

// Memory modification detection result
struct MemoryModification {
    void* address;
    size_t size;
    std::string regionName;
    std::string modificationType;  // "HASH_MISMATCH", "PROTECTION_CHANGED", "VIRTUAL_PROTECT_HOOKED"
    DWORD expectedHash;
    DWORD actualHash;
    DWORD expectedProtection;
    DWORD actualProtection;
    ULONGLONG timestamp;
};

// VirtualProtect/VirtualAlloc hook detection
struct ApiHookInfo {
    std::string apiName;
    void* expectedAddress;
    void* actualAddress;
    bool isHooked;
    ULONGLONG detectionTime;
};

class MemoryIntegrity {
public:
    MemoryIntegrity();
    ~MemoryIntegrity();

    // ===== Core API =====
    
    // Register a critical memory region for monitoring
    // For .text sections, pass base address and size from PE headers
    void RegisterCriticalRegion(void* address, size_t size, const std::string& name = "", bool useSHA256 = false);
    
    // Unregister a region
    void UnregisterCriticalRegion(void* address);
    
    // Verify integrity of all registered regions
    bool VerifyIntegrity();
    
    // Check specific region by address
    bool VerifyRegion(void* address);
    
    // Get all detected modifications
    std::vector<MemoryModification> GetModifications() const { return m_modifications; }
    
    // Clear modification history
    void ClearModifications() { std::lock_guard<std::mutex> lock(m_mutex); m_modifications.clear(); }

    // ===== Hash Calculation =====
    
    // Calculate CRC32 hash for a memory region
    DWORD CalculateCRC32(void* address, size_t size);
    
    // Calculate SHA256 hash for a memory region
    SHA256::Hash CalculateSHA256(void* address, size_t size);

    // ===== Memory Modification Detection =====
    
    // Detect any memory modifications (hash mismatch)
    bool DetectMemoryModifications();
    
    // Check if page protection has changed
    bool CheckPageProtection();
    
    // Detect VirtualProtect/VirtualAlloc hooks
    bool DetectApiHooks();

    // ===== Auto-Registration Helpers =====
    
    // Auto-register all .text sections from loaded modules
    void RegisterAllTextSections(bool useSHA256 = false);
    
    // Register .text section from specific module
    void RegisterModuleTextSection(HMODULE hModule, const std::string& moduleName = "", bool useSHA256 = false);

    // ===== Configuration =====
    
    // Set periodic check interval (for background validation)
    void SetCheckInterval(DWORD intervalMs) { m_checkIntervalMs = intervalMs; }
    
    // Set violation threshold before triggering detection
    void SetViolationThreshold(int threshold) { m_violationThreshold = threshold; }
    
    // Enable/disable SHA256 (slower but more secure)
    void SetUseSHA256(bool enable) { m_useSHA256 = enable; }
    
    // Enable/disable API hook detection
    void SetEnableApiHookDetection(bool enable) { m_enableApiHookDetection = enable; }

    // ===== Statistics =====
    
    int GetRegisteredRegionCount() const { return static_cast<int>(m_regions.size()); }
    int GetModificationCount() const { return static_cast<int>(m_modifications.size()); }
    std::vector<std::string> GetRegisteredRegionNames() const;

    // ===== Background Monitoring =====
    
    // Start background monitoring thread
    void StartMonitoring();
    
    // Stop background monitoring
    void StopMonitoring();
    
    bool IsMonitoring() const { return m_isMonitoring; }

private:
    // Registered critical regions (key = base address)
    std::unordered_map<void*, CriticalRegion> m_regions;
    
    // Detected modifications
    std::vector<MemoryModification> m_modifications;
    
    // API hook information
    std::vector<ApiHookInfo> m_apiHooks;
    
    // Thread synchronization
    mutable std::mutex m_mutex;
    
    // Background monitoring
    HANDLE m_monitorThread;
    bool m_isMonitoring;
    bool m_shouldStop;
    
    // Configuration
    DWORD m_checkIntervalMs;
    int m_violationThreshold;
    bool m_useSHA256;
    bool m_enableApiHookDetection;
    
    // Original API addresses (for hook detection)
    void* m_originalVirtualProtect;
    void* m_originalVirtualProtectEx;
    void* m_originalVirtualAlloc;
    void* m_originalVirtualAllocEx;
    
    // Helper functions
    bool ReadMemorySafe(void* address, void* buffer, size_t size);
    bool GetMemoryProtection(void* address, DWORD& protection);
    void UpdateRegionHash(CriticalRegion& region);
    void DetectApiHooksInternal();
    void* GetApiAddress(const char* moduleName, const char* functionName);
    
    // Background monitoring thread procedure
    static DWORD WINAPI MonitorThreadProc(LPVOID param);
};
