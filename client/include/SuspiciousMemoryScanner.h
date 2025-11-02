#pragma once
#include <Windows.h>
#include <vector>
#include <string>

// Memory region classification
enum class MemoryType {
    UNKNOWN,
    PRIVATE_ALLOCATION,
    MAPPED_FILE,
    IMAGE_SECTION,
    STACK,
    HEAP
};

// Suspicious memory region info
struct SuspiciousMemoryRegion {
    PVOID baseAddress;
    SIZE_T size;
    DWORD protection;
    DWORD state;
    DWORD type;
    MemoryType classification;
    std::string suspiciousReason;
    DWORD timestamp;
    
    // Additional analysis
    bool hasExecutableCode;
    bool hasNOPSled;
    bool hasShellcodePattern;
    int entropyScore;  // 0-100, higher = more random/encrypted
};

// Scan statistics
struct MemoryScanStats {
    int totalRegions;
    int suspiciousRegions;
    int rwxRegions;
    int privateExecutable;
    SIZE_T totalSuspiciousSize;
    DWORD scanDuration;
};

class SuspiciousMemoryScanner {
public:
    SuspiciousMemoryScanner();
    ~SuspiciousMemoryScanner();

    // Main scanning function
    bool ScanMemory();

    // Get results
    std::vector<SuspiciousMemoryRegion> GetSuspiciousRegions() const { return m_suspiciousRegions; }
    MemoryScanStats GetStatistics() const { return m_stats; }

    // Clear previous results
    void ClearResults();

    // Configuration
    void SetTargetProcess(HANDLE hProcess, DWORD pid);
    void SetMinRegionSize(SIZE_T minSize) { m_minRegionSize = minSize; }
    void SetEnablePatternAnalysis(bool enable) { m_enablePatternAnalysis = enable; }
    void SetEnableEntropyCheck(bool enable) { m_enableEntropyCheck = enable; }
    void SetFlagRWX(bool flag) { m_flagRWX = flag; }
    void SetFlagPrivateExecutable(bool flag) { m_flagPrivateExecutable = flag; }

private:
    // Memory enumeration
    bool EnumerateMemoryRegions();
    
    // Classification
    MemoryType ClassifyMemoryRegion(const MEMORY_BASIC_INFORMATION& mbi);
    bool IsStackRegion(const MEMORY_BASIC_INFORMATION& mbi);
    bool IsHeapRegion(const MEMORY_BASIC_INFORMATION& mbi);
    
    // Suspicion detection
    bool IsSuspiciousProtection(DWORD protection);
    bool IsSuspiciousType(DWORD type);
    std::string GetSuspiciousReason(const MEMORY_BASIC_INFORMATION& mbi, MemoryType classification);

    // Pattern analysis
    bool AnalyzeRegionContent(PVOID address, SIZE_T size, SuspiciousMemoryRegion& region);
    bool HasExecutableCode(const BYTE* buffer, SIZE_T size);
    bool HasNOPSled(const BYTE* buffer, SIZE_T size);
    bool HasShellcodePattern(const BYTE* buffer, SIZE_T size);
    int CalculateEntropy(const BYTE* buffer, SIZE_T size);

    // Helper functions
    bool ReadMemory(PVOID address, BYTE* buffer, SIZE_T size);
    std::string ProtectionToString(DWORD protection);
    bool IsExecutable(DWORD protection);
    bool IsWriteable(DWORD protection);
    bool IsReadable(DWORD protection);

private:
    HANDLE m_hProcess;
    DWORD m_targetPid;
    std::vector<SuspiciousMemoryRegion> m_suspiciousRegions;
    MemoryScanStats m_stats;

    // Configuration
    SIZE_T m_minRegionSize;
    bool m_enablePatternAnalysis;
    bool m_enableEntropyCheck;
    bool m_flagRWX;
    bool m_flagPrivateExecutable;
    bool m_isInitialized;

    // For stack/heap detection
    std::vector<PVOID> m_knownStacks;
    std::vector<PVOID> m_knownHeaps;
};
