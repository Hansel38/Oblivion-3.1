#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <unordered_map>

// Heap spray detection patterns
enum class SprayPattern {
    NONE,
    REPEATED_DWORD,      // Same DWORD value repeated
    REPEATED_QWORD,      // Same QWORD value repeated
    NOP_SLED,            // 0x90909090... pattern
    PATTERN_SEQUENCE,    // Repeating byte sequence
    INCREMENTAL,         // Incrementing pattern (shellcode prep)
    ADDRESS_SPRAY        // Repeated addresses (heap feng shui)
};

// Heap spray detection result
struct HeapSprayDetection {
    PVOID baseAddress;
    SIZE_T size;
    SprayPattern pattern;
    std::string patternDescription;
    DWORD repeatedValue;
    int repeatCount;
    double patternDensity;  // 0.0-1.0, how much of the region matches the pattern
    DWORD timestamp;
    
    // Analysis
    bool likelyExploit;
    int riskScore;  // 0-100
};

// Heap allocation statistics
struct HeapAllocationStats {
    int totalAllocations;
    SIZE_T totalSize;
    SIZE_T averageSize;
    SIZE_T largestAllocation;
    int suspiciousAllocations;
    int sprayPatternCount;
};

class HeapSprayAnalyzer {
public:
    HeapSprayAnalyzer();
    ~HeapSprayAnalyzer();

    // Main analysis function
    bool AnalyzeHeaps();

    // Get results
    std::vector<HeapSprayDetection> GetDetections() const { return m_detections; }
    HeapAllocationStats GetStatistics() const { return m_stats; }

    // Clear previous results
    void ClearResults();

    // Configuration
    void SetTargetProcess(HANDLE hProcess, DWORD pid);
    void SetMinSpraySize(SIZE_T minSize) { m_minSpraySize = minSize; }
    void SetMinRepeatCount(int count) { m_minRepeatCount = count; }
    void SetMinPatternDensity(double density) { m_minPatternDensity = density; }
    void SetEnableNOPDetection(bool enable) { m_enableNOPDetection = enable; }
    void SetEnableAddressSprayDetection(bool enable) { m_enableAddressSpray = enable; }

private:
    // Heap enumeration
    bool EnumerateHeapAllocations();
    bool AnalyzeHeapRegion(PVOID address, SIZE_T size);

    // Pattern detection
    SprayPattern DetectPattern(const BYTE* buffer, SIZE_T size, DWORD& repeatedValue, int& repeatCount);
    bool DetectRepeatedDWORD(const BYTE* buffer, SIZE_T size, DWORD& value, int& count);
    bool DetectRepeatedQWORD(const BYTE* buffer, SIZE_T size, DWORD& value, int& count);
    bool DetectNOPSled(const BYTE* buffer, SIZE_T size, int& count);
    bool DetectRepeatingSequence(const BYTE* buffer, SIZE_T size, int& count);
    bool DetectAddressSpray(const BYTE* buffer, SIZE_T size, DWORD& address, int& count);
    
    // Density calculation
    double CalculatePatternDensity(const BYTE* buffer, SIZE_T size, SprayPattern pattern, DWORD value);
    
    // Risk assessment
    int CalculateRiskScore(const HeapSprayDetection& detection);
    bool IsLikelyExploit(const HeapSprayDetection& detection);

    // Helper functions
    bool ReadMemory(PVOID address, BYTE* buffer, SIZE_T size);
    std::string PatternToString(SprayPattern pattern);
    std::string GetPatternDescription(SprayPattern pattern, DWORD value, int count, double density);

private:
    HANDLE m_hProcess;
    DWORD m_targetPid;
    std::vector<HeapSprayDetection> m_detections;
    HeapAllocationStats m_stats;

    // Configuration
    SIZE_T m_minSpraySize;
    int m_minRepeatCount;
    double m_minPatternDensity;
    bool m_enableNOPDetection;
    bool m_enableAddressSpray;
    bool m_isInitialized;

    // Tracking
    std::unordered_map<PVOID, SIZE_T> m_analyzedRegions;
};
