#include "../pch.h"
#include "../include/HeapSprayAnalyzer.h"
#include <sstream>
#include <algorithm>
#include <iomanip>

HeapSprayAnalyzer::HeapSprayAnalyzer()
    : m_hProcess(nullptr)
    , m_targetPid(0)
    , m_minSpraySize(0x10000)       // 64KB minimum for spray detection
    , m_minRepeatCount(100)          // At least 100 repetitions
    , m_minPatternDensity(0.8)       // 80% of region must match pattern
    , m_enableNOPDetection(true)
    , m_enableAddressSpray(true)
    , m_isInitialized(false)
{
    memset(&m_stats, 0, sizeof(m_stats));
}

HeapSprayAnalyzer::~HeapSprayAnalyzer()
{
    if (m_hProcess && m_hProcess != GetCurrentProcess()) {
        CloseHandle(m_hProcess);
    }
}

void HeapSprayAnalyzer::SetTargetProcess(HANDLE hProcess, DWORD pid)
{
    if (m_hProcess && m_hProcess != GetCurrentProcess()) {
        CloseHandle(m_hProcess);
    }

    m_hProcess = hProcess;
    m_targetPid = pid;
    m_isInitialized = (hProcess != nullptr);
}

void HeapSprayAnalyzer::ClearResults()
{
    m_detections.clear();
    memset(&m_stats, 0, sizeof(m_stats));
    m_analyzedRegions.clear();
}

bool HeapSprayAnalyzer::AnalyzeHeaps()
{
    if (!m_isInitialized) {
        return false;
    }

    ClearResults();
    return EnumerateHeapAllocations();
}

bool HeapSprayAnalyzer::EnumerateHeapAllocations()
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    PVOID address = nullptr;

    while (VirtualQueryEx(m_hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Look for committed private memory (likely heap)
        if (mbi.State == MEM_COMMIT && 
            mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            
            m_stats.totalAllocations++;
            m_stats.totalSize += mbi.RegionSize;

            if (mbi.RegionSize > m_stats.largestAllocation) {
                m_stats.largestAllocation = mbi.RegionSize;
            }

            // Analyze regions that are large enough
            if (mbi.RegionSize >= m_minSpraySize) {
                AnalyzeHeapRegion(mbi.BaseAddress, mbi.RegionSize);
            }
        }

        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    // Calculate average allocation size
    if (m_stats.totalAllocations > 0) {
        m_stats.averageSize = m_stats.totalSize / m_stats.totalAllocations;
    }

    return true;
}

bool HeapSprayAnalyzer::AnalyzeHeapRegion(PVOID address, SIZE_T size)
{
    // Limit analysis size for performance
    SIZE_T analyzeSize = (size > 0x100000) ? 0x100000 : size;  // Max 1MB per region
    
    std::vector<BYTE> buffer(analyzeSize);
    
    if (!ReadMemory(address, buffer.data(), analyzeSize)) {
        return false;
    }

    // Detect spray patterns
    DWORD repeatedValue = 0;
    int repeatCount = 0;
    SprayPattern pattern = DetectPattern(buffer.data(), analyzeSize, repeatedValue, repeatCount);

    if (pattern != SprayPattern::NONE && repeatCount >= m_minRepeatCount) {
        // Calculate pattern density
        double density = CalculatePatternDensity(buffer.data(), analyzeSize, pattern, repeatedValue);

        if (density >= m_minPatternDensity) {
            HeapSprayDetection detection;
            detection.baseAddress = address;
            detection.size = size;
            detection.pattern = pattern;
            detection.repeatedValue = repeatedValue;
            detection.repeatCount = repeatCount;
            detection.patternDensity = density;
            detection.timestamp = GetTickCount();
            detection.patternDescription = GetPatternDescription(pattern, repeatedValue, repeatCount, density);
            
            // Risk assessment
            detection.riskScore = CalculateRiskScore(detection);
            detection.likelyExploit = IsLikelyExploit(detection);

            m_detections.push_back(detection);
            m_stats.sprayPatternCount++;
            m_stats.suspiciousAllocations++;
        }
    }

    m_analyzedRegions[address] = size;
    return true;
}

SprayPattern HeapSprayAnalyzer::DetectPattern(
    const BYTE* buffer, 
    SIZE_T size, 
    DWORD& repeatedValue, 
    int& repeatCount)
{
    // Check for NOP sled first (most common in exploits)
    if (m_enableNOPDetection && DetectNOPSled(buffer, size, repeatCount)) {
        repeatedValue = 0x90909090;
        return SprayPattern::NOP_SLED;
    }

    // Check for repeated DWORD
    if (DetectRepeatedDWORD(buffer, size, repeatedValue, repeatCount)) {
        return SprayPattern::REPEATED_DWORD;
    }

    // Check for repeated QWORD
    if (DetectRepeatedQWORD(buffer, size, repeatedValue, repeatCount)) {
        return SprayPattern::REPEATED_QWORD;
    }

    // Check for address spray (heap feng shui)
    if (m_enableAddressSpray && DetectAddressSpray(buffer, size, repeatedValue, repeatCount)) {
        return SprayPattern::ADDRESS_SPRAY;
    }

    // Check for repeating sequence
    if (DetectRepeatingSequence(buffer, size, repeatCount)) {
        return SprayPattern::PATTERN_SEQUENCE;
    }

    return SprayPattern::NONE;
}

bool HeapSprayAnalyzer::DetectRepeatedDWORD(const BYTE* buffer, SIZE_T size, DWORD& value, int& count)
{
    if (size < sizeof(DWORD) * 4) {
        return false;
    }

    std::unordered_map<DWORD, int> dwordCounts;
    
    // Count DWORD occurrences
    for (SIZE_T i = 0; i <= size - sizeof(DWORD); i += sizeof(DWORD)) {
        DWORD dword = *(DWORD*)(buffer + i);
        dwordCounts[dword]++;
    }

    // Find most common DWORD
    DWORD maxDword = 0;
    int maxCount = 0;

    for (const auto& pair : dwordCounts) {
        if (pair.second > maxCount) {
            maxDword = pair.first;
            maxCount = pair.second;
        }
    }

    // Check if it's significant (more than 10% of total DWORDs)
    int totalDwords = static_cast<int>(size / sizeof(DWORD));
    if (maxCount > totalDwords / 10) {
        value = maxDword;
        count = maxCount;
        return true;
    }

    return false;
}

bool HeapSprayAnalyzer::DetectRepeatedQWORD(const BYTE* buffer, SIZE_T size, DWORD& value, int& count)
{
    if (size < sizeof(DWORD64) * 4) {
        return false;
    }

    std::unordered_map<DWORD64, int> qwordCounts;
    
    for (SIZE_T i = 0; i <= size - sizeof(DWORD64); i += sizeof(DWORD64)) {
        DWORD64 qword = *(DWORD64*)(buffer + i);
        qwordCounts[qword]++;
    }

    DWORD64 maxQword = 0;
    int maxCount = 0;

    for (const auto& pair : qwordCounts) {
        if (pair.second > maxCount) {
            maxQword = pair.first;
            maxCount = pair.second;
        }
    }

    int totalQwords = static_cast<int>(size / sizeof(DWORD64));
    if (maxCount > totalQwords / 10) {
        value = static_cast<DWORD>(maxQword & 0xFFFFFFFF);
        count = maxCount;
        return true;
    }

    return false;
}

bool HeapSprayAnalyzer::DetectNOPSled(const BYTE* buffer, SIZE_T size, int& count)
{
    int nopCount = 0;
    int consecutiveNops = 0;
    int maxConsecutive = 0;

    for (SIZE_T i = 0; i < size; i++) {
        if (buffer[i] == 0x90) {
            nopCount++;
            consecutiveNops++;
            if (consecutiveNops > maxConsecutive) {
                maxConsecutive = consecutiveNops;
            }
        }
        else {
            consecutiveNops = 0;
        }
    }

    count = nopCount;
    
    // NOP sled detection: either many total NOPs or long consecutive sequence
    return (nopCount > static_cast<int>(size) / 4) || (maxConsecutive > 256);
}

bool HeapSprayAnalyzer::DetectRepeatingSequence(const BYTE* buffer, SIZE_T size, int& count)
{
    // Look for repeating patterns of 4-16 bytes
    for (int patternLen = 4; patternLen <= 16; patternLen++) {
        if (size < static_cast<SIZE_T>(patternLen * 4)) {
            continue;
        }

        int matches = 0;
        for (SIZE_T i = 0; i <= size - (patternLen * 2); i += patternLen) {
            bool isMatch = true;
            for (int j = 0; j < patternLen; j++) {
                if (buffer[i + j] != buffer[i + patternLen + j]) {
                    isMatch = false;
                    break;
                }
            }
            if (isMatch) {
                matches++;
            }
        }

        // If pattern repeats throughout most of the buffer
        int possibleMatches = static_cast<int>((size / patternLen) / 2);
        if (matches > possibleMatches / 2) {
            count = matches;
            return true;
        }
    }

    return false;
}

bool HeapSprayAnalyzer::DetectAddressSpray(const BYTE* buffer, SIZE_T size, DWORD& address, int& count)
{
    // Look for repeated address values (common in heap feng shui attacks)
    std::unordered_map<DWORD, int> addressCounts;

    for (SIZE_T i = 0; i <= size - sizeof(DWORD); i += sizeof(DWORD)) {
        DWORD value = *(DWORD*)(buffer + i);
        
        // Check if value looks like an address (user-mode range)
        if ((value > 0x00010000 && value < 0x7FFFFFFF) ||
            (value > 0x80000000 && value < 0xFFFFFFFF)) {
            addressCounts[value]++;
        }
    }

    // Find most repeated address
    DWORD maxAddress = 0;
    int maxCount = 0;

    for (const auto& pair : addressCounts) {
        if (pair.second > maxCount) {
            maxAddress = pair.first;
            maxCount = pair.second;
        }
    }

    if (maxCount > 100) {  // Address repeated more than 100 times
        address = maxAddress;
        count = maxCount;
        return true;
    }

    return false;
}

double HeapSprayAnalyzer::CalculatePatternDensity(
    const BYTE* buffer, 
    SIZE_T size, 
    SprayPattern pattern, 
    DWORD value)
{
    if (size == 0) return 0.0;

    int matchingBytes = 0;

    switch (pattern) {
    case SprayPattern::REPEATED_DWORD:
    case SprayPattern::ADDRESS_SPRAY:
        for (SIZE_T i = 0; i <= size - sizeof(DWORD); i += sizeof(DWORD)) {
            if (*(DWORD*)(buffer + i) == value) {
                matchingBytes += sizeof(DWORD);
            }
        }
        break;

    case SprayPattern::NOP_SLED:
        for (SIZE_T i = 0; i < size; i++) {
            if (buffer[i] == 0x90) {
                matchingBytes++;
            }
        }
        break;

    default:
        return 0.0;
    }

    return static_cast<double>(matchingBytes) / size;
}

int HeapSprayAnalyzer::CalculateRiskScore(const HeapSprayDetection& detection)
{
    int score = 0;

    // Base score from pattern type
    switch (detection.pattern) {
    case SprayPattern::NOP_SLED:
        score += 50;  // High risk
        break;
    case SprayPattern::REPEATED_DWORD:
    case SprayPattern::ADDRESS_SPRAY:
        score += 30;
        break;
    default:
        score += 20;
        break;
    }

    // Add score for high density
    score += static_cast<int>(detection.patternDensity * 30);

    // Add score for large size
    if (detection.size > 0x100000) {  // > 1MB
        score += 20;
    }

    return (score > 100) ? 100 : score;
}

bool HeapSprayAnalyzer::IsLikelyExploit(const HeapSprayDetection& detection)
{
    // High confidence exploit indicators:
    // 1. NOP sled with high density
    if (detection.pattern == SprayPattern::NOP_SLED && detection.patternDensity > 0.9) {
        return true;
    }

    // 2. Large spray with repeated addresses
    if (detection.pattern == SprayPattern::ADDRESS_SPRAY && 
        detection.size > 0x100000 &&
        detection.repeatCount > 1000) {
        return true;
    }

    // 3. Very high risk score
    if (detection.riskScore > 70) {
        return true;
    }

    return false;
}

bool HeapSprayAnalyzer::ReadMemory(PVOID address, BYTE* buffer, SIZE_T size)
{
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(m_hProcess, address, buffer, size, &bytesRead) &&
           (bytesRead == size);
}

std::string HeapSprayAnalyzer::PatternToString(SprayPattern pattern)
{
    switch (pattern) {
    case SprayPattern::REPEATED_DWORD: return "REPEATED_DWORD";
    case SprayPattern::REPEATED_QWORD: return "REPEATED_QWORD";
    case SprayPattern::NOP_SLED: return "NOP_SLED";
    case SprayPattern::PATTERN_SEQUENCE: return "PATTERN_SEQUENCE";
    case SprayPattern::INCREMENTAL: return "INCREMENTAL";
    case SprayPattern::ADDRESS_SPRAY: return "ADDRESS_SPRAY";
    default: return "NONE";
    }
}

std::string HeapSprayAnalyzer::GetPatternDescription(
    SprayPattern pattern, 
    DWORD value, 
    int count, 
    double density)
{
    std::ostringstream oss;
    
    oss << PatternToString(pattern) << ": ";
    
    switch (pattern) {
    case SprayPattern::NOP_SLED:
        oss << "NOP sled detected (" << count << " NOPs, " 
            << std::fixed << std::setprecision(1) << (density * 100) << "% density)";
        break;
        
    case SprayPattern::REPEATED_DWORD:
        oss << "DWORD 0x" << std::hex << std::setw(8) << std::setfill('0') << value
            << " repeated " << std::dec << count << " times ("
            << std::fixed << std::setprecision(1) << (density * 100) << "% density)";
        break;
        
    case SprayPattern::ADDRESS_SPRAY:
        oss << "Address 0x" << std::hex << std::setw(8) << std::setfill('0') << value
            << " repeated " << std::dec << count << " times - possible heap feng shui";
        break;
        
    default:
        oss << "Pattern repeated " << count << " times";
        break;
    }
    
    return oss.str();
}
