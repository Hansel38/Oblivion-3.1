#include "../pch.h"
#include "../include/SuspiciousMemoryScanner.h"
#include "../include/SimdUtils.h"
#include <sstream>
#include <cmath>
#include <unordered_map>

SuspiciousMemoryScanner::SuspiciousMemoryScanner()
    : m_hProcess(nullptr)
    , m_targetPid(0)
    , m_minRegionSize(4096)  // Default 4KB minimum
    , m_enablePatternAnalysis(true)
    , m_enableEntropyCheck(true)
    , m_flagRWX(true)
    , m_flagPrivateExecutable(true)
    , m_isInitialized(false)
{
    memset(&m_stats, 0, sizeof(m_stats));
}

SuspiciousMemoryScanner::~SuspiciousMemoryScanner()
{
    if (m_hProcess && m_hProcess != GetCurrentProcess()) {
        CloseHandle(m_hProcess);
    }
}

void SuspiciousMemoryScanner::SetTargetProcess(HANDLE hProcess, DWORD pid)
{
    if (m_hProcess && m_hProcess != GetCurrentProcess()) {
        CloseHandle(m_hProcess);
    }

    m_hProcess = hProcess;
    m_targetPid = pid;
    m_isInitialized = (hProcess != nullptr);
}

void SuspiciousMemoryScanner::ClearResults()
{
    m_suspiciousRegions.clear();
    memset(&m_stats, 0, sizeof(m_stats));
    m_knownStacks.clear();
    m_knownHeaps.clear();
}

bool SuspiciousMemoryScanner::ScanMemory()
{
    if (!m_isInitialized) {
        return false;
    }

    ClearResults();
    DWORD startTime = GetTickCount();

    bool success = EnumerateMemoryRegions();

    m_stats.scanDuration = GetTickCount() - startTime;
    return success;
}

bool SuspiciousMemoryScanner::EnumerateMemoryRegions()
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    PVOID address = nullptr;
    
    while (VirtualQueryEx(m_hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        m_stats.totalRegions++;

        // Skip free/reserved regions
        if (mbi.State != MEM_COMMIT) {
            address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
            continue;
        }

        // Skip regions smaller than minimum
        if (mbi.RegionSize < m_minRegionSize) {
            address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
            continue;
        }

        // Classify the region
        MemoryType classification = ClassifyMemoryRegion(mbi);

        // Check for suspicious characteristics
        bool isSuspicious = false;
        std::string suspiciousReason;

        // Check 1: RWX (Read-Write-Execute) protection
        if (m_flagRWX && IsSuspiciousProtection(mbi.Protect)) {
            isSuspicious = true;
            suspiciousReason = "RWX Protection (Read-Write-Execute)";
            m_stats.rwxRegions++;
        }

        // Check 2: Private executable memory
        if (m_flagPrivateExecutable && 
            mbi.Type == MEM_PRIVATE && 
            IsExecutable(mbi.Protect) &&
            classification != MemoryType::STACK) {
            isSuspicious = true;
            if (!suspiciousReason.empty()) suspiciousReason += " + ";
            suspiciousReason += "Private Executable Memory";
            m_stats.privateExecutable++;
        }

        // Check 3: Large private allocations with execute rights
        if (mbi.Type == MEM_PRIVATE && 
            IsExecutable(mbi.Protect) && 
            mbi.RegionSize > (1024 * 1024)) {  // > 1MB
            isSuspicious = true;
            if (!suspiciousReason.empty()) suspiciousReason += " + ";
            suspiciousReason += "Large Private Executable Allocation";
        }

        if (isSuspicious) {
            SuspiciousMemoryRegion region;
            region.baseAddress = mbi.BaseAddress;
            region.size = mbi.RegionSize;
            region.protection = mbi.Protect;
            region.state = mbi.State;
            region.type = mbi.Type;
            region.classification = classification;
            region.suspiciousReason = suspiciousReason;
            region.timestamp = GetTickCount();
            region.hasExecutableCode = false;
            region.hasNOPSled = false;
            region.hasShellcodePattern = false;
            region.entropyScore = 0;

            // Analyze content if enabled
            if (m_enablePatternAnalysis || m_enableEntropyCheck) {
                AnalyzeRegionContent(mbi.BaseAddress, mbi.RegionSize, region);
            }

            m_suspiciousRegions.push_back(region);
            m_stats.suspiciousRegions++;
            m_stats.totalSuspiciousSize += mbi.RegionSize;
        }

        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    return !m_suspiciousRegions.empty() || m_stats.totalRegions > 0;
}

MemoryType SuspiciousMemoryScanner::ClassifyMemoryRegion(const MEMORY_BASIC_INFORMATION& mbi)
{
    // Image sections (DLLs, EXEs)
    if (mbi.Type == MEM_IMAGE) {
        return MemoryType::IMAGE_SECTION;
    }

    // Mapped files
    if (mbi.Type == MEM_MAPPED) {
        return MemoryType::MAPPED_FILE;
    }

    // Private allocations
    if (mbi.Type == MEM_PRIVATE) {
        // Try to identify stacks and heaps
        if (IsStackRegion(mbi)) {
            return MemoryType::STACK;
        }
        if (IsHeapRegion(mbi)) {
            return MemoryType::HEAP;
        }
        return MemoryType::PRIVATE_ALLOCATION;
    }

    return MemoryType::UNKNOWN;
}

bool SuspiciousMemoryScanner::IsStackRegion(const MEMORY_BASIC_INFORMATION& mbi)
{
    // Stack typically has PAGE_READWRITE or PAGE_GUARD protection
    // and is in the higher address space
    if ((mbi.Protect & (PAGE_READWRITE | PAGE_GUARD)) &&
        (ULONG_PTR)mbi.BaseAddress > 0x10000) {
        
        // Cache known stacks
        m_knownStacks.push_back(mbi.BaseAddress);
        return true;
    }
    
    return false;
}

bool SuspiciousMemoryScanner::IsHeapRegion(const MEMORY_BASIC_INFORMATION& mbi)
{
    // Heap detection is harder - typically PAGE_READWRITE
    // We'll use heuristics: medium-sized private RW regions
    if ((mbi.Protect & PAGE_READWRITE) &&
        mbi.RegionSize >= 0x1000 &&
        mbi.RegionSize <= 0x100000) {
        
        m_knownHeaps.push_back(mbi.BaseAddress);
        return true;
    }
    
    return false;
}

bool SuspiciousMemoryScanner::IsSuspiciousProtection(DWORD protection)
{
    // Check for RWX combinations
    return (protection & PAGE_EXECUTE_READWRITE) ||
           (protection & PAGE_EXECUTE_WRITECOPY);
}

std::string SuspiciousMemoryScanner::GetSuspiciousReason(
    const MEMORY_BASIC_INFORMATION& mbi, 
    MemoryType classification)
{
    std::ostringstream oss;
    
    if (IsSuspiciousProtection(mbi.Protect)) {
        oss << "RWX Protection; ";
    }
    
    if (mbi.Type == MEM_PRIVATE && IsExecutable(mbi.Protect)) {
        oss << "Private Executable; ";
    }
    
    return oss.str();
}

bool SuspiciousMemoryScanner::AnalyzeRegionContent(
    PVOID address, 
    SIZE_T size, 
    SuspiciousMemoryRegion& region)
{
    // Limit analysis to first 64KB for performance
    SIZE_T analyzeSize = (size > 0x10000) ? 0x10000 : size;
    
    std::vector<BYTE> buffer(analyzeSize);
    
    if (!ReadMemory(address, buffer.data(), analyzeSize)) {
        return false;
    }

    if (m_enablePatternAnalysis) {
        region.hasExecutableCode = HasExecutableCode(buffer.data(), analyzeSize);
        region.hasNOPSled = HasNOPSled(buffer.data(), analyzeSize);
        region.hasShellcodePattern = HasShellcodePattern(buffer.data(), analyzeSize);
    }

    if (m_enableEntropyCheck) {
        region.entropyScore = CalculateEntropy(buffer.data(), analyzeSize);
    }

    return true;
}

bool SuspiciousMemoryScanner::HasExecutableCode(const BYTE* buffer, SIZE_T size)
{
    // Look for common x86/x64 instruction patterns
    // This is a simplified check - real shellcode detection is more complex
    
    int suspiciousPatternCount = 0;
    
    for (SIZE_T i = 0; i < size - 4; i++) {
        // Check for common prologue patterns
        if (buffer[i] == 0x55 && buffer[i + 1] == 0x8B && buffer[i + 2] == 0xEC) {
            // push ebp; mov ebp, esp
            suspiciousPatternCount++;
        }
        
        // Call instructions
        if (buffer[i] == 0xE8 || buffer[i] == 0xFF) {
            suspiciousPatternCount++;
        }
        
        // Syscall/sysenter
        if (buffer[i] == 0x0F && (buffer[i + 1] == 0x05 || buffer[i + 1] == 0x34)) {
            suspiciousPatternCount += 3;
        }
    }
    
    // If we found more than 10 patterns in the scanned region
    return suspiciousPatternCount > 10;
}

bool SuspiciousMemoryScanner::HasNOPSled(const BYTE* buffer, SIZE_T size)
{
    // Look for sequences of NOPs (0x90)
    int consecutiveNops = 0;
    int maxConsecutiveNops = 0;
    
    for (SIZE_T i = 0; i < size; i++) {
        if (buffer[i] == 0x90) {
            consecutiveNops++;
            if (consecutiveNops > maxConsecutiveNops) {
                maxConsecutiveNops = consecutiveNops;
            }
        }
        else {
            consecutiveNops = 0;
        }
    }
    
    // If we have more than 32 consecutive NOPs, likely a NOP sled
    return maxConsecutiveNops > 32;
}

bool SuspiciousMemoryScanner::HasShellcodePattern(const BYTE* buffer, SIZE_T size)
{
    // Look for common shellcode patterns:
    // - GetProcAddress/LoadLibrary hashes
    // - PEB walking patterns
    // - Encoded strings
    
    int patternScore = 0;
    
    for (SIZE_T i = 0; i < size - 8; i++) {
        // PEB walking: mov eax, fs:[0x30]
        if (buffer[i] == 0x64 && buffer[i + 1] == 0xA1 && 
            buffer[i + 2] == 0x30 && buffer[i + 3] == 0x00) {
            patternScore += 5;
        }
        
        // Common API hash values (simplified)
        // LoadLibraryA hash often appears
        if (*(DWORD*)(buffer + i) == 0xEC0E4E8E ||  // LoadLibraryA hash
            *(DWORD*)(buffer + i) == 0x7C0DFCAA) {  // GetProcAddress hash
            patternScore += 10;
        }
    }
    
    return patternScore > 10;
}

int SuspiciousMemoryScanner::CalculateEntropy(const BYTE* buffer, SIZE_T size)
{
    if (size == 0) return 0;
    float H = ComputeEntropyShannon(buffer, size, m_enableSIMD);
    int score = static_cast<int>((H / 8.0f) * 100.0f);
    return (score > 100) ? 100 : score;
}

bool SuspiciousMemoryScanner::ReadMemory(PVOID address, BYTE* buffer, SIZE_T size)
{
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(m_hProcess, address, buffer, size, &bytesRead) && 
           (bytesRead == size);
}

std::string SuspiciousMemoryScanner::ProtectionToString(DWORD protection)
{
    std::ostringstream oss;
    
    if (protection & PAGE_EXECUTE_READWRITE) oss << "RWX ";
    else if (protection & PAGE_EXECUTE_READ) oss << "RX ";
    else if (protection & PAGE_EXECUTE_WRITECOPY) oss << "RWC ";
    else if (protection & PAGE_EXECUTE) oss << "X ";
    else if (protection & PAGE_READWRITE) oss << "RW ";
    else if (protection & PAGE_READONLY) oss << "R ";
    else if (protection & PAGE_WRITECOPY) oss << "WC ";
    
    if (protection & PAGE_GUARD) oss << "+GUARD ";
    if (protection & PAGE_NOCACHE) oss << "+NOCACHE ";
    
    return oss.str();
}

bool SuspiciousMemoryScanner::IsExecutable(DWORD protection)
{
    return (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool SuspiciousMemoryScanner::IsWriteable(DWORD protection)
{
    return (protection & (PAGE_READWRITE | PAGE_WRITECOPY | 
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool SuspiciousMemoryScanner::IsReadable(DWORD protection)
{
    return (protection & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}
