#include "../pch.h"
#include "../include/HardwareBreakpointMonitor.h"
#include <TlHelp32.h>
#include <sstream>

HardwareBreakpointMonitor::HardwareBreakpointMonitor()
    : m_targetPid(0)
    , m_maxBpThreshold(4)
    , m_enableAnomalyDetection(true)
    , m_trackHistory(true)
    , m_isInitialized(false)
    , m_lastScanTime(0)
    , m_totalScans(0)
{
}

HardwareBreakpointMonitor::~HardwareBreakpointMonitor()
{
}

void HardwareBreakpointMonitor::SetTargetProcess(DWORD pid)
{
    m_targetPid = pid;
    m_isInitialized = (pid != 0);
}

void HardwareBreakpointMonitor::ClearResults()
{
    m_debugRegData.clear();
    m_anomalies.clear();
}

bool HardwareBreakpointMonitor::ScanAllThreads()
{
    if (!m_isInitialized) {
        return false;
    }

    ClearResults();
    m_lastScanTime = GetTickCount();
    m_totalScans++;

    std::vector<DWORD> threadIds = EnumerateThreads();
    if (threadIds.empty()) {
        return false;
    }

    bool success = false;
    for (DWORD tid : threadIds) {
        if (ScanThread(tid)) {
            success = true;
        }
    }

    return success;
}

bool HardwareBreakpointMonitor::ScanThread(DWORD threadId)
{
    DebugRegisterInfo info = { 0 };
    
    if (!ReadThreadDebugRegisters(threadId, info)) {
        return false;
    }

    // Store the data
    m_debugRegData.push_back(info);

    // Update history
    if (m_trackHistory) {
        UpdateHistory(info);
    }

    // Detect anomalies
    if (m_enableAnomalyDetection) {
        DetectAnomalies(info);
    }

    return true;
}

std::vector<DWORD> HardwareBreakpointMonitor::EnumerateThreads()
{
    std::vector<DWORD> threadIds;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return threadIds;
    }

    THREADENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == m_targetPid) {
                threadIds.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return threadIds;
}

bool HardwareBreakpointMonitor::GetThreadContext(HANDLE hThread, CONTEXT& ctx)
{
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return ::GetThreadContext(hThread, &ctx) != FALSE;
}

bool HardwareBreakpointMonitor::ReadThreadDebugRegisters(DWORD threadId, DebugRegisterInfo& info)
{
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) {
        return false;
    }

    CONTEXT ctx = { 0 };
    bool success = GetThreadContext(hThread, ctx);
    
    if (success) {
        info.threadId = threadId;
        info.dr0 = ctx.Dr0;
        info.dr1 = ctx.Dr1;
        info.dr2 = ctx.Dr2;
        info.dr3 = ctx.Dr3;
        info.dr6 = ctx.Dr6;
        info.dr7 = ctx.Dr7;
        info.timestamp = GetTickCount();
        info.isActive = (ctx.Dr7 != 0);
    }

    CloseHandle(hThread);
    return success;
}

std::vector<HardwareBreakpoint> HardwareBreakpointMonitor::ParseDR7(
    DWORD_PTR dr7, 
    DWORD_PTR dr0, 
    DWORD_PTR dr1, 
    DWORD_PTR dr2, 
    DWORD_PTR dr3)
{
    std::vector<HardwareBreakpoint> breakpoints;
    DWORD_PTR drAddresses[4] = { dr0, dr1, dr2, dr3 };

    for (int i = 0; i < 4; i++) {
        if (IsBreakpointEnabled(dr7, i)) {
            HardwareBreakpoint bp;
            bp.registerIndex = i;
            bp.address = drAddresses[i];
            bp.type = GetBreakpointType(dr7, i);
            bp.size = GetBreakpointSize(dr7, i);
            bp.enabled = true;
            bp.local = IsBreakpointLocal(dr7, i);
            bp.global = IsBreakpointGlobal(dr7, i);
            
            breakpoints.push_back(bp);
        }
    }

    return breakpoints;
}

bool HardwareBreakpointMonitor::IsBreakpointEnabled(DWORD_PTR dr7, int index)
{
    // Check L0-L3 (local enable) or G0-G3 (global enable) bits
    int localBit = index * 2;
    int globalBit = index * 2 + 1;
    
    return ((dr7 & (1ULL << localBit)) != 0) || ((dr7 & (1ULL << globalBit)) != 0);
}

bool HardwareBreakpointMonitor::IsBreakpointLocal(DWORD_PTR dr7, int index)
{
    int localBit = index * 2;
    return (dr7 & (1ULL << localBit)) != 0;
}

bool HardwareBreakpointMonitor::IsBreakpointGlobal(DWORD_PTR dr7, int index)
{
    int globalBit = index * 2 + 1;
    return (dr7 & (1ULL << globalBit)) != 0;
}

BreakpointType HardwareBreakpointMonitor::GetBreakpointType(DWORD_PTR dr7, int index)
{
    // RW bits are at positions 16-17, 20-21, 24-25, 28-29 for DR0-DR3
    int bitPosition = 16 + (index * 4);
    int typeValue = (dr7 >> bitPosition) & 0x3;
    
    return static_cast<BreakpointType>(typeValue);
}

BreakpointSize HardwareBreakpointMonitor::GetBreakpointSize(DWORD_PTR dr7, int index)
{
    // LEN bits are at positions 18-19, 22-23, 26-27, 30-31 for DR0-DR3
    int bitPosition = 18 + (index * 4);
    int sizeValue = (dr7 >> bitPosition) & 0x3;
    
    return static_cast<BreakpointSize>(sizeValue);
}

void HardwareBreakpointMonitor::DetectAnomalies(const DebugRegisterInfo& info)
{
    if (info.dr7 == 0) {
        return; // No breakpoints set
    }

    DetectExcessiveUsage(info);
    DetectSuspiciousPatterns(info);
    DetectContextSwitchAnomalies(info.threadId);
}

void HardwareBreakpointMonitor::DetectExcessiveUsage(const DebugRegisterInfo& info)
{
    auto breakpoints = ParseDR7(info.dr7, info.dr0, info.dr1, info.dr2, info.dr3);
    
    if (breakpoints.size() > static_cast<size_t>(m_maxBpThreshold)) {
        HardwareBreakpointAnomaly anomaly;
        anomaly.threadId = info.threadId;
        anomaly.anomalyType = "EXCESSIVE_USE";
        anomaly.breakpointCount = static_cast<int>(breakpoints.size());
        anomaly.timestamp = GetTickCount();
        anomaly.breakpoints = breakpoints;

        std::ostringstream oss;
        oss << "Thread " << info.threadId << " has " << breakpoints.size() 
            << " hardware breakpoints (threshold: " << m_maxBpThreshold << ")";
        anomaly.description = oss.str();

        m_anomalies.push_back(anomaly);
    }
}

void HardwareBreakpointMonitor::DetectSuspiciousPatterns(const DebugRegisterInfo& info)
{
    auto breakpoints = ParseDR7(info.dr7, info.dr0, info.dr1, info.dr2, info.dr3);
    
    if (breakpoints.empty()) {
        return;
    }

    // Pattern 1: All 4 breakpoints enabled (common in debuggers)
    if (breakpoints.size() == 4) {
        HardwareBreakpointAnomaly anomaly;
        anomaly.threadId = info.threadId;
        anomaly.anomalyType = "SUSPICIOUS_PATTERN";
        anomaly.breakpointCount = 4;
        anomaly.timestamp = GetTickCount();
        anomaly.breakpoints = breakpoints;
        anomaly.description = "All 4 hardware breakpoints enabled - possible debugger";
        
        m_anomalies.push_back(anomaly);
    }

    // Pattern 2: Check for breakpoints on common anti-debug locations
    // This would require knowledge of the target process memory layout
    // For now, we'll just flag if there are execute breakpoints on low addresses
    for (const auto& bp : breakpoints) {
        if (bp.type == BreakpointType::EXECUTE && bp.address < 0x10000) {
            HardwareBreakpointAnomaly anomaly;
            anomaly.threadId = info.threadId;
            anomaly.anomalyType = "SUSPICIOUS_PATTERN";
            anomaly.breakpointCount = static_cast<int>(breakpoints.size());
            anomaly.timestamp = GetTickCount();
            anomaly.breakpoints = breakpoints;

            std::ostringstream oss;
            oss << "Execute breakpoint on suspicious low address: 0x" 
                << std::hex << bp.address;
            anomaly.description = oss.str();
            
            m_anomalies.push_back(anomaly);
            break;
        }
    }

    // Pattern 3: Check DR6 for triggered breakpoints
    if (info.dr6 != 0) {
        // DR6 bits 0-3 indicate which breakpoint was hit
        int triggeredCount = 0;
        for (int i = 0; i < 4; i++) {
            if (info.dr6 & (1ULL << i)) {
                triggeredCount++;
            }
        }

        if (triggeredCount > 0) {
            HardwareBreakpointAnomaly anomaly;
            anomaly.threadId = info.threadId;
            anomaly.anomalyType = "HIDDEN_DEBUGGER";
            anomaly.breakpointCount = static_cast<int>(breakpoints.size());
            anomaly.timestamp = GetTickCount();
            anomaly.breakpoints = breakpoints;

            std::ostringstream oss;
            oss << "DR6 indicates " << triggeredCount 
                << " breakpoint(s) were triggered (DR6=0x" << std::hex << info.dr6 << ")";
            anomaly.description = oss.str();
            
            m_anomalies.push_back(anomaly);
        }
    }
}

void HardwareBreakpointMonitor::DetectContextSwitchAnomalies(DWORD threadId)
{
    if (!m_trackHistory) {
        return;
    }

    // Check if this thread's debug registers changed frequently
    if (m_changeFrequency.find(threadId) != m_changeFrequency.end()) {
        int frequency = m_changeFrequency[threadId];
        
        // If debug registers changed more than 50% of the time, it's suspicious
        if (m_totalScans > 10 && frequency > m_totalScans / 2) {
            HardwareBreakpointAnomaly anomaly;
            anomaly.threadId = threadId;
            anomaly.anomalyType = "CONTEXT_SWITCH_ANOMALY";
            anomaly.breakpointCount = 0;
            anomaly.timestamp = GetTickCount();

            std::ostringstream oss;
            oss << "Debug registers changed " << frequency << " times out of " 
                << m_totalScans << " scans - possible debugger manipulation";
            anomaly.description = oss.str();
            
            m_anomalies.push_back(anomaly);
        }
    }
}

void HardwareBreakpointMonitor::UpdateHistory(const DebugRegisterInfo& info)
{
    auto it = m_previousState.find(info.threadId);
    
    if (it != m_previousState.end()) {
        // Check if changed
        if (HasHistoryChanged(info.threadId, info)) {
            m_changeFrequency[info.threadId]++;
        }
    }
    
    // Update previous state
    m_previousState[info.threadId] = info;
}

bool HardwareBreakpointMonitor::HasHistoryChanged(DWORD threadId, const DebugRegisterInfo& info)
{
    auto it = m_previousState.find(threadId);
    if (it == m_previousState.end()) {
        return false;
    }

    const DebugRegisterInfo& prev = it->second;
    
    return (prev.dr0 != info.dr0 ||
            prev.dr1 != info.dr1 ||
            prev.dr2 != info.dr2 ||
            prev.dr3 != info.dr3 ||
            prev.dr7 != info.dr7);
}

int HardwareBreakpointMonitor::GetTotalActiveBreakpoints() const
{
    int total = 0;
    for (const auto& info : m_debugRegData) {
        auto bps = const_cast<HardwareBreakpointMonitor*>(this)->ParseDR7(
            info.dr7, info.dr0, info.dr1, info.dr2, info.dr3);
        total += static_cast<int>(bps.size());
    }
    return total;
}

int HardwareBreakpointMonitor::GetThreadsWithBreakpoints() const
{
    int count = 0;
    for (const auto& info : m_debugRegData) {
        if (info.dr7 != 0) {
            count++;
        }
    }
    return count;
}

bool HardwareBreakpointMonitor::HasSuspiciousPatterns() const
{
    return !m_anomalies.empty();
}
