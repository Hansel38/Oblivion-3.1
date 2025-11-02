#include "../pch.h"
#include "../include/VADManipulationDetector.h"
#include <algorithm>

VADManipulationDetector::VADManipulationDetector()
    : m_hDriver(INVALID_HANDLE_VALUE), 
      m_SizeThreshold(100 * 1024 * 1024), // 100MB default
      m_bInitialized(FALSE)
{
    InitializeCriticalSection(&m_Lock);
}

VADManipulationDetector::~VADManipulationDetector()
{
    Cleanup();
    DeleteCriticalSection(&m_Lock);
}

BOOL VADManipulationDetector::Initialize(HANDLE hDriverHandle)
{
    EnterCriticalSection(&m_Lock);
    
    if (m_bInitialized) {
        LeaveCriticalSection(&m_Lock);
        return TRUE;
    }

    m_hDriver = hDriverHandle;
    m_bInitialized = TRUE;

    LeaveCriticalSection(&m_Lock);
    return TRUE;
}

void VADManipulationDetector::Cleanup()
{
    EnterCriticalSection(&m_Lock);
    
    ClearResults();
    m_hDriver = INVALID_HANDLE_VALUE;
    m_bInitialized = FALSE;

    LeaveCriticalSection(&m_Lock);
}

DWORD VADManipulationDetector::ScanForVADManipulation()
{
    return ScanForVADManipulation(GetCurrentProcessId());
}

DWORD VADManipulationDetector::ScanForVADManipulation(DWORD dwProcessId)
{
    if (!m_bInitialized || m_hDriver == INVALID_HANDLE_VALUE) {
        return 0;
    }

    EnterCriticalSection(&m_Lock);
    ClearResults();

    // Step 1: Query VAD entries from kernel
    std::vector<KAC_VAD_ENTRY> vadEntries;
    if (!QueryVADEntries(dwProcessId, vadEntries)) {
        LeaveCriticalSection(&m_Lock);
        return 0;
    }

    // Step 2: Enumerate memory regions via VirtualQueryEx
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
    if (hProcess == NULL) {
        LeaveCriticalSection(&m_Lock);
        return 0;
    }

    std::vector<VAD_MemoryRegionInfo> regions;
    EnumerateMemoryRegions(hProcess, regions);
    CloseHandle(hProcess);

    // Step 3: Cross-reference VAD and VirtualQueryEx results
    DWORD discrepancies = CrossReferenceVADAndMemory(vadEntries, regions);

    // Step 4: Analyze individual VAD entries for suspicious characteristics
    for (const auto& entry : vadEntries) {
        if (AnalyzeVADEntry(entry)) {
            // Suspicious entry already added by AnalyzeVADEntry
        }
    }

    DWORD totalAnomalies = (DWORD)m_Anomalies.size();
    LeaveCriticalSection(&m_Lock);

    return totalAnomalies;
}

BOOL VADManipulationDetector::ValidateMemoryRegion(ULONG_PTR baseAddress)
{
    if (!m_bInitialized || m_hDriver == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Query specific VAD entry from kernel
    std::vector<KAC_VAD_ENTRY> vadEntries;
    
    // Query with specific base address
    const ULONG MaxVads = 16;
    size_t bufferSize = sizeof(KAC_VAD_INFO_RESPONSE) + (MaxVads - 1) * sizeof(KAC_VAD_ENTRY);
    std::vector<BYTE> buffer(bufferSize);
    
    PKAC_VAD_INFO_REQUEST request = (PKAC_VAD_INFO_REQUEST)buffer.data();
    PKAC_VAD_INFO_RESPONSE response = (PKAC_VAD_INFO_RESPONSE)buffer.data();

    request->ProcessId = GetCurrentProcessId();
    request->BaseAddress = baseAddress;
    request->MaxVadCount = MaxVads;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        m_hDriver,
        IOCTL_OBLIVIONAC_GET_VAD_INFO,
        request,
        sizeof(KAC_VAD_INFO_REQUEST),
        response,
        (DWORD)bufferSize,
        &bytesReturned,
        NULL
    );

    if (!success || response->VadCount == 0) {
        return FALSE; // VAD not found for this address
    }

    // Check if any VAD entry matches the address
    for (ULONG i = 0; i < response->VadCount; i++) {
        const KAC_VAD_ENTRY& entry = response->Vads[i];
        if (baseAddress >= entry.StartingAddress && baseAddress <= entry.EndingAddress) {
            return !entry.IsSuspicious; // Valid if not suspicious
        }
    }

    return FALSE;
}

const std::vector<VADInfo>& VADManipulationDetector::GetAnomalies() const
{
    return m_Anomalies;
}

void VADManipulationDetector::ClearResults()
{
    m_Anomalies.clear();
}

void VADManipulationDetector::SetSizeThreshold(SIZE_T sizeBytes)
{
    EnterCriticalSection(&m_Lock);
    m_SizeThreshold = sizeBytes;
    LeaveCriticalSection(&m_Lock);
}

BOOL VADManipulationDetector::QueryVADEntries(DWORD dwProcessId, 
                                              std::vector<KAC_VAD_ENTRY>& vadEntries)
{
    vadEntries.clear();

    // Allocate buffer for request/response
    // Assume max 1024 VAD entries
    const ULONG MaxVads = 1024;
    size_t bufferSize = sizeof(KAC_VAD_INFO_RESPONSE) + (MaxVads - 1) * sizeof(KAC_VAD_ENTRY);
    std::vector<BYTE> buffer(bufferSize);
    
    PKAC_VAD_INFO_REQUEST request = (PKAC_VAD_INFO_REQUEST)buffer.data();
    PKAC_VAD_INFO_RESPONSE response = (PKAC_VAD_INFO_RESPONSE)buffer.data();

    request->ProcessId = dwProcessId;
    request->BaseAddress = 0; // Get all VADs
    request->MaxVadCount = MaxVads;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        m_hDriver,
        IOCTL_OBLIVIONAC_GET_VAD_INFO,
        request,
        sizeof(KAC_VAD_INFO_REQUEST),
        response,
        (DWORD)bufferSize,
        &bytesReturned,
        NULL
    );

    if (!success) {
        return FALSE;
    }

    // Copy VAD entries to output vector
    for (ULONG i = 0; i < response->VadCount; i++) {
        vadEntries.push_back(response->Vads[i]);
    }

    return TRUE;
}

BOOL VADManipulationDetector::EnumerateMemoryRegions(HANDLE hProcess, 
                                                     std::vector<VAD_MemoryRegionInfo>& regions)
{
    regions.clear();

    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR address = 0;

    while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            VAD_MemoryRegionInfo info;
            info.BaseAddress = (ULONG_PTR)mbi.BaseAddress;
            info.RegionSize = mbi.RegionSize;
            info.Protection = mbi.Protect;
            info.State = mbi.State;
            info.Type = mbi.Type;

            regions.push_back(info);
        }

        address = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        
        // Safety check to prevent infinite loop
        if (address == 0) {
            break;
        }
    }

    return TRUE;
}

DWORD VADManipulationDetector::CrossReferenceVADAndMemory(
    const std::vector<KAC_VAD_ENTRY>& vadEntries,
    const std::vector<VAD_MemoryRegionInfo>& regions)
{
    DWORD discrepancies = 0;

    // Check for VAD entries not found in VirtualQueryEx
    for (const auto& vad : vadEntries) {
        BOOL foundInMemory = FALSE;
        
        for (const auto& region : regions) {
            // Check if VAD overlaps with memory region
            if (vad.StartingAddress <= region.BaseAddress + region.RegionSize &&
                vad.EndingAddress >= region.BaseAddress) {
                foundInMemory = TRUE;
                
                // Check protection mismatch
                if (vad.Protection != 0 && vad.Protection != region.Protection) {
                    VADInfo info;
                    info.StartingAddress = vad.StartingAddress;
                    info.EndingAddress = vad.EndingAddress;
                    info.SizeInBytes = vad.SizeInBytes;
                    info.Protection = vad.Protection;
                    info.VadType = vad.VadType;
                    info.IsPrivate = vad.IsPrivate;
                    info.IsSuspicious = TRUE;
                    info.DetectionType = VADDetectionType::VAD_PROTECTION_MISMATCH;
                    info.DetectionReason = "VAD protection (0x" + 
                        std::to_string(vad.Protection) + 
                        ") differs from VirtualQueryEx (0x" + 
                        std::to_string(region.Protection) + ")";
                    
                    AddAnomaly(info);
                    discrepancies++;
                }
                
                break;
            }
        }

        if (!foundInMemory) {
            // VAD entry exists but not found in VirtualQueryEx - potential hiding
            VADInfo info;
            info.StartingAddress = vad.StartingAddress;
            info.EndingAddress = vad.EndingAddress;
            info.SizeInBytes = vad.SizeInBytes;
            info.Protection = vad.Protection;
            info.VadType = vad.VadType;
            info.IsPrivate = vad.IsPrivate;
            info.IsSuspicious = TRUE;
            info.DetectionType = VADDetectionType::VAD_HIDDEN_REGION;
            info.DetectionReason = "Memory region exists in VAD tree but not queryable via VirtualQueryEx";
            
            AddAnomaly(info);
            discrepancies++;
        }
    }

    // Check for memory regions not found in VAD (less common, but possible)
    for (const auto& region : regions) {
        BOOL foundInVAD = FALSE;
        
        for (const auto& vad : vadEntries) {
            if (region.BaseAddress >= vad.StartingAddress &&
                region.BaseAddress <= vad.EndingAddress) {
                foundInVAD = TRUE;
                break;
            }
        }

        if (!foundInVAD && region.Type == MEM_PRIVATE) {
            // Memory region queryable but not in VAD - unusual
            VADInfo info;
            info.StartingAddress = region.BaseAddress;
            info.EndingAddress = region.BaseAddress + region.RegionSize - 1;
            info.SizeInBytes = region.RegionSize;
            info.Protection = region.Protection;
            info.VadType = region.Type;
            info.IsPrivate = TRUE;
            info.IsSuspicious = TRUE;
            info.DetectionType = VADDetectionType::VAD_MISSING_FROM_VAD;
            info.DetectionReason = "Memory region queryable but not found in VAD tree";
            
            AddAnomaly(info);
            discrepancies++;
        }
    }

    return discrepancies;
}

BOOL VADManipulationDetector::AnalyzeVADEntry(const KAC_VAD_ENTRY& entry)
{
    BOOL isSuspicious = FALSE;

    // Check if already flagged as suspicious by kernel
    if (entry.IsSuspicious) {
        VADInfo info;
        info.StartingAddress = entry.StartingAddress;
        info.EndingAddress = entry.EndingAddress;
        info.SizeInBytes = entry.SizeInBytes;
        info.Protection = entry.Protection;
        info.VadType = entry.VadType;
        info.IsPrivate = entry.IsPrivate;
        info.IsSuspicious = TRUE;
        info.DetectionType = VADDetectionType::VAD_SUSPICIOUS_SIZE;
        info.DetectionReason = "Kernel flagged VAD as suspicious (likely large region)";
        
        AddAnomaly(info);
        isSuspicious = TRUE;
    }

    // Check for abnormally large regions
    if (entry.SizeInBytes > m_SizeThreshold) {
        VADInfo info;
        info.StartingAddress = entry.StartingAddress;
        info.EndingAddress = entry.EndingAddress;
        info.SizeInBytes = entry.SizeInBytes;
        info.Protection = entry.Protection;
        info.VadType = entry.VadType;
        info.IsPrivate = entry.IsPrivate;
        info.IsSuspicious = TRUE;
        info.DetectionType = VADDetectionType::VAD_SUSPICIOUS_SIZE;
        info.DetectionReason = "Abnormally large memory region (" + 
            std::to_string(entry.SizeInBytes / (1024 * 1024)) + " MB)";
        
        AddAnomaly(info);
        isSuspicious = TRUE;
    }

    // Check for suspicious protection (RWX)
    if ((entry.Protection & PAGE_EXECUTE_READWRITE) || 
        (entry.Protection & PAGE_EXECUTE_WRITECOPY)) {
        VADInfo info;
        info.StartingAddress = entry.StartingAddress;
        info.EndingAddress = entry.EndingAddress;
        info.SizeInBytes = entry.SizeInBytes;
        info.Protection = entry.Protection;
        info.VadType = entry.VadType;
        info.IsPrivate = entry.IsPrivate;
        info.IsSuspicious = TRUE;
        info.DetectionType = VADDetectionType::VAD_SUSPICIOUS_PROTECTION;
        info.DetectionReason = "Suspicious RWX protection: " + ProtectionToString(entry.Protection);
        
        AddAnomaly(info);
        isSuspicious = TRUE;
    }

    return isSuspicious;
}

void VADManipulationDetector::AddAnomaly(const VADInfo& info)
{
    // Check if already exists (avoid duplicates)
    auto it = std::find_if(m_Anomalies.begin(), m_Anomalies.end(),
        [&info](const VADInfo& existing) {
            return existing.StartingAddress == info.StartingAddress &&
                   existing.DetectionType == info.DetectionType;
        });

    if (it == m_Anomalies.end()) {
        m_Anomalies.push_back(info);
    }
}

std::string VADManipulationDetector::ProtectionToString(ULONG protection) const
{
    std::string result;
    
    if (protection & PAGE_EXECUTE) result += "X";
    if (protection & PAGE_EXECUTE_READ) result += "RX";
    if (protection & PAGE_EXECUTE_READWRITE) result += "RWX";
    if (protection & PAGE_EXECUTE_WRITECOPY) result += "WCX";
    if (protection & PAGE_READONLY) result += "R";
    if (protection & PAGE_READWRITE) result += "RW";
    if (protection & PAGE_WRITECOPY) result += "WC";
    if (protection & PAGE_NOACCESS) result += "NA";
    
    if (result.empty()) {
        result = "0x" + std::to_string(protection);
    }
    
    return result;
}

std::string VADManipulationDetector::GetDetectionTypeString(VADDetectionType type) const
{
    switch (type) {
    case VADDetectionType::VAD_HIDDEN_REGION:
        return "VAD_HIDDEN_REGION";
    case VADDetectionType::VAD_PROTECTION_MISMATCH:
        return "VAD_PROTECTION_MISMATCH";
    case VADDetectionType::VAD_TYPE_MISMATCH:
        return "VAD_TYPE_MISMATCH";
    case VADDetectionType::VAD_SUSPICIOUS_SIZE:
        return "VAD_SUSPICIOUS_SIZE";
    case VADDetectionType::VAD_SUSPICIOUS_PROTECTION:
        return "VAD_SUSPICIOUS_PROTECTION";
    case VADDetectionType::VAD_MISSING_FROM_VAD:
        return "VAD_MISSING_FROM_VAD";
    default:
        return "UNKNOWN";
    }
}
