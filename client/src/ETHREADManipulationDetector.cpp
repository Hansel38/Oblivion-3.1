#include "../pch.h"
#include "../include/ETHREADManipulationDetector.h"
#include <TlHelp32.h>
#include <algorithm>

ETHREADManipulationDetector::ETHREADManipulationDetector()
    : m_hDriver(INVALID_HANDLE_VALUE), m_bInitialized(FALSE)
{
    InitializeCriticalSection(&m_Lock);
}

ETHREADManipulationDetector::~ETHREADManipulationDetector()
{
    Cleanup();
    DeleteCriticalSection(&m_Lock);
}

BOOL ETHREADManipulationDetector::Initialize(HANDLE hDriverHandle)
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

void ETHREADManipulationDetector::Cleanup()
{
    EnterCriticalSection(&m_Lock);
    
    ClearResults();
    m_hDriver = INVALID_HANDLE_VALUE;
    m_bInitialized = FALSE;

    LeaveCriticalSection(&m_Lock);
}

DWORD ETHREADManipulationDetector::ScanForHiddenThreads()
{
    return ScanForHiddenThreads(GetCurrentProcessId());
}

DWORD ETHREADManipulationDetector::ScanForHiddenThreads(DWORD dwProcessId)
{
    if (!m_bInitialized || m_hDriver == INVALID_HANDLE_VALUE) {
        return 0;
    }

    EnterCriticalSection(&m_Lock);
    ClearResults();

    // Step 1: Enumerate threads via kernel mode
    std::vector<KAC_ETHREAD_INFO> kernelThreads;
    if (!EnumerateKernelThreads(dwProcessId, kernelThreads)) {
        LeaveCriticalSection(&m_Lock);
        return 0;
    }

    // Step 2: Enumerate threads via user mode
    std::vector<DWORD> userThreadIds;
    if (!EnumerateUserThreads(dwProcessId, userThreadIds)) {
        LeaveCriticalSection(&m_Lock);
        return 0;
    }

    // Step 3: Cross-reference and detect discrepancies
    DWORD detectionCount = CrossReferenceThreads(kernelThreads, userThreadIds);

    // Step 4: Check kernel thread flags for suspicious threads
    for (const auto& kThread : kernelThreads) {
        if (kThread.IsHidden || kThread.IsSuspicious) {
            HiddenThreadInfo info;
            info.ThreadId = kThread.ThreadId;
            info.StartAddress = kThread.StartAddress;
            info.Win32StartAddress = kThread.Win32StartAddress;
            info.IsHidden = kThread.IsHidden;
            info.IsSuspicious = kThread.IsSuspicious;
            info.State = kThread.State;
            info.WaitReason = kThread.WaitReason;

            if (kThread.IsHidden) {
                info.DetectionType = ETHREADDetectionType::HIDDEN_FROM_KERNEL_LIST;
                info.DetectionReason = "Thread not in EPROCESS->ThreadListHead";
            }
            else if (kThread.IsSuspicious) {
                info.DetectionType = ETHREADDetectionType::SUSPICIOUS_FLAGS;
                info.DetectionReason = "Suspicious thread flags detected (HideFromDebugger, etc.)";
            }

            AddHiddenThread(info);
        }
    }

    DWORD totalDetections = (DWORD)m_HiddenThreads.size();
    LeaveCriticalSection(&m_Lock);

    return totalDetections;
}

BOOL ETHREADManipulationDetector::ValidateThread(DWORD dwThreadId)
{
    if (!m_bInitialized || m_hDriver == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    KAC_VALIDATE_ETHREAD_RESPONSE response;
    if (!ValidateThreadViaIOCTL(GetCurrentProcessId(), dwThreadId, response)) {
        return FALSE;
    }

    // Thread is valid if it exists and is not hidden
    return response.ThreadExists && !response.IsHidden;
}

const std::vector<HiddenThreadInfo>& ETHREADManipulationDetector::GetHiddenThreads() const
{
    return m_HiddenThreads;
}

void ETHREADManipulationDetector::ClearResults()
{
    m_HiddenThreads.clear();
}

BOOL ETHREADManipulationDetector::EnumerateKernelThreads(DWORD dwProcessId, 
                                                         std::vector<KAC_ETHREAD_INFO>& kernelThreads)
{
    kernelThreads.clear();

    // Allocate buffer for request/response
    // Assume max 512 threads (adjust if needed)
    const ULONG MaxThreads = 512;
    size_t bufferSize = sizeof(KAC_ENUM_ETHREAD_RESPONSE) + 
                       (MaxThreads - 1) * sizeof(KAC_ETHREAD_INFO);
    
    std::vector<BYTE> buffer(bufferSize);
    PKAC_ENUM_ETHREAD_REQUEST request = (PKAC_ENUM_ETHREAD_REQUEST)buffer.data();
    PKAC_ENUM_ETHREAD_RESPONSE response = (PKAC_ENUM_ETHREAD_RESPONSE)buffer.data();

    request->ProcessId = dwProcessId;
    request->MaxThreadCount = MaxThreads;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        m_hDriver,
        IOCTL_OBLIVIONAC_ENUM_ETHREAD,
        request,
        sizeof(KAC_ENUM_ETHREAD_REQUEST),
        response,
        (DWORD)bufferSize,
        &bytesReturned,
        NULL
    );

    if (!success) {
        return FALSE;
    }

    // Copy thread info to output vector
    for (ULONG i = 0; i < response->ThreadCount; i++) {
        kernelThreads.push_back(response->Threads[i]);
    }

    return TRUE;
}

BOOL ETHREADManipulationDetector::EnumerateUserThreads(DWORD dwProcessId, 
                                                       std::vector<DWORD>& userThreadIds)
{
    userThreadIds.clear();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32)) {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        if (te32.th32OwnerProcessID == dwProcessId) {
            userThreadIds.push_back(te32.th32ThreadID);
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);
    return TRUE;
}

DWORD ETHREADManipulationDetector::CrossReferenceThreads(
    const std::vector<KAC_ETHREAD_INFO>& kernelThreads,
    const std::vector<DWORD>& userThreadIds)
{
    DWORD discrepancies = 0;

    // Check for threads in kernel but not in user snapshot
    for (const auto& kThread : kernelThreads) {
        auto it = std::find(userThreadIds.begin(), userThreadIds.end(), kThread.ThreadId);
        if (it == userThreadIds.end()) {
            // Thread exists in kernel but not visible to user-mode snapshot
            HiddenThreadInfo info;
            info.ThreadId = kThread.ThreadId;
            info.StartAddress = kThread.StartAddress;
            info.Win32StartAddress = kThread.Win32StartAddress;
            info.DetectionType = ETHREADDetectionType::HIDDEN_FROM_USER_SNAPSHOT;
            info.DetectionReason = "Thread exists in kernel but not visible to CreateToolhelp32Snapshot";
            info.IsHidden = TRUE;
            info.IsSuspicious = TRUE;
            info.State = kThread.State;
            info.WaitReason = kThread.WaitReason;

            AddHiddenThread(info);
            discrepancies++;
        }
    }

    // Check for threads in user snapshot but not in kernel (less common, but possible)
    for (DWORD userTid : userThreadIds) {
        auto it = std::find_if(kernelThreads.begin(), kernelThreads.end(),
            [userTid](const KAC_ETHREAD_INFO& kt) { return kt.ThreadId == userTid; });
        
        if (it == kernelThreads.end()) {
            // Thread visible in user-mode but not enumerated by kernel
            // This is unusual and potentially indicates kernel-mode hiding
            HiddenThreadInfo info;
            info.ThreadId = userTid;
            info.StartAddress = 0;
            info.Win32StartAddress = 0;
            info.DetectionType = ETHREADDetectionType::CROSS_REFERENCE_MISMATCH;
            info.DetectionReason = "Thread in user snapshot but not kernel enumeration (unusual)";
            info.IsHidden = FALSE;
            info.IsSuspicious = TRUE;
            info.State = 0;
            info.WaitReason = 0;

            AddHiddenThread(info);
            discrepancies++;
        }
    }

    return discrepancies;
}

BOOL ETHREADManipulationDetector::ValidateThreadViaIOCTL(DWORD dwProcessId, DWORD dwThreadId,
                                                         KAC_VALIDATE_ETHREAD_RESPONSE& response)
{
    KAC_VALIDATE_ETHREAD_REQUEST request;
    request.ProcessId = dwProcessId;
    request.ThreadId = dwThreadId;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        m_hDriver,
        IOCTL_OBLIVIONAC_VALIDATE_ETHREAD,
        &request,
        sizeof(KAC_VALIDATE_ETHREAD_REQUEST),
        &response,
        sizeof(KAC_VALIDATE_ETHREAD_RESPONSE),
        &bytesReturned,
        NULL
    );

    return success && bytesReturned >= sizeof(KAC_VALIDATE_ETHREAD_RESPONSE);
}

void ETHREADManipulationDetector::AddHiddenThread(const HiddenThreadInfo& info)
{
    // Check if already exists
    auto it = std::find_if(m_HiddenThreads.begin(), m_HiddenThreads.end(),
        [&info](const HiddenThreadInfo& existing) {
            return existing.ThreadId == info.ThreadId &&
                   existing.DetectionType == info.DetectionType;
        });

    if (it == m_HiddenThreads.end()) {
        m_HiddenThreads.push_back(info);
    }
}

std::string ETHREADManipulationDetector::GetDetectionTypeString(ETHREADDetectionType type) const
{
    switch (type) {
    case ETHREADDetectionType::HIDDEN_FROM_KERNEL_LIST:
        return "HIDDEN_FROM_KERNEL_LIST";
    case ETHREADDetectionType::HIDDEN_FROM_USER_SNAPSHOT:
        return "HIDDEN_FROM_USER_SNAPSHOT";
    case ETHREADDetectionType::SUSPICIOUS_FLAGS:
        return "SUSPICIOUS_FLAGS";
    case ETHREADDetectionType::CROSS_REFERENCE_MISMATCH:
        return "CROSS_REFERENCE_MISMATCH";
    case ETHREADDetectionType::VALIDATION_FAILURE:
        return "VALIDATION_FAILURE";
    default:
        return "UNKNOWN";
    }
}
