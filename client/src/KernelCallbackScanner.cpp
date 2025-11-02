#include "../pch.h"
#include "../include/KernelCallbackScanner.h"
#include <algorithm>

KernelCallbackScanner::KernelCallbackScanner()
    : m_hDriver(INVALID_HANDLE_VALUE), m_bInitialized(FALSE)
{
    InitializeCriticalSection(&m_Lock);
    
    // Set default expected drivers (Windows system drivers + anti-cheat)
    m_ExpectedDrivers = {
        L"ntoskrnl.exe",
        L"OblivionAC.sys",
        L"OblivionAC",
        L"ci.dll",
        L"win32k.sys",
        L"win32kbase.sys",
        L"fltmgr.sys"
    };
}

KernelCallbackScanner::~KernelCallbackScanner()
{
    Cleanup();
    DeleteCriticalSection(&m_Lock);
}

BOOL KernelCallbackScanner::Initialize(HANDLE hDriverHandle)
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

void KernelCallbackScanner::Cleanup()
{
    EnterCriticalSection(&m_Lock);
    
    ClearResults();
    m_hDriver = INVALID_HANDLE_VALUE;
    m_bInitialized = FALSE;

    LeaveCriticalSection(&m_Lock);
}

DWORD KernelCallbackScanner::ScanAllCallbacks()
{
    if (!m_bInitialized || m_hDriver == INVALID_HANDLE_VALUE) {
        return 0;
    }

    EnterCriticalSection(&m_Lock);
    ClearResults();

    DWORD totalAnomalies = 0;
    totalAnomalies += ScanCallbackType(CallbackType::PROCESS_NOTIFY);
    totalAnomalies += ScanCallbackType(CallbackType::THREAD_NOTIFY);
    totalAnomalies += ScanCallbackType(CallbackType::IMAGE_NOTIFY);

    DWORD result = (DWORD)m_Anomalies.size();
    LeaveCriticalSection(&m_Lock);

    return result;
}

DWORD KernelCallbackScanner::ScanCallbackType(CallbackType type)
{
    if (!m_bInitialized || m_hDriver == INVALID_HANDLE_VALUE) {
        return 0;
    }

    std::vector<KAC_CALLBACK_ENTRY> callbacks;
    if (!QueryKernelCallbacks(type, callbacks)) {
        return 0;
    }

    return AnalyzeCallbacks(type, callbacks);
}

const std::vector<CallbackInfo>& KernelCallbackScanner::GetAnomalies() const
{
    return m_Anomalies;
}

void KernelCallbackScanner::ClearResults()
{
    m_Anomalies.clear();
}

void KernelCallbackScanner::SetExpectedDrivers(const std::vector<std::wstring>& driverNames)
{
    EnterCriticalSection(&m_Lock);
    m_ExpectedDrivers = driverNames;
    LeaveCriticalSection(&m_Lock);
}

BOOL KernelCallbackScanner::QueryKernelCallbacks(CallbackType type, 
                                                 std::vector<KAC_CALLBACK_ENTRY>& callbacks)
{
    callbacks.clear();

    // Allocate buffer for request/response
    // Assume max 64 callbacks per type
    const ULONG MaxCallbacks = 64;
    size_t bufferSize = sizeof(KAC_CALLBACK_INFO_RESPONSE) + 
                       (MaxCallbacks - 1) * sizeof(KAC_CALLBACK_ENTRY);
    
    std::vector<BYTE> buffer(bufferSize);
    PKAC_CALLBACK_INFO_REQUEST request = (PKAC_CALLBACK_INFO_REQUEST)buffer.data();
    PKAC_CALLBACK_INFO_RESPONSE response = (PKAC_CALLBACK_INFO_RESPONSE)buffer.data();

    request->CallbackType = static_cast<ULONG>(type);
    request->MaxCallbackCount = MaxCallbacks;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        m_hDriver,
        IOCTL_OBLIVIONAC_GET_CALLBACKS,
        request,
        sizeof(KAC_CALLBACK_INFO_REQUEST),
        response,
        (DWORD)bufferSize,
        &bytesReturned,
        NULL
    );

    if (!success) {
        return FALSE;
    }

    // Copy callback info to output vector
    for (ULONG i = 0; i < response->CallbackCount; i++) {
        callbacks.push_back(response->Callbacks[i]);
    }

    return TRUE;
}

DWORD KernelCallbackScanner::AnalyzeCallbacks(CallbackType type, 
                                               const std::vector<KAC_CALLBACK_ENTRY>& callbacks)
{
    DWORD anomalyCount = 0;

    for (const auto& cb : callbacks) {
        CallbackInfo info;
        info.Type = type;
        info.Index = cb.Index;
        info.CallbackAddress = cb.CallbackAddress;
        info.DriverBase = cb.DriverBase;
        info.DriverName = cb.DriverName;
        info.IsHooked = cb.IsHooked;
        info.IsUnhooked = cb.IsUnhooked;
        info.IsSuspicious = cb.IsSuspicious;

        BOOL hasAnomaly = FALSE;

        // Check if callback is unhooked
        if (cb.IsUnhooked) {
            info.AnomalyType = CallbackAnomalyType::CALLBACK_UNHOOKED;
            info.AnomalyReason = "Callback was removed from callback array";
            hasAnomaly = TRUE;
        }
        // Check if callback is hooked
        else if (cb.IsHooked) {
            info.AnomalyType = CallbackAnomalyType::CALLBACK_HOOKED;
            info.AnomalyReason = "Callback appears to have been modified";
            hasAnomaly = TRUE;
        }
        // Check if callback address is invalid
        else if (cb.CallbackAddress == 0 || cb.CallbackAddress < 0xFFFF800000000000) {
            info.AnomalyType = CallbackAnomalyType::CALLBACK_INVALID_ADDRESS;
            info.AnomalyReason = "Callback address is invalid or null";
            hasAnomaly = TRUE;
        }
        // Check if driver is not in expected list
        else if (!IsExpectedDriver(cb.DriverName)) {
            info.AnomalyType = CallbackAnomalyType::CALLBACK_SUSPICIOUS_DRIVER;
            info.AnomalyReason = "Callback from unexpected/unknown driver";
            hasAnomaly = TRUE;
        }
        // Check generic suspicious flag
        else if (cb.IsSuspicious) {
            info.AnomalyType = CallbackAnomalyType::CALLBACK_SUSPICIOUS_DRIVER;
            info.AnomalyReason = "Kernel flagged callback as suspicious";
            hasAnomaly = TRUE;
        }

        if (hasAnomaly) {
            AddAnomaly(info);
            anomalyCount++;
        }
    }

    // Check if expected callbacks are present
    // For example, our own OblivionAC callback should always be present
    BOOL foundOblivionAC = FALSE;
    for (const auto& cb : callbacks) {
        if (wcsstr(cb.DriverName, L"OblivionAC") != nullptr) {
            foundOblivionAC = TRUE;
            break;
        }
    }

    if (!foundOblivionAC && callbacks.size() > 0) {
        // Our callback is missing - potential unhook
        CallbackInfo info;
        info.Type = type;
        info.Index = 0;
        info.CallbackAddress = 0;
        info.DriverBase = 0;
        info.DriverName = L"OblivionAC.sys";
        info.IsHooked = FALSE;
        info.IsUnhooked = TRUE;
        info.IsSuspicious = TRUE;
        info.AnomalyType = CallbackAnomalyType::CALLBACK_MISSING_EXPECTED;
        info.AnomalyReason = "OblivionAC callback not found in callback array (potential unhook)";
        
        AddAnomaly(info);
        anomalyCount++;
    }

    return anomalyCount;
}

BOOL KernelCallbackScanner::IsExpectedDriver(const std::wstring& driverName) const
{
    if (driverName.empty()) {
        return FALSE;
    }

    for (const auto& expected : m_ExpectedDrivers) {
        // Case-insensitive comparison
        if (_wcsicmp(driverName.c_str(), expected.c_str()) == 0) {
            return TRUE;
        }
        // Also check if driver name contains expected name
        if (wcsstr(driverName.c_str(), expected.c_str()) != nullptr) {
            return TRUE;
        }
    }

    return FALSE;
}

void KernelCallbackScanner::AddAnomaly(const CallbackInfo& info)
{
    // Check if already exists
    auto it = std::find_if(m_Anomalies.begin(), m_Anomalies.end(),
        [&info](const CallbackInfo& existing) {
            return existing.Type == info.Type &&
                   existing.Index == info.Index &&
                   existing.CallbackAddress == info.CallbackAddress;
        });

    if (it == m_Anomalies.end()) {
        m_Anomalies.push_back(info);
    }
}

std::string KernelCallbackScanner::GetCallbackTypeString(CallbackType type) const
{
    switch (type) {
    case CallbackType::PROCESS_NOTIFY:
        return "PROCESS_NOTIFY";
    case CallbackType::THREAD_NOTIFY:
        return "THREAD_NOTIFY";
    case CallbackType::IMAGE_NOTIFY:
        return "IMAGE_NOTIFY";
    default:
        return "UNKNOWN";
    }
}

std::string KernelCallbackScanner::GetAnomalyTypeString(CallbackAnomalyType type) const
{
    switch (type) {
    case CallbackAnomalyType::CALLBACK_UNHOOKED:
        return "CALLBACK_UNHOOKED";
    case CallbackAnomalyType::CALLBACK_HOOKED:
        return "CALLBACK_HOOKED";
    case CallbackAnomalyType::CALLBACK_SUSPICIOUS_DRIVER:
        return "CALLBACK_SUSPICIOUS_DRIVER";
    case CallbackAnomalyType::CALLBACK_INVALID_ADDRESS:
        return "CALLBACK_INVALID_ADDRESS";
    case CallbackAnomalyType::CALLBACK_MISSING_EXPECTED:
        return "CALLBACK_MISSING_EXPECTED";
    default:
        return "UNKNOWN";
    }
}
