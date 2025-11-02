#pragma once
#include "../../common/OblivionAC_ioctl.h"
#include <Windows.h>
#include <string>
#include <vector>

/**
 * @file KernelCallbackScanner.h
 * @brief Scans and verifies kernel callback integrity
 * 
 * PRIORITY 3 - Stealth & Evasion Detection
 * 
 * Detection Techniques:
 * 1. Enumerate kernel callbacks via IOCTL (PsSetCreateProcessNotifyRoutine, etc.)
 * 2. Verify callback addresses belong to legitimate drivers
 * 3. Detect unhooked/removed callbacks
 * 4. Check for suspicious callback characteristics
 * 5. Cross-reference with known good driver list
 * 
 * Callback Types Monitored:
 * - Process creation/termination callbacks (PsSetCreateProcessNotifyRoutineEx)
 * - Thread creation/termination callbacks (PsSetCreateThreadNotifyRoutine)
 * - Image load callbacks (PsSetLoadImageNotifyRoutine)
 * 
 * Evasion Tactics Detected:
 * - Callback unhooking (removing anti-cheat callbacks)
 * - Callback address manipulation
 * - Suspicious driver callbacks
 * - Callback array tampering
 */

enum class CallbackType {
    PROCESS_NOTIFY = 0,
    THREAD_NOTIFY = 1,
    IMAGE_NOTIFY = 2
};

enum class CallbackAnomalyType {
    CALLBACK_UNHOOKED,          // Callback was removed
    CALLBACK_HOOKED,            // Callback appears modified
    CALLBACK_SUSPICIOUS_DRIVER, // Callback from suspicious driver
    CALLBACK_INVALID_ADDRESS,   // Callback address invalid
    CALLBACK_MISSING_EXPECTED   // Expected callback not found
};

struct CallbackInfo {
    CallbackType Type;
    ULONG Index;
    ULONG_PTR CallbackAddress;
    ULONG_PTR DriverBase;
    std::wstring DriverName;
    BOOLEAN IsHooked;
    BOOLEAN IsUnhooked;
    BOOLEAN IsSuspicious;
    CallbackAnomalyType AnomalyType;
    std::string AnomalyReason;
};

class KernelCallbackScanner {
public:
    KernelCallbackScanner();
    ~KernelCallbackScanner();

    /**
     * @brief Initialize the scanner
     * @param hDriverHandle Handle to OblivionAC driver (\\.\OblivionAC)
     * @return TRUE on success, FALSE on failure
     */
    BOOL Initialize(HANDLE hDriverHandle);

    /**
     * @brief Cleanup resources
     */
    void Cleanup();

    /**
     * @brief Scan all callback types
     * @return Number of anomalies detected
     */
    DWORD ScanAllCallbacks();

    /**
     * @brief Scan specific callback type
     * @param type Callback type to scan
     * @return Number of anomalies detected for this type
     */
    DWORD ScanCallbackType(CallbackType type);

    /**
     * @brief Get list of detected anomalies
     * @return Vector of callback anomaly information
     */
    const std::vector<CallbackInfo>& GetAnomalies() const;

    /**
     * @brief Clear scan results
     */
    void ClearResults();

    /**
     * @brief Set expected callback drivers (for baseline comparison)
     * @param driverNames List of expected driver names
     */
    void SetExpectedDrivers(const std::vector<std::wstring>& driverNames);

private:
    /**
     * @brief Query kernel callbacks via IOCTL
     * @param type Callback type
     * @param callbacks Output vector of callback entries
     * @return TRUE on success
     */
    BOOL QueryKernelCallbacks(CallbackType type, std::vector<KAC_CALLBACK_ENTRY>& callbacks);

    /**
     * @brief Analyze callbacks for anomalies
     * @param type Callback type
     * @param callbacks Callback entries
     * @return Number of anomalies found
     */
    DWORD AnalyzeCallbacks(CallbackType type, const std::vector<KAC_CALLBACK_ENTRY>& callbacks);

    /**
     * @brief Check if driver is expected/known good
     * @param driverName Driver name to check
     * @return TRUE if driver is in expected list
     */
    BOOL IsExpectedDriver(const std::wstring& driverName) const;

    /**
     * @brief Add anomaly to results
     */
    void AddAnomaly(const CallbackInfo& info);

    /**
     * @brief Get callback type string
     */
    std::string GetCallbackTypeString(CallbackType type) const;

    /**
     * @brief Get anomaly type string
     */
    std::string GetAnomalyTypeString(CallbackAnomalyType type) const;

private:
    HANDLE m_hDriver;                           // Driver handle
    std::vector<CallbackInfo> m_Anomalies;      // Detected anomalies
    std::vector<std::wstring> m_ExpectedDrivers; // Expected legitimate drivers
    CRITICAL_SECTION m_Lock;                    // Thread safety
    BOOL m_bInitialized;                        // Initialization flag
};
