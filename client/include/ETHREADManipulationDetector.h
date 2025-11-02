#pragma once
#include "../../common/OblivionAC_ioctl.h"
#include <Windows.h>
#include <string>
#include <vector>

/**
 * @file ETHREADManipulationDetector.h
 * @brief Detects hidden threads via ETHREAD list walking in kernel mode
 * 
 * PRIORITY 3 - Stealth & Evasion Detection
 * 
 * Detection Techniques:
 * 1. Kernel-mode ETHREAD enumeration via IOCTL
 * 2. Compare with user-mode CreateToolhelp32Snapshot thread enumeration
 * 3. Validate ETHREAD presence in ThreadListHead
 * 4. Detect suspicious thread flags (HideFromDebugger, etc.)
 * 5. Cross-reference thread IDs between kernel and user mode
 * 
 * Evasion Tactics Detected:
 * - Thread unlinking from EPROCESS->ThreadListHead
 * - Hidden debugger threads
 * - Suspicious thread flags manipulation
 * - Threads not visible to CreateToolhelp32Snapshot
 */

enum class ETHREADDetectionType {
    HIDDEN_FROM_KERNEL_LIST,    // Thread not in EPROCESS->ThreadListHead
    HIDDEN_FROM_USER_SNAPSHOT,  // Thread not visible to CreateToolhelp32Snapshot
    SUSPICIOUS_FLAGS,           // HideFromDebugger or other suspicious flags
    CROSS_REFERENCE_MISMATCH,   // Thread exists in kernel but not user mode or vice versa
    VALIDATION_FAILURE          // Thread validation failed
};

struct HiddenThreadInfo {
    ULONG ThreadId;
    ULONG_PTR StartAddress;
    ULONG_PTR Win32StartAddress;
    ETHREADDetectionType DetectionType;
    std::string DetectionReason;
    BOOLEAN IsHidden;
    BOOLEAN IsSuspicious;
    UCHAR State;
    UCHAR WaitReason;
};

class ETHREADManipulationDetector {
public:
    ETHREADManipulationDetector();
    ~ETHREADManipulationDetector();

    /**
     * @brief Initialize the detector
     * @param hDriverHandle Handle to OblivionAC driver (\\.\OblivionAC)
     * @return TRUE on success, FALSE on failure
     */
    BOOL Initialize(HANDLE hDriverHandle);

    /**
     * @brief Cleanup resources
     */
    void Cleanup();

    /**
     * @brief Scan for hidden threads in current process
     * @return Number of hidden threads detected
     */
    DWORD ScanForHiddenThreads();

    /**
     * @brief Scan for hidden threads in specific process
     * @param dwProcessId Process ID to scan
     * @return Number of hidden threads detected
     */
    DWORD ScanForHiddenThreads(DWORD dwProcessId);

    /**
     * @brief Validate specific thread
     * @param dwThreadId Thread ID to validate
     * @return TRUE if thread is valid and in ThreadListHead, FALSE otherwise
     */
    BOOL ValidateThread(DWORD dwThreadId);

    /**
     * @brief Get list of detected hidden threads
     * @return Vector of hidden thread information
     */
    const std::vector<HiddenThreadInfo>& GetHiddenThreads() const;

    /**
     * @brief Clear detection results
     */
    void ClearResults();

private:
    /**
     * @brief Enumerate threads via kernel IOCTL
     * @param dwProcessId Process ID
     * @param kernelThreads Output vector of kernel thread info
     * @return TRUE on success
     */
    BOOL EnumerateKernelThreads(DWORD dwProcessId, std::vector<KAC_ETHREAD_INFO>& kernelThreads);

    /**
     * @brief Enumerate threads via CreateToolhelp32Snapshot
     * @param dwProcessId Process ID
     * @param userThreadIds Output vector of thread IDs
     * @return TRUE on success
     */
    BOOL EnumerateUserThreads(DWORD dwProcessId, std::vector<DWORD>& userThreadIds);

    /**
     * @brief Cross-reference kernel and user thread lists
     * @param kernelThreads Kernel thread info
     * @param userThreadIds User thread IDs
     * @return Number of discrepancies found
     */
    DWORD CrossReferenceThreads(const std::vector<KAC_ETHREAD_INFO>& kernelThreads,
                                const std::vector<DWORD>& userThreadIds);

    /**
     * @brief Validate thread via kernel IOCTL
     * @param dwProcessId Process ID
     * @param dwThreadId Thread ID
     * @param response Output validation response
     * @return TRUE on success
     */
    BOOL ValidateThreadViaIOCTL(DWORD dwProcessId, DWORD dwThreadId, 
                                KAC_VALIDATE_ETHREAD_RESPONSE& response);

    /**
     * @brief Add hidden thread to detection results
     */
    void AddHiddenThread(const HiddenThreadInfo& info);

    /**
     * @brief Get detection type string
     */
    std::string GetDetectionTypeString(ETHREADDetectionType type) const;

private:
    HANDLE m_hDriver;                           // Driver handle
    std::vector<HiddenThreadInfo> m_HiddenThreads; // Detected hidden threads
    CRITICAL_SECTION m_Lock;                    // Thread safety
    BOOL m_bInitialized;                        // Initialization flag
};
