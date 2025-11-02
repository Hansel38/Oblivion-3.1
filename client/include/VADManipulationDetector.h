#pragma once
#include "../../common/OblivionAC_ioctl.h"
#include <Windows.h>
#include <string>
#include <vector>

/**
 * @file VADManipulationDetector.h
 * @brief Detects Virtual Address Descriptor (VAD) tree tampering
 * 
 * PRIORITY 3 - Stealth & Evasion Detection
 * 
 * Detection Techniques:
 * 1. Enumerate VAD entries via kernel IOCTL
 * 2. Cross-reference with VirtualQueryEx results
 * 3. Detect hidden memory regions (in VAD but not queryable)
 * 4. Detect suspicious VAD characteristics (protection, size, type)
 * 5. Compare VAD tree with memory snapshot
 * 
 * VAD Tampering Tactics Detected:
 * - VAD unlinking (hiding memory regions)
 * - VAD protection flag manipulation
 * - VAD type tampering (Private -> Image conversion)
 * - Abnormally large private regions
 * - Memory regions with suspicious characteristics
 */

enum class VADDetectionType {
    VAD_HIDDEN_REGION,          // Memory region in VAD but not queryable
    VAD_PROTECTION_MISMATCH,    // VAD protection differs from VirtualQueryEx
    VAD_TYPE_MISMATCH,          // VAD type differs from VirtualQueryEx
    VAD_SUSPICIOUS_SIZE,        // Abnormally large memory region
    VAD_SUSPICIOUS_PROTECTION,  // Suspicious protection flags (RWX)
    VAD_MISSING_FROM_VAD        // Memory region queryable but not in VAD
};

struct VADInfo {
    ULONG_PTR StartingAddress;
    ULONG_PTR EndingAddress;
    SIZE_T SizeInBytes;
    ULONG Protection;
    ULONG VadType;
    BOOLEAN IsPrivate;
    BOOLEAN IsSuspicious;
    VADDetectionType DetectionType;
    std::string DetectionReason;
};

struct VAD_MemoryRegionInfo {
    ULONG_PTR BaseAddress;
    SIZE_T RegionSize;
    ULONG Protection;
    ULONG State;
    ULONG Type;
};

class VADManipulationDetector {
public:
    VADManipulationDetector();
    ~VADManipulationDetector();

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
     * @brief Scan for VAD manipulation in current process
     * @return Number of anomalies detected
     */
    DWORD ScanForVADManipulation();

    /**
     * @brief Scan for VAD manipulation in specific process
     * @param dwProcessId Process ID to scan
     * @return Number of anomalies detected
     */
    DWORD ScanForVADManipulation(DWORD dwProcessId);

    /**
     * @brief Validate specific memory region
     * @param baseAddress Base address to validate
     * @return TRUE if region is valid and matches VAD
     */
    BOOL ValidateMemoryRegion(ULONG_PTR baseAddress);

    /**
     * @brief Get list of detected VAD anomalies
     * @return Vector of VAD anomaly information
     */
    const std::vector<VADInfo>& GetAnomalies() const;

    /**
     * @brief Clear detection results
     */
    void ClearResults();

    /**
     * @brief Set size threshold for suspicious regions (default: 100MB)
     * @param sizeBytes Size threshold in bytes
     */
    void SetSizeThreshold(SIZE_T sizeBytes);

private:
    /**
     * @brief Query VAD entries via kernel IOCTL
     * @param dwProcessId Process ID
     * @param vadEntries Output vector of VAD entries
     * @return TRUE on success
     */
    BOOL QueryVADEntries(DWORD dwProcessId, std::vector<KAC_VAD_ENTRY>& vadEntries);

    /**
     * @brief Enumerate memory regions via VirtualQueryEx
     * @param hProcess Process handle
     * @param regions Output vector of memory regions
     * @return TRUE on success
     */
    BOOL EnumerateMemoryRegions(HANDLE hProcess, std::vector<VAD_MemoryRegionInfo>& regions);

    /**
     * @brief Cross-reference VAD and VirtualQueryEx results
     * @param vadEntries VAD entries from kernel
     * @param regions Memory regions from VirtualQueryEx
     * @return Number of discrepancies found
     */
    DWORD CrossReferenceVADAndMemory(const std::vector<KAC_VAD_ENTRY>& vadEntries,
                                     const std::vector<VAD_MemoryRegionInfo>& regions);

    /**
     * @brief Analyze VAD entry for suspicious characteristics
     * @param entry VAD entry to analyze
     * @return TRUE if suspicious
     */
    BOOL AnalyzeVADEntry(const KAC_VAD_ENTRY& entry);

    /**
     * @brief Add VAD anomaly to results
     */
    void AddAnomaly(const VADInfo& info);

    /**
     * @brief Convert protection flags to string
     */
    std::string ProtectionToString(ULONG protection) const;

    /**
     * @brief Get detection type string
     */
    std::string GetDetectionTypeString(VADDetectionType type) const;

private:
    HANDLE m_hDriver;                           // Driver handle
    std::vector<VADInfo> m_Anomalies;           // Detected VAD anomalies
    SIZE_T m_SizeThreshold;                     // Size threshold for suspicious regions
    CRITICAL_SECTION m_Lock;                    // Thread safety
    BOOL m_bInitialized;                        // Initialization flag
};
