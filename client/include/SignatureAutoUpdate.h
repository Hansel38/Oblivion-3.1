// ===== PRIORITY 4.2.3: Signature Auto-Update System =====
// Enterprise-grade signature auto-update system with:
// - Delta updates (only download changed signatures)
// - Digital signature verification (RSA + SHA-256)
// - Rollback mechanism (automatic fallback on failure)
// - A/B testing (canary deployments)
// - Version control and changelog
// - Bandwidth optimization (compression)
// - Integrity validation (checksums)
// Version: 1.0
// Author: Oblivion AntiCheat Team
// Date: 2025-11-02

#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>

// Forward declarations
class ConfigLoader;
struct ClientConfig;
class NetworkClient;

// ===== Update Package Metadata =====
struct SignaturePackageMetadata {
    int version;                        // Package version number
    std::string timestamp;              // ISO 8601 timestamp
    std::string buildId;                // Unique build identifier (git commit hash)
    std::string channel;                // "stable", "beta", "canary"
    int minClientVersion;               // Minimum client version required
    int maxClientVersion;               // Maximum client version supported
    
    size_t totalSize;                   // Total package size in bytes
    size_t compressedSize;              // Compressed size (if applicable)
    std::string compressionType;        // "none", "deflate", "lz4"
    
    std::string checksum;               // SHA-256 hash of package content
    std::string digitalSignature;       // RSA signature (hex encoded)
    std::string signingKey;             // Public key identifier
    
    std::string changelog;              // Human-readable changes
    std::vector<std::string> tags;      // Feature tags (e.g., "ce74_support", "critical_fix")
    
    bool isDelta;                       // True if delta update
    int baseVersion;                    // Base version for delta (if isDelta)
    
    // Deployment control
    int rolloutPercentage;              // 0-100, for gradual rollout
    std::string rolloutGroup;           // Target group (e.g., "group_a", "all")
    bool forceUpdate;                   // Bypass canary/rollout rules
    ULONGLONG expiryTimestamp;          // Signature expiry (0 = never)
    
    SignaturePackageMetadata()
        : version(0), minClientVersion(0), maxClientVersion(999999),
          totalSize(0), compressedSize(0), compressionType("none"),
          isDelta(false), baseVersion(0), rolloutPercentage(100),
          forceUpdate(false), expiryTimestamp(0) {}
};

// ===== Delta Update Entry =====
struct DeltaUpdateEntry {
    enum class Operation {
        ADD,        // Add new signature
        MODIFY,     // Modify existing signature
        DELETE_SIG  // Remove signature (renamed to avoid Windows macro)
    };
    
    Operation operation;
    std::string signatureId;            // Unique signature identifier
    std::string category;               // Signature category
    std::string oldChecksum;            // For MODIFY: old signature hash
    std::string newChecksum;            // For ADD/MODIFY: new signature hash
    std::string content;                // Signature content (hex/base64)
    
    DeltaUpdateEntry() : operation(Operation::ADD) {}
};

// ===== Update Result =====
struct UpdateResult {
    enum Status {
        SUCCESS,                        // Update successful
        NO_UPDATE_AVAILABLE,            // Already at latest version
        DOWNLOAD_FAILED,                // Network/server error
        VALIDATION_FAILED,              // Checksum/signature verification failed
        INCOMPATIBLE_VERSION,           // Client version mismatch
        ROLLOUT_SKIPPED,                // Not in rollout group
        ROLLBACK_TRIGGERED,             // Update failed, rolled back
        EXPIRED_PACKAGE,                // Package expired
        STORAGE_ERROR                   // Disk I/O error
    };
    
    Status status;
    int oldVersion;
    int newVersion;
    std::string errorMessage;
    size_t bytesDownloaded;
    DWORD downloadTimeMs;
    bool rolledBack;
    
    UpdateResult()
        : status(NO_UPDATE_AVAILABLE), oldVersion(0), newVersion(0),
          bytesDownloaded(0), downloadTimeMs(0), rolledBack(false) {}
};

// ===== Update Configuration =====
struct AutoUpdateConfig {
    // Update intervals
    DWORD checkIntervalMs;              // How often to check for updates (default: 5 min)
    DWORD retryIntervalMs;              // Retry interval on failure (default: 1 min)
    DWORD maxRetries;                   // Max retry attempts (default: 3)
    
    // Channels
    std::string updateChannel;          // "stable", "beta", "canary"
    bool allowChannelSwitch;            // Allow automatic channel changes
    
    // Rollout control
    std::string rolloutGroup;           // Client rollout group identifier
    bool participateInCanary;           // Opt-in to canary testing
    int canaryPercentage;               // % chance to be in canary group (0-100)
    
    // Validation
    bool requireDigitalSignature;       // Enforce signature verification
    bool strictVersionCheck;            // Enforce min/max version checks
    std::vector<std::string> trustedKeys; // Trusted public key identifiers
    
    // Rollback
    bool enableAutoRollback;            // Auto rollback on validation failure
    int rollbackThreshold;              // Seconds before rollback (0 = immediate)
    int keepBackupVersions;             // Number of backup versions to keep
    
    // Bandwidth optimization
    bool preferDeltaUpdates;            // Use delta updates when available
    bool enableCompression;             // Accept compressed packages
    size_t maxDownloadSizeBytes;        // Max download size (safety limit)
    
    // Storage
    std::wstring updateCachePath;       // Where to cache downloaded packages
    std::wstring backupPath;            // Where to store backups
    bool persistMetadata;               // Save metadata to disk
    
    AutoUpdateConfig()
        : checkIntervalMs(300000),      // 5 minutes
          retryIntervalMs(60000),       // 1 minute
          maxRetries(3),
          updateChannel("stable"),
          allowChannelSwitch(false),
          rolloutGroup("default"),
          participateInCanary(false),
          canaryPercentage(5),
          requireDigitalSignature(true),
          strictVersionCheck(true),
          enableAutoRollback(true),
          rollbackThreshold(0),
          keepBackupVersions(3),
          preferDeltaUpdates(true),
          enableCompression(true),
          maxDownloadSizeBytes(10 * 1024 * 1024),  // 10 MB
          updateCachePath(L"signatures\\cache"),
          backupPath(L"signatures\\backup"),
          persistMetadata(true)
    {
        trustedKeys.push_back("oblivion-signing-key-2025");
    }
};

// ===== Main Auto-Update Manager =====
class SignatureAutoUpdate {
public:
    explicit SignatureAutoUpdate(NetworkClient* netClient, ClientConfig* config);
    ~SignatureAutoUpdate();
    
    // Lifecycle
    bool Initialize(const AutoUpdateConfig& config);
    void Start();
    void Stop();
    
    // Manual operations
    UpdateResult CheckForUpdates();
    UpdateResult DownloadAndApplyUpdate(const SignaturePackageMetadata& metadata);
    bool RollbackToVersion(int version);
    
    // Query
    int GetCurrentVersion() const { return m_currentVersion; }
    SignaturePackageMetadata GetCurrentMetadata() const;
    std::vector<SignaturePackageMetadata> GetAvailableVersions();
    UpdateResult GetLastUpdateResult() const { return m_lastResult; }
    
    // Statistics
    struct UpdateStatistics {
        int totalUpdatesApplied;
        int totalUpdatesFailed;
        int totalRollbacks;
        size_t totalBytesDownloaded;
        ULONGLONG totalDownloadTimeMs;
        ULONGLONG lastCheckTime;
        ULONGLONG lastSuccessfulUpdateTime;
        int consecutiveFailures;
    };
    
    UpdateStatistics GetStatistics() const;
    
    // Configuration
    void SetConfig(const AutoUpdateConfig& config);
    AutoUpdateConfig GetConfig() const { return m_config; }
    
    // Testing support
    void SetTestMode(bool enable) { m_testMode = enable; }
    void SimulateUpdate(const SignaturePackageMetadata& metadata);

private:
    // Background update thread
    static DWORD WINAPI UpdateThreadProc(LPVOID param);
    void UpdateLoop();
    
    // Update operations
    bool QueryServerForUpdates(SignaturePackageMetadata& outMetadata);
    bool DownloadPackage(const SignaturePackageMetadata& metadata, std::vector<BYTE>& outData);
    bool ValidatePackage(const SignaturePackageMetadata& metadata, const std::vector<BYTE>& data);
    bool ApplyUpdate(const SignaturePackageMetadata& metadata, const std::vector<BYTE>& data);
    bool ApplyDeltaUpdate(const std::vector<DeltaUpdateEntry>& deltas);
    bool ApplyFullUpdate(const std::vector<BYTE>& data);
    
    // Validation
    bool VerifyDigitalSignature(const std::string& data, const std::string& signature, const std::string& keyId);
    bool VerifyChecksum(const std::vector<BYTE>& data, const std::string& expectedChecksum);
    bool IsVersionCompatible(const SignaturePackageMetadata& metadata);
    bool IsInRolloutGroup(const SignaturePackageMetadata& metadata);
    
    // Rollback management
    bool CreateBackup(int version);
    bool RestoreBackup(int version);
    void CleanupOldBackups();
    
    // Storage
    bool SavePackageToCache(const SignaturePackageMetadata& metadata, const std::vector<BYTE>& data);
    bool LoadPackageFromCache(int version, SignaturePackageMetadata& outMetadata, std::vector<BYTE>& outData);
    bool SaveMetadata(const SignaturePackageMetadata& metadata);
    bool LoadMetadata(int version, SignaturePackageMetadata& outMetadata);
    
    // Compression
    std::vector<BYTE> DecompressData(const std::vector<BYTE>& compressed, const std::string& compressionType);
    
    // Delta processing
    std::vector<DeltaUpdateEntry> ParseDeltaUpdate(const std::vector<BYTE>& data);
    
    // Utilities
    std::string ComputeSHA256(const std::vector<BYTE>& data);
    std::string GetClientFingerprint();  // For rollout group assignment
    bool IsInCanaryGroup();
    
    // Members
    NetworkClient* m_netClient;         // Not owned
    ClientConfig* m_clientConfig;       // Not owned
    AutoUpdateConfig m_config;
    
    // State
    int m_currentVersion;
    SignaturePackageMetadata m_currentMetadata;
    UpdateResult m_lastResult;
    UpdateStatistics m_stats;
    
    // Thread management
    HANDLE m_updateThread;
    HANDLE m_stopEvent;
    mutable std::mutex m_mutex;
    
    // Testing
    bool m_testMode;
    
    // Constants
    static constexpr int JSON_PROTOCOL_VERSION = 1;
    static constexpr const char* UPDATE_ENDPOINT = "/api/v1/signatures/update";
    static constexpr const char* METADATA_ENDPOINT = "/api/v1/signatures/metadata";
};

// ===== Utility: Digital Signature Validator =====
class RSASignatureValidator {
public:
    RSASignatureValidator();
    ~RSASignatureValidator();
    
    // Load public key from PEM string or file
    bool LoadPublicKey(const std::string& pemKey);
    bool LoadPublicKeyFromFile(const std::wstring& filePath);
    
    // Verify RSA-SHA256 signature
    bool Verify(const std::string& data, const std::string& signatureHex);
    
private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// ===== Utility: Delta Patcher =====
class SignatureDeltaPatcher {
public:
    static bool ApplyPatch(
        const std::unordered_map<std::string, std::string>& currentSignatures,
        const std::vector<DeltaUpdateEntry>& deltas,
        std::unordered_map<std::string, std::string>& outNewSignatures);
    
    static std::vector<DeltaUpdateEntry> ComputeDelta(
        const std::unordered_map<std::string, std::string>& oldSigs,
        const std::unordered_map<std::string, std::string>& newSigs);
};
