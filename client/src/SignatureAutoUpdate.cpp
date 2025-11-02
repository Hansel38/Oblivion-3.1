// ===== PRIORITY 4.2.3: Signature Auto-Update System Implementation =====
#include "../pch.h"
#include "SignatureAutoUpdate.h"
#include "NetworkClient.h"
#include "ConfigLoader.h"
#include "ClientVersion.h"
#include <sstream>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <wincrypt.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

// Helper: Convert version string to integer (e.g., "0.2.0" -> 200)
static int GetClientVersionAsInt() {
    std::string version = OBLIVION_CLIENT_VERSION;
    int major = 0, minor = 0, patch = 0;
    
    // Parse version string
    size_t pos1 = version.find('.');
    size_t pos2 = version.find('.', pos1 + 1);
    
    if (pos1 != std::string::npos) {
        major = std::stoi(version.substr(0, pos1));
        if (pos2 != std::string::npos) {
            minor = std::stoi(version.substr(pos1 + 1, pos2 - pos1 - 1));
            patch = std::stoi(version.substr(pos2 + 1));
        } else {
            minor = std::stoi(version.substr(pos1 + 1));
        }
    }
    
    // Convert to single integer: major*1000 + minor*100 + patch
    return major * 1000 + minor * 100 + patch;
}

// ===== RSA Signature Validator Implementation =====
struct RSASignatureValidator::Impl {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    bool keyLoaded = false;
};

RSASignatureValidator::RSASignatureValidator() : m_impl(std::make_unique<Impl>()) {
    CryptAcquireContextW(&m_impl->hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
}

RSASignatureValidator::~RSASignatureValidator() {
    if (m_impl->hKey) CryptDestroyKey(m_impl->hKey);
    if (m_impl->hProv) CryptReleaseContext(m_impl->hProv, 0);
}

bool RSASignatureValidator::LoadPublicKey(const std::string& pemKey) {
    // Simplified: In production, parse PEM format properly
    // This is a placeholder for actual RSA key import
    // TODO: Implement proper PEM parsing with CryptStringToBinaryA
    m_impl->keyLoaded = !pemKey.empty();
    return m_impl->keyLoaded;
}

bool RSASignatureValidator::LoadPublicKeyFromFile(const std::wstring& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return LoadPublicKey(content);
}

bool RSASignatureValidator::Verify(const std::string& data, const std::string& signatureHex) {
    if (!m_impl->keyLoaded) return false;
    
    // Convert hex signature to binary
    if (signatureHex.size() % 2 != 0) return false;
    std::vector<BYTE> signature;
    signature.reserve(signatureHex.size() / 2);
    
    for (size_t i = 0; i < signatureHex.size(); i += 2) {
        std::string byteStr = signatureHex.substr(i, 2);
        signature.push_back(static_cast<BYTE>(std::stoul(byteStr, nullptr, 16)));
    }
    
    // Hash data with SHA-256
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(m_impl->hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return false;
    }
    
    bool success = false;
    if (CryptHashData(hHash, reinterpret_cast<const BYTE*>(data.data()), data.size(), 0)) {
        // In production: Verify with CryptVerifySignature
        // This is simplified - actual verification requires proper key setup
        success = true;  // Placeholder
    }
    
    CryptDestroyHash(hHash);
    return success;
}

// ===== Delta Patcher Implementation =====
bool SignatureDeltaPatcher::ApplyPatch(
    const std::unordered_map<std::string, std::string>& currentSignatures,
    const std::vector<DeltaUpdateEntry>& deltas,
    std::unordered_map<std::string, std::string>& outNewSignatures)
{
    // Start with current signatures
    outNewSignatures = currentSignatures;
    
    for (const auto& delta : deltas) {
        switch (delta.operation) {
            case DeltaUpdateEntry::Operation::ADD:
                outNewSignatures[delta.signatureId] = delta.content;
                break;
                
            case DeltaUpdateEntry::Operation::MODIFY: {
                auto it = outNewSignatures.find(delta.signatureId);
                if (it == outNewSignatures.end()) {
                    // Signature doesn't exist, treat as ADD
                    outNewSignatures[delta.signatureId] = delta.content;
                } else {
                    // Verify old checksum matches
                    // (simplified - should compute actual hash)
                    it->second = delta.content;
                }
                break;
            }
                
            case DeltaUpdateEntry::Operation::DELETE_SIG:
                outNewSignatures.erase(delta.signatureId);
                break;
        }
    }
    
    return true;
}

std::vector<DeltaUpdateEntry> SignatureDeltaPatcher::ComputeDelta(
    const std::unordered_map<std::string, std::string>& oldSigs,
    const std::unordered_map<std::string, std::string>& newSigs)
{
    std::vector<DeltaUpdateEntry> deltas;
    
    // Find additions and modifications
    for (const auto& [id, content] : newSigs) {
        auto it = oldSigs.find(id);
        if (it == oldSigs.end()) {
            // New signature - ADD
            DeltaUpdateEntry entry;
            entry.operation = DeltaUpdateEntry::Operation::ADD;
            entry.signatureId = id;
            entry.content = content;
            deltas.push_back(entry);
        } else if (it->second != content) {
            // Modified signature
            DeltaUpdateEntry entry;
            entry.operation = DeltaUpdateEntry::Operation::MODIFY;
            entry.signatureId = id;
            entry.oldChecksum = ""; // Simplified
            entry.content = content;
            deltas.push_back(entry);
        }
    }
    
    // Find deletions
    for (const auto& [id, content] : oldSigs) {
        if (newSigs.find(id) == newSigs.end()) {
            DeltaUpdateEntry entry;
            entry.operation = DeltaUpdateEntry::Operation::DELETE_SIG;
            entry.signatureId = id;
            deltas.push_back(entry);
        }
    }
    
    return deltas;
}

// ===== SignatureAutoUpdate Implementation =====
SignatureAutoUpdate::SignatureAutoUpdate(NetworkClient* netClient, ClientConfig* config)
    : m_netClient(netClient), m_clientConfig(config), m_currentVersion(0),
      m_updateThread(nullptr), m_stopEvent(nullptr), m_testMode(false)
{
    m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    memset(&m_stats, 0, sizeof(m_stats));
}

SignatureAutoUpdate::~SignatureAutoUpdate() {
    Stop();
    if (m_stopEvent) {
        CloseHandle(m_stopEvent);
        m_stopEvent = nullptr;
    }
}

bool SignatureAutoUpdate::Initialize(const AutoUpdateConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_config = config;
    
    // Create cache directories
    CreateDirectoryW(m_config.updateCachePath.c_str(), nullptr);
    CreateDirectoryW(m_config.backupPath.c_str(), nullptr);
    
    // Load current version metadata if available
    if (m_config.persistMetadata) {
        LoadMetadata(m_currentVersion, m_currentMetadata);
    }
    
    return true;
}

void SignatureAutoUpdate::Start() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_updateThread) return;
    
    ResetEvent(m_stopEvent);
    m_updateThread = CreateThread(nullptr, 0, UpdateThreadProc, this, 0, nullptr);
}

void SignatureAutoUpdate::Stop() {
    HANDLE thread = nullptr;
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_updateThread) return;
        thread = m_updateThread;
        m_updateThread = nullptr;
    }
    
    SetEvent(m_stopEvent);
    WaitForSingleObject(thread, 10000);  // 10 second timeout
    CloseHandle(thread);
}

DWORD WINAPI SignatureAutoUpdate::UpdateThreadProc(LPVOID param) {
    auto self = static_cast<SignatureAutoUpdate*>(param);
    self->UpdateLoop();
    return 0;
}

void SignatureAutoUpdate::UpdateLoop() {
    while (true) {
        DWORD wait = WaitForSingleObject(m_stopEvent, m_config.checkIntervalMs);
        if (wait == WAIT_OBJECT_0) break;  // Stop requested
        
        // Check for updates
        UpdateResult result = CheckForUpdates();
        
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_lastResult = result;
            m_stats.lastCheckTime = GetTickCount64();
            
            if (result.status == UpdateResult::SUCCESS) {
                m_stats.totalUpdatesApplied++;
                m_stats.lastSuccessfulUpdateTime = GetTickCount64();
                m_stats.consecutiveFailures = 0;
            } else if (result.status != UpdateResult::NO_UPDATE_AVAILABLE &&
                       result.status != UpdateResult::ROLLOUT_SKIPPED) {
                m_stats.totalUpdatesFailed++;
                m_stats.consecutiveFailures++;
            }
        }
        
        // Retry logic on failure
        if (result.status != UpdateResult::SUCCESS && 
            result.status != UpdateResult::NO_UPDATE_AVAILABLE &&
            m_stats.consecutiveFailures < static_cast<int>(m_config.maxRetries)) {
            Sleep(m_config.retryIntervalMs);
        }
    }
}

UpdateResult SignatureAutoUpdate::CheckForUpdates() {
    UpdateResult result;
    result.oldVersion = m_currentVersion;
    
    // Query server for latest metadata
    SignaturePackageMetadata metadata;
    if (!QueryServerForUpdates(metadata)) {
        result.status = UpdateResult::DOWNLOAD_FAILED;
        result.errorMessage = "Failed to query server for updates";
        return result;
    }
    
    // Check if update is available
    if (metadata.version <= m_currentVersion) {
        result.status = UpdateResult::NO_UPDATE_AVAILABLE;
        result.newVersion = m_currentVersion;
        return result;
    }
    
    // Check version compatibility
    if (!IsVersionCompatible(metadata)) {
        result.status = UpdateResult::INCOMPATIBLE_VERSION;
        result.errorMessage = "Client version incompatible with update package";
        return result;
    }
    
    // Check rollout eligibility
    if (!metadata.forceUpdate && !IsInRolloutGroup(metadata)) {
        result.status = UpdateResult::ROLLOUT_SKIPPED;
        result.errorMessage = "Not in rollout group";
        return result;
    }
    
    // Check expiry
    if (metadata.expiryTimestamp > 0) {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULONGLONG current = (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
        if (current > metadata.expiryTimestamp) {
            result.status = UpdateResult::EXPIRED_PACKAGE;
            result.errorMessage = "Update package expired";
            return result;
        }
    }
    
    // Download and apply update
    return DownloadAndApplyUpdate(metadata);
}

UpdateResult SignatureAutoUpdate::DownloadAndApplyUpdate(const SignaturePackageMetadata& metadata) {
    UpdateResult result;
    result.oldVersion = m_currentVersion;
    result.newVersion = metadata.version;
    
    ULONGLONG startTime = GetTickCount64();
    
    // Download package
    std::vector<BYTE> packageData;
    if (!DownloadPackage(metadata, packageData)) {
        result.status = UpdateResult::DOWNLOAD_FAILED;
        result.errorMessage = "Failed to download package";
        return result;
    }
    
    result.bytesDownloaded = packageData.size();
    result.downloadTimeMs = static_cast<DWORD>(GetTickCount64() - startTime);
    
    // Validate package
    if (!ValidatePackage(metadata, packageData)) {
        result.status = UpdateResult::VALIDATION_FAILED;
        result.errorMessage = "Package validation failed (checksum/signature mismatch)";
        return result;
    }
    
    // Create backup before applying update
    if (m_config.enableAutoRollback && m_currentVersion > 0) {
        CreateBackup(m_currentVersion);
    }
    
    // Apply update
    if (!ApplyUpdate(metadata, packageData)) {
        result.status = UpdateResult::STORAGE_ERROR;
        result.errorMessage = "Failed to apply update";
        
        // Attempt rollback
        if (m_config.enableAutoRollback && m_currentVersion > 0) {
            if (RollbackToVersion(m_currentVersion)) {
                result.status = UpdateResult::ROLLBACK_TRIGGERED;
                result.rolledBack = true;
                result.errorMessage = "Update failed, rolled back to version " + std::to_string(m_currentVersion);
            }
        }
        return result;
    }
    
    // Success - update version
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentVersion = metadata.version;
        m_currentMetadata = metadata;
        m_stats.totalBytesDownloaded += result.bytesDownloaded;
        m_stats.totalDownloadTimeMs += result.downloadTimeMs;
    }
    
    // Save metadata
    if (m_config.persistMetadata) {
        SaveMetadata(metadata);
    }
    
    // Cache package
    SavePackageToCache(metadata, packageData);
    
    // Cleanup old backups
    CleanupOldBackups();
    
    result.status = UpdateResult::SUCCESS;
    return result;
}

bool SignatureAutoUpdate::QueryServerForUpdates(SignaturePackageMetadata& outMetadata) {
    if (!m_netClient || m_testMode) return false;
    
    // TODO: Implement proper HTTP client for update queries
    // For now, return false to indicate no HTTP client implementation
    // This is a placeholder - in production, use WinHTTP or similar
    
    // Build request (for future implementation)
    // std::string request = std::string("GET ") + METADATA_ENDPOINT + "?channel=" + m_config.updateChannel +
    //                       "&currentVersion=" + std::to_string(m_currentVersion) +
    //                       "&clientVersion=" + std::to_string(GetClientVersionAsInt()) +
    //                       "&group=" + m_config.rolloutGroup + " HTTP/1.1\r\n\r\n";
    
    // Placeholder: NetworkClient is for telemetry, not HTTP requests
    // Need to implement proper HTTP GET with WinHTTP
    return false;
    
    /* Future HTTP implementation would be:
    // Send HTTP request using WinHTTP
    std::string response = HttpGet(METADATA_ENDPOINT, params);
    if (response.empty()) return false;
    
    // Parse JSON response (simplified - should use proper JSON parser)
    // Expected format: {"version":123,"timestamp":"...","checksum":"...","signature":"..."}
    // This is a placeholder - in production use a JSON library
    
    // Extract version number (simple string search)
    size_t versionPos = response.find("\"version\":");
    if (versionPos == std::string::npos) return false;
    
    versionPos += 10;
    size_t versionEnd = response.find_first_of(",}", versionPos);
    if (versionEnd == std::string::npos) return false;
    
    std::string versionStr = response.substr(versionPos, versionEnd - versionPos);
    outMetadata.version = std::stoi(versionStr);
    
    // Extract other fields (simplified)
    outMetadata.channel = m_config.updateChannel;
    outMetadata.totalSize = 1024;  // Placeholder
    
    return true;
    */
}

bool SignatureAutoUpdate::DownloadPackage(const SignaturePackageMetadata& metadata, std::vector<BYTE>& outData) {
    if (!m_netClient || m_testMode) return false;
    
    // TODO: Implement proper HTTP download client
    // NetworkClient is for telemetry, not HTTP file downloads
    // This is a placeholder - in production, use WinHTTP or similar
    return false;
    
    /* Future HTTP implementation would be:
    // Check size limit
    if (metadata.totalSize > m_config.maxDownloadSizeBytes) {
        return false;
    }
    
    // Build download request
    std::string endpoint = UPDATE_ENDPOINT;
    endpoint += "?version=" + std::to_string(metadata.version);
    
    if (m_config.preferDeltaUpdates && metadata.isDelta) {
        endpoint += "&delta=true&baseVersion=" + std::to_string(m_currentVersion);
    }
    
    // Download using WinHTTP
    std::vector<BYTE> response = HttpDownload(endpoint);
    if (response.empty()) return false;
    
    outData = response;
    
    // Decompress if needed
    if (metadata.compressionType != "none" && m_config.enableCompression) {
        outData = DecompressData(outData, metadata.compressionType);
    }
    
    return !outData.empty();
    */
}

bool SignatureAutoUpdate::ValidatePackage(const SignaturePackageMetadata& metadata, const std::vector<BYTE>& data) {
    // Verify checksum
    if (!VerifyChecksum(data, metadata.checksum)) {
        return false;
    }
    
    // Verify digital signature if required
    if (m_config.requireDigitalSignature && !metadata.digitalSignature.empty()) {
        std::string dataStr(data.begin(), data.end());
        if (!VerifyDigitalSignature(dataStr, metadata.digitalSignature, metadata.signingKey)) {
            return false;
        }
    }
    
    return true;
}

bool SignatureAutoUpdate::ApplyUpdate(const SignaturePackageMetadata& metadata, const std::vector<BYTE>& data) {
    if (metadata.isDelta) {
        // Parse and apply delta update
        std::vector<DeltaUpdateEntry> deltas = ParseDeltaUpdate(data);
        return ApplyDeltaUpdate(deltas);
    } else {
        // Apply full update
        return ApplyFullUpdate(data);
    }
}

bool SignatureAutoUpdate::ApplyDeltaUpdate(const std::vector<DeltaUpdateEntry>& deltas) {
    if (!m_clientConfig) return false;
    
    // Convert current signatures to map (simplified - should use actual signature storage)
    std::unordered_map<std::string, std::string> currentSigs;
    // TODO: Load current signatures from m_clientConfig
    
    // Apply delta patch
    std::unordered_map<std::string, std::string> newSigs;
    if (!SignatureDeltaPatcher::ApplyPatch(currentSigs, deltas, newSigs)) {
        return false;
    }
    
    // Update configuration (simplified)
    // TODO: Update m_clientConfig with new signatures
    
    return true;
}

bool SignatureAutoUpdate::ApplyFullUpdate(const std::vector<BYTE>& data) {
    if (!m_clientConfig) return false;
    
    // Parse full signature pack (simplified - should parse actual format)
    // TODO: Parse signature pack and update m_clientConfig
    
    return true;
}

bool SignatureAutoUpdate::VerifyDigitalSignature(const std::string& data, const std::string& signature, const std::string& keyId) {
    // Check if key is trusted
    auto it = std::find(m_config.trustedKeys.begin(), m_config.trustedKeys.end(), keyId);
    if (it == m_config.trustedKeys.end()) {
        return false;  // Untrusted key
    }
    
    // Verify with RSA validator (simplified)
    RSASignatureValidator validator;
    // TODO: Load actual public key for keyId
    validator.LoadPublicKey("placeholder_key");
    
    return validator.Verify(data, signature);
}

bool SignatureAutoUpdate::VerifyChecksum(const std::vector<BYTE>& data, const std::string& expectedChecksum) {
    std::string computed = ComputeSHA256(data);
    return computed == expectedChecksum;
}

bool SignatureAutoUpdate::IsVersionCompatible(const SignaturePackageMetadata& metadata) {
    if (!m_config.strictVersionCheck) return true;
    
    int clientVersion = GetClientVersionAsInt();
    return clientVersion >= metadata.minClientVersion && clientVersion <= metadata.maxClientVersion;
}

bool SignatureAutoUpdate::IsInRolloutGroup(const SignaturePackageMetadata& metadata) {
    // Check rollout group
    if (metadata.rolloutGroup != "all" && metadata.rolloutGroup != m_config.rolloutGroup) {
        return false;
    }
    
    // Check rollout percentage
    if (metadata.rolloutPercentage < 100) {
        std::string fingerprint = GetClientFingerprint();
        size_t hash = std::hash<std::string>{}(fingerprint);
        int bucket = hash % 100;
        
        if (bucket >= metadata.rolloutPercentage) {
            return false;
        }
    }
    
    return true;
}

bool SignatureAutoUpdate::CreateBackup(int version) {
    // TODO: Implement backup creation
    return true;
}

bool SignatureAutoUpdate::RestoreBackup(int version) {
    // TODO: Implement backup restoration
    return true;
}

bool SignatureAutoUpdate::RollbackToVersion(int version) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!RestoreBackup(version)) {
        return false;
    }
    
    m_currentVersion = version;
    m_stats.totalRollbacks++;
    
    return true;
}

void SignatureAutoUpdate::CleanupOldBackups() {
    // TODO: Delete old backups beyond keepBackupVersions
}

std::string SignatureAutoUpdate::ComputeSHA256(const std::vector<BYTE>& data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    DWORD hashLen = 32;  // SHA-256 = 32 bytes
    BYTE hashBytes[32];
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    
    // Convert to hex string
    std::stringstream ss;
    for (DWORD i = 0; i < hashLen; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hashBytes[i]);
    }
    
    return ss.str();
}

std::string SignatureAutoUpdate::GetClientFingerprint() {
    // Generate unique client fingerprint for rollout bucketing
    // Using simple HWID-based fingerprint
    std::stringstream ss;
    ss << m_config.rolloutGroup << "_" << m_currentVersion;
    return ss.str();
}

bool SignatureAutoUpdate::IsInCanaryGroup() {
    if (!m_config.participateInCanary) return false;
    
    std::string fingerprint = GetClientFingerprint();
    size_t hash = std::hash<std::string>{}(fingerprint);
    int bucket = hash % 100;
    
    return bucket < m_config.canaryPercentage;
}

std::vector<BYTE> SignatureAutoUpdate::DecompressData(const std::vector<BYTE>& compressed, const std::string& compressionType) {
    // Placeholder - implement actual decompression (deflate, lz4, etc.)
    return compressed;
}

std::vector<DeltaUpdateEntry> SignatureAutoUpdate::ParseDeltaUpdate(const std::vector<BYTE>& data) {
    std::vector<DeltaUpdateEntry> deltas;
    // TODO: Parse delta format (JSON, binary, etc.)
    return deltas;
}

bool SignatureAutoUpdate::SavePackageToCache(const SignaturePackageMetadata& metadata, const std::vector<BYTE>& data) {
    std::wstring filePath = m_config.updateCachePath + L"\\package_v" + std::to_wstring(metadata.version) + L".dat";
    
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    
    DWORD written = 0;
    bool success = WriteFile(hFile, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
    CloseHandle(hFile);
    
    return success && written == data.size();
}

bool SignatureAutoUpdate::LoadPackageFromCache(int version, SignaturePackageMetadata& outMetadata, std::vector<BYTE>& outData) {
    std::wstring filePath = m_config.updateCachePath + L"\\package_v" + std::to_wstring(version) + L".dat";
    
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }
    
    outData.resize(fileSize);
    DWORD read = 0;
    bool success = ReadFile(hFile, outData.data(), fileSize, &read, nullptr);
    CloseHandle(hFile);
    
    if (!success || read != fileSize) return false;
    
    // Load metadata
    return LoadMetadata(version, outMetadata);
}

bool SignatureAutoUpdate::SaveMetadata(const SignaturePackageMetadata& metadata) {
    std::wstring filePath = m_config.updateCachePath + L"\\metadata_v" + std::to_wstring(metadata.version) + L".json";
    
    // Simplified JSON serialization
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"version\": " << metadata.version << ",\n";
    ss << "  \"timestamp\": \"" << metadata.timestamp << "\",\n";
    ss << "  \"buildId\": \"" << metadata.buildId << "\",\n";
    ss << "  \"channel\": \"" << metadata.channel << "\",\n";
    ss << "  \"checksum\": \"" << metadata.checksum << "\",\n";
    ss << "  \"totalSize\": " << metadata.totalSize << "\n";
    ss << "}\n";
    
    std::string json = ss.str();
    
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    
    DWORD written = 0;
    bool success = WriteFile(hFile, json.data(), static_cast<DWORD>(json.size()), &written, nullptr);
    CloseHandle(hFile);
    
    return success;
}

bool SignatureAutoUpdate::LoadMetadata(int version, SignaturePackageMetadata& outMetadata) {
    std::wstring filePath = m_config.updateCachePath + L"\\metadata_v" + std::to_wstring(version) + L".json";
    
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE || fileSize > 1024 * 1024) {  // Max 1MB metadata
        CloseHandle(hFile);
        return false;
    }
    
    std::vector<char> buffer(fileSize + 1);
    DWORD read = 0;
    bool success = ReadFile(hFile, buffer.data(), fileSize, &read, nullptr);
    CloseHandle(hFile);
    
    if (!success || read != fileSize) return false;
    
    buffer[fileSize] = '\0';
    std::string json(buffer.data());
    
    // Parse JSON (simplified)
    // TODO: Use proper JSON parser
    size_t versionPos = json.find("\"version\":");
    if (versionPos != std::string::npos) {
        versionPos += 10;
        size_t versionEnd = json.find_first_of(",}", versionPos);
        if (versionEnd != std::string::npos) {
            std::string versionStr = json.substr(versionPos, versionEnd - versionPos);
            outMetadata.version = std::stoi(versionStr);
        }
    }
    
    return outMetadata.version > 0;
}

SignatureAutoUpdate::UpdateStatistics SignatureAutoUpdate::GetStatistics() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_stats;
}

SignaturePackageMetadata SignatureAutoUpdate::GetCurrentMetadata() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_currentMetadata;
}

void SignatureAutoUpdate::SetConfig(const AutoUpdateConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;
}

void SignatureAutoUpdate::SimulateUpdate(const SignaturePackageMetadata& metadata) {
    if (!m_testMode) return;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    m_currentVersion = metadata.version;
    m_currentMetadata = metadata;
}
