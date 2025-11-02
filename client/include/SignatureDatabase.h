#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <map>

// Signature types for different detection scenarios
enum class SignatureType {
    MODULE_NAME,        // Match against loaded module names
    FILE_SIGNATURE,     // Match against file on disk
    MEMORY_PATTERN,     // Scan memory for byte patterns
    REGISTRY_KEY,       // Check registry for CE artifacts
    WINDOW_CLASS,       // Window class name detection
    DRIVER_DEVICE,      // Device object name for drivers
    NETWORK_ARTIFACT,   // Network-based detection (ports, hostnames)
    PROCESS_NAME        // Process name matching
};

// Severity levels for detections
enum class SignatureSeverity {
    LOW = 1,            // Suspicious but may be legitimate tool
    MEDIUM = 2,         // Likely cheat tool
    HIGH = 3,           // Known cheat tool
    CRITICAL = 4        // Active exploitation detected
};

// Individual signature entry
struct Signature {
    std::string id;                     // Unique signature ID (e.g., "CE_74_MAIN_MODULE")
    std::string name;                   // Human-readable name
    std::string description;            // Detection description
    SignatureType type;                 // Type of signature
    SignatureSeverity severity;         // Severity level
    std::string pattern;                // Pattern to match (depends on type)
    std::vector<std::string> tags;      // Tags for categorization (e.g., "cheat-engine", "memory-editor")
    int version;                        // Signature version
    bool enabled;                       // Whether signature is active
    
    // Pattern-specific fields
    std::vector<BYTE> hexPattern;       // For MEMORY_PATTERN: compiled hex bytes
    std::vector<bool> wildcardMask;     // For MEMORY_PATTERN: wildcard positions (true = wildcard)
    
    Signature() 
        : type(SignatureType::MODULE_NAME)
        , severity(SignatureSeverity::MEDIUM)
        , version(1)
        , enabled(true)
    {}
};

// Signature category for organization
struct SignatureCategory {
    std::string name;                   // Category name (e.g., "Cheat Engine 7.4")
    std::string description;            // Category description
    std::vector<Signature> signatures;  // Signatures in this category
    bool enabled;                       // Enable/disable entire category
    
    SignatureCategory() : enabled(true) {}
};

// Complete signature database
class SignatureDatabase {
public:
    SignatureDatabase();
    ~SignatureDatabase();
    
    // Load/Save operations
    bool LoadFromJson(const std::wstring& filePath);
    bool LoadFromString(const std::string& jsonContent);
    bool SaveToJson(const std::wstring& filePath) const;
    std::string ExportToJsonString() const;
    
    // Signature management
    bool AddSignature(const std::string& categoryName, const Signature& sig);
    bool RemoveSignature(const std::string& signatureId);
    bool UpdateSignature(const std::string& signatureId, const Signature& sig);
    bool EnableSignature(const std::string& signatureId, bool enable);
    bool EnableCategory(const std::string& categoryName, bool enable);
    
    // Query operations
    const Signature* GetSignature(const std::string& signatureId) const;
    std::vector<const Signature*> GetSignaturesByType(SignatureType type) const;
    std::vector<const Signature*> GetSignaturesByTag(const std::string& tag) const;
    std::vector<const Signature*> GetAllEnabledSignatures() const;
    std::vector<std::string> GetCategoryNames() const;
    const SignatureCategory* GetCategory(const std::string& categoryName) const;
    
    // Statistics
    int GetTotalSignatureCount() const;
    int GetEnabledSignatureCount() const;
    int GetSignatureCountByType(SignatureType type) const;
    
    // Utility: compile pattern string to binary (e.g., "AA BB ?? CC DD" -> bytes + mask)
    static bool CompileHexPattern(const std::string& patternStr, 
                                   std::vector<BYTE>& outBytes, 
                                   std::vector<bool>& outWildcards);
    
    // Utility: pattern string to wide string for legacy config
    static std::wstring ConvertToLegacyFormat(const std::vector<const Signature*>& signatures);
    
    // Version management
    void SetDatabaseVersion(int version) { m_databaseVersion = version; }
    int GetDatabaseVersion() const { return m_databaseVersion; }
    
    // Metadata
    void SetLastUpdateTime(const std::string& timestamp) { m_lastUpdate = timestamp; }
    std::string GetLastUpdateTime() const { return m_lastUpdate; }
    
    // Clear all signatures
    void Clear();
    
private:
    std::vector<SignatureCategory> m_categories;
    std::map<std::string, Signature*> m_signatureIndex;  // Fast lookup by ID
    int m_databaseVersion;
    std::string m_lastUpdate;
    
    // Helper functions
    void RebuildIndex();
    std::string SignatureTypeToString(SignatureType type) const;
    SignatureType StringToSignatureType(const std::string& str) const;
    std::string SeverityToString(SignatureSeverity sev) const;
    SignatureSeverity StringToSeverity(const std::string& str) const;
};

// Global signature database instance (initialized in dllmain.cpp)
extern SignatureDatabase* g_pSignatureDB;

