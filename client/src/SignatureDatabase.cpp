#include "../pch.h"
#include "SignatureDatabase.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

// JSON parsing helper (simple implementation without external libraries)
namespace JsonHelper {
    // Trim whitespace
    static std::string Trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = str.find_last_not_of(" \t\r\n");
        return str.substr(start, end - start + 1);
    }
    
    // Extract string value from JSON (simple parser)
    static std::string GetStringValue(const std::string& json, const std::string& key) {
        std::string search = "\"" + key + "\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return "";
        
        pos = json.find("\"", pos);
        if (pos == std::string::npos) return "";
        
        size_t endPos = json.find("\"", pos + 1);
        if (endPos == std::string::npos) return "";
        
        return json.substr(pos + 1, endPos - pos - 1);
    }
    
    // Extract integer value from JSON
    static int GetIntValue(const std::string& json, const std::string& key, int defaultVal = 0) {
        std::string search = "\"" + key + "\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return defaultVal;
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return defaultVal;
        
        std::string numStr;
        for (size_t i = pos + 1; i < json.size(); ++i) {
            char c = json[i];
            if (std::isdigit(c) || c == '-') {
                numStr += c;
            } else if (!numStr.empty()) {
                break;
            }
        }
        
        if (numStr.empty()) return defaultVal;
        return std::stoi(numStr);
    }
    
    // Extract boolean value from JSON
    static bool GetBoolValue(const std::string& json, const std::string& key, bool defaultVal = false) {
        std::string search = "\"" + key + "\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return defaultVal;
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return defaultVal;
        
        size_t truePos = json.find("true", pos);
        size_t falsePos = json.find("false", pos);
        
        if (truePos != std::string::npos && (falsePos == std::string::npos || truePos < falsePos)) {
            return true;
        }
        return false;
    }
    
    // Extract array of strings
    static std::vector<std::string> GetStringArray(const std::string& json, const std::string& key) {
        std::vector<std::string> result;
        std::string search = "\"" + key + "\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return result;
        
        pos = json.find("[", pos);
        if (pos == std::string::npos) return result;
        
        size_t endPos = json.find("]", pos);
        if (endPos == std::string::npos) return result;
        
        std::string arrayContent = json.substr(pos + 1, endPos - pos - 1);
        size_t start = 0;
        while (true) {
            size_t quoteStart = arrayContent.find("\"", start);
            if (quoteStart == std::string::npos) break;
            
            size_t quoteEnd = arrayContent.find("\"", quoteStart + 1);
            if (quoteEnd == std::string::npos) break;
            
            result.push_back(arrayContent.substr(quoteStart + 1, quoteEnd - quoteStart - 1));
            start = quoteEnd + 1;
        }
        
        return result;
    }
}

// Global instance (declared in header, defined here)
SignatureDatabase* g_pSignatureDB = nullptr;

SignatureDatabase::SignatureDatabase()
    : m_databaseVersion(0)
{
}

SignatureDatabase::~SignatureDatabase()
{
    Clear();
}

bool SignatureDatabase::LoadFromJson(const std::wstring& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open()) return false;
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    file.close();
    
    return LoadFromString(content);
}

bool SignatureDatabase::LoadFromString(const std::string& jsonContent)
{
    try {
        Clear();
        
        // Parse database metadata
        m_databaseVersion = JsonHelper::GetIntValue(jsonContent, "database_version", 1);
        m_lastUpdate = JsonHelper::GetStringValue(jsonContent, "last_update");
        
        // Find categories array
        size_t categoriesPos = jsonContent.find("\"categories\"");
        if (categoriesPos == std::string::npos) return false;
        
        size_t arrayStart = jsonContent.find("[", categoriesPos);
        if (arrayStart == std::string::npos) return false;
        
        // Simple category parser - find each category object
        size_t pos = arrayStart + 1;
        int braceCount = 0;
        size_t categoryStart = 0;
        
        for (size_t i = pos; i < jsonContent.size(); ++i) {
            char c = jsonContent[i];
            
            if (c == '{') {
                if (braceCount == 0) categoryStart = i;
                braceCount++;
            } else if (c == '}') {
                braceCount--;
                if (braceCount == 0 && categoryStart > 0) {
                    // Extract category object
                    std::string categoryJson = jsonContent.substr(categoryStart, i - categoryStart + 1);
                    
                    SignatureCategory category;
                    category.name = JsonHelper::GetStringValue(categoryJson, "name");
                    category.description = JsonHelper::GetStringValue(categoryJson, "description");
                    category.enabled = JsonHelper::GetBoolValue(categoryJson, "enabled", true);
                    
                    // Parse signatures in this category
                    size_t sigArrayPos = categoryJson.find("\"signatures\"");
                    if (sigArrayPos != std::string::npos) {
                        size_t sigArrayStart = categoryJson.find("[", sigArrayPos);
                        if (sigArrayStart != std::string::npos) {
                            size_t sigPos = sigArrayStart + 1;
                            int sigBraceCount = 0;
                            size_t sigStart = 0;
                            
                            for (size_t j = sigPos; j < categoryJson.size(); ++j) {
                                char sc = categoryJson[j];
                                
                                if (sc == '{') {
                                    if (sigBraceCount == 0) sigStart = j;
                                    sigBraceCount++;
                                } else if (sc == '}') {
                                    sigBraceCount--;
                                    if (sigBraceCount == 0 && sigStart > 0) {
                                        // Extract signature object
                                        std::string sigJson = categoryJson.substr(sigStart, j - sigStart + 1);
                                        
                                        Signature sig;
                                        sig.id = JsonHelper::GetStringValue(sigJson, "id");
                                        sig.name = JsonHelper::GetStringValue(sigJson, "name");
                                        sig.description = JsonHelper::GetStringValue(sigJson, "description");
                                        sig.pattern = JsonHelper::GetStringValue(sigJson, "pattern");
                                        sig.version = JsonHelper::GetIntValue(sigJson, "version", 1);
                                        sig.enabled = JsonHelper::GetBoolValue(sigJson, "enabled", true);
                                        
                                        std::string typeStr = JsonHelper::GetStringValue(sigJson, "type");
                                        sig.type = StringToSignatureType(typeStr);
                                        
                                        std::string sevStr = JsonHelper::GetStringValue(sigJson, "severity");
                                        sig.severity = StringToSeverity(sevStr);
                                        
                                        sig.tags = JsonHelper::GetStringArray(sigJson, "tags");
                                        
                                        // Compile hex pattern if type is MEMORY_PATTERN
                                        if (sig.type == SignatureType::MEMORY_PATTERN) {
                                            CompileHexPattern(sig.pattern, sig.hexPattern, sig.wildcardMask);
                                        }
                                        
                                        category.signatures.push_back(sig);
                                        sigStart = 0;
                                    }
                                } else if (sc == ']') {
                                    break;
                                }
                            }
                        }
                    }
                    
                    m_categories.push_back(category);
                    categoryStart = 0;
                }
            } else if (c == ']' && braceCount == 0) {
                break;
            }
        }
        
        RebuildIndex();
        return true;
        
    } catch (...) {
        Clear();
        return false;
    }
}

bool SignatureDatabase::SaveToJson(const std::wstring& filePath) const
{
    std::string jsonContent = ExportToJsonString();
    if (jsonContent.empty()) return false;
    
    std::ofstream file(filePath);
    if (!file.is_open()) return false;
    
    file << jsonContent;
    file.close();
    
    return true;
}

std::string SignatureDatabase::ExportToJsonString() const
{
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"database_version\": " << m_databaseVersion << ",\n";
    ss << "  \"last_update\": \"" << m_lastUpdate << "\",\n";
    ss << "  \"categories\": [\n";
    
    for (size_t i = 0; i < m_categories.size(); ++i) {
        const auto& cat = m_categories[i];
        ss << "    {\n";
        ss << "      \"name\": \"" << cat.name << "\",\n";
        ss << "      \"description\": \"" << cat.description << "\",\n";
        ss << "      \"enabled\": " << (cat.enabled ? "true" : "false") << ",\n";
        ss << "      \"signatures\": [\n";
        
        for (size_t j = 0; j < cat.signatures.size(); ++j) {
            const auto& sig = cat.signatures[j];
            ss << "        {\n";
            ss << "          \"id\": \"" << sig.id << "\",\n";
            ss << "          \"name\": \"" << sig.name << "\",\n";
            ss << "          \"description\": \"" << sig.description << "\",\n";
            ss << "          \"type\": \"" << SignatureTypeToString(sig.type) << "\",\n";
            ss << "          \"severity\": \"" << SeverityToString(sig.severity) << "\",\n";
            ss << "          \"pattern\": \"" << sig.pattern << "\",\n";
            ss << "          \"tags\": [";
            for (size_t k = 0; k < sig.tags.size(); ++k) {
                ss << "\"" << sig.tags[k] << "\"";
                if (k < sig.tags.size() - 1) ss << ", ";
            }
            ss << "],\n";
            ss << "          \"version\": " << sig.version << ",\n";
            ss << "          \"enabled\": " << (sig.enabled ? "true" : "false") << "\n";
            ss << "        }";
            if (j < cat.signatures.size() - 1) ss << ",";
            ss << "\n";
        }
        
        ss << "      ]\n";
        ss << "    }";
        if (i < m_categories.size() - 1) ss << ",";
        ss << "\n";
    }
    
    ss << "  ]\n";
    ss << "}\n";
    
    return ss.str();
}

bool SignatureDatabase::AddSignature(const std::string& categoryName, const Signature& sig)
{
    // Find or create category
    SignatureCategory* cat = nullptr;
    for (auto& c : m_categories) {
        if (c.name == categoryName) {
            cat = &c;
            break;
        }
    }
    
    if (!cat) {
        SignatureCategory newCat;
        newCat.name = categoryName;
        newCat.enabled = true;
        m_categories.push_back(newCat);
        cat = &m_categories.back();
    }
    
    cat->signatures.push_back(sig);
    RebuildIndex();
    return true;
}

bool SignatureDatabase::RemoveSignature(const std::string& signatureId)
{
    for (auto& cat : m_categories) {
        auto it = std::remove_if(cat.signatures.begin(), cat.signatures.end(),
            [&signatureId](const Signature& sig) { return sig.id == signatureId; });
        
        if (it != cat.signatures.end()) {
            cat.signatures.erase(it, cat.signatures.end());
            RebuildIndex();
            return true;
        }
    }
    return false;
}

bool SignatureDatabase::UpdateSignature(const std::string& signatureId, const Signature& sig)
{
    for (auto& cat : m_categories) {
        for (auto& s : cat.signatures) {
            if (s.id == signatureId) {
                s = sig;
                RebuildIndex();
                return true;
            }
        }
    }
    return false;
}

bool SignatureDatabase::EnableSignature(const std::string& signatureId, bool enable)
{
    for (auto& cat : m_categories) {
        for (auto& sig : cat.signatures) {
            if (sig.id == signatureId) {
                sig.enabled = enable;
                return true;
            }
        }
    }
    return false;
}

bool SignatureDatabase::EnableCategory(const std::string& categoryName, bool enable)
{
    for (auto& cat : m_categories) {
        if (cat.name == categoryName) {
            cat.enabled = enable;
            return true;
        }
    }
    return false;
}

const Signature* SignatureDatabase::GetSignature(const std::string& signatureId) const
{
    auto it = m_signatureIndex.find(signatureId);
    if (it != m_signatureIndex.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<const Signature*> SignatureDatabase::GetSignaturesByType(SignatureType type) const
{
    std::vector<const Signature*> result;
    for (const auto& cat : m_categories) {
        if (!cat.enabled) continue;
        for (const auto& sig : cat.signatures) {
            if (sig.type == type && sig.enabled) {
                result.push_back(&sig);
            }
        }
    }
    return result;
}

std::vector<const Signature*> SignatureDatabase::GetSignaturesByTag(const std::string& tag) const
{
    std::vector<const Signature*> result;
    for (const auto& cat : m_categories) {
        if (!cat.enabled) continue;
        for (const auto& sig : cat.signatures) {
            if (!sig.enabled) continue;
            auto it = std::find(sig.tags.begin(), sig.tags.end(), tag);
            if (it != sig.tags.end()) {
                result.push_back(&sig);
            }
        }
    }
    return result;
}

std::vector<const Signature*> SignatureDatabase::GetAllEnabledSignatures() const
{
    std::vector<const Signature*> result;
    for (const auto& cat : m_categories) {
        if (!cat.enabled) continue;
        for (const auto& sig : cat.signatures) {
            if (sig.enabled) {
                result.push_back(&sig);
            }
        }
    }
    return result;
}

std::vector<std::string> SignatureDatabase::GetCategoryNames() const
{
    std::vector<std::string> result;
    for (const auto& cat : m_categories) {
        result.push_back(cat.name);
    }
    return result;
}

const SignatureCategory* SignatureDatabase::GetCategory(const std::string& categoryName) const
{
    for (const auto& cat : m_categories) {
        if (cat.name == categoryName) {
            return &cat;
        }
    }
    return nullptr;
}

int SignatureDatabase::GetTotalSignatureCount() const
{
    int count = 0;
    for (const auto& cat : m_categories) {
        count += static_cast<int>(cat.signatures.size());
    }
    return count;
}

int SignatureDatabase::GetEnabledSignatureCount() const
{
    int count = 0;
    for (const auto& cat : m_categories) {
        if (!cat.enabled) continue;
        for (const auto& sig : cat.signatures) {
            if (sig.enabled) count++;
        }
    }
    return count;
}

int SignatureDatabase::GetSignatureCountByType(SignatureType type) const
{
    int count = 0;
    for (const auto& cat : m_categories) {
        for (const auto& sig : cat.signatures) {
            if (sig.type == type) count++;
        }
    }
    return count;
}

bool SignatureDatabase::CompileHexPattern(const std::string& patternStr,
                                           std::vector<BYTE>& outBytes,
                                           std::vector<bool>& outWildcards)
{
    outBytes.clear();
    outWildcards.clear();
    
    std::string cleaned;
    for (char c : patternStr) {
        if (!std::isspace(c)) cleaned += c;
    }
    
    for (size_t i = 0; i < cleaned.size(); i += 2) {
        if (i + 1 >= cleaned.size()) break;
        
        std::string byteStr = cleaned.substr(i, 2);
        
        if (byteStr == "??" || byteStr == "**") {
            outBytes.push_back(0x00);
            outWildcards.push_back(true);
        } else {
            try {
                int value = std::stoi(byteStr, nullptr, 16);
                outBytes.push_back(static_cast<BYTE>(value));
                outWildcards.push_back(false);
            } catch (...) {
                return false;
            }
        }
    }
    
    return !outBytes.empty();
}

std::wstring SignatureDatabase::ConvertToLegacyFormat(const std::vector<const Signature*>& signatures)
{
    std::wstring result;
    
    for (const auto* sig : signatures) {
        if (sig->type != SignatureType::MEMORY_PATTERN) continue;
        
        if (!result.empty()) result += L";";
        
        std::wstring name(sig->name.begin(), sig->name.end());
        std::wstring pattern(sig->pattern.begin(), sig->pattern.end());
        
        result += name + L"=" + pattern;
    }
    
    return result;
}

void SignatureDatabase::Clear()
{
    m_categories.clear();
    m_signatureIndex.clear();
    m_databaseVersion = 0;
    m_lastUpdate.clear();
}

void SignatureDatabase::RebuildIndex()
{
    m_signatureIndex.clear();
    for (auto& cat : m_categories) {
        for (auto& sig : cat.signatures) {
            m_signatureIndex[sig.id] = &sig;
        }
    }
}

std::string SignatureDatabase::SignatureTypeToString(SignatureType type) const
{
    switch (type) {
        case SignatureType::MODULE_NAME: return "MODULE_NAME";
        case SignatureType::FILE_SIGNATURE: return "FILE_SIGNATURE";
        case SignatureType::MEMORY_PATTERN: return "MEMORY_PATTERN";
        case SignatureType::REGISTRY_KEY: return "REGISTRY_KEY";
        case SignatureType::WINDOW_CLASS: return "WINDOW_CLASS";
        case SignatureType::DRIVER_DEVICE: return "DRIVER_DEVICE";
        case SignatureType::NETWORK_ARTIFACT: return "NETWORK_ARTIFACT";
        case SignatureType::PROCESS_NAME: return "PROCESS_NAME";
        default: return "UNKNOWN";
    }
}

SignatureType SignatureDatabase::StringToSignatureType(const std::string& str) const
{
    if (str == "MODULE_NAME") return SignatureType::MODULE_NAME;
    if (str == "FILE_SIGNATURE") return SignatureType::FILE_SIGNATURE;
    if (str == "MEMORY_PATTERN") return SignatureType::MEMORY_PATTERN;
    if (str == "REGISTRY_KEY") return SignatureType::REGISTRY_KEY;
    if (str == "WINDOW_CLASS") return SignatureType::WINDOW_CLASS;
    if (str == "DRIVER_DEVICE") return SignatureType::DRIVER_DEVICE;
    if (str == "NETWORK_ARTIFACT") return SignatureType::NETWORK_ARTIFACT;
    if (str == "PROCESS_NAME") return SignatureType::PROCESS_NAME;
    return SignatureType::MODULE_NAME;
}

std::string SignatureDatabase::SeverityToString(SignatureSeverity sev) const
{
    switch (sev) {
        case SignatureSeverity::LOW: return "LOW";
        case SignatureSeverity::MEDIUM: return "MEDIUM";
        case SignatureSeverity::HIGH: return "HIGH";
        case SignatureSeverity::CRITICAL: return "CRITICAL";
        default: return "MEDIUM";
    }
}

SignatureSeverity SignatureDatabase::StringToSeverity(const std::string& str) const
{
    if (str == "LOW") return SignatureSeverity::LOW;
    if (str == "MEDIUM") return SignatureSeverity::MEDIUM;
    if (str == "HIGH") return SignatureSeverity::HIGH;
    if (str == "CRITICAL") return SignatureSeverity::CRITICAL;
    return SignatureSeverity::MEDIUM;
}
