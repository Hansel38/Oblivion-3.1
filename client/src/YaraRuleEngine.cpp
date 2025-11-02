#include "../pch.h"
#include "YaraRuleEngine.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

// Global instance
YaraRuleEngine* g_pYaraEngine = nullptr;

// ===== YaraRule Implementation =====

YaraRule::YaraRule() : m_compiled(false)
{
}

YaraRule::~YaraRule()
{
}

void YaraRule::AddPattern(const YaraPattern& pattern)
{
    patterns.push_back(pattern);
    m_compiled = false;
}

void YaraRule::SetCondition(std::shared_ptr<YaraCondition> cond)
{
    condition = cond;
}

bool YaraRule::Compile()
{
    for (auto& pattern : patterns) {
        if (pattern.type == YaraPatternType::HEX) {
            if (!YaraRuleEngine::CompileHexPattern(pattern.pattern, pattern.compiledBytes, pattern.wildcardMask)) {
                return false;
            }
        }
    }
    m_compiled = true;
    return true;
}

// ===== YaraRuleEngine Implementation =====

YaraRuleEngine::YaraRuleEngine()
{
}

YaraRuleEngine::~YaraRuleEngine()
{
    ClearRules();
}

bool YaraRuleEngine::LoadRulesFromFile(const std::wstring& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return false;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    file.close();
    
    return LoadRulesFromString(content);
}

bool YaraRuleEngine::LoadRulesFromString(const std::string& rulesContent)
{
    // Simple YARA-like parser
    // Format:
    // rule RuleName : tag1 tag2 {
    //   meta:
    //     key = "value"
    //   strings:
    //     $a = "text"
    //     $b = { AA BB ?? CC }
    //   condition:
    //     $a or $b
    // }
    
    size_t pos = 0;
    while (true) {
        // Find "rule" keyword
        pos = rulesContent.find("rule ", pos);
        if (pos == std::string::npos) break;
        
        // Find opening brace
        size_t braceStart = rulesContent.find("{", pos);
        if (braceStart == std::string::npos) break;
        
        // Find matching closing brace
        int braceCount = 1;
        size_t braceEnd = braceStart + 1;
        while (braceEnd < rulesContent.size() && braceCount > 0) {
            if (rulesContent[braceEnd] == '{') braceCount++;
            else if (rulesContent[braceEnd] == '}') braceCount--;
            braceEnd++;
        }
        
        if (braceCount != 0) break;
        
        std::string ruleText = rulesContent.substr(pos, braceEnd - pos);
        
        YaraRule rule;
        if (ParseRule(ruleText, rule)) {
            if (rule.Compile()) {
                AddRule(rule);
            }
        }
        
        pos = braceEnd;
    }
    
    return m_rules.size() > 0;
}

bool YaraRuleEngine::AddRule(const YaraRule& rule)
{
    if (!rule.IsCompiled()) {
        return false;
    }
    
    m_rules.push_back(rule);
    m_ruleEnabled[rule.name] = true;
    return true;
}

std::vector<std::string> YaraRuleEngine::ScanMemory(const BYTE* data, size_t size)
{
    std::vector<std::string> matches;
    
    ULONGLONG startTime = GetTickCount64();
    m_lastStats = ScanStats();
    m_lastStats.bytesScanned = size;
    
    for (const auto& rule : m_rules) {
        // Check if rule is enabled
        auto it = m_ruleEnabled.find(rule.name);
        if (it != m_ruleEnabled.end() && !it->second) {
            continue;
        }
        
        m_lastStats.rulesEvaluated++;
        
        // Match all patterns
        std::map<std::string, YaraPatternMatch> patternMatches;
        
        for (const auto& pattern : rule.patterns) {
            YaraPatternMatch match;
            if (MatchPattern(pattern, data, size, match)) {
                patternMatches[pattern.id] = match;
            }
        }
        
        // Evaluate condition
        if (rule.condition && EvaluateCondition(*rule.condition, patternMatches, size)) {
            matches.push_back(rule.name);
            m_lastStats.rulesMatched++;
        }
    }
    
    m_lastStats.scanTimeMs = GetTickCount64() - startTime;
    return matches;
}

std::vector<std::string> YaraRuleEngine::ScanFile(const std::wstring& filePath)
{
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return std::vector<std::string>();
    }
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart > 100 * 1024 * 1024) {
        CloseHandle(hFile);
        return std::vector<std::string>();
    }
    
    std::vector<BYTE> buffer(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    
    if (!ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr)) {
        CloseHandle(hFile);
        return std::vector<std::string>();
    }
    
    CloseHandle(hFile);
    
    return ScanMemory(buffer.data(), bytesRead);
}

std::vector<std::string> YaraRuleEngine::ScanProcess(DWORD pid)
{
    std::vector<std::string> allMatches;
    
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        return allMatches;
    }
    
    MEMORY_BASIC_INFORMATION mbi = {};
    BYTE* address = nullptr;
    
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 && (mbi.Protect & PAGE_NOACCESS) == 0) {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;
            
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead) && bytesRead > 0) {
                auto matches = ScanMemory(buffer.data(), bytesRead);
                allMatches.insert(allMatches.end(), matches.begin(), matches.end());
            }
        }
        
        address = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    
    CloseHandle(hProcess);
    
    // Remove duplicates
    std::sort(allMatches.begin(), allMatches.end());
    allMatches.erase(std::unique(allMatches.begin(), allMatches.end()), allMatches.end());
    
    return allMatches;
}

void YaraRuleEngine::ClearRules()
{
    m_rules.clear();
    m_ruleEnabled.clear();
}

bool YaraRuleEngine::EnableRule(const std::string& ruleName, bool enable)
{
    auto it = m_ruleEnabled.find(ruleName);
    if (it != m_ruleEnabled.end()) {
        it->second = enable;
        return true;
    }
    return false;
}

// ===== Pattern Matching =====

bool YaraRuleEngine::MatchPattern(const YaraPattern& pattern, const BYTE* data, size_t size, YaraPatternMatch& result)
{
    result.patternId = pattern.id;
    result.matchCount = 0;
    result.offsets.clear();
    
    switch (pattern.type) {
        case YaraPatternType::HEX:
            return MatchHexPattern(pattern, data, size, result);
        case YaraPatternType::TEXT:
        case YaraPatternType::WIDE_STRING:
            return MatchTextPattern(pattern, data, size, result);
        default:
            return false;
    }
}

bool YaraRuleEngine::MatchHexPattern(const YaraPattern& pattern, const BYTE* data, size_t size, YaraPatternMatch& result)
{
    if (pattern.compiledBytes.empty()) {
        return false;
    }
    
    result.offsets = BoyerMooreSearch(data, size, pattern.compiledBytes.data(), pattern.compiledBytes.size(), pattern.wildcardMask);
    result.matchCount = static_cast<int>(result.offsets.size());
    
    return result.matchCount > 0;
}

bool YaraRuleEngine::MatchTextPattern(const YaraPattern& pattern, const BYTE* data, size_t size, YaraPatternMatch& result)
{
    std::vector<BYTE> searchBytes(pattern.pattern.begin(), pattern.pattern.end());
    std::vector<bool> noWildcards(searchBytes.size(), false);
    
    if (pattern.modifiers.nocase) {
        // Convert to lowercase for case-insensitive search
        for (auto& b : searchBytes) {
            if (b >= 'A' && b <= 'Z') {
                b = b - 'A' + 'a';
            }
        }
        
        // Also need to search in lowercase data
        std::vector<BYTE> lowerData(size);
        for (size_t i = 0; i < size; ++i) {
            BYTE b = data[i];
            if (b >= 'A' && b <= 'Z') {
                lowerData[i] = b - 'A' + 'a';
            } else {
                lowerData[i] = b;
            }
        }
        
        result.offsets = BoyerMooreSearch(lowerData.data(), size, searchBytes.data(), searchBytes.size(), noWildcards);
    } else {
        result.offsets = BoyerMooreSearch(data, size, searchBytes.data(), searchBytes.size(), noWildcards);
    }
    
    result.matchCount = static_cast<int>(result.offsets.size());
    return result.matchCount > 0;
}

// ===== Condition Evaluation =====

bool YaraRuleEngine::EvaluateCondition(const YaraCondition& cond, const std::map<std::string, YaraPatternMatch>& matches, size_t dataSize)
{
    switch (cond.type) {
        case YaraConditionType::PATTERN_MATCH: {
            auto it = matches.find(cond.patternId);
            return it != matches.end() && it->second.matchCount > 0;
        }
        
        case YaraConditionType::PATTERN_COUNT: {
            auto it = matches.find(cond.patternId);
            if (it == matches.end()) return false;
            return it->second.matchCount >= cond.count;
        }
        
        case YaraConditionType::ALL_OF_THEM: {
            for (const auto& pair : matches) {
                if (pair.second.matchCount == 0) return false;
            }
            return !matches.empty();
        }
        
        case YaraConditionType::ANY_OF_THEM: {
            for (const auto& pair : matches) {
                if (pair.second.matchCount > 0) return true;
            }
            return false;
        }
        
        case YaraConditionType::N_OF_THEM: {
            int count = 0;
            for (const auto& pair : matches) {
                if (pair.second.matchCount > 0) count++;
            }
            return count >= cond.count;
        }
        
        case YaraConditionType::AND: {
            if (!cond.left || !cond.right) return false;
            return EvaluateCondition(*cond.left, matches, dataSize) && EvaluateCondition(*cond.right, matches, dataSize);
        }
        
        case YaraConditionType::OR: {
            if (!cond.left || !cond.right) return false;
            return EvaluateCondition(*cond.left, matches, dataSize) || EvaluateCondition(*cond.right, matches, dataSize);
        }
        
        case YaraConditionType::NOT: {
            if (!cond.child) return false;
            return !EvaluateCondition(*cond.child, matches, dataSize);
        }
        
        case YaraConditionType::ALWAYS_TRUE:
            return true;
            
        case YaraConditionType::ALWAYS_FALSE:
            return false;
            
        default:
            return false;
    }
}

// ===== Boyer-Moore Search =====

std::vector<size_t> YaraRuleEngine::BoyerMooreSearch(const BYTE* text, size_t textLen, const BYTE* pattern, size_t patternLen, const std::vector<bool>& wildcards)
{
    std::vector<size_t> results;
    
    if (patternLen == 0 || patternLen > textLen) {
        return results;
    }
    
    // Build bad character table
    int badChar[256];
    for (int i = 0; i < 256; ++i) {
        badChar[i] = static_cast<int>(patternLen);
    }
    
    for (size_t i = 0; i < patternLen - 1; ++i) {
        if (!wildcards[i]) {
            badChar[pattern[i]] = static_cast<int>(patternLen - 1 - i);
        }
    }
    
    // Search
    size_t shift = 0;
    while (shift <= textLen - patternLen) {
        int j = static_cast<int>(patternLen) - 1;
        
        while (j >= 0 && (wildcards[j] || pattern[j] == text[shift + j])) {
            j--;
        }
        
        if (j < 0) {
            results.push_back(shift);
            shift += patternLen;
        } else {
            shift += badChar[text[shift + j]];
        }
    }
    
    return results;
}

// ===== Helper Functions =====

bool YaraRuleEngine::CompileHexPattern(const std::string& hexStr, std::vector<BYTE>& outBytes, std::vector<bool>& outWildcards)
{
    outBytes.clear();
    outWildcards.clear();
    
    std::string cleaned;
    for (char c : hexStr) {
        if (!std::isspace(c) && c != '{' && c != '}') {
            cleaned += c;
        }
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

bool YaraRuleEngine::ParseRule(const std::string& ruleText, YaraRule& outRule)
{
    // Extract rule name
    size_t rulePos = ruleText.find("rule ");
    if (rulePos == std::string::npos) return false;
    
    size_t nameStart = rulePos + 5;
    size_t nameEnd = ruleText.find_first_of(" \t\n\r:{", nameStart);
    if (nameEnd == std::string::npos) return false;
    
    outRule.name = ruleText.substr(nameStart, nameEnd - nameStart);
    
    // Find strings section
    size_t stringsPos = ruleText.find("strings:");
    size_t conditionPos = ruleText.find("condition:");
    
    if (stringsPos != std::string::npos && conditionPos != std::string::npos) {
        std::string stringsSection = ruleText.substr(stringsPos + 8, conditionPos - stringsPos - 8);
        ParsePatterns(stringsSection, outRule);
    }
    
    if (conditionPos != std::string::npos) {
        size_t condEnd = ruleText.find("}", conditionPos);
        std::string conditionSection = ruleText.substr(conditionPos + 10, condEnd - conditionPos - 10);
        ParseCondition(conditionSection, outRule.condition);
    }
    
    return true;
}

bool YaraRuleEngine::ParsePatterns(const std::string& patternsSection, YaraRule& rule)
{
    // Simple pattern parser
    // Format: $id = "text" or $id = { hex }
    
    size_t pos = 0;
    while (true) {
        pos = patternsSection.find("$", pos);
        if (pos == std::string::npos) break;
        
        size_t idEnd = patternsSection.find_first_of(" =\t\n\r", pos);
        if (idEnd == std::string::npos) break;
        
        std::string id = patternsSection.substr(pos, idEnd - pos);
        
        size_t eqPos = patternsSection.find("=", idEnd);
        if (eqPos == std::string::npos) break;
        
        YaraPattern pattern;
        pattern.id = id;
        
        // Check for hex pattern
        size_t hexStart = patternsSection.find("{", eqPos);
        size_t textStart = patternsSection.find("\"", eqPos);
        
        if (hexStart != std::string::npos && (textStart == std::string::npos || hexStart < textStart)) {
            size_t hexEnd = patternsSection.find("}", hexStart);
            if (hexEnd != std::string::npos) {
                pattern.type = YaraPatternType::HEX;
                pattern.pattern = patternsSection.substr(hexStart + 1, hexEnd - hexStart - 1);
            }
        } else if (textStart != std::string::npos) {
            size_t textEnd = patternsSection.find("\"", textStart + 1);
            if (textEnd != std::string::npos) {
                pattern.type = YaraPatternType::TEXT;
                pattern.pattern = patternsSection.substr(textStart + 1, textEnd - textStart - 1);
            }
        }
        
        rule.AddPattern(pattern);
        pos = eqPos + 1;
    }
    
    return true;
}

bool YaraRuleEngine::ParseCondition(const std::string& conditionSection, std::shared_ptr<YaraCondition>& outCondition)
{
    // Simple condition parser - supports basic constructs
    std::string trimmed = conditionSection;
    
    // Remove whitespace
    trimmed.erase(std::remove_if(trimmed.begin(), trimmed.end(), ::isspace), trimmed.end());
    
    // Check for simple patterns
    if (trimmed.find("all") == 0 && trimmed.find("them") != std::string::npos) {
        outCondition = std::make_shared<YaraCondition>(YaraConditionType::ALL_OF_THEM);
        return true;
    }
    
    if (trimmed.find("any") == 0 && trimmed.find("them") != std::string::npos) {
        outCondition = std::make_shared<YaraCondition>(YaraConditionType::ANY_OF_THEM);
        return true;
    }
    
    // Check for pattern references
    if (trimmed.find("$") == 0) {
        outCondition = std::make_shared<YaraCondition>(YaraConditionType::PATTERN_MATCH);
        outCondition->patternId = trimmed;
        return true;
    }
    
    // Default: any of them
    outCondition = std::make_shared<YaraCondition>(YaraConditionType::ANY_OF_THEM);
    return true;
}

// ===== Condition Builder Helpers =====

namespace YaraConditionBuilder {
    std::shared_ptr<YaraCondition> PatternMatch(const std::string& patternId) {
        auto cond = std::make_shared<YaraCondition>(YaraConditionType::PATTERN_MATCH);
        cond->patternId = patternId;
        return cond;
    }
    
    std::shared_ptr<YaraCondition> PatternCount(const std::string& patternId, int count) {
        auto cond = std::make_shared<YaraCondition>(YaraConditionType::PATTERN_COUNT);
        cond->patternId = patternId;
        cond->count = count;
        return cond;
    }
    
    std::shared_ptr<YaraCondition> AllOfThem() {
        return std::make_shared<YaraCondition>(YaraConditionType::ALL_OF_THEM);
    }
    
    std::shared_ptr<YaraCondition> AnyOfThem() {
        return std::make_shared<YaraCondition>(YaraConditionType::ANY_OF_THEM);
    }
    
    std::shared_ptr<YaraCondition> NOfThem(int n) {
        auto cond = std::make_shared<YaraCondition>(YaraConditionType::N_OF_THEM);
        cond->count = n;
        return cond;
    }
    
    std::shared_ptr<YaraCondition> And(std::shared_ptr<YaraCondition> left, std::shared_ptr<YaraCondition> right) {
        auto cond = std::make_shared<YaraCondition>(YaraConditionType::AND);
        cond->left = left;
        cond->right = right;
        return cond;
    }
    
    std::shared_ptr<YaraCondition> Or(std::shared_ptr<YaraCondition> left, std::shared_ptr<YaraCondition> right) {
        auto cond = std::make_shared<YaraCondition>(YaraConditionType::OR);
        cond->left = left;
        cond->right = right;
        return cond;
    }
    
    std::shared_ptr<YaraCondition> Not(std::shared_ptr<YaraCondition> child) {
        auto cond = std::make_shared<YaraCondition>(YaraConditionType::NOT);
        cond->child = child;
        return cond;
    }
}
