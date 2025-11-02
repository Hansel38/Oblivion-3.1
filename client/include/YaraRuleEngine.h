#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <memory>

// ===== PRIORITY 4.2.2: YARA-like Rule Engine =====

// Forward declarations
class YaraCondition;
class YaraRule;

// Pattern types for YARA rules
enum class YaraPatternType {
    HEX,            // Hex byte pattern (e.g., "AA BB ?? CC DD")
    TEXT,           // Text/string pattern
    REGEX,          // Regular expression pattern
    WIDE_STRING     // Wide character string
};

// Pattern modifiers
struct YaraPatternModifiers {
    bool nocase;        // Case-insensitive matching
    bool wide;          // Match wide strings (Unicode)
    bool ascii;         // Match ASCII strings
    bool fullword;      // Match only full words
    
    YaraPatternModifiers() 
        : nocase(false), wide(false), ascii(true), fullword(false) {}
};

// Single pattern/string definition
struct YaraPattern {
    std::string id;                         // Pattern identifier (e.g., "$a", "$hex1")
    YaraPatternType type;                   // Pattern type
    std::string pattern;                    // Raw pattern string
    YaraPatternModifiers modifiers;         // Pattern modifiers
    
    // Compiled pattern data
    std::vector<BYTE> compiledBytes;        // For hex patterns
    std::vector<bool> wildcardMask;         // Wildcard positions
    
    YaraPattern() : type(YaraPatternType::TEXT) {}
};

// Condition node types
enum class YaraConditionType {
    PATTERN_MATCH,      // Pattern must be found (e.g., "$a")
    PATTERN_COUNT,      // Pattern count condition (e.g., "#a > 5")
    PATTERN_AT,         // Pattern at specific offset (e.g., "$a at 0x1000")
    PATTERN_IN_RANGE,   // Pattern in range (e.g., "$a in (0..1024)")
    ALL_OF_THEM,        // All patterns must match
    ANY_OF_THEM,        // Any pattern must match
    N_OF_THEM,          // N patterns must match (e.g., "2 of them")
    AND,                // Logical AND
    OR,                 // Logical OR
    NOT,                // Logical NOT
    FILESIZE,           // File/memory size condition
    ALWAYS_TRUE,        // Always true
    ALWAYS_FALSE        // Always false
};

// Condition node in the expression tree
class YaraCondition {
public:
    YaraConditionType type;
    std::string patternId;                  // For PATTERN_* types
    int count;                              // For N_OF_THEM, PATTERN_COUNT
    size_t offset;                          // For PATTERN_AT
    size_t rangeStart;                      // For PATTERN_IN_RANGE
    size_t rangeEnd;                        // For PATTERN_IN_RANGE
    size_t filesize;                        // For FILESIZE
    
    std::shared_ptr<YaraCondition> left;    // For binary operators (AND/OR)
    std::shared_ptr<YaraCondition> right;   // For binary operators (AND/OR)
    std::shared_ptr<YaraCondition> child;   // For unary operators (NOT)
    
    YaraCondition(YaraConditionType t = YaraConditionType::ALWAYS_TRUE) 
        : type(t), count(0), offset(0), rangeStart(0), rangeEnd(0), filesize(0) {}
};

// Match result for a single pattern
struct YaraPatternMatch {
    std::string patternId;
    std::vector<size_t> offsets;            // All offsets where pattern was found
    int matchCount;
    
    YaraPatternMatch() : matchCount(0) {}
};

// Complete rule with metadata, patterns, and condition
class YaraRule {
public:
    YaraRule();
    ~YaraRule();
    
    // Rule metadata
    std::string name;
    std::map<std::string, std::string> metadata;
    std::vector<std::string> tags;
    
    // Patterns (strings section)
    std::vector<YaraPattern> patterns;
    
    // Condition expression
    std::shared_ptr<YaraCondition> condition;
    
    // Add pattern to rule
    void AddPattern(const YaraPattern& pattern);
    
    // Set condition
    void SetCondition(std::shared_ptr<YaraCondition> cond);
    
    // Compile all patterns
    bool Compile();
    
    // Check if rule is compiled
    bool IsCompiled() const { return m_compiled; }
    
private:
    bool m_compiled;
};

// YARA rule engine - loads and evaluates rules
class YaraRuleEngine {
public:
    YaraRuleEngine();
    ~YaraRuleEngine();
    
    // Load rules from YARA rule file
    bool LoadRulesFromFile(const std::wstring& filePath);
    
    // Load rules from string
    bool LoadRulesFromString(const std::string& rulesContent);
    
    // Add single rule programmatically
    bool AddRule(const YaraRule& rule);
    
    // Scan memory region with all loaded rules
    std::vector<std::string> ScanMemory(const BYTE* data, size_t size);
    
    // Scan file with all loaded rules
    std::vector<std::string> ScanFile(const std::wstring& filePath);
    
    // Scan process memory
    std::vector<std::string> ScanProcess(DWORD pid);
    
    // Get number of loaded rules
    int GetRuleCount() const { return static_cast<int>(m_rules.size()); }
    
    // Clear all rules
    void ClearRules();
    
    // Enable/disable specific rule
    bool EnableRule(const std::string& ruleName, bool enable);
    
    // Statistics
    struct ScanStats {
        int rulesEvaluated;
        int rulesMatched;
        ULONGLONG scanTimeMs;
        size_t bytesScanned;
        
        ScanStats() : rulesEvaluated(0), rulesMatched(0), scanTimeMs(0), bytesScanned(0) {}
    };
    
    ScanStats GetLastScanStats() const { return m_lastStats; }
    
private:
    std::vector<YaraRule> m_rules;
    std::map<std::string, bool> m_ruleEnabled;  // Rule name -> enabled flag
    ScanStats m_lastStats;
    
    // Rule parsing helpers
    bool ParseRule(const std::string& ruleText, YaraRule& outRule);
    bool ParsePatterns(const std::string& patternsSection, YaraRule& rule);
    bool ParseCondition(const std::string& conditionSection, std::shared_ptr<YaraCondition>& outCondition);
    
    // Pattern matching
    bool MatchPattern(const YaraPattern& pattern, const BYTE* data, size_t size, YaraPatternMatch& result);
    bool MatchHexPattern(const YaraPattern& pattern, const BYTE* data, size_t size, YaraPatternMatch& result);
    bool MatchTextPattern(const YaraPattern& pattern, const BYTE* data, size_t size, YaraPatternMatch& result);
    
    // Condition evaluation
    bool EvaluateCondition(const YaraCondition& cond, const std::map<std::string, YaraPatternMatch>& matches, size_t dataSize);
    
    // Boyer-Moore pattern search
    std::vector<size_t> BoyerMooreSearch(const BYTE* text, size_t textLen, const BYTE* pattern, size_t patternLen, const std::vector<bool>& wildcards);
    
    // Helper: compile hex pattern string to bytes
public:
    static bool CompileHexPattern(const std::string& hexStr, std::vector<BYTE>& outBytes, std::vector<bool>& outWildcards);
private:
};

// Helper functions for building conditions programmatically
namespace YaraConditionBuilder {
    std::shared_ptr<YaraCondition> PatternMatch(const std::string& patternId);
    std::shared_ptr<YaraCondition> PatternCount(const std::string& patternId, int count);
    std::shared_ptr<YaraCondition> AllOfThem();
    std::shared_ptr<YaraCondition> AnyOfThem();
    std::shared_ptr<YaraCondition> NOfThem(int n);
    std::shared_ptr<YaraCondition> And(std::shared_ptr<YaraCondition> left, std::shared_ptr<YaraCondition> right);
    std::shared_ptr<YaraCondition> Or(std::shared_ptr<YaraCondition> left, std::shared_ptr<YaraCondition> right);
    std::shared_ptr<YaraCondition> Not(std::shared_ptr<YaraCondition> child);
}

// Global YARA engine instance
extern YaraRuleEngine* g_pYaraEngine;
