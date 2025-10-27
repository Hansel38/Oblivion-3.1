#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct MemorySignatureFinding {
    std::wstring moduleName; // optional module path
    void* address = nullptr;
    std::wstring patternName;
    int indicators = 0;
};

struct MemSigPattern {
    std::string name;
    std::vector<unsigned char> bytes; // value bytes
    std::vector<unsigned char> mask;  // mask per byte: 0xFF exact, 0xF0 high nibble, 0x0F low nibble, 0x00 wildcard
    int weight = 1;                    // severity weight per match
};

class MemorySignatureScanner
{
public:
    void SetThreshold(int t) { m_threshold = t; }
    void SetPatterns(const std::vector<MemSigPattern>& pats) { m_patterns = pats; }
    void SetModuleWhitelistPrefixes(const std::vector<std::wstring>& prefixes) { m_modulePrefixes = prefixes; }
    void SetImagesOnly(bool v) { m_imagesOnly = v; }

    bool RunOnceScan(MemorySignatureFinding& outFinding);

private:
    bool ScanRegion(BYTE* base, SIZE_T size, const std::wstring* regionModule, MemorySignatureFinding& outFinding, int& score);
    bool MatchAt(BYTE* p, SIZE_T size, const MemSigPattern& pat) const;

    int m_threshold = 1;
    std::vector<MemSigPattern> m_patterns;
    std::vector<std::wstring> m_modulePrefixes; // if non-empty, restrict scanning to modules with these prefixes
    bool m_imagesOnly = true;
};
