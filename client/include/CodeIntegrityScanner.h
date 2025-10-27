#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "ProcessThreadWatcher.h" // for DetectionResult

class CodeIntegrityScanner {
public:
    CodeIntegrityScanner();
    void SetThreshold(int thr) { m_threshold = thr; }
    void SetWhitelistPrefixes(const std::vector<std::wstring>& prefixes) { m_whitelist = prefixes; }

    // Returns true if any suspicious finding collected into outResult
    bool RunOnceScan(DetectionResult& outResult);

private:
    int m_threshold = 3;
    std::vector<std::wstring> m_whitelist;

    bool IsWhitelistedPath(const std::wstring& path) const;
};
