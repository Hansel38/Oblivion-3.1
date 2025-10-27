#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct IntegrityFinding {
    std::wstring path;
    std::string expectedHex; // optional
    std::string actualHex;   // computed
    int indicators = 0; // 2 if mismatch, 1 if missing expected and path outside install dir, etc.
};

class FileIntegrityChecker {
public:
    void SetItems(const std::vector<std::pair<std::wstring, std::string>>& items) { m_items = items; }
    bool RunOnceScan(IntegrityFinding& out);

    static bool ComputeSHA256File(const std::wstring& path, std::string& outHex);

private:
    std::vector<std::pair<std::wstring, std::string>> m_items; // path, expectedHex
};
