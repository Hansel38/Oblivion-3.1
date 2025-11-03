// Utility: Convert std::wstring to UTF-8 std::string
inline std::string WToUtf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
}
#pragma once
#include <windows.h>
#include <string>

// Forward declaration
struct DetectionResult;

// Simple JSON builder for detection reports
class JsonBuilder {
public:
    // New parameter 'hwid' will be emitted as its own JSON field
    static std::string BuildDetectionReport(DWORD pid, const std::wstring& processName, const std::wstring& reason, const std::string& subtype = "generic", int protocolVersion = 1, const std::string& hwid = "", const std::string& clientVersion = "", int indicators = 0);
    
    // ===== PRIORITY 4.1.5: ML-aware detection report builder =====
    static std::string BuildDetectionReportWithML(const DetectionResult& result, const std::string& subtype, const std::string& hwid, const std::string& clientVersion);
    
private:
    static std::string WStringToString(const std::wstring& wstr);
    static std::string EscapeJson(const std::string& str);
};
