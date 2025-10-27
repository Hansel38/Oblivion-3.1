#pragma once
#include <windows.h>
#include <string>

// Simple JSON builder for detection reports
class JsonBuilder {
public:
    // New parameter 'hwid' will be emitted as its own JSON field
    static std::string BuildDetectionReport(DWORD pid, const std::wstring& processName, const std::wstring& reason, const std::string& subtype = "generic", int protocolVersion = 1, const std::string& hwid = "", const std::string& clientVersion = "", int indicators = 0);
private:
    static std::string WStringToString(const std::wstring& wstr);
    static std::string EscapeJson(const std::string& str);
};
