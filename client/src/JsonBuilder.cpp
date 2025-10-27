#include "../pch.h"
#include "JsonBuilder.h"
#include <sstream>
#include <iomanip>
#include <ctime>

std::string JsonBuilder::BuildDetectionReport(DWORD pid, const std::wstring& processName, const std::wstring& reason, const std::string& subtype, int protocolVersion, const std::string& hwid, const std::string& clientVersion, int indicators)
{
    time_t now = time(nullptr);
    char timeBuffer[26];
    ctime_s(timeBuffer, sizeof(timeBuffer), &now);
    std::string timestamp(timeBuffer);
    // Remove newline
    if (!timestamp.empty() && timestamp.back() == '\n') {
        timestamp.pop_back();
    }

    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"version\": " << protocolVersion << ",\n";
    oss << "  \"client_version\": \"" << EscapeJson(clientVersion) << "\",\n";
    oss << "  \"type\": \"detection\",\n";
    oss << "  \"subtype\": \"" << EscapeJson(subtype) << "\",\n";
    oss << "  \"pid\": " << pid << ",\n";
    oss << "  \"process\": \"" << EscapeJson(WStringToString(processName)) << "\",\n";
    oss << "  \"reason\": \"" << EscapeJson(WStringToString(reason)) << "\",\n";
    if (indicators > 0) {
        oss << "  \"indicators\": " << indicators << ",\n";
    }
    if (!hwid.empty()) {
        oss << "  \"hwid\": \"" << EscapeJson(hwid) << "\",\n";
    }
    oss << "  \"timestamp\": \"" << EscapeJson(timestamp) << "\"\n";
    oss << "}";

    return oss.str();
}

std::string JsonBuilder::WStringToString(const std::wstring& wstr)
{
    if (wstr.empty()) return std::string();
    
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &result[0], sizeNeeded, nullptr, nullptr);
    
    return result;
}

std::string JsonBuilder::EscapeJson(const std::string& str)
{
    std::ostringstream oss;
    for (unsigned char c : str) {
        switch (c) {
        case '\"': oss << "\\\""; break;
        case '\\': oss << "\\\\"; break;
        case '\b': oss << "\\b"; break;
        case '\f': oss << "\\f"; break;
        case '\n': oss << "\\n"; break;
        case '\r': oss << "\\r"; break;
        case '\t': oss << "\\t"; break;
        default:
            if (c <= 0x1F) {
                oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            } else {
                oss << c;
            }
        }
    }
    return oss.str();
}
