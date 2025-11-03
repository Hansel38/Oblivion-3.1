#include "pch.h"
#include "Logger.h"
#include <windows.h>
#include <codecvt>
#include <locale>

Logger::Logger() : m_initialized(false) {
}

Logger::~Logger() {
    Shutdown();
}

Logger& Logger::GetInstance() {
    static Logger instance;
    return instance;
}

void Logger::Initialize(HMODULE hModule) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        return;
    }

    // Get DLL directory
    wchar_t dllPath[MAX_PATH] = { 0 };
    GetModuleFileNameW(hModule, dllPath, MAX_PATH);
    
    std::wstring pathW(dllPath);
    size_t pos = pathW.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        pathW = pathW.substr(0, pos + 1);
    }
    
    // Create log file path
    pathW += L"oblivion_client.log";
    m_logFilePath = WStringToString(pathW);
    
    // Open log file in append mode
    m_logFile.open(m_logFilePath, std::ios::out | std::ios::app);
    
    if (m_logFile.is_open()) {
        m_initialized = true;
        // Write initialization message
        m_logFile << "\n========================================\n";
        m_logFile << "Logger initialized at " << GetTimestamp() << "\n";
        m_logFile << "DLL Path: " << WStringToString(dllPath) << "\n";
        m_logFile << "========================================\n";
        m_logFile.flush();
    }
}

void Logger::Log(LogLevel level, const std::string& message) {
    if (!m_initialized) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_logFile.is_open()) {
        m_logFile << "[" << GetTimestamp() << "] "
                  << "[" << LogLevelToString(level) << "] "
                  << message << std::endl;
        m_logFile.flush(); // Flush immediately to ensure errors are written
    }
}

void Logger::Log(LogLevel level, const std::wstring& message) {
    Log(level, WStringToString(message));
}

void Logger::LogInfo(const std::string& message) {
    Log(LogLevel::LOG_INFO, message);
}

void Logger::LogWarning(const std::string& message) {
    Log(LogLevel::LOG_WARNING, message);
}

void Logger::LogError(const std::string& message) {
    Log(LogLevel::LOG_ERROR, message);
}

void Logger::LogCritical(const std::string& message) {
    Log(LogLevel::LOG_CRITICAL, message);
}

void Logger::LogEx(LogLevel level, const char* function, int line, const std::string& message) {
    std::ostringstream oss;
    oss << "[" << function << ":" << line << "] " << message;
    Log(level, oss.str());
}

void Logger::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized && m_logFile.is_open()) {
        m_logFile << "[" << GetTimestamp() << "] Logger shutting down\n";
        m_logFile << "========================================\n\n";
        m_logFile.close();
        m_initialized = false;
    }
}

std::string Logger::GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::tm tm_buf;
    localtime_s(&tm_buf, &time);
    
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    
    return oss.str();
}

std::string Logger::LogLevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::LOG_INFO:     return "INFO";
        case LogLevel::LOG_WARNING:  return "WARNING";
        case LogLevel::LOG_ERROR:    return "ERROR";
        case LogLevel::LOG_CRITICAL: return "CRITICAL";
        default:                     return "UNKNOWN";
    }
}

std::string Logger::WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) {
        return std::string();
    }
    
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), 
                                          (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), 
                        &strTo[0], size_needed, NULL, NULL);
    
    return strTo;
}
