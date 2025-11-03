#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>

// Don't include windows.h here to avoid macro conflicts
// HMODULE will be available when this header is included after windows.h (via pch.h)
#ifndef _WINDEF_
struct HINSTANCE__;
typedef struct HINSTANCE__ *HMODULE;
#endif

// Logger class for DLL error and event logging
class Logger 
{
public:
    enum class LogLevel 
    {
        LOG_INFO,
        LOG_WARNING,
        LOG_ERROR,
        LOG_CRITICAL
    };

    // Get singleton instance
    static Logger& GetInstance();

    // Initialize logger with DLL path
    void Initialize(HMODULE hModule);

    // Log methods
    void Log(LogLevel level, const std::string& message);
    void Log(LogLevel level, const std::wstring& message);
    void LogInfo(const std::string& message);
    void LogWarning(const std::string& message);
    void LogError(const std::string& message);
    void LogCritical(const std::string& message);

    // Log with function name and line number
    void LogEx(LogLevel level, const char* function, int line, const std::string& message);

    // Cleanup
    void Shutdown();

private:
    Logger();
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    std::string GetTimestamp();
    std::string LogLevelToString(LogLevel level);
    std::string WStringToString(const std::wstring& wstr);

    std::ofstream m_logFile;
    std::mutex m_mutex;
    bool m_initialized;
    std::string m_logFilePath;
};

// Macro untuk logging dengan informasi function dan line number
#define LOG_INFO(msg) Logger::GetInstance().LogInfo(msg)
#define LOG_WARNING(msg) Logger::GetInstance().LogWarning(msg)
#define LOG_ERROR(msg) Logger::GetInstance().LogError(msg)
#define LOG_CRITICAL(msg) Logger::GetInstance().LogCritical(msg)
#define LOG_EX(level, msg) Logger::GetInstance().LogEx(level, __FUNCTION__, __LINE__, msg)

// Macro untuk logging dengan format
#define LOG_ERROR_FMT(fmt, ...) \
    do { \
        char buf[512]; \
        snprintf(buf, sizeof(buf), fmt, __VA_ARGS__); \
        Logger::GetInstance().LogError(buf); \
    } while(0)

#define LOG_INFO_FMT(fmt, ...) \
    do { \
        char buf[512]; \
        snprintf(buf, sizeof(buf), fmt, __VA_ARGS__); \
        Logger::GetInstance().LogInfo(buf); \
    } while(0)

#define LOG_WARNING_FMT(fmt, ...) \
    do { \
        char buf[512]; \
        snprintf(buf, sizeof(buf), fmt, __VA_ARGS__); \
        Logger::GetInstance().LogWarning(buf); \
    } while(0)

#define LOG_CRITICAL_FMT(fmt, ...) \
    do { \
        char buf[512]; \
        snprintf(buf, sizeof(buf), fmt, __VA_ARGS__); \
        Logger::GetInstance().LogCritical(buf); \
    } while(0)
