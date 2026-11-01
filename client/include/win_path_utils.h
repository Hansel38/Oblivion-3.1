#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace Oblivion {
namespace WinPath {

// Resolve a module path without silently truncating it at MAX_PATH.
// An empty result means the path could not be resolved completely.
inline std::wstring GetModulePath(HMODULE module) {
    constexpr size_t kInitialPathCapacity = MAX_PATH;
    constexpr size_t kMaxPathCapacity = 32768;

    std::vector<wchar_t> pathBuffer(kInitialPathCapacity, L'\0');
    while (pathBuffer.size() <= kMaxPathCapacity) {
        const DWORD pathLength = GetModuleFileNameW(
            module, pathBuffer.data(), static_cast<DWORD>(pathBuffer.size()));
        if (pathLength == 0) {
            return L"";
        }

        // Windows returns the buffer length when the result may be truncated.
        if (static_cast<size_t>(pathLength) < pathBuffer.size()) {
            return std::wstring(pathBuffer.data(), pathLength);
        }

        if (pathBuffer.size() == kMaxPathCapacity) {
            break;
        }

        const size_t doubledCapacity = pathBuffer.size() * 2;
        const size_t nextCapacity =
            doubledCapacity > kMaxPathCapacity ? kMaxPathCapacity : doubledCapacity;
        pathBuffer.resize(nextCapacity, L'\0');
    }

    return L"";
}


 
// Resolve a process image path without assuming that MAX_PATH is sufficient.
// QueryFullProcessImageNameW reports ERROR_INSUFFICIENT_BUFFER when the
// provided buffer cannot hold the complete path.
inline std::wstring GetProcessImagePath(HANDLE process) {
    if (process == nullptr || process == INVALID_HANDLE_VALUE) {
        return L"";
    }

    constexpr size_t kInitialPathCapacity = MAX_PATH;
    constexpr size_t kMaxPathCapacity = 32768;
    std::vector<wchar_t> pathBuffer(kInitialPathCapacity, L'\0');

    while (pathBuffer.size() <= kMaxPathCapacity) {
        DWORD pathLength = static_cast<DWORD>(pathBuffer.size());
        if (QueryFullProcessImageNameW(
                process, 0, pathBuffer.data(), &pathLength)) {
            if (pathLength == 0 || static_cast<size_t>(pathLength) > pathBuffer.size()) {
                return L"";
            }
            return std::wstring(pathBuffer.data(), pathLength);
        }

        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
            pathBuffer.size() == kMaxPathCapacity) {
            return L"";
        }

        const size_t doubledCapacity = pathBuffer.size() * 2;
        const size_t nextCapacity =
            doubledCapacity > kMaxPathCapacity ? kMaxPathCapacity : doubledCapacity;
        pathBuffer.resize(nextCapacity, L'\0');
    }

    return L"";
}

} // namespace WinPath
} // namespace Oblivion
