#pragma once

#include <cwctype>
#include <string>

namespace Oblivion::PathPolicy {

// Normalize separators and letter case before applying Windows path-prefix checks.
// This header has no Win32 dependency so its policy can be tested cross-platform.
inline std::wstring NormalizeWindowsPath(std::wstring path) {
    for (wchar_t& ch : path) {
        if (ch == L'/') {
            ch = L'\\';
        } else {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }
    }

    // Keep drive roots such as "c:\\" intact; remove redundant trailing
    // separators elsewhere so directory-boundary checks stay consistent.
    while (path.size() > 3 && !path.empty() && path.back() == L'\\') {
        path.pop_back();
    }
    return path;
}

inline bool IsPathWithinDirectory(
    const std::wstring& candidate,
    const std::wstring& directory) {
    const std::wstring path = NormalizeWindowsPath(candidate);
    const std::wstring root = NormalizeWindowsPath(directory);
    if (path.empty() || root.empty()) {
        return false;
    }
    if (path == root) {
        return true;
    }
    if (path.size() <= root.size() ||
        path.compare(0, root.size(), root) != 0) {
        return false;
    }

    // "C:\\WindowsBackup\\x.dll" is not under "C:\\Windows".
    return root.back() == L'\\' || path[root.size()] == L'\\';
}


// Preserve a legacy unsigned-DLL exemption only when both the filename is
// explicitly allowlisted and the resolved module path stays within the game
// installation. A matching name from a temp or unrelated directory is not
// sufficient evidence of trust.
inline bool CanTrustUnsignedModuleByName(
    bool isAllowlistedName,
    const std::wstring& modulePath,
    const std::wstring& gameDirectory) {
    return isAllowlistedName && IsPathWithinDirectory(modulePath, gameDirectory);
}

} // namespace Oblivion::PathPolicy
