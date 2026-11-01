#pragma once

#include <cwctype>
#include <string>
#include <vector>

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

    // Preserve the namespace/root prefix while collapsing "." and ".." path
    // components. Without this, "game-dir\\..\\outside.dll" can appear to
    // be inside game-dir to a naive string-prefix comparison.
    std::wstring prefix;
    size_t cursor = 0;
    size_t protectedComponents = 0;
    bool absolute = false;

    if (path.compare(0, 8, L"\\\\?\\unc\\") == 0) {
        prefix = L"\\\\?\\unc\\";
        cursor = 8;
        protectedComponents = 2; // UNC server + share
        absolute = true;
    } else if (path.compare(0, 4, L"\\\\?\\") == 0) {
        prefix = L"\\\\?\\";
        cursor = 4;
        absolute = true;
        if (path.size() >= cursor + 3 &&
            path[cursor + 1] == L':' &&
            path[cursor + 2] == L'\\') {
            prefix.append(path, cursor, 3); // extended drive root: \\?\\c:\\
            cursor += 3;
        } else {
            // For volume/device namespaces, the first component is the root.
            protectedComponents = 1;
        }
    } else if (path.compare(0, 4, L"\\\\.\\") == 0) {
        prefix = L"\\\\.\\";
        cursor = 4;
        protectedComponents = 1;
        absolute = true;
    } else if (path.compare(0, 2, L"\\\\") == 0) {
        prefix = L"\\\\";
        cursor = 2;
        protectedComponents = 2; // UNC server + share
        absolute = true;
    } else if (path.size() >= 3 &&
               path[1] == L':' && path[2] == L'\\') {
        prefix.assign(path, 0, 3); // drive root: c:\\
        cursor = 3;
        absolute = true;
    } else if (!path.empty() && path[0] == L'\\') {
        prefix = L"\\";
        cursor = 1;
        absolute = true;
    }

    std::vector<std::wstring> components;
    while (cursor < path.size()) {
        while (cursor < path.size() && path[cursor] == L'\\') {
            ++cursor;
        }
        if (cursor >= path.size()) {
            break;
        }
        const size_t separator = path.find(L'\\', cursor);
        const size_t componentEnd =
            separator == std::wstring::npos ? path.size() : separator;
        const std::wstring component = path.substr(cursor, componentEnd - cursor);
        cursor = componentEnd;

        if (component.empty() || component == L".") {
            continue;
        }
        if (component == L"..") {
            if (components.size() > protectedComponents &&
                components.back() != L"..") {
                components.pop_back();
            } else if (!absolute) {
                components.push_back(component);
            }
            // Absolute paths cannot walk above their root/share.
            continue;
        }
        components.push_back(component);
    }

    std::wstring normalized = prefix;
    for (const auto& component : components) {
        if (!normalized.empty() && normalized.back() != L'\\') {
            normalized.push_back(L'\\');
        }
        normalized += component;
    }

    // Remove redundant trailing separators except for a drive or root path.
    while (normalized.size() > 3 &&
           !normalized.empty() &&
           normalized.back() == L'\\') {
        normalized.pop_back();
    }
    return normalized;
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


inline bool ShouldWhitelistWindowsSystemProcess(
    bool nameIsKnownSystemProcess,
    bool imagePathResolved,
    bool imageIsInsideWindowsDirectory,
    bool hasTrustedSignature) noexcept {
    return nameIsKnownSystemProcess &&
        imagePathResolved &&
        imageIsInsideWindowsDirectory &&
        hasTrustedSignature;
}

} // namespace Oblivion::PathPolicy
