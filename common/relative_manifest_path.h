#pragma once

#include <string>
#include <cwctype>

namespace Oblivion {
namespace Security {

// Manifest entries are relative to the game executable directory. Accept
// ordinary nested paths, but reject traversal, rooted paths, drive/ADS syntax,
// empty components, and Windows device names before any filesystem operation.
inline bool IsSafeRelativeManifestPath(const std::wstring& path) {
    if (path.empty() || path.size() > 1024 ||
        path.front() == L'\\' || path.front() == L'/' ||
        path.back() == L'\\' || path.back() == L'/' ||
        path.find(L':') != std::wstring::npos) {
        return false;
    }

    auto validComponent = [](const std::wstring& component) {
        if (component.empty() || component == L"." || component == L".." ||
            component.back() == L'.' || component.back() == L' ') {
            return false;
        }
        for (wchar_t ch : component) {
            if (ch < 0x20 || ch == 0x7f ||
                ch == L'<' || ch == L'>' || ch == L'"' ||
                ch == L'|' || ch == L'?' || ch == L'*' || ch == L':') {
                return false;
            }
        }

        std::wstring deviceBase;
        const std::size_t dot = component.find(L'.');
        deviceBase = component.substr(0, dot);
        for (wchar_t& ch : deviceBase) {
            ch = static_cast<wchar_t>(std::towupper(ch));
        }
        if (deviceBase == L"CON" || deviceBase == L"PRN" ||
            deviceBase == L"AUX" || deviceBase == L"NUL" ||
            deviceBase == L"CONIN$" || deviceBase == L"CONOUT$") {
            return false;
        }
        if (deviceBase.size() == 4 &&
            (deviceBase.compare(0, 3, L"COM") == 0 ||
             deviceBase.compare(0, 3, L"LPT") == 0) &&
            deviceBase[3] >= L'1' && deviceBase[3] <= L'9') {
            return false;
        }
        return true;
    };

    std::size_t componentStart = 0;
    for (std::size_t i = 0; i <= path.size(); ++i) {
        if (i == path.size() || path[i] == L'\\' || path[i] == L'/') {
            if (!validComponent(path.substr(componentStart, i - componentStart))) {
                return false;
            }
            componentStart = i + 1;
        }
    }
    return true;
}

} // namespace Security
} // namespace Oblivion
