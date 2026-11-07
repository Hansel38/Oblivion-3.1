#pragma once

#include <string>
#include <cwctype>

namespace Oblivion {
namespace Security {

// Compare a loaded module's file name against one semicolon-delimited
// whitelist entry. The policy intentionally accepts exact file names only:
// paths, wildcards, and substring matches must never grant hook suppression.
inline bool IsExactModuleWhitelistMatch(
    const std::wstring& moduleFileName,
    const std::wstring& configuredEntry) {
    std::size_t first = configuredEntry.find_first_not_of(L" \t");
    if (first == std::wstring::npos || moduleFileName.empty()) {
        return false;
    }

    const std::size_t last = configuredEntry.find_last_not_of(L" \t");
    const std::wstring entry = configuredEntry.substr(first, last - first + 1);
    if (entry.empty() ||
        entry.find_first_of(L"\\/:*?\"<>|") != std::wstring::npos ||
        moduleFileName.find_first_of(L"\\/:") != std::wstring::npos ||
        moduleFileName.size() != entry.size()) {
        return false;
    }

    for (std::size_t i = 0; i < entry.size(); ++i) {
        if (std::towlower(moduleFileName[i]) != std::towlower(entry[i])) {
            return false;
        }
    }
    return true;
}

} // namespace Security
} // namespace Oblivion
