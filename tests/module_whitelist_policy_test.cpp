#include "../common/module_whitelist_policy.h"

#include <cstdlib>
#include <iostream>

static void Expect(bool value, const char* description) {
    if (!value) {
        std::cerr << "FAIL: " << description << '\n';
        std::exit(1);
    }
}

int main() {
    using Oblivion::Security::IsExactModuleWhitelistMatch;
    Expect(IsExactModuleWhitelistMatch(L"ntdll.dll", L"ntdll.dll"),
           "exact module name is accepted");
    Expect(IsExactModuleWhitelistMatch(L"NTDLL.DLL", L" ntdll.dll \t"),
           "comparison is case-insensitive and trims whitespace");
    Expect(!IsExactModuleWhitelistMatch(L"evil-ntdll.dll", L"ntdll.dll"),
           "prefixed module name is not accepted");
    Expect(!IsExactModuleWhitelistMatch(L"ntdll.dll.backup", L"ntdll.dll"),
           "suffixed module name is not accepted");
    Expect(!IsExactModuleWhitelistMatch(L"ntdll.dll", L"ntdll"),
           "partial module name is not accepted");
    Expect(!IsExactModuleWhitelistMatch(L"ntdll.dll", L"C:\\Windows\\System32\\ntdll.dll"),
           "path entries are not accepted as module names");
    Expect(!IsExactModuleWhitelistMatch(L"ntdll.dll", L"*.dll"),
           "wildcard entries are not accepted");
    std::cout << "module_whitelist_policy_test: PASS\n";
    return 0;
}
