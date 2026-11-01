#include "../common/windows_path_policy.h"

#include <cstdlib>
#include <iostream>

namespace {
void Expect(bool condition, const char* description) {
    if (!condition) {
        std::cerr << "FAIL: " << description << '\n';
        std::exit(1);
    }
}
}

int main() {
    using Oblivion::PathPolicy::IsPathWithinDirectory;

    Expect(IsPathWithinDirectory(
        L"C:\\Windows\\System32\\kernel32.dll", L"C:\\Windows"),
        "a module under the actual Windows directory is recognized");
    Expect(!IsPathWithinDirectory(
        L"C:\\Games\\Windows\\Injected.dll", L"C:\\Windows"),
        "a nested game folder named Windows is not the Windows root");
    Expect(!IsPathWithinDirectory(
        L"C:\\WindowsBackup\\Injected.dll", L"C:\\Windows"),
        "a sibling with a shared textual prefix is not a child directory");
    Expect(IsPathWithinDirectory(
        L"c:/program files/Ragnarok/client.dll",
        L"C:\\Program Files\\Ragnarok\\"),
        "matching is case-insensitive and accepts either separator");
    Expect(!IsPathWithinDirectory(
        L"C:\\Program Files2\\Injected.dll", L"C:\\Program Files"),
        "Program Files2 is not inside Program Files");
    Expect(IsPathWithinDirectory(
        L"C:\\Program Files\\Ragnarok\\Injected.dll",
        L"C:\\Program Files\\Ragnarok"),
        "game-local modules remain detectable under Program Files");
    Expect(!IsPathWithinDirectory(L"", L"C:\\Windows"), "empty candidate is rejected");
    Expect(!IsPathWithinDirectory(L"C:\\Windows\\x.dll", L""), "empty root is rejected");

    std::cout << "Windows path policy regression tests passed\n";
    return 0;
}
