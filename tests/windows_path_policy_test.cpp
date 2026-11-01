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


    using Oblivion::PathPolicy::CanTrustUnsignedModuleByName;
    Expect(CanTrustUnsignedModuleByName(
        true,
        L"C:\\Games\\Ragnarok\\client.dll",
        L"C:\\Games\\Ragnarok"),
        "an allowlisted unsigned DLL under the game directory retains compatibility");
    Expect(!CanTrustUnsignedModuleByName(
        true,
        L"C:\\Users\\Player\\AppData\\Local\\Temp\\client.dll",
        L"C:\\Games\\Ragnarok"),
        "an allowlisted filename outside the game directory is not trusted");
    Expect(!CanTrustUnsignedModuleByName(
        false,
        L"C:\\Games\\Ragnarok\\unknown.dll",
        L"C:\\Games\\Ragnarok"),
        "an unlisted filename is not accepted by the unsigned-DLL exemption");
    Expect(!CanTrustUnsignedModuleByName(
        true,
        L"C:\\Games\\RagnarokBackup\\client.dll",
        L"C:\\Games\\Ragnarok"),
        "a sibling directory sharing a prefix is not trusted");

    using Oblivion::PathPolicy::ShouldWhitelistWindowsSystemProcess;
    Expect(ShouldWhitelistWindowsSystemProcess(true, true, true, true),
        "known Windows processes require path and signature checks");
    Expect(!ShouldWhitelistWindowsSystemProcess(true, true, false, true),
        "a system process name outside the Windows directory is rejected");
    Expect(!ShouldWhitelistWindowsSystemProcess(true, true, true, false),
        "an untrusted signature cannot use the Windows process exemption");
    Expect(!ShouldWhitelistWindowsSystemProcess(true, false, false, false),
        "an unresolved process path is not exempted");
    Expect(!ShouldWhitelistWindowsSystemProcess(false, true, true, true),
        "a valid Microsoft signature does not make an unrelated name a system process");

    std::cout << "Windows path policy regression tests passed\n";
    return 0;
}
