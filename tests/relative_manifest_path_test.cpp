#include "../common/relative_manifest_path.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

static void Expect(bool value, const char* description) {
    if (!value) {
        std::cerr << "FAIL: " << description << '\n';
        std::exit(1);
    }
}

int main() {
    using Oblivion::Security::IsSafeRelativeManifestPath;

    for (const std::wstring& path : {
            L"RRO.exe", L"en.grf", L"DATA.ini",
            L"data\\patch\\manifest.grf", L"data/patch/manifest.grf",
            L"folder name/file-name.ini"}) {
        Expect(IsSafeRelativeManifestPath(path), "ordinary relative manifest path is accepted");
    }

    for (const std::wstring& path : {
            L"", L"..", L"../outside.dll", L"..\\outside.dll",
            L"data/../../outside.dll", L"folder/../outside.dll",
            L"/etc/passwd", L"\\\\server\\share\\file.dll",
            L"C:\\Windows\\System32\\ntdll.dll", L"file.dll:stream",
            L"folder//file.dll", L"folder/./file.dll", L"folder/",
            L"CON", L"nul.txt", L"COM1.log", L"LPT9.bin",
            L"bad?.dll", L"trailing. ", std::wstring(1025, L'a')}) {
        Expect(!IsSafeRelativeManifestPath(path), "unsafe manifest path is rejected");
    }

    std::cout << "relative_manifest_path_test: PASS\n";
    return 0;
}
