#include "../pch.h"
#include "IATHookScanner.h"
#include <Psapi.h>
#include <algorithm>

#pragma pack(push, 1)
struct IMAGE_IMPORT_DESCRIPTOR_ {
    DWORD OriginalFirstThunk;
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
};
#pragma pack(pop)

static std::wstring tolower_ws(const std::wstring& s){ std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }

static PBYTE RvaToVa(PBYTE imageBase, DWORD rva)
{
    return imageBase + rva;
}

bool IATHookScanner::IsWhitelistedModule(const std::wstring& moduleLower)
{
    if (m_modWhitelist.empty()) return false;
    for (const auto& w : m_modWhitelist) {
        auto wl = tolower_ws(w);
        if (!wl.empty() && (moduleLower == wl || moduleLower.rfind(wl, 0) == 0)) return true;
    }
    return false;
}

static bool IsSystemPath(const std::wstring& pathLower)
{
    return pathLower.find(L"\\windows\\system32\\") != std::wstring::npos || pathLower.find(L"\\windows\\syswow64\\") != std::wstring::npos;
}

bool IATHookScanner::RunOnceScan(IATHookFinding& out)
{
    out = IATHookFinding{};

    HMODULE hMain = GetModuleHandleW(nullptr);
    if (!hMain) return false;

    auto base = (PBYTE)hMain;
    auto dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (IMAGE_NT_HEADERS*)((PBYTE)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return false;

    auto imp = (IMAGE_IMPORT_DESCRIPTOR_*)RvaToVa(base, dir.VirtualAddress);
    for (; imp->Name != 0; ++imp) {
        const char* dllName = (const char*)RvaToVa(base, imp->Name);
        std::string dllNameStr = dllName ? dllName : "";

        auto thunk = (IMAGE_THUNK_DATA*)RvaToVa(base, imp->FirstThunk);
        for (; thunk && thunk->u1.Function; ++thunk) {
            auto pFunc = (PVOID)thunk->u1.Function;
            HMODULE mods[1024]; DWORD needed=0;
            std::wstring tgtModuleLower;
            if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
                size_t count = needed/sizeof(HMODULE);
                for (size_t i=0;i<count;++i) {
                    MODULEINFO mi{}; if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) continue;
                    BYTE* b = (BYTE*)mi.lpBaseOfDll; SIZE_T s = mi.SizeOfImage;
                    if ((BYTE*)pFunc >= b && (BYTE*)pFunc < b+s) {
                        wchar_t path[MAX_PATH]{}; GetModuleFileNameW(mods[i], path, MAX_PATH);
                        tgtModuleLower = tolower_ws(path);
                        break;
                    }
                }
            }

            int score = 0;
            if (tgtModuleLower.empty()) score += 2; // points outside any module
            else {
                if (!IsWhitelistedModule(tgtModuleLower) && !IsSystemPath(tgtModuleLower)) score += 1; // non-whitelisted and not a system dll
            }

            if (score >= m_threshold) {
                out.moduleName = L"<main>";
                out.importName = dllNameStr; // store dll name (we don't resolve function name reliably here)
                out.iatAddress = &thunk->u1.Function;
                out.targetAddress = pFunc;
                out.targetModule = tgtModuleLower;
                out.indicators = score;
                return true;
            }
        }
    }

    return false;
}
