#include "../pch.h"
#include "InjectionScanner.h"
#include <algorithm>

static std::wstring tolower_ws2(const std::wstring& s) { std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }

bool InjectionScanner::RunOnceScan(InjectionFinding& out)
{
    out = InjectionFinding{};

    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    if (!Module32FirstW(snap, &me)) { CloseHandle(snap); return false; }

    do {
        std::wstring path = me.szExePath;
        std::wstring name = me.szModule;
        int score =0;

        const bool suspPath = IsSuspiciousPath(path);
        const bool suspName = NameHasSuspiciousTerms(name);
        const bool whitelisted = IsWhitelisted(path);

        if (suspPath) score +=1;
        if (suspName) score +=1;
        // Not being whitelisted alone is not enough; add a small bonus only if there is another indicator
        if (!whitelisted && (suspPath || suspName)) score +=1;

        if (score >= m_threshold) {
            out.modulePath = path;
            out.moduleName = name;
            out.indicators = score;
            CloseHandle(snap);
            return true;
        }
    } while (Module32NextW(snap, &me));

    CloseHandle(snap);
    return false;
}

bool InjectionScanner::IsSuspiciousPath(const std::wstring& path)
{
    auto p = tolower_ws2(path);
    return p.find(L"\\temp\\") != std::wstring::npos ||
           p.find(L"\\appdata\\local\\") != std::wstring::npos ||
           p.find(L"\\users\\") != std::wstring::npos;
}

bool InjectionScanner::NameHasSuspiciousTerms(const std::wstring& name)
{
    auto n = tolower_ws2(name);
    static const wchar_t* terms[] = { L"inject", L"hook", L"cheat", L"proxy", L"dllmain" };
    for (auto t : terms) {
        if (n.find(t) != std::wstring::npos) return true;
    }
    return false;
}

bool InjectionScanner::IsWhitelisted(const std::wstring& path)
{
    if (m_whitelist.empty()) return false; // no whitelist provided -> treat as not whitelisted
    auto p = tolower_ws2(path);
    for (const auto& w : m_whitelist) {
        auto wl = tolower_ws2(w);
        if (!wl.empty() && p.rfind(wl,0) ==0) return true; // prefix match
    }
    return false;
}
