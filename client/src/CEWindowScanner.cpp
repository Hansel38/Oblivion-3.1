#include "../pch.h"
#include "CEWindowScanner.h"
#include <vector>

static std::wstring ToLower(const std::wstring& s){ std::wstring t=s; for(auto& c:t) c=(wchar_t)towlower(c); return t; }

// Subsequence fuzzy match: does pattern chars appear in order inside text
static bool SubsequenceMatch(const std::wstring& text, const std::wstring& pattern)
{
    size_t i=0,j=0; while (i<text.size() && j<pattern.size()) { if (text[i]==pattern[j]) ++j; ++i; } return j==pattern.size();
}

bool CEWindowScanner::IsCheatEngineTitleFuzzy(const std::wstring& title)
{
    std::wstring t=title; // normalize: lowercase and strip non-alpha
    for (auto& c: t) c=(wchar_t)towlower(c);
    std::wstring s; s.reserve(t.size());
    for (wchar_t c: t) { if ((c>=L'a'&&c<=L'z')) s.push_back(c); }
    if (s.find(L"cheatengine") != std::wstring::npos) return true;
    // fuzzy subsequence: c h e a t e n g i n e
    const std::wstring pat = L"cheatengine";
    return SubsequenceMatch(s, pat);
}

static BOOL CALLBACK EnumChildTextProc(HWND h, LPARAM lp)
{
    int len = GetWindowTextLengthW(h); if (len<=0) return TRUE;
    std::wstring text(len+1, L'\0'); GetWindowTextW(h, &text[0], len+1); if (!text.empty() && text.back()==L'\0') text.pop_back();
    std::wstring lt = ToLower(text);
    // common CE controls/labels/buttons
    static const wchar_t* tokens[] = { L"first scan", L"next scan", L"new scan", L"value", L"type", L"scan type", L"memory view" };
    for (auto* tok: tokens) { std::wstring t=tok; if (lt.find(t)!=std::wstring::npos) { *(bool*)lp = true; return FALSE; } }
    return TRUE;
}

bool CEWindowScanner::HasCEChildControls(HWND hWnd)
{
    bool found = false;
    EnumChildWindows(hWnd, EnumChildTextProc, (LPARAM)&found);
    return found;
}

bool CEWindowScanner::ScanForCEWindows(WindowFinding& out)
{
    out = {};
    struct Ctx { WindowFinding* out; } ctx{ &out };

    auto cb = [](HWND hWnd, LPARAM lp)->BOOL{
        if (!IsWindowVisible(hWnd)) return TRUE;
        wchar_t cls[128] = {0}; GetClassNameW(hWnd, cls, 127);
        int tl = GetWindowTextLengthW(hWnd);
        std::wstring title; title.resize(tl);
        if (tl>0) { title.resize(tl+1); GetWindowTextW(hWnd, &title[0], tl+1); if (!title.empty() && title.back()==L'\0') title.pop_back(); }
        std::wstring lcls = ToLower(cls);
        int indicators = 0;
        if (lcls.find(L"tmainform") != std::wstring::npos || lcls.find(L"tcemainform") != std::wstring::npos) indicators += 2;
        if (CEWindowScanner::IsCheatEngineTitleFuzzy(title)) indicators += 2;
        if (CEWindowScanner::HasCEChildControls(hWnd)) indicators += 1;
        if (indicators >= 3) {
            DWORD pid = 0; GetWindowThreadProcessId(hWnd, &pid);
            Ctx* c = reinterpret_cast<Ctx*>(lp);
            c->out->detected = true; c->out->indicators = indicators; c->out->pid = pid;
            c->out->className = cls; c->out->windowTitle = title;
            return FALSE; // stop enumeration on first confident hit
        }
        return TRUE;
    };

    EnumWindows((WNDENUMPROC)cb, (LPARAM)&ctx);
    return out.detected;
}
