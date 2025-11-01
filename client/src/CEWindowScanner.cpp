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
    // 1) Check child control class names (Delphi/Lazarus typical classes)
    wchar_t cls[128]; cls[0] = 0; GetClassNameW(h, cls, 127);
    std::wstring lcls = ToLower(cls);
    static const wchar_t* classTokens[] = {
        L"tbutton", L"tpanel", L"tlistview", L"ttreeview", L"tstatusbar", L"ttoolbar",
        L"tpagecontrol", L"ttabcontrol", L"tcombobox", L"tedit", L"tcheckbox", L"tlistbox",
        L"tstringgrid", L"tprogressbar", L"tmenuitem"
    };
    for (auto* tok : classTokens) {
        std::wstring t = tok; if (!t.empty() && lcls.find(t) != std::wstring::npos) { *(bool*)lp = true; return FALSE; }
    }

    // 2) Check child window text tokens typical for CE UI
    int len = GetWindowTextLengthW(h);
    if (len > 0) {
        std::wstring text(len + 1, L'\0');
        GetWindowTextW(h, &text[0], len + 1);
        if (!text.empty() && text.back() == L'\0') text.pop_back();
        std::wstring lt = ToLower(text);
        // common CE controls/labels/buttons
        static const wchar_t* tokens[] = {
            L"first scan", L"next scan", L"new scan", L"value", L"type", L"scan type", L"memory view",
            L"add address manually", L"found", L"addresses", L"hex", L"float", L"double",
            L"exact value", L"unknown initial value", L"scan settings", L"writable", L"readable",
            L"fast scan", L"pause the game"
        };
        for (auto* tok : tokens) { std::wstring t = tok; if (lt.find(t) != std::wstring::npos) { *(bool*)lp = true; return FALSE; } }
    }
    return TRUE;
}

// Detailed counting of CE-like child controls: count per-child class and per-child text hits
struct ChildCountState {
    int classHits = 0;
    int textHits = 0;
};

static BOOL CALLBACK EnumChildCountProc(HWND h, LPARAM lp)
{
    ChildCountState* st = reinterpret_cast<ChildCountState*>(lp);
    if (!st) return FALSE;

    // Class name check
    wchar_t cls[128]; cls[0] = 0; GetClassNameW(h, cls, 127);
    std::wstring lcls = ToLower(cls);
    static const wchar_t* classTokens[] = {
        L"tbutton", L"tpanel", L"tlistview", L"ttreeview", L"tstatusbar", L"ttoolbar",
        L"tpagecontrol", L"ttabcontrol", L"tcombobox", L"tedit", L"tcheckbox", L"tlistbox",
        L"tstringgrid", L"tprogressbar", L"tmenuitem"
    };
    bool classHit = false;
    for (auto* tok : classTokens) {
        std::wstring t = tok;
        if (!t.empty() && lcls.find(t) != std::wstring::npos) { classHit = true; break; }
    }
    if (classHit) st->classHits += 1;

    // Text token check (count at most 1 per child)
    int len = GetWindowTextLengthW(h);
    if (len > 0) {
        std::wstring text(len + 1, L'\0');
        GetWindowTextW(h, &text[0], len + 1);
        if (!text.empty() && text.back() == L'\0') text.pop_back();
        std::wstring lt = ToLower(text);
        static const wchar_t* tokens[] = {
            L"first scan", L"next scan", L"new scan", L"value", L"type", L"scan type", L"memory view",
            L"add address manually", L"found", L"addresses", L"hex", L"float", L"double",
            L"exact value", L"unknown initial value", L"scan settings", L"writable", L"readable",
            L"fast scan", L"pause the game"
        };
        for (auto* tok : tokens) {
            std::wstring t = tok;
            if (!t.empty() && lt.find(t) != std::wstring::npos) { st->textHits += 1; break; }
        }
    }
    return TRUE;
}

static void CountCEChildSignals(HWND hWnd, int& outClassHits, int& outTextHits)
{
    ChildCountState st{};
    EnumChildWindows(hWnd, EnumChildCountProc, reinterpret_cast<LPARAM>(&st));
    outClassHits = st.classHits;
    outTextHits = st.textHits;
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
        // Base child control presence adds +1
        bool hasChild = CEWindowScanner::HasCEChildControls(hWnd);
        if (hasChild) indicators += 1;
        // Extra weighting: if multiple child signals or both class+text present
        int classHits = 0, textHits = 0;
        CountCEChildSignals(hWnd, classHits, textHits);
        int extra = 0;
        if (classHits > 0 && textHits > 0) extra += 1;           // synergy of class + text
        if (classHits >= 2 || textHits >= 2) extra += 1;          // multiple child signals
        if (extra > 0) indicators += extra;
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
