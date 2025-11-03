#include "../pch.h"
#include "CEWindowScanner.h"
#include "AntiTampering.h"
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
    const std::wstring ceTok = OBFUSCATE_W("cheatengine");
    if (s.find(ceTok) != std::wstring::npos) return true;
    // fuzzy subsequence: c h e a t e n g i n e
    const std::wstring pat = ceTok;
    return SubsequenceMatch(s, pat);
}

static BOOL CALLBACK EnumChildTextProc(HWND h, LPARAM lp)
{
    // 1) Check child control class names (Delphi/Lazarus typical classes)
    wchar_t cls[128]; cls[0] = 0; GetClassNameW(h, cls, 127);
    std::wstring lcls = ToLower(cls);
    static const std::wstring classTokens[] = {
        OBFUSCATE_W("tbutton"), OBFUSCATE_W("tpanel"), OBFUSCATE_W("tlistview"), OBFUSCATE_W("ttreeview"), OBFUSCATE_W("tstatusbar"), OBFUSCATE_W("ttoolbar"),
        OBFUSCATE_W("tpagecontrol"), OBFUSCATE_W("ttabcontrol"), OBFUSCATE_W("tcombobox"), OBFUSCATE_W("tedit"), OBFUSCATE_W("tcheckbox"), OBFUSCATE_W("tlistbox"),
        OBFUSCATE_W("tstringgrid"), OBFUSCATE_W("tprogressbar"), OBFUSCATE_W("tmenuitem")
    };
        for (const auto& tok : classTokens) {
            const std::wstring& t = tok; if (!t.empty() && lcls.find(t) != std::wstring::npos) { *(bool*)lp = true; return FALSE; }
        }

    // 2) Check child window text tokens typical for CE UI
    int len = GetWindowTextLengthW(h);
    if (len > 0) {
        std::wstring text(len + 1, L'\0');
        GetWindowTextW(h, &text[0], len + 1);
        if (!text.empty() && text.back() == L'\0') text.pop_back();
        std::wstring lt = ToLower(text);
        // common CE controls/labels/buttons
        static const std::wstring tokens[] = {
            OBFUSCATE_W("first scan"), OBFUSCATE_W("next scan"), OBFUSCATE_W("new scan"), OBFUSCATE_W("value"), OBFUSCATE_W("type"), OBFUSCATE_W("scan type"), OBFUSCATE_W("memory view"),
            OBFUSCATE_W("add address manually"), OBFUSCATE_W("found"), OBFUSCATE_W("addresses"), OBFUSCATE_W("hex"), OBFUSCATE_W("float"), OBFUSCATE_W("double"),
            OBFUSCATE_W("exact value"), OBFUSCATE_W("unknown initial value"), OBFUSCATE_W("scan settings"), OBFUSCATE_W("writable"), OBFUSCATE_W("readable"),
            OBFUSCATE_W("fast scan"), OBFUSCATE_W("pause the game")
        };
        for (const auto& tok : tokens) { const std::wstring& t = tok; if (lt.find(t) != std::wstring::npos) { *(bool*)lp = true; return FALSE; } }
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
    static const std::wstring classTokens[] = {
        L"tbutton", L"tpanel", L"tlistview", L"ttreeview", L"tstatusbar", L"ttoolbar",
        L"tpagecontrol", L"ttabcontrol", L"tcombobox", L"tedit", L"tcheckbox", L"tlistbox",
        L"tstringgrid", L"tprogressbar", L"tmenuitem"
    };
    bool classHit = false;
    for (const auto& tok : classTokens) {
        const std::wstring& t = tok;
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
        static const std::wstring tokens[] = {
            OBFUSCATE_W("first scan"), OBFUSCATE_W("next scan"), OBFUSCATE_W("new scan"), OBFUSCATE_W("value"), OBFUSCATE_W("type"), OBFUSCATE_W("scan type"), OBFUSCATE_W("memory view"),
            OBFUSCATE_W("add address manually"), OBFUSCATE_W("found"), OBFUSCATE_W("addresses"), OBFUSCATE_W("hex"), OBFUSCATE_W("float"), OBFUSCATE_W("double"),
            OBFUSCATE_W("exact value"), OBFUSCATE_W("unknown initial value"), OBFUSCATE_W("scan settings"), OBFUSCATE_W("writable"), OBFUSCATE_W("readable"),
            OBFUSCATE_W("fast scan"), OBFUSCATE_W("pause the game")
        };
        for (const auto& tok : tokens) {
            const std::wstring& t = tok;
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
    const std::wstring tmain = OBFUSCATE_W("tmainform");
    const std::wstring tcemain = OBFUSCATE_W("tcemainform");
    if (lcls.find(tmain) != std::wstring::npos || lcls.find(tcemain) != std::wstring::npos) indicators += 2;
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

    ObfuscatedAPI::ObfEnumWindows((WNDENUMPROC)cb, (LPARAM)&ctx);
    return out.detected;
}
