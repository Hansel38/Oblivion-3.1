#include "../pch.h"
#include "OverlayScanner.h"
#include "blacklist_overlay.h"
#include <algorithm>
#include <tlhelp32.h>
#include "AntiTampering.h"

OverlayScanner::OverlayScanner() {}

static std::wstring tolower_ws(const std::wstring& s) {
    std::wstring r = s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r;
}

bool OverlayScanner::RunOnceScan(OverlayFinding& finding)
{
    finding = OverlayFinding{};

    struct Pack { OverlayScanner* self; OverlayFinding* out; } pack{ this, &finding };

    auto enumThunk = [](HWND hWnd, LPARAM lParam) -> BOOL {
        auto p = reinterpret_cast<Pack*>(lParam);
        if (!IsWindowVisible(hWnd)) return TRUE;
        OverlayFinding tmp;
        if (p->self->EvaluateWindow(hWnd, tmp)) {
            *(p->out) = tmp;
            return FALSE; // stop
        }
        return TRUE;
    };

    ObfuscatedAPI::ObfEnumWindows((WNDENUMPROC)enumThunk, reinterpret_cast<LPARAM>(&pack));
    return finding.indicators >= m_closeThreshold;
}

static bool GetProcessExeNameLower(DWORD pid, std::wstring& outLower)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    bool ok=false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                outLower = tolower_ws(pe.szExeFile);
                ok=true; break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return ok;
}

std::wstring OverlayScanner::GetOwnerExeNameLower(HWND hWnd)
{
    DWORD pid=0; GetWindowThreadProcessId(hWnd, &pid);
    std::wstring name;
    if (GetProcessExeNameLower(pid, name)) return name;
    return L"";
}

bool OverlayScanner::IsBenignOwnerName(const std::wstring& ownerLower)
{
    static const wchar_t* kBenign[] = { L"discord.exe", L"steam.exe", L"gamebar.exe", L"obs64.exe", L"nvcontainer.exe", L"rtss.exe" };
    for (auto b : kBenign) { if (ownerLower == b) return true; }
    return false;
}

bool OverlayScanner::IsLargeOnPrimaryScreen(const RECT& rc)
{
    RECT r = rc;
    int w = r.right - r.left; int h = r.bottom - r.top;
    if (w <=0 || h <=0) return false;
    RECT scr{}; GetWindowRect(GetDesktopWindow(), &scr);
    int sw = scr.right - scr.left; int sh = scr.bottom - scr.top;
    if (sw <=0 || sh <=0) return false;
    long long area =1LL * w * h;
    long long sarea =1LL * sw * sh;
    return area *4 >= sarea; // >=25%
}

bool OverlayScanner::HasGpuOverlayHooks(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    bool hit = false;
    if (Module32FirstW(snap, &me)) {
        do {
            std::wstring base = tolower_ws(me.szModule);
            std::wstring path = tolower_ws(me.szExePath);
            // Known hook/overlay components
            bool isKnownOverlay = (base.find(L"reshade") != std::wstring::npos || base.find(L"rtsshook") != std::wstring::npos || base.find(L"overlay") != std::wstring::npos);
            bool isApiShim = (base == L"d3d9.dll" || base == L"d3d11.dll" || base == L"dinput8.dll" || base == L"opengl32.dll" || base == L"dxgi.dll");
            bool isSystem = (path.find(L"\\windows\\system32\\") != std::wstring::npos) || (path.find(L"\\windows\\syswow64\\") != std::wstring::npos);
            if ((isKnownOverlay) || (isApiShim && !isSystem)) { hit = true; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return hit;
}

bool OverlayScanner::EvaluateWindow(HWND hWnd, OverlayFinding& out)
{
    std::wstring title = GetWindowTextWStr(hWnd);
    std::wstring cls = GetClassNameWStr(hWnd);

    LONG_PTR exStyle = GetWindowLongPtrW(hWnd, GWL_EXSTYLE);
    int score =0;
    int styleScore =0;

    if (exStyle & WS_EX_TOPMOST) { score++; styleScore++; }
    if (exStyle & WS_EX_LAYERED) { score++; styleScore++; }
    if (exStyle & WS_EX_TRANSPARENT) { score++; styleScore++; } // click-through overlay

    RECT rc{}; GetWindowRect(hWnd, &rc);
    out.rect = rc;

    // area-based scoring: big overlays are more suspicious
    if (IsLargeOnPrimaryScreen(rc)) { score++; styleScore++; }

    auto lowerTitle = tolower_ws(title);
    auto lowerClass = tolower_ws(cls);

    bool blacklistHit = ContainsAny(lowerTitle, GetDefaultOverlayTitleBlacklist()) || ContainsAny(lowerClass, GetDefaultOverlayTitleBlacklist());
    if (blacklistHit) score +=2; // strong indicator

    DWORD pid =0; GetWindowThreadProcessId(hWnd, &pid);
    auto ownerName = GetOwnerExeNameLower(hWnd);

    // GPU hook/overlay hint if process has known hook modules
    bool hookHit = HasGpuOverlayHooks(pid);
    if (hookHit) score +=2;

    // Reduce FPs: require both style/size signals and either blacklist or hook evidence
    if (styleScore <2) return false;
    if (!(blacklistHit || hookHit)) return false;

    // skip benign owners unless multiple strong hits (require score>=5)
    if (IsBenignOwnerName(ownerName) && score <5) {
        return false;
    }

    if (score >=3) {
        out.pid = pid;
        out.windowTitle = title;
        out.className = cls;
        out.indicators = score;
        return true;
    }
    return false;
}

std::wstring OverlayScanner::GetWindowTextWStr(HWND hWnd)
{
    int len = GetWindowTextLengthW(hWnd);
    if (len <=0) return L"";
    std::wstring s(len +1, L'\0');
    GetWindowTextW(hWnd, &s[0], len +1);
    s.resize(wcslen(s.c_str()));
    return s;
}

std::wstring OverlayScanner::GetClassNameWStr(HWND hWnd)
{
    wchar_t buf[256]{};
    int n = GetClassNameW(hWnd, buf,256);
    if (n <=0) return L"";
    return std::wstring(buf, n);
}

bool OverlayScanner::ContainsAny(const std::wstring& haystack, const std::vector<std::wstring>& needles)
{
    auto lowerHay = tolower_ws(haystack);
    for (const auto& n : needles) {
        if (lowerHay.find(tolower_ws(n)) != std::wstring::npos) return true;
    }
    return false;
}
