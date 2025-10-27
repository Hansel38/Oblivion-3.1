#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct OverlayFinding {
    DWORD pid;
    std::wstring windowTitle;
    std::wstring className;
    RECT rect{0,0,0,0};
    int indicators = 0; // heuristic score
};

class OverlayScanner {
public:
    OverlayScanner();

    // Configure thresholds
    void SetCloseThreshold(int v) { m_closeThreshold = v; }

    // Run a one-shot scan of top-level windows for suspicious overlays
    // Returns true if a suspicious overlay reaches threshold (and fills out finding)
    bool RunOnceScan(OverlayFinding& finding);

private:
    int m_closeThreshold = 2;

    bool EvaluateWindow(HWND hWnd, OverlayFinding& out); // returns true if suspicious

    // helpers
    std::wstring GetWindowTextWStr(HWND hWnd);
    std::wstring GetClassNameWStr(HWND hWnd);
    bool ContainsAny(const std::wstring& haystack, const std::vector<std::wstring>& needles);

    // new helpers for tuning
    std::wstring GetOwnerExeNameLower(HWND hWnd);
    bool IsBenignOwnerName(const std::wstring& ownerLower);
    bool IsLargeOnPrimaryScreen(const RECT& rc); // >= 25% area of primary screen

    // GPU overlay/DXGI/D3D hooking heuristic
    bool HasGpuOverlayHooks(DWORD pid);
};
