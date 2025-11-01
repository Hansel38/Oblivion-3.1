#pragma once
#include <windows.h>
#include <string>

class CEWindowScanner {
public:
    struct WindowFinding {
        bool detected = false;
        int indicators = 0;
        DWORD pid = 0;
        std::wstring windowTitle;
        std::wstring className;
    };

    CEWindowScanner() = default;
    ~CEWindowScanner() = default;

    // Scan top-level windows for CE-like UI heuristics
    bool ScanForCEWindows(WindowFinding& out);

private:
    static bool IsCheatEngineTitleFuzzy(const std::wstring& title);
    static bool HasCEChildControls(HWND hWnd);
};
