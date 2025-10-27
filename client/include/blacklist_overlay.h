#pragma once
#include <vector>
#include <string>

// Overlay window title/class substrings considered suspicious (case-insensitive)
// Keep this conservative to avoid false positives; customize as needed.
inline std::vector<std::wstring> GetDefaultOverlayTitleBlacklist() {
    return {
        L"cheat", L"engine", L"speedhack", L"wpe", L"rpe", L"packet editor", L"bot overlay", L"aimbot", L"esp"
    };
}

// Known benign overlay substrings to down-weight (not outright whitelist)
inline std::vector<std::wstring> GetBenignOverlayHints() {
    return { L"discord", L"steam", L"geforce", L"nvidia", L"obs", L"shadowplay", L"xbox game bar", L"rtss" };
}
