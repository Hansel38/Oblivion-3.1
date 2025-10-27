#pragma once
#include <vector>
#include <string>

// Blacklist of known cheat process names (case-insensitive)
// Users should customize this list based on their specific needs
inline std::vector<std::wstring> GetDefaultProcessBlacklist() {
    return {
        L"cheatengine.exe",
        L"cheatengine-x86_64.exe",
        L"cheatengine-x86_64-ssex.exe",
        L"cheatengine-i386.exe",
        L"openkore.exe",
        L"wpe.exe",
        L"wpe pro.exe",
        L"rpe.exe",
        L"tsearch.exe",
        L"artmoney.exe",
        L"speedhack.exe",
        L"gamecih.exe",
        L"gameguardian.exe",
        L"scanmem.exe",
        L"cheat engine.exe",
        L"ce.exe",
        L"x64dbg.exe",
        L"x32dbg.exe",
        L"ollydbg.exe",
        L"ida.exe",
        L"ida64.exe",
        L"windbg.exe",
        L"wireshark.exe",
        L"fiddler.exe"
    };
}

// Tokens for Cheat Engine related artifacts seen in module names/paths and UI text.
// Keep here so they can be maintained centrally; callers should lowercase both sides before matching.
inline const std::vector<std::wstring>& GetDefaultCeArtifactTokens()
{
    static const std::vector<std::wstring> kTokens = {
        // Core CE names
        L"cheatengine", L"cheat engine", L"ce.exe", L"dark byte",
        // Modules and features commonly present
        L"vehdebug", L"speedhack", L"dbk", L"cedriver", L"ceserver", L"celua", L"monohelper",
        // UI/Window clues often present in CE
        L"address list", L"value type", L"scan type", L"found:", L"first scan", L"next scan"
    };
    return kTokens;
}
