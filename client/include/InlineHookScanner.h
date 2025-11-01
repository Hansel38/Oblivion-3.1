#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct InlineHookFinding {
    std::wstring moduleName;
    std::string functionName;
    PVOID functionAddress = nullptr;
    PVOID hookTargetAddress = nullptr;
    std::wstring hookModule;
    int indicators = 0;
    std::string hookType; // "jmp_rel32", "jmp_abs", "push_ret", "call_rel32", etc.
};

class InlineHookScanner {
public:
    void SetThreshold(int t) { m_threshold = t; }
    void SetWhitelistModules(const std::vector<std::wstring>& wl) { m_modWhitelist = wl; }

    // Scan exports of specified module for inline hooks
    bool ScanModuleExports(HMODULE hMod, InlineHookFinding& out);
    
    // Scan specific critical functions (NtCreateThread, LoadLibrary, etc.)
    bool ScanCriticalFunctions(InlineHookFinding& out);

private:
    int m_threshold = 2;
    std::vector<std::wstring> m_modWhitelist;

    bool IsWhitelistedModule(const std::wstring& moduleLower);
    bool IsSystemModule(HMODULE hMod);
    bool DetectTrampolinePattern(BYTE* funcPtr, std::string& hookType, PVOID& target);
    PVOID ResolveJumpTarget(BYTE* jmpInstr);
    HMODULE FindModuleByAddress(PVOID addr);
    std::wstring GetModulePath(HMODULE hMod);
};

// VTable hook scanner
struct VTableHookFinding {
    std::wstring objectType;
    void** vtable = nullptr;
    size_t entryIndex = 0;
    PVOID hookedAddress = nullptr;
    std::wstring hookModule;
    int indicators = 0;
};

class VTableHookScanner {
public:
    void SetThreshold(int t) { m_threshold = t; }
    
    // Scan known VTable locations (D3D, OpenGL, etc.)
    bool ScanKnownVTables(VTableHookFinding& out);

private:
    int m_threshold = 2;
    
    bool ScanVTable(void** vtable, size_t entries, const wchar_t* objectType, VTableHookFinding& out);
    bool IsSystemModule(HMODULE hMod);
    HMODULE FindModuleByAddress(PVOID addr);
};
