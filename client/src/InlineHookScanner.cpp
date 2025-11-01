#include "../pch.h"
#include "../include/InlineHookScanner.h"
#include <Psapi.h>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

static std::wstring tolower_ws(const std::wstring& s) { 
    std::wstring r = s; 
    std::transform(r.begin(), r.end(), r.begin(), ::towlower); 
    return r; 
}

std::wstring InlineHookScanner::GetModulePath(HMODULE hMod) {
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(hMod, path, MAX_PATH);
    return path;
}

bool InlineHookScanner::IsWhitelistedModule(const std::wstring& moduleLower) {
    if (m_modWhitelist.empty()) return false;
    for (const auto& w : m_modWhitelist) {
        auto wl = tolower_ws(w);
        if (!wl.empty() && (moduleLower == wl || moduleLower.rfind(wl, 0) == 0)) 
            return true;
    }
    return false;
}

bool InlineHookScanner::IsSystemModule(HMODULE hMod) {
    std::wstring path = tolower_ws(GetModulePath(hMod));
    return path.find(L"\\windows\\system32\\") != std::wstring::npos ||
           path.find(L"\\windows\\syswow64\\") != std::wstring::npos;
}

HMODULE InlineHookScanner::FindModuleByAddress(PVOID addr) {
    HMODULE mods[1024]; 
    DWORD needed = 0;
    
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        size_t count = needed / sizeof(HMODULE);
        for (size_t i = 0; i < count; ++i) {
            MODULEINFO mi = {0};
            if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) 
                continue;
                
            BYTE* base = (BYTE*)mi.lpBaseOfDll;
            SIZE_T size = mi.SizeOfImage;
            
            if ((BYTE*)addr >= base && (BYTE*)addr < base + size) {
                return mods[i];
            }
        }
    }
    return nullptr;
}

PVOID InlineHookScanner::ResolveJumpTarget(BYTE* jmpInstr) {
    if (!jmpInstr) return nullptr;
    
    // JMP rel32 (E9 xx xx xx xx)
    if (jmpInstr[0] == 0xE9) {
        int32_t offset = *(int32_t*)(jmpInstr + 1);
        return jmpInstr + 5 + offset;
    }
    
    // JMP rel8 (EB xx)
    if (jmpInstr[0] == 0xEB) {
        int8_t offset = *(int8_t*)(jmpInstr + 1);
        return jmpInstr + 2 + offset;
    }
    
    // JMP [rip+disp32] (FF 25 xx xx xx xx) - x64
#ifdef _M_X64
    if (jmpInstr[0] == 0xFF && jmpInstr[1] == 0x25) {
        int32_t offset = *(int32_t*)(jmpInstr + 2);
        PVOID* pTarget = (PVOID*)(jmpInstr + 6 + offset);
        return *pTarget;
    }
#endif
    
    // PUSH imm32 + RET (68 xx xx xx xx C3)
    if (jmpInstr[0] == 0x68 && jmpInstr[5] == 0xC3) {
        return *(PVOID*)(jmpInstr + 1);
    }
    
    return nullptr;
}

bool InlineHookScanner::DetectTrampolinePattern(BYTE* funcPtr, std::string& hookType, PVOID& target) {
    if (!funcPtr) return false;
    
    __try {
        // JMP rel32 (E9 xx xx xx xx) - Most common hook
        if (funcPtr[0] == 0xE9) {
            hookType = "jmp_rel32";
            target = ResolveJumpTarget(funcPtr);
            return true;
        }
        
        // JMP rel8 (EB xx)
        if (funcPtr[0] == 0xEB) {
            hookType = "jmp_rel8";
            target = ResolveJumpTarget(funcPtr);
            return true;
        }
        
        // PUSH + RET trampoline (68 xx xx xx xx C3) - x86
        if (funcPtr[0] == 0x68 && funcPtr[5] == 0xC3) {
            hookType = "push_ret";
            target = ResolveJumpTarget(funcPtr);
            return true;
        }
        
        // JMP [rip+disp] (FF 25 xx xx xx xx) - x64 absolute jump
#ifdef _M_X64
        if (funcPtr[0] == 0xFF && funcPtr[1] == 0x25) {
            hookType = "jmp_abs_x64";
            target = ResolveJumpTarget(funcPtr);
            return true;
        }
#endif
        
        // MOV rax, imm64 + JMP rax (48 B8 xx xx xx xx xx xx xx xx FF E0) - x64
#ifdef _M_X64
        if (funcPtr[0] == 0x48 && funcPtr[1] == 0xB8 && funcPtr[10] == 0xFF && funcPtr[11] == 0xE0) {
            hookType = "mov_jmp_rax";
            target = *(PVOID*)(funcPtr + 2);
            return true;
        }
#endif
        
        // CALL rel32 (E8 xx xx xx xx) - Less common but possible
        if (funcPtr[0] == 0xE8) {
            hookType = "call_rel32";
            int32_t offset = *(int32_t*)(funcPtr + 1);
            target = funcPtr + 5 + offset;
            return true;
        }
        
        // RET instruction at beginning (C3 or C2 xx xx) - Suspicious
        if (funcPtr[0] == 0xC3 || funcPtr[0] == 0xC2) {
            hookType = "early_ret";
            target = nullptr;
            return true;
        }
        
        // INT3 breakpoint (CC) - Debug hook
        if (funcPtr[0] == 0xCC) {
            hookType = "int3_breakpoint";
            target = nullptr;
            return true;
        }
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    
    return false;
}

bool InlineHookScanner::ScanModuleExports(HMODULE hMod, InlineHookFinding& out) {
    out = InlineHookFinding{};
    
    if (!hMod) return false;
    
    BYTE* base = (BYTE*)hMod;
    auto dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    
    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    
    auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0 || expDir.Size == 0) return false;
    
    auto exp = (IMAGE_EXPORT_DIRECTORY*)(base + expDir.VirtualAddress);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ords = (WORD*)(base + exp->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* funcName = (const char*)(base + names[i]);
        DWORD funcRva = funcs[ords[i]];
        BYTE* funcPtr = base + funcRva;
        
        std::string hookType;
        PVOID target = nullptr;
        
        if (DetectTrampolinePattern(funcPtr, hookType, target)) {
            int score = 0;
            
            // Check if target is outside module
            HMODULE targetMod = target ? FindModuleByAddress(target) : nullptr;
            
            if (target && !targetMod) {
                score += 3; // Points to unmapped memory - very suspicious
            } else if (target && targetMod != hMod) {
                // Points to different module
                std::wstring targetPath = tolower_ws(GetModulePath(targetMod));
                
                if (!IsSystemModule(targetMod) && !IsWhitelistedModule(targetPath)) {
                    score += 2; // Non-system, non-whitelisted module
                } else {
                    score += 1; // System module but still redirected
                }
            }
            
            // Special patterns are more suspicious
            if (hookType == "push_ret" || hookType == "mov_jmp_rax" || 
                hookType == "int3_breakpoint" || hookType == "early_ret") {
                score += 1;
            }
            
            if (score >= m_threshold) {
                out.moduleName = GetModulePath(hMod);
                out.functionName = funcName;
                out.functionAddress = funcPtr;
                out.hookTargetAddress = target;
                out.hookModule = targetMod ? GetModulePath(targetMod) : L"<unknown>";
                out.indicators = score;
                out.hookType = hookType;
                return true;
            }
        }
    }
    
    return false;
}

bool InlineHookScanner::ScanCriticalFunctions(InlineHookFinding& out) {
    out = InlineHookFinding{};
    
    // List of critical functions commonly hooked by cheats
    struct CriticalFunc {
        const wchar_t* module;
        const char* function;
    };
    
    CriticalFunc criticalFuncs[] = {
        // ntdll.dll - Process/Thread creation
        {L"ntdll.dll", "NtCreateThread"},
        {L"ntdll.dll", "NtCreateThreadEx"},
        {L"ntdll.dll", "NtQueueApcThread"},
        {L"ntdll.dll", "NtWriteVirtualMemory"},
        {L"ntdll.dll", "NtReadVirtualMemory"},
        {L"ntdll.dll", "NtProtectVirtualMemory"},
        {L"ntdll.dll", "NtAllocateVirtualMemory"},
        {L"ntdll.dll", "LdrLoadDll"},
        
        // kernel32.dll - Process/Module operations
        {L"kernel32.dll", "CreateThread"},
        {L"kernel32.dll", "CreateRemoteThread"},
        {L"kernel32.dll", "LoadLibraryA"},
        {L"kernel32.dll", "LoadLibraryW"},
        {L"kernel32.dll", "LoadLibraryExA"},
        {L"kernel32.dll", "LoadLibraryExW"},
        {L"kernel32.dll", "GetProcAddress"},
        {L"kernel32.dll", "VirtualProtect"},
        {L"kernel32.dll", "VirtualAlloc"},
        {L"kernel32.dll", "WriteProcessMemory"},
        {L"kernel32.dll", "ReadProcessMemory"},
        
        // user32.dll - Input hooks
        {L"user32.dll", "SetWindowsHookExA"},
        {L"user32.dll", "SetWindowsHookExW"},
        {L"user32.dll", "GetAsyncKeyState"},
        {L"user32.dll", "GetKeyState"},
        
        // Graphics APIs (commonly hooked for ESP/aimbot)
        {L"d3d9.dll", "Direct3DCreate9"},
        {L"d3d11.dll", "D3D11CreateDevice"},
        {L"dxgi.dll", "CreateDXGIFactory"},
        {L"opengl32.dll", "wglSwapBuffers"}
    };
    
    for (const auto& cf : criticalFuncs) {
        HMODULE hMod = GetModuleHandleW(cf.module);
        if (!hMod) continue;
        
        FARPROC proc = GetProcAddress(hMod, cf.function);
        if (!proc) continue;
        
        BYTE* funcPtr = (BYTE*)proc;
        std::string hookType;
        PVOID target = nullptr;
        
        if (DetectTrampolinePattern(funcPtr, hookType, target)) {
            int score = 2; // Critical functions get base score
            
            HMODULE targetMod = target ? FindModuleByAddress(target) : nullptr;
            
            if (target && !targetMod) {
                score += 3; // Unmapped memory
            } else if (target && targetMod != hMod) {
                std::wstring targetPath = tolower_ws(GetModulePath(targetMod));
                if (!IsSystemModule(targetMod) && !IsWhitelistedModule(targetPath)) {
                    score += 3; // Critical function hooked to non-system module!
                }
            }
            
            if (score >= m_threshold) {
                out.moduleName = GetModulePath(hMod);
                out.functionName = cf.function;
                out.functionAddress = funcPtr;
                out.hookTargetAddress = target;
                out.hookModule = targetMod ? GetModulePath(targetMod) : L"<unknown>";
                out.indicators = score;
                out.hookType = hookType;
                return true;
            }
        }
    }
    
    return false;
}

// ============== VTable Hook Scanner ==============

bool VTableHookScanner::IsSystemModule(HMODULE hMod) {
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(hMod, path, MAX_PATH);
    std::wstring pathLower = path;
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
    
    return pathLower.find(L"\\windows\\system32\\") != std::wstring::npos ||
           pathLower.find(L"\\windows\\syswow64\\") != std::wstring::npos;
}

HMODULE VTableHookScanner::FindModuleByAddress(PVOID addr) {
    HMODULE mods[1024]; 
    DWORD needed = 0;
    
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        size_t count = needed / sizeof(HMODULE);
        for (size_t i = 0; i < count; ++i) {
            MODULEINFO mi = {0};
            if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) 
                continue;
                
            BYTE* base = (BYTE*)mi.lpBaseOfDll;
            SIZE_T size = mi.SizeOfImage;
            
            if ((BYTE*)addr >= base && (BYTE*)addr < base + size) {
                return mods[i];
            }
        }
    }
    return nullptr;
}

bool VTableHookScanner::ScanVTable(void** vtable, size_t entries, const wchar_t* objectType, VTableHookFinding& out) {
    if (!vtable) return false;
    
    __try {
        for (size_t i = 0; i < entries; ++i) {
            PVOID funcPtr = vtable[i];
            if (!funcPtr) continue;
            
            HMODULE owner = FindModuleByAddress(funcPtr);
            if (!owner) {
                // VTable entry points to unmapped memory - highly suspicious
                out.objectType = objectType;
                out.vtable = vtable;
                out.entryIndex = i;
                out.hookedAddress = funcPtr;
                out.hookModule = L"<unmapped>";
                out.indicators = 5;
                return true;
            }
            
            if (!IsSystemModule(owner)) {
                // VTable entry points to non-system module
                wchar_t modPath[MAX_PATH] = {0};
                GetModuleFileNameW(owner, modPath, MAX_PATH);
                
                int score = 2;
                
                // D3D/OpenGL hooks to non-system DLL very suspicious
                if (wcsstr(objectType, L"D3D") || wcsstr(objectType, L"OpenGL")) {
                    score += 2;
                }
                
                if (score >= m_threshold) {
                    out.objectType = objectType;
                    out.vtable = vtable;
                    out.entryIndex = i;
                    out.hookedAddress = funcPtr;
                    out.hookModule = modPath;
                    out.indicators = score;
                    return true;
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    
    return false;
}

bool VTableHookScanner::ScanKnownVTables(VTableHookFinding& out) {
    out = VTableHookFinding{};
    
    // Note: This is a simplified example. In a real implementation,
    // you would need to obtain actual VTable pointers from D3D/OpenGL objects
    // This requires creating device instances or hooking object creation
    
    // Example for D3D9 (if device exists):
    // IDirect3DDevice9* pDevice = GetD3D9Device(); // implementation specific
    // if (pDevice) {
    //     void** vtable = *(void***)pDevice;
    //     if (ScanVTable(vtable, 119, L"IDirect3DDevice9", out)) {
    //         return true;
    //     }
    // }
    
    // For now, return false as we need actual object instances
    // This should be integrated with the game's graphics initialization
    return false;
}
