// Simple DLL injector for testing OblivionClient.dll
// Build: Console App (x86), C++17. Link with: advapi32.lib

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <iostream>

static void PrintUsage()
{
    std::wcout << L"Usage: loader.exe <ProcessName.exe|PID> <FullPathToDLL>" << std::endl;
}

static bool EnableSeDebugPrivilege()
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    return ok;
}

static DWORD FindProcessIdByName(const std::wstring& name)
{
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        std::wstring target = name; 
        for (auto& c : target) c = towlower(c);
        do {
            std::wstring pn = pe.szExeFile; for (auto& c : pn) c = towlower(c);
            if (pn == target) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static bool IsNumber(const std::wstring& s)
{
    if (s.empty()) return false;
    for (wchar_t c : s) if (c < L'0' || c > L'9') return false;
    return true;
}

static bool InjectDll(DWORD pid, const std::wstring& dllPath)
{
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        std::wcerr << L"OpenProcess failed: " << GetLastError() << std::endl;
        return false;
    }

    size_t bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(hProc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        std::wcerr << L"VirtualAllocEx failed: " << GetLastError() << std::endl;
        CloseHandle(hProc);
        return false;
    }

    if (!WriteProcessMemory(hProc, remote, dllPath.c_str(), bytes, nullptr)) {
        std::wcerr << L"WriteProcessMemory failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLib = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!loadLib) {
        std::wcerr << L"GetProcAddress(LoadLibraryW) failed" << std::endl;
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLib, remote, 0, nullptr);
    if (!hThread) {
        std::wcerr << L"CreateRemoteThread failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    WaitForSingleObject(hThread, 10000);

    DWORD exitCode = 0; GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (exitCode == 0) {
        std::wcerr << L"LoadLibraryW in remote process failed (exitCode=0)" << std::endl;
        return false;
    }

    return true;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 3) { PrintUsage(); return 1; }

    std::wstring procArg = argv[1];
    std::wstring dllPath = argv[2];

    EnableSeDebugPrivilege(); // best-effort

    DWORD pid = 0;
    if (IsNumber(procArg)) {
        pid = (DWORD)std::wcstoul(procArg.c_str(), nullptr, 10);
    } else {
        pid = FindProcessIdByName(procArg);
    }

    if (pid == 0) {
        std::wcerr << L"Target process not found: " << procArg << std::endl;
        return 2;
    }

    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"DLL not found: " << dllPath << std::endl;
        return 3;
    }

    std::wcout << L"Injecting '" << dllPath << L"' into PID " << pid << L"..." << std::endl;
    if (!InjectDll(pid, dllPath)) {
        std::wcerr << L"Injection failed." << std::endl;
        return 4;
    }

    std::wcout << L"Injection succeeded." << std::endl;
    return 0;
}
