#include "../pch.h"
#include "KernelBridge.h"
#include "../include/NetworkClient.h"
#include "../include/JsonBuilder.h"
#include "../../common/OblivionAC_ioctl.h"
#include <atomic>
#include <thread>

static std::atomic<bool> g_kbRun{false};
static std::thread g_kbThread;
static NetworkClient* g_kbNet = nullptr;
static std::atomic<bool> g_kbDisabled{false};

static std::string WToUtf8(const std::wstring& ws)
{
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
}

static bool ProbeDriverOnce()
{
    HANDLE h = CreateFileW(OBLIVIONAC_USER_SYMLINK, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    KAC_STATUS st{}; DWORD out = 0; BOOL ok = DeviceIoControl(h, IOCTL_OBLIVIONAC_PEEK, nullptr, 0, &st, sizeof(st), &out, nullptr);
    CloseHandle(h);
    if (!ok) return false;
    if (out < sizeof(KAC_STATUS)) return false; // malformed/mismatched driver
    return true;
}

static void Loop()
{
    HANDLE h = CreateFileW(OBLIVIONAC_USER_SYMLINK, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { g_kbDisabled.store(true); return; }

    // Best-effort: set protected PID = current game proc (ignore failure)
    KAC_PROTECT_CFG cfg{}; cfg.Pid = GetCurrentProcessId(); DWORD bytes = 0;
    (void)DeviceIoControl(h, IOCTL_OBLIVIONAC_SET_PROTECTED_PID, &cfg, sizeof(cfg), nullptr, 0, &bytes, nullptr);

    DWORD consecutiveFails = 0;

    while (g_kbRun.load()) {
        KAC_STATUS st{}; DWORD out = 0;
        BOOL ok = DeviceIoControl(h, IOCTL_OBLIVIONAC_PEEK, nullptr, 0, &st, sizeof(st), &out, nullptr);
        if (!ok || out < sizeof(KAC_STATUS)) {
            if (++consecutiveFails >= 3) {
                // Give up this session to avoid stressing a buggy driver
                break;
            }
            Sleep(1000);
            continue;
        }
        consecutiveFails = 0;

        if (st.Events != 0 && g_kbNet) {
            std::wstring reason;
            if (st.Events & KAC_EVENT_DBK_DRIVER_DETECTED) reason += L"DBK driver detected; ";
            if (st.Events & KAC_EVENT_BLOCKED_HANDLE_RIGHTS) reason += L"Blocked suspicious handle rights; ";
            if (st.Events & KAC_EVENT_SUSPICIOUS_IMAGE) reason += L"Suspicious image load; ";
            if (st.Events & KAC_EVENT_REG_TAMPER) reason += L"Registry tamper under service key; ";
            if (st.Events & KAC_EVENT_DRIVER_HASH_MISMATCH) reason += L"Driver self-hash mismatch; ";
            if (st.Events & KAC_EVENT_CI_TAMPER) reason += L"Code Integrity/test signing enabled; ";
            if (st.Events & KAC_EVENT_THREAD_ACTIVITY) reason += L"Thread activity in protected process; ";
            if (st.Events & KAC_EVENT_TIME_DILATION) reason += L"Time dilation/speedhack suspected by kernel; ";
            if (st.Events & KAC_EVENT_DEBUG_SUSPEND_ATTEMPT) reason += L"Debugger-specific suspend rights attempt; ";
            if (!reason.empty()) {
                std::string msg = JsonBuilder::BuildDetectionReport(GetCurrentProcessId(), L"<kernel>", reason, "kernel", 1, "", "");
                g_kbNet->SendMessage(msg);
            }
        }
        Sleep(300);
    }
    CloseHandle(h);
}

void KernelBridge_Start(NetworkClient* netClient)
{
    // Allow opt-out via env var to avoid BSOD on problematic systems
    wchar_t buf[8]{}; if (GetEnvironmentVariableW(L"OBLIVION_KB_DISABLE", buf, 8) > 0) { g_kbDisabled.store(true); }
    if (g_kbDisabled.load()) return;

    // Probe driver before spinning a thread
    if (!ProbeDriverOnce()) { g_kbDisabled.store(true); return; }

    g_kbNet = netClient; g_kbRun.store(true);
    g_kbThread = std::thread(Loop);
}

void KernelBridge_Stop()
{
    g_kbRun.store(false);
    if (g_kbThread.joinable()) g_kbThread.join();
}
