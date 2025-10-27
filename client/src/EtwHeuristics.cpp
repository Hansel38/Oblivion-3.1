#include "../pch.h"
#include "EtwHeuristics.h"
#include "../include/NetworkClient.h"
#include "../include/JsonBuilder.h"
#include "../include/ClientVersion.h"
#include "../include/HWID.h"
#include <evntrace.h>
#include <tdh.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <cwchar>
#pragma comment(lib, "tdh.lib")

// GUIDs for kernel providers (Classic kernel providers on NT Kernel Logger)
static const GUID GUID_KERNEL_PROCESS = {0x3D6FA8D0,0xFE05,0x11D0,{0x9E,0xFB,0x00,0xAA,0x00,0x61,0xB0,0x6C}};
static const GUID GUID_KERNEL_THREAD  = {0x3D6FA8D1,0xFE05,0x11D0,{0x9E,0xFB,0x00,0xAA,0x00,0x61,0xB0,0x6C}};
static const GUID GUID_KERNEL_IMAGE   = {0x2CB15D1D,0x5FC1,0x11D2,{0xAB,0xE1,0x00,0xA0,0xC9,0x11,0xF5,0x18}};
static const GUID GUID_KERNEL_MEMORY  = {0x3D6FA8D3,0xFE05,0x11D0,{0x9E,0xFB,0x00,0xAA,0x00,0x61,0xB0,0x6C}};
static const GUID GUID_KERNEL_FILE    = {0xEDD08927,0x9CC4,0x4E65,{0xB9,0x70,0xC2,0x56,0x0F,0xB5,0xC2,0x89}};

struct Counter { ULONG count=0; ULONGLONG start=0; };

struct SeqState { ULONGLONG lastOpen=0; ULONGLONG lastMem=0; ULONGLONG lastMap=0; ULONGLONG lastThr=0; ULONGLONG lastReport=0; };

struct EtwState {
    TRACEHANDLE trace = 0;
    std::atomic<bool>* run = nullptr;
    DWORD pid = 0;
    int threshold = 10; // default burst threshold per window
    ULONG windowMs = 3000;
    std::unordered_map<ULONG, Counter> thrByPid; // thread starts per PID
    std::unordered_map<ULONG, Counter> imgByPid; // image loads per PID
    std::unordered_map<ULONG, Counter> memByPid; // memory events per PID
    std::unordered_map<ULONG, Counter> fileByPid; // file map events per PID
    std::unordered_map<ULONG, Counter> procByPid; // process API events per PID (OpenProcess, etc.)
    std::unordered_map<ULONG, SeqState> seq; // sequence correlation per PID
    NetworkClient* net = nullptr;
};

static void SendEtwBurst(NetworkClient* net, DWORD targetPid, const wchar_t* what, ULONG count)
{
    std::wstring reason = L"ETW burst: "; reason += what; reason += L" x"; reason += std::to_wstring(count);
    std::string json = JsonBuilder::BuildDetectionReport(targetPid, L"<etw>", reason, "etw", 1, GetHWID(), OBLIVION_CLIENT_VERSION, (int)count);
    if (net) net->SendMessage(json);
}

static void SendEtwSeq(NetworkClient* net, DWORD targetPid, const wchar_t* label)
{
    std::wstring reason = L"ETW sequence: "; reason += label;
    std::string json = JsonBuilder::BuildDetectionReport(targetPid, L"<etw>", reason, "etw", 1, GetHWID(), OBLIVION_CLIENT_VERSION, 3);
    if (net) net->SendMessage(json);
}

// Try to fetch event name/task/opcode from TDH metadata for flexible matching
static void GetEventNameParts(PEVENT_RECORD rec, std::wstring& evtName, std::wstring& taskName, std::wstring& opcodeName)
{
    evtName.clear(); taskName.clear(); opcodeName.clear();
    DWORD size = 0; PTRACE_EVENT_INFO info = nullptr;
    if (TdhGetEventInformation(rec, 0, nullptr, nullptr, &size) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> buf(size);
        info = reinterpret_cast<PTRACE_EVENT_INFO>(buf.data());
        if (TdhGetEventInformation(rec, 0, nullptr, info, &size) == ERROR_SUCCESS) {
            if (info->EventNameOffset) evtName.assign((wchar_t*)((BYTE*)info + info->EventNameOffset));
            if (info->TaskNameOffset) taskName.assign((wchar_t*)((BYTE*)info + info->TaskNameOffset));
            if (info->OpcodeNameOffset) opcodeName.assign((wchar_t*)((BYTE*)info + info->OpcodeNameOffset));
        }
    }
}

static bool WcsContainsInsensitive(const std::wstring& hay, const wchar_t* needle)
{
    if (needle == nullptr || *needle == 0) return false;
    std::wstring n(needle);
    // naive lowercase compare
    auto tolow = [](std::wstring s){ for (auto& c : s) c = (wchar_t)towlower(c); return s; };
    std::wstring H = tolow(hay), N = tolow(n);
    return H.find(N) != std::wstring::npos;
}

static void MaybeTriggerSeq(EtwState* st, ULONG pid, ULONGLONG now)
{
    SeqState& ss = st->seq[pid];
    const ULONGLONG win = st->windowMs;
    auto inwin = [&](ULONGLONG t){ return t && (now - t) <= win; };
    if (ss.lastReport && (now - ss.lastReport) < (win*2)) return; // rate limit per pid

    bool haveOpen = inwin(ss.lastOpen);
    bool haveMem = inwin(ss.lastMem);
    bool haveMap = inwin(ss.lastMap);
    bool haveThr = inwin(ss.lastThr);

    if (haveOpen && haveMem && haveThr) {
        ss.lastReport = now;
        SendEtwSeq(st->net, pid, L"OpenProcess + Write/ReadVirtual + CreateThread");
        return;
    }
    if (haveOpen && haveMap && haveThr) {
        ss.lastReport = now;
        SendEtwSeq(st->net, pid, L"OpenProcess + MapView + CreateThread");
        return;
    }
}

static void CALLBACK OnEvent(PEVENT_RECORD rec)
{
    EtwState* st = reinterpret_cast<EtwState*>(rec->UserContext);
    if (!st || !st->run || !st->run->load()) return;

    const GUID& prov = rec->EventHeader.ProviderId;
    ULONG pid = rec->EventHeader.ProcessId;
    if (pid == 0 || pid == 4 || pid == st->pid) return; // skip idle/system/self
    const ULONGLONG now = GetTickCount64();

    auto bump = [&](std::unordered_map<ULONG, Counter>& m, ULONG key, const wchar_t* label){
        Counter& c = m[key];
        if (c.start == 0 || (now - c.start) > st->windowMs) { c.start = now; c.count = 0; }
        ++c.count;
        if ((int)c.count >= st->threshold) {
            // trigger once per window
            c.count = 0; c.start = now;
            SendEtwBurst(st->net, key, label, st->threshold);
        }
    };

    // Fast-path by provider where possible
    if (IsEqualGUID(prov, GUID_KERNEL_THREAD)) {
        // Event ID 1 = ThreadStart
        if (rec->EventHeader.EventDescriptor.Id == 1) {
            bump(st->thrByPid, pid, L"ThreadStart");
            st->seq[pid].lastThr = now;
            MaybeTriggerSeq(st, pid, now);
        }
        return;
    }
    if (IsEqualGUID(prov, GUID_KERNEL_IMAGE)) {
        bump(st->imgByPid, pid, L"ImageLoad");
        return;
    }
    if (IsEqualGUID(prov, GUID_KERNEL_MEMORY)) {
        bump(st->memByPid, pid, L"Memory");
        st->seq[pid].lastMem = now;
        MaybeTriggerSeq(st, pid, now);
        // Fallthrough to TDH name matching as well
    }
    if (IsEqualGUID(prov, GUID_KERNEL_FILE)) {
        bump(st->fileByPid, pid, L"FileMap");
        st->seq[pid].lastMap = now;
        MaybeTriggerSeq(st, pid, now);
        // Fallthrough to TDH name matching as well
    }
    if (IsEqualGUID(prov, GUID_KERNEL_PROCESS)) {
        // Use TDH name to detect OpenProcess
        std::wstring ev, task, opc; GetEventNameParts(rec, ev, task, opc);
        if (WcsContainsInsensitive(ev, L"OpenProcess") || WcsContainsInsensitive(task, L"OpenProcess") || WcsContainsInsensitive(opc, L"OpenProcess")) {
            bump(st->procByPid, pid, L"OpenProcess");
            st->seq[pid].lastOpen = now;
            MaybeTriggerSeq(st, pid, now);
            return;
        }
    }

    // Generic TDH name matching to catch: ReadVirtualMemory, WriteVirtualMemory, MapViewOfSection/MapViewOfFile, CreateThread
    std::wstring ev, task, opc; GetEventNameParts(rec, ev, task, opc);
    if (!ev.empty() || !task.empty() || !opc.empty()) {
        if (WcsContainsInsensitive(ev, L"ReadVirtual") || WcsContainsInsensitive(task, L"ReadVirtual") || WcsContainsInsensitive(opc, L"ReadVirtual")) {
            bump(st->memByPid, pid, L"ReadVirtualMemory");
            st->seq[pid].lastMem = now; MaybeTriggerSeq(st, pid, now);
            return;
        }
        if (WcsContainsInsensitive(ev, L"WriteVirtual") || WcsContainsInsensitive(task, L"WriteVirtual") || WcsContainsInsensitive(opc, L"WriteVirtual")) {
            bump(st->memByPid, pid, L"WriteVirtualMemory");
            st->seq[pid].lastMem = now; MaybeTriggerSeq(st, pid, now);
            return;
        }
        if (WcsContainsInsensitive(ev, L"MapView") || WcsContainsInsensitive(task, L"MapView") || WcsContainsInsensitive(opc, L"MapView")) {
            bump(st->fileByPid, pid, L"MapViewOfSection");
            st->seq[pid].lastMap = now; MaybeTriggerSeq(st, pid, now);
            return;
        }
        if (WcsContainsInsensitive(ev, L"CreateThread") || WcsContainsInsensitive(task, L"CreateThread") || WcsContainsInsensitive(opc, L"CreateThread")) {
            bump(st->thrByPid, pid, L"CreateThread");
            st->seq[pid].lastThr = now; MaybeTriggerSeq(st, pid, now);
            return;
        }
    }
}

EtwHeuristics::EtwHeuristics(NetworkClient* net, int threshold, DWORD windowMs)
    : m_net(net), m_threshold(threshold), m_windowMs(windowMs) {}

EtwHeuristics::~EtwHeuristics() { Stop(); }

bool EtwHeuristics::Start()
{
    if (m_run.exchange(true)) return true;
    m_thread = std::thread(ThreadMain, this);
    return true;
}

void EtwHeuristics::Stop()
{
    if (!m_run.exchange(false)) return;
    if (m_thread.joinable()) m_thread.join();
}

void EtwHeuristics::UpdateParameters(int threshold, DWORD windowMs)
{
    if (threshold > 0) m_threshold.store(threshold);
    if (windowMs >= 100) m_windowMs.store(windowMs);
}

void EtwHeuristics::ThreadMain(EtwHeuristics* self)
{
    self->Run();
}

void EtwHeuristics::Run()
{
    // Try to consume the NT Kernel Logger real-time session.
    EVENT_TRACE_LOGFILEW log = {0};
    log.LoggerName = (LPWSTR)KERNEL_LOGGER_NAME; // L"NT Kernel Logger"
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;

    EtwState st{}; st.run = &m_run; st.pid = GetCurrentProcessId(); st.threshold = max(5, m_threshold.load()); st.windowMs = m_windowMs.load(); st.net = m_net;
    log.EventRecordCallback = OnEvent;
    log.Context = &st;

    TRACEHANDLE h = OpenTraceW(&log);
    if (h == INVALID_PROCESSTRACE_HANDLE) {
        // Unable to attach (no privs or not running). Fallback to idle loop.
        while (m_run.load()) Sleep(500);
        return;
    }

    st.trace = h;
    // Process events until stop
    ProcessTrace(&h, 1, nullptr, nullptr);

    CloseTrace(h);
}
