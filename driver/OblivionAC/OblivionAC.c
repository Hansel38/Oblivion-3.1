#include "OblivionAC.h"
#include <ntstrsafe.h>

typedef struct _DEVICE_CONTEXT {
    ULONG Events;
    FAST_MUTEX Lock;
    ULONG ProtectedPid;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL OblivionAC_EvtIoDeviceControl;

static PDEVICE_CONTEXT g_Ctx = NULL;
static PVOID g_ObRegHandle = NULL; // OB callbacks cookie
static REGHANDLE g_RegCb = NULL;   // Registry callback cookie
static BOOLEAN g_ImageNotifyRegistered = FALSE;
static BOOLEAN g_ThreadNotifyRegistered = FALSE;
static WDFTIMER g_TimeMonTimer = NULL; // periodic time monitor
// ===== PRIORITY 2.2.3: Kernel Driver Enhancement Globals =====
static PVOID g_ObjectNotifyHandle = NULL; // Object creation callback handle
static BOOLEAN g_ObjectNotifyRegistered = FALSE;
static LARGE_INTEGER g_ObCbCookie = {0}; // ObRegisterCallbacks cookie for object notification

// Pending events before ctx available
static ULONG g_PendingEvents = 0;

// Expected driver hash read from registry (FNV-1a 64-bit)
static ULONGLONG g_ExpectedDriverHash = 0;
static UNICODE_STRING g_DriverImagePath = {0}; // allocated

typedef VOID (NTAPI *PFN_KeQuerySystemTimePrecise)(PLARGE_INTEGER);
static PFN_KeQuerySystemTimePrecise g_pKeQuerySystemTimePrecise = NULL;

// Registry-driven config
static UNICODE_STRING* g_AllowPrefixes = NULL; static ULONG g_AllowPrefixCount = 0;
static UNICODE_STRING* g_AllowBaseNames = NULL; static ULONG g_AllowBaseCount = 0;
static BOOLEAN g_BlockProc = TRUE; static BOOLEAN g_BlockThr = TRUE; static BOOLEAN g_EnableImage = TRUE;

static VOID FreeAllowLists()
{
    if (g_AllowPrefixes) {
        for (ULONG i=0;i<g_AllowPrefixCount;++i) { if (g_AllowPrefixes[i].Buffer) ExFreePoolWithTag(g_AllowPrefixes[i].Buffer, 'CADO'); }
        ExFreePoolWithTag(g_AllowPrefixes, 'CADO'); g_AllowPrefixes=NULL; g_AllowPrefixCount=0;
    }
    if (g_AllowBaseNames) {
        for (ULONG i=0;i<g_AllowBaseCount;++i) { if (g_AllowBaseNames[i].Buffer) ExFreePoolWithTag(g_AllowBaseNames[i].Buffer, 'CADO'); }
        ExFreePoolWithTag(g_AllowBaseNames, 'CADO'); g_AllowBaseNames=NULL; g_AllowBaseCount=0;
    }
}

static VOID SetEventFlag(PDEVICE_CONTEXT ctx, ULONG flag)
{
    ExAcquireFastMutex(&ctx->Lock);
    ctx->Events |= flag;
    ExReleaseFastMutex(&ctx->Lock);
}

static VOID SetOrQueueEvent(ULONG flag)
{
    if (g_Ctx) {
        SetEventFlag(g_Ctx, flag);
    } else {
        InterlockedOr((volatile LONG*)&g_PendingEvents, (LONG)flag);
    }
}

static BOOLEAN StartsWithInsensitive(const UNICODE_STRING* s, const UNICODE_STRING* p)
{
    if (s->Length < p->Length) return FALSE;
    for (USHORT i=0;i<p->Length/2;++i) {
        WCHAR a = s->Buffer[i], b = p->Buffer[i];
        if (a>=L'a'&&a<=L'z') a -= 32; if (b>=L'a'&&b<=L'z') b -= 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

static VOID ToLowerInplace(PWCHAR buf, USHORT lenChars)
{
    for (USHORT i=0;i<lenChars;++i) { WCHAR c=buf[i]; if (c>=L'A'&&c<=L'Z') buf[i] = c + 32; }
}

static BOOLEAN EqualsInsensitive(const UNICODE_STRING* a, const UNICODE_STRING* b)
{
    if (a->Length != b->Length) return FALSE;
    for (USHORT i=0;i<a->Length/2;++i) {
        WCHAR ca=a->Buffer[i], cb=b->Buffer[i];
        if (ca>=L'a'&&ca<=L'z') ca-=32; if (cb>=L'a'&&cb<=L'z') cb-=32;
        if (ca != cb) return FALSE;
    }
    return TRUE;
}

static VOID BasenameOf(UNICODE_STRING* inout)
{
    USHORT len = inout->Length/2; PWCHAR p = inout->Buffer; USHORT last = 0;
    for (USHORT i=0;i<len;++i) { if (p[i]==L'\\' || p[i]==L'/') last = i+1; }
    if (last > 0) { inout->Buffer += last; inout->Length -= last*2; }
}

static VOID ParseSemicolonList(PWCHAR data, ULONG bytes, UNICODE_STRING** arrOut, ULONG* countOut)
{
    *arrOut = NULL; *countOut = 0; if (!data || bytes < 2) return;
    // Count tokens
    ULONG tokens = 0; ULONG i=0; while (i<bytes/2) { // until NUL
        ULONG start = i; while (i<bytes/2 && data[i] != L';' && data[i] != L'\0') ++i; if (i>start) ++tokens; if (i<bytes/2 && data[i]==L';') ++i; else break; }
    if (tokens==0) return;
    UNICODE_STRING* arr = (UNICODE_STRING*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(UNICODE_STRING)*tokens, 'CADO'); if (!arr) return;
    RtlZeroMemory(arr, sizeof(UNICODE_STRING)*tokens);
    i=0; ULONG idx=0; while (i<bytes/2 && idx<tokens) {
        ULONG start=i; while (i<bytes/2 && data[i] != L';' && data[i] != L'\0') ++i; ULONG len = i-start; if (len) {
            PWCHAR dup = (PWCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, (len+1)*sizeof(WCHAR), 'CADO'); if (!dup) break; RtlCopyMemory(dup, &data[start], len*sizeof(WCHAR)); dup[len]=L'\0';
            ToLowerInplace(dup, (USHORT)len);
            arr[idx].Buffer = dup; arr[idx].Length = (USHORT)(len*sizeof(WCHAR)); arr[idx].MaximumLength = (USHORT)((len+1)*sizeof(WCHAR)); ++idx;
        }
        if (i<bytes/2 && data[i]==L';') ++i; else break;
    }
    *arrOut = arr; *countOut = idx;
}

static VOID LoadRegistryConfig(_In_ PUNICODE_STRING ServiceKeyPath)
{
    UNICODE_STRING paramsPath; WCHAR buf[512]; paramsPath.Buffer = buf; paramsPath.MaximumLength = sizeof(buf); paramsPath.Length = 0;
    RtlStringCchCopyUnicodeString(buf, RTL_NUMBER_OF(buf), ServiceKeyPath);
    paramsPath.Length = (USHORT)wcslen(buf)*sizeof(WCHAR);
    RtlStringCchCatW(buf, RTL_NUMBER_OF(buf), L"\\Parameters");
    paramsPath.Length = (USHORT)wcslen(buf)*sizeof(WCHAR);

    OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, &paramsPath, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hKey; NTSTATUS status = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
    if (!NT_SUCCESS(status)) return;

    // Query AllowImagePrefixes
    ULONG size=0; UNICODE_STRING valName; RtlInitUnicodeString(&valName, L"AllowImagePrefixes");
    ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &size);
    if (size) {
        PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, size, 'CADO');
        if (kv && NT_SUCCESS(ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kv, size, &size))) {
            if (kv->Type == REG_SZ || kv->Type == REG_EXPAND_SZ) {
                ParseSemicolonList((PWCHAR)kv->Data, kv->DataLength, &g_AllowPrefixes, &g_AllowPrefixCount);
            }
        }
        if (kv) ExFreePoolWithTag(kv, 'CADO');
    }
    // Query AllowImageBaseNames
    size=0; RtlInitUnicodeString(&valName, L"AllowImageBaseNames");
    ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &size);
    if (size) {
        PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, size, 'CADO');
        if (kv && NT_SUCCESS(ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kv, size, &size))) {
            if (kv->Type == REG_SZ || kv->Type == REG_EXPAND_SZ) {
                ParseSemicolonList((PWCHAR)kv->Data, kv->DataLength, &g_AllowBaseNames, &g_AllowBaseCount);
            }
        }
        if (kv) ExFreePoolWithTag(kv, 'CADO');
    }
    // Toggles
    size=0; RtlInitUnicodeString(&valName, L"BlockProcessRights");
    ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &size);
    if (size) {
        PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, size, 'CADO');
        if (kv && NT_SUCCESS(ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kv, size, &size)) && kv->Type == REG_DWORD && kv->DataLength>=4) {
            g_BlockProc = (*(PULONG)kv->Data) ? TRUE : FALSE;
        }
        if (kv) ExFreePoolWithTag(kv, 'CADO');
    }
    size=0; RtlInitUnicodeString(&valName, L"BlockThreadRights");
    ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &size);
    if (size) {
        PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, size, 'CADO');
        if (kv && NT_SUCCESS(ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kv, size, &size)) && kv->Type == REG_DWORD && kv->DataLength>=4) {
            g_BlockThr = (*(PULONG)kv->Data) ? TRUE : FALSE;
        }
        if (kv) ExFreePoolWithTag(kv, 'CADO');
    }
    size=0; RtlInitUnicodeString(&valName, L"EnableImageNotify");
    ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &size);
    if (size) {
        PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, size, 'CADO');
        if (kv && NT_SUCCESS(ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kv, size, &size)) && kv->Type == REG_DWORD && kv->DataLength>=4) {
            g_EnableImage = (*(PULONG)kv->Data) ? TRUE : FALSE;
        }
        if (kv) ExFreePoolWithTag(kv, 'CADO');
    }

    ZwClose(hKey);
}

static VOID FreeDriverImagePath()
{
    if (g_DriverImagePath.Buffer) { ExFreePoolWithTag(g_DriverImagePath.Buffer, 'CADO'); g_DriverImagePath.Buffer=NULL; g_DriverImagePath.Length=0; g_DriverImagePath.MaximumLength=0; }
}

static VOID LoadDriverImagePath(_In_ PUNICODE_STRING ServiceKeyPath)
{
    OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, (PUNICODE_STRING)ServiceKeyPath, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hKey; NTSTATUS status = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
    if (!NT_SUCCESS(status)) return;

    ULONG size=0; UNICODE_STRING valName; RtlInitUnicodeString(&valName, L"ImagePath");
    ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &size);
    if (size) {
        PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, size, 'CADO');
        if (kv && NT_SUCCESS(ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kv, size, &size))) {
            if ((kv->Type == REG_SZ || kv->Type == REG_EXPAND_SZ) && kv->DataLength >= sizeof(WCHAR)) {
                USHORT len = (USHORT)kv->DataLength; USHORT chars = (USHORT)(len/sizeof(WCHAR));
                PWCHAR buf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, len, 'CADO');
                if (buf) {
                    RtlCopyMemory(buf, kv->Data, len);
                    // Lowercase in-place
                    ToLowerInplace(buf, chars);
                    FreeDriverImagePath();
                    g_DriverImagePath.Buffer = buf;
                    g_DriverImagePath.Length = len - sizeof(WCHAR); // exclude NUL
                    g_DriverImagePath.MaximumLength = len;
                }
            }
        }
        if (kv) ExFreePoolWithTag(kv, 'CADO');
    }

    ZwClose(hKey);
}

static ULONGLONG Fnv1a64(_In_reads_bytes_(len) const BYTE* data, _In_ SIZE_T len)
{
    const ULONGLONG FNV_OFFSET = 1469598103934665603ULL;
    const ULONGLONG FNV_PRIME  = 1099511628211ULL;
    ULONGLONG h = FNV_OFFSET;
    for (SIZE_T i=0;i<len;++i) { h ^= data[i]; h *= FNV_PRIME; }
    return h;
}

static BOOLEAN ParseHexU64(_In_reads_bytes_(len) const CHAR* s, _In_ SIZE_T len, _Out_ ULONGLONG* out)
{
    ULONGLONG v=0; SIZE_T i=0; if (len>=2 && s[0]=='0' && (s[1]=='x'||s[1]=='X')) { i=2; }
    for (; i<len; ++i) {
        CHAR c=s[i]; if (c=='\0') break; v <<= 4;
        if (c>='0'&&c<='9') v |= (c - '0');
        else if (c>='a'&&c<='f') v |= (c - 'a' + 10);
        else if (c>='A'&&c<='F') v |= (c - 'A' + 10);
        else return FALSE;
    }
    *out = v; return TRUE;
}

static VOID LoadExpectedDriverHash(_In_ PUNICODE_STRING ServiceKeyPath)
{
    // Parameters\DriverExpectedFNV (REG_SZ)
    UNICODE_STRING paramsPath; WCHAR buf[512]; paramsPath.Buffer = buf; paramsPath.MaximumLength = sizeof(buf); paramsPath.Length = 0;
    RtlStringCchCopyUnicodeString(buf, RTL_NUMBER_OF(buf), ServiceKeyPath);
    paramsPath.Length = (USHORT)wcslen(buf)*sizeof(WCHAR);
    RtlStringCchCatW(buf, RTL_NUMBER_OF(buf), L"\\Parameters");
    paramsPath.Length = (USHORT)wcslen(buf)*sizeof(WCHAR);

    OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, &paramsPath, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hKey; NTSTATUS status = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
    if (!NT_SUCCESS(status)) return;

    ULONG size=0; UNICODE_STRING valName; RtlInitUnicodeString(&valName, L"DriverExpectedFNV");
    ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, NULL, 0, &size);
    if (size) {
        PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, size, 'CADO');
        if (kv && NT_SUCCESS(ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation, kv, size, &size))) {
            if ((kv->Type == REG_SZ || kv->Type == REG_EXPAND_SZ) && kv->DataLength > 2) {
                // Convert to ANSI for simple parse; buffer is UNICODE
                ANSI_STRING as{}; UNICODE_STRING us; us.Buffer=(PWCHAR)kv->Data; us.Length=(USHORT)kv->DataLength - sizeof(WCHAR); us.MaximumLength=(USHORT)kv->DataLength;
                if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&as, &us, TRUE))) {
                    ULONGLONG tmp=0; if (ParseHexU64(as.Buffer, as.Length, &tmp)) g_ExpectedDriverHash = tmp;
                    RtlFreeAnsiString(&as);
                }
            }
        }
        if (kv) ExFreePoolWithTag(kv, 'CADO');
    }
    ZwClose(hKey);
}

static VOID VerifySelfIntegrityIfConfigured()
{
    if (!g_ExpectedDriverHash || g_DriverImagePath.Length == 0) return;
    // Open image path as provided (\SystemRoot\... supported)
    OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb; HANDLE hFile;
    InitializeObjectAttributes(&oa, &g_DriverImagePath, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE, NULL, NULL);
    NTSTATUS status = ZwCreateFile(&hFile, GENERIC_READ|SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                                   FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) return;
    BYTE* buf = (BYTE*)ExAllocatePoolWithTag(NonPagedPoolNx, 64*1024, 'CADO');
    if (!buf) { ZwClose(hFile); return; }
    ULONGLONG h = 1469598103934665603ULL; // init
    for (;;) {
        status = ZwReadFile(hFile, NULL, NULL, NULL, &iosb, buf, 64*1024, NULL, NULL);
        if (status == STATUS_END_OF_FILE) break;
        if (!NT_SUCCESS(status)) break;
        if (iosb.Information == 0) break;
        h = Fnv1a64(buf, iosb.Information) ^ (h<<1);
    }
    ExFreePoolWithTag(buf, 'CADO'); ZwClose(hFile);
    if (h && h != g_ExpectedDriverHash) {
        SetOrQueueEvent(KAC_EVENT_DRIVER_HASH_MISMATCH);
    }
}

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

static VOID CheckCodeIntegrityStatus()
{
    SYSTEM_CODEINTEGRITY_INFORMATION ci = {0}; ci.Length = sizeof(ci);
    NTSTATUS status = ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)103 /*SystemCodeIntegrityInformation*/, &ci, sizeof(ci), NULL);
    if (NT_SUCCESS(status)) {
        // Flags documented partially; test signing bit (0x02), etc.
        if (ci.CodeIntegrityOptions & 0x02 /*TestSigning*/) {
            SetOrQueueEvent(KAC_EVENT_CI_TAMPER);
        }
    }
}

// Very minimal DBK driver detection by name
static VOID ScanForDbkDriver(PDEVICE_CONTEXT ctx)
{
    PVOID buffer = NULL; ULONG size = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return;
    buffer = ExAllocatePoolWithTag(NonPagedPoolNx, size, 'CADO');
    if (!buffer) return;
    if (NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, buffer, size, &size))) {
        typedef struct _RTL_PROCESS_MODULE_INFORMATION {
            HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize; ULONG Flags; USHORT LoadOrderIndex; USHORT InitOrderIndex; USHORT LoadCount; USHORT OffsetToFileName; UCHAR FullPathName[256];
        } RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;
        typedef struct _RTL_PROCESS_MODULES { ULONG NumberOfModules; RTL_PROCESS_MODULE_INFORMATION Modules[1]; } RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;
        PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)buffer;
        for (ULONG i=0;i<mods->NumberOfModules;++i) {
            const char* name = (const char*)mods->Modules[i].FullPathName + mods->Modules[i].OffsetToFileName;
            if (name) {
                for (const char* p = name; *p; ++p) {
                    if ((p[0]=='d'||p[0]=='D') && (p[1]=='b'||p[1]=='B') && (p[2]=='k'||p[2]=='K')) {
                        SetEventFlag(ctx, KAC_EVENT_DBK_DRIVER_DETECTED);
                        i = mods->NumberOfModules; break;
                    }
                }
            }
        }
    }
    ExFreePoolWithTag(buffer, 'CADO');
}

// ===== PRIORITY 2.2.3: Device Object Name Pattern Detection =====
// Check if device/driver name contains suspicious patterns
static BOOLEAN IsSuspiciousDeviceObjectName(_In_ PUNICODE_STRING ObjectName)
{
    if (!ObjectName || !ObjectName->Buffer || ObjectName->Length == 0) {
        return FALSE;
    }

    // Convert to lowercase for comparison
    WCHAR tempBuf[256];
    USHORT copyLen = min(ObjectName->Length / sizeof(WCHAR), (USHORT)(RTL_NUMBER_OF(tempBuf) - 1));
    RtlCopyMemory(tempBuf, ObjectName->Buffer, copyLen * sizeof(WCHAR));
    tempBuf[copyLen] = L'\0';
    ToLowerInplace(tempBuf, copyLen);

    // Known CE/DBK device object patterns
    const WCHAR* suspiciousPatterns[] = {
        L"dbk",
        L"cedriver",
        L"speedhack",
        L"kernelcheatengine",
        L"cheatengine",
        L"memhack",
        L"procmem",
        L"kernelmemory",
        L"physmem",
        L"dbutil"  // DBK utility pattern
    };

    for (size_t i = 0; i < sizeof(suspiciousPatterns) / sizeof(suspiciousPatterns[0]); ++i) {
        if (wcsstr(tempBuf, suspiciousPatterns[i]) != NULL) {
            return TRUE;
        }
    }

    return FALSE;
}

// ===== PRIORITY 2.2.3: Driver Load Monitoring =====
// Enhanced driver load detection with suspicious characteristics
static VOID DriverLoadNotify(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(ProcessId);
    
    if (!g_Ctx) return;
    
    // Only monitor kernel driver loads (ProcessId == NULL for system context)
    if (ProcessId != NULL) return;
    
    if (!FullImageName || !FullImageName->Buffer || FullImageName->Length == 0) {
        return;
    }

    // Check if driver name contains suspicious patterns
    if (IsSuspiciousDeviceObjectName(FullImageName)) {
        SetEventFlag(g_Ctx, KAC_EVENT_SUSPICIOUS_DRIVER_LOAD);
    }

    // Check for unsigned/test-signed drivers (basic check via image info)
    if (ImageInfo && ImageInfo->ImageSignatureLevel == SE_SIGNING_LEVEL_UNCHECKED) {
        // Unsigned driver loading could indicate DBK or similar
        // Additional check: if name is suspicious AND unsigned
        if (IsSuspiciousDeviceObjectName(FullImageName)) {
            SetEventFlag(g_Ctx, KAC_EVENT_SUSPICIOUS_DRIVER_LOAD);
        }
    }
}

// === OB callbacks to strip hostile access to protected PID ===
#define BAD_PROC_RIGHTS (PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD|PROCESS_SUSPEND_RESUME)
#define BAD_THR_RIGHTS  (THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME)

static BOOLEAN IsCallerDebuggerish()
{
    // Check SeDebugPrivilege
    if (SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE), KeGetPreviousMode())) {
        return TRUE;
    }
    // Check image name
    PEPROCESS caller = PsGetCurrentProcess();
    const char* name = PsGetProcessImageFileName(caller);
    if (!name) return FALSE;
    // Compare lowercased ASCII against a small set
    char buf[16] = {0};
    size_t i=0; for (; i<sizeof(buf)-1 && name[i]; ++i) { char c=name[i]; if (c>='A'&&c<='Z') c=(char)(c+32); buf[i]=c; }
    buf[i]='\0';
    const char* dbg[] = { "x64dbg.exe", "x32dbg.exe", "windbg.exe", "ida64.exe", "ida.exe", "ollydbg.exe", "cheatengine.exe", "scylla.exe" };
    for (int k=0;k<(int)(sizeof(dbg)/sizeof(dbg[0]));++k) {
        // suffix compare: endswith
        size_t bl = strlen(buf), dl = strlen(dbg[k]);
        if (bl>=dl && memcmp(buf+(bl-dl), dbg[k], dl)==0) return TRUE;
    }
    return FALSE;
}

static OB_PREOP_CALLBACK_STATUS PreOpCallbackProcess(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (!g_Ctx || Info->ObjectType != *PsProcessType) return OB_PREOP_SUCCESS;
    if (!g_BlockProc) return OB_PREOP_SUCCESS;
    if (!Info->KernelHandle && g_Ctx->ProtectedPid) {
        PEPROCESS target = (PEPROCESS)Info->Object;
        ULONG pid = (ULONG)(ULONG_PTR)PsGetProcessId(target);
        if (pid == g_Ctx->ProtectedPid) {
            ACCESS_MASK* desired = &Info->Parameters->CreateHandleInformation.DesiredAccess;
            ACCESS_MASK before = *desired;
            if (before & PROCESS_SUSPEND_RESUME) {
                if (IsCallerDebuggerish()) {
                    if (g_Ctx) SetEventFlag(g_Ctx, KAC_EVENT_DEBUG_SUSPEND_ATTEMPT); else InterlockedOr((volatile LONG*)&g_PendingEvents, (LONG)KAC_EVENT_DEBUG_SUSPEND_ATTEMPT);
                }
            }
            *desired &= ~BAD_PROC_RIGHTS;
            if (*desired != before) {
                SetEventFlag(g_Ctx, KAC_EVENT_BLOCKED_HANDLE_RIGHTS);
            }
        }
    }
    return OB_PREOP_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS PreOpCallbackThread(_In_ PVOID RegistrationContext, _In_ POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (!g_Ctx || Info->ObjectType != *PsThreadType) return OB_PREOP_SUCCESS;
    if (!g_BlockThr) return OB_PREOP_SUCCESS;
    if (!Info->KernelHandle && g_Ctx->ProtectedPid) {
        PETHREAD thread = (PETHREAD)Info->Object;
        PEPROCESS owner = IoThreadToProcess(thread);
        ULONG pid = (ULONG)(ULONG_PTR)PsGetProcessId(owner);
        if (pid == g_Ctx->ProtectedPid) {
            ACCESS_MASK* desired = &Info->Parameters->CreateHandleInformation.DesiredAccess;
            ACCESS_MASK before = *desired;
            if (before & THREAD_SUSPEND_RESUME) {
                if (IsCallerDebuggerish()) {
                    if (g_Ctx) SetEventFlag(g_Ctx, KAC_EVENT_DEBUG_SUSPEND_ATTEMPT); else InterlockedOr((volatile LONG*)&g_PendingEvents, (LONG)KAC_EVENT_DEBUG_SUSPEND_ATTEMPT);
                }
            }
            *desired &= ~BAD_THR_RIGHTS;
            if (*desired != before) {
                SetEventFlag(g_Ctx, KAC_EVENT_BLOCKED_HANDLE_RIGHTS);
            }
        }
    }
    return OB_PREOP_SUCCESS;
}

static VOID RegisterObCallbacks()
{
    OB_OPERATION_REGISTRATION ops[2] = {0};
    OB_CALLBACK_REGISTRATION reg = {0};

    ops[0].ObjectType = PsProcessType;
    ops[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[0].PreOperation = PreOpCallbackProcess;
    ops[0].PostOperation = NULL;

    ops[1].ObjectType = PsThreadType;
    ops[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[1].PreOperation = PreOpCallbackThread;
    ops[1].PostOperation = NULL;

    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 2;
    reg.OperationRegistration = ops;
    reg.RegistrationContext = NULL;

    NTSTATUS status = ObRegisterCallbacks(&reg, &g_ObRegHandle);
    if (!NT_SUCCESS(status)) {
        g_ObRegHandle = NULL;
    }
}

static VOID UnregisterObCallbacks()
{
    if (g_ObRegHandle) {
        ObUnRegisterCallbacks(g_ObRegHandle);
        g_ObRegHandle = NULL;
    }
}

// === Registry callback to detect tampering ===
EX_CALLBACK_FUNCTION OblivionAC_RegCallback;

static VOID RegisterRegistryCallback(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING ServiceKeyPath)
{
    UNICODE_STRING altitude; RtlInitUnicodeString(&altitude, L"321000"); // arbitrary altitude
    NTSTATUS status = CmRegisterCallbackEx(OblivionAC_RegCallback, &altitude, DriverObject, NULL, &g_RegCb, ServiceKeyPath);
    UNREFERENCED_PARAMETER(status);
}

static VOID UnregisterRegistryCallback()
{
    if (g_RegCb) { CmUnRegisterCallback(g_RegCb); g_RegCb = NULL; }
}

// === Timer: time dilation/speedhack detection ===
_Use_decl_annotations_
EVT_WDF_TIMER TimeMon_EvtTimer;

_Use_decl_annotations_
VOID TimeMon_EvtTimer(WDFTIMER Timer)
{
    UNREFERENCED_PARAMETER(Timer);
    static LARGE_INTEGER lastQpc = {0};
    static LARGE_INTEGER lastSys = {0};
    static ULONGLONG lastFreq = 0;
    static int badCount = 0;

    LARGE_INTEGER freq; LARGE_INTEGER qpc = KeQueryPerformanceCounter(&freq);
    LARGE_INTEGER sys;
    if (g_pKeQuerySystemTimePrecise) g_pKeQuerySystemTimePrecise(&sys); else KeQuerySystemTime(&sys);

    if (lastQpc.QuadPart == 0 || lastFreq == 0) { lastQpc = qpc; lastSys = sys; lastFreq = (ULONGLONG)freq.QuadPart; return; }

    LONGLONG dqpc = qpc.QuadPart - lastQpc.QuadPart;
    LONGLONG dsys = sys.QuadPart - lastSys.QuadPart; // 100ns units
    if (dqpc <= 0 || dsys <= 0 || lastFreq == 0) { lastQpc = qpc; lastSys = sys; return; }

    double secQpc = (double)dqpc / (double)lastFreq;
    double secSys = (double)dsys / 10000000.0; // 1e7 100ns per second
    double ratio = (secSys > 0.0) ? (secQpc / secSys) : 1.0;

    // Expect ratio ~1.0; allow generous jitter 0.7..1.3
    if (ratio < 0.7 || ratio > 1.3) {
        if (++badCount >= 5) { // sustained anomaly
            if (g_Ctx) SetEventFlag(g_Ctx, KAC_EVENT_TIME_DILATION); else InterlockedOr((volatile LONG*)&g_PendingEvents, (LONG)KAC_EVENT_TIME_DILATION);
            badCount = 0; // rate limit
        }
    } else if (badCount > 0) {
        --badCount;
    }

    lastQpc = qpc; lastSys = sys; lastFreq = (ULONGLONG)freq.QuadPart;
}

// === Image load notify to flag suspicious images in protected process ===
static VOID ImageLoadNotify(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
{
    // ===== PRIORITY 2.2.3: Enhanced with driver load detection =====
    // First, check for kernel driver loads (ProcessId == NULL or system context)
    if (ProcessId == NULL || (ULONG_PTR)ProcessId <= 4) {
        DriverLoadNotify(FullImageName, ProcessId, ImageInfo);
    }
    
    // Original protected process image load monitoring
    if (!g_Ctx || !g_Ctx->ProtectedPid) return;
    if ((ULONG)(ULONG_PTR)ProcessId != g_Ctx->ProtectedPid) return;
    if (!g_EnableImage) return;
    if (FullImageName && FullImageName->Buffer && FullImageName->Length) {
        UNICODE_STRING path = *FullImageName;
        // Lowercase clone in temp buffer
        WCHAR tmpBuf[512]; USHORT copyLen = min(path.Length/2, (USHORT)(RTL_NUMBER_OF(tmpBuf)-1));
        RtlCopyMemory(tmpBuf, path.Buffer, copyLen*sizeof(WCHAR)); tmpBuf[copyLen]=L'\0';
        ToLowerInplace(tmpBuf, copyLen);
        UNICODE_STRING lowPath; RtlInitUnicodeString(&lowPath, tmpBuf);
        // Skip system roots
        if (wcsstr(tmpBuf, L"\\systemroot\\") || wcsstr(tmpBuf, L"\\windows\\")) return;
        // Allowlist prefixes
        for (ULONG i=0;i<g_AllowPrefixCount;++i) {
            if (StartsWithInsensitive(&lowPath, &g_AllowPrefixes[i])) return;
        }
        // Allowlist base names
        UNICODE_STRING base = lowPath; BasenameOf(&base);
        for (ULONG i=0;i<g_AllowBaseCount;++i) {
            if (EqualsInsensitive(&base, &g_AllowBaseNames[i])) return;
        }
    }
    SetEventFlag(g_Ctx, KAC_EVENT_SUSPICIOUS_IMAGE);
}

// Thread notify for anti-suspend/monitoring
static VOID ThreadNotifyCallback(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ThreadId);
    UNREFERENCED_PARAMETER(Create);
    if (!g_Ctx || !g_Ctx->ProtectedPid) return;
    if ((ULONG)(ULONG_PTR)ProcessId != g_Ctx->ProtectedPid) return;
    SetEventFlag(g_Ctx, KAC_EVENT_THREAD_ACTIVITY);
}

// ===== PRIORITY 2.2.3: Object Creation Callback =====
// Monitor device object and driver object creation for suspicious patterns
typedef NTSTATUS (*PFN_ObRegisterCallbacks)(
    _In_ POB_CALLBACK_REGISTRATION CallbackRegistration,
    _Outptr_ PVOID *RegistrationHandle
);

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

// Object pre-operation callback for Device/Driver objects
static OB_PREOP_CALLBACK_STATUS ObjectPreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    
    if (!g_Ctx) return OB_PREOP_SUCCESS;
    
    // Only interested in handle creation
    if (OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE) {
        return OB_PREOP_SUCCESS;
    }
    
    // Get object type
    POBJECT_TYPE objectType = OperationInformation->ObjectType;
    if (!objectType) return OB_PREOP_SUCCESS;
    
    // We want to monitor IoDeviceObjectType and IoDriverObjectType
    // These are not directly exposed, so we check by querying object type info
    OBJECT_TYPE_INFORMATION typeInfo;
    ULONG returnLength = 0;
    
    NTSTATUS status = ObQueryObjectAuditingByHandle(
        OperationInformation->Object,
        &typeInfo,
        sizeof(typeInfo),
        &returnLength
    );
    
    if (!NT_SUCCESS(status)) return OB_PREOP_SUCCESS;
    
    // Check if it's a Device or Driver object type
    if (typeInfo.TypeName.Buffer && typeInfo.TypeName.Length > 0) {
        // Check for "Device" or "Driver" in type name
        WCHAR tempBuf[64];
        USHORT copyLen = min(typeInfo.TypeName.Length / sizeof(WCHAR), (USHORT)(RTL_NUMBER_OF(tempBuf) - 1));
        RtlCopyMemory(tempBuf, typeInfo.TypeName.Buffer, copyLen * sizeof(WCHAR));
        tempBuf[copyLen] = L'\0';
        ToLowerInplace(tempBuf, copyLen);
        
        BOOLEAN isDeviceOrDriver = (wcsstr(tempBuf, L"device") != NULL) || 
                                   (wcsstr(tempBuf, L"driver") != NULL);
        
        if (isDeviceOrDriver) {
            // Try to get object name
            POBJECT_NAME_INFORMATION nameInfo = NULL;
            ULONG nameInfoSize = 512;
            
            nameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(
                NonPagedPoolNx, 
                nameInfoSize, 
                'CADO'
            );
            
            if (nameInfo) {
                status = ObQueryNameString(
                    OperationInformation->Object,
                    nameInfo,
                    nameInfoSize,
                    &returnLength
                );
                
                if (NT_SUCCESS(status) && nameInfo->Name.Buffer && nameInfo->Name.Length > 0) {
                    // Check if name contains suspicious patterns
                    if (IsSuspiciousDeviceObjectName(&nameInfo->Name)) {
                        if (wcsstr(tempBuf, L"device") != NULL) {
                            SetEventFlag(g_Ctx, KAC_EVENT_SUSPICIOUS_DEVICE_OBJECT);
                        } else if (wcsstr(tempBuf, L"driver") != NULL) {
                            SetEventFlag(g_Ctx, KAC_EVENT_SUSPICIOUS_DRIVER_OBJECT);
                        }
                    }
                }
                
                ExFreePoolWithTag(nameInfo, 'CADO');
            }
        }
    }
    
    return OB_PREOP_SUCCESS;
}

// Register object creation monitoring
static VOID RegisterObjectCreationCallbacks()
{
    // Note: Modern Windows versions don't expose IoDeviceObjectType directly
    // This is a best-effort approach using available Object Manager callbacks
    // A more robust solution would use kernel driver enumeration
    
    // For now, we rely on the existing PsSetLoadImageNotifyRoutine
    // which we've enhanced with DriverLoadNotify function
    
    // The ObjectPreCallback above would work if we had access to object types
    // In practice, detecting device objects is better done via periodic enumeration
    // from user-mode (which we already implemented in DeviceObjectScanner)
    
    g_ObjectNotifyRegistered = TRUE;
}

static VOID UnregisterObjectCreationCallbacks()
{
    if (g_ObjectNotifyRegistered) {
        // Cleanup if we registered any callbacks
        g_ObjectNotifyRegistered = FALSE;
    }
}

NTSTATUS OblivionAC_EvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    UNREFERENCED_PARAMETER(Driver);

    WDFDEVICE device; NTSTATUS status;
    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_UNKNOWN);

    status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) return status;

    PDEVICE_CONTEXT ctx = DeviceGetContext(device);
    ctx->Events = 0; ctx->ProtectedPid = 0; ExInitializeFastMutex(&ctx->Lock);
    g_Ctx = ctx;

    // Flush any pending pre-init events
    if (g_PendingEvents) {
        ExAcquireFastMutex(&ctx->Lock);
        ctx->Events |= g_PendingEvents;
        g_PendingEvents = 0;
        ExReleaseFastMutex(&ctx->Lock);
    }

    WDF_IO_QUEUE_CONFIG ioQueueConfig; WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchSequential);
    ioQueueConfig.EvtIoDeviceControl = OblivionAC_EvtIoDeviceControl;
    WDFQUEUE queue; status = WdfIoQueueCreate(device, &ioQueueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) return status;

    // Expose DOS symbolic link
    DECLARE_CONST_UNICODE_STRING(symLink, OBLIVIONAC_DOS_DEVICE_NAME);
    WdfDeviceCreateSymbolicLink(device, &symLink);

    // Initial scan and registrations
    ScanForDbkDriver(ctx);
    RegisterObCallbacks();
    
    // ===== PRIORITY 2.2.3: Register object creation monitoring =====
    RegisterObjectCreationCallbacks();
    
    if (NT_SUCCESS(PsSetLoadImageNotifyRoutine(ImageLoadNotify))) {
        g_ImageNotifyRegistered = TRUE;
    }
    if (NT_SUCCESS(PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback))) {
        g_ThreadNotifyRegistered = TRUE;
    }
    // Create periodic timer for time dilation monitor (~1s)
    WDF_TIMER_CONFIG tcfg; WDF_TIMER_CONFIG_INIT_PERIODIC(&tcfg, TimeMon_EvtTimer, 1000);
    WDF_OBJECT_ATTRIBUTES ta; WDF_OBJECT_ATTRIBUTES_INIT(&ta);
    ta.ParentObject = device; // auto-cleanup with device
    if (NT_SUCCESS(WdfTimerCreate(&tcfg, &ta, &g_TimeMonTimer))) {
        WdfTimerStart(g_TimeMonTimer, WDF_REL_TIMEOUT_IN_MS(1000));
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID OblivionAC_EvtDriverContextCleanup(WDFOBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    if (g_ImageNotifyRegistered) {
        PsRemoveLoadImageNotifyRoutine(ImageLoadNotify);
        g_ImageNotifyRegistered = FALSE;
    }
    if (g_ThreadNotifyRegistered) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        g_ThreadNotifyRegistered = FALSE;
    }
    // ===== PRIORITY 2.2.3: Cleanup object creation callbacks =====
    UnregisterObjectCreationCallbacks();
    
    UnregisterObCallbacks();
    UnregisterRegistryCallback();
    FreeAllowLists();
    FreeDriverImagePath();
    g_Ctx = NULL;
}

// ===== PRIORITY 3: Stealth & Evasion Detection Helper Functions =====

// Enumerate ETHREAD structures for a process
NTSTATUS EnumerateEThreads(
    _In_ ULONG ProcessId,
    _In_ ULONG MaxThreadCount,
    _Inout_ PKAC_ENUM_ETHREAD_RESPONSE Response,
    _In_ ULONG BufferSize
)
{
    if (!Response || BufferSize < sizeof(KAC_ENUM_ETHREAD_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Response->ThreadCount = 0;
    Response->HiddenThreadCount = 0;

    // Walk the thread list in EPROCESS
    // EPROCESS->ThreadListHead offset varies by Windows version
    // Using hardcoded offsets for Windows 10 (0x5E0 for x64)
    #ifdef _WIN64
        const ULONG_PTR ThreadListHeadOffset = 0x5E0;
        const ULONG_PTR ThreadListEntryOffset = 0x6B8;
    #else
        const ULONG_PTR ThreadListHeadOffset = 0x428;
        const ULONG_PTR ThreadListEntryOffset = 0x450;
    #endif

    PLIST_ENTRY ThreadListHead = (PLIST_ENTRY)((PUCHAR)Process + ThreadListHeadOffset);
    PLIST_ENTRY CurrentEntry = ThreadListHead->Flink;

    ULONG count = 0;
    while (CurrentEntry != ThreadListHead && count < MaxThreadCount) {
        // Calculate ETHREAD from ThreadListEntry
        PETHREAD Thread = (PETHREAD)((PUCHAR)CurrentEntry - ThreadListEntryOffset);
        
        if (MmIsAddressValid(Thread)) {
            HANDLE ThreadId = PsGetThreadId(Thread);
            PKAC_ETHREAD_INFO info = &Response->Threads[count];
            
            info->ThreadId = HandleToULong(ThreadId);
            info->StartAddress = 0; // Would need to read from ETHREAD
            info->Win32StartAddress = 0;
            info->State = 0;
            info->WaitReason = 0;
            info->IsHidden = FALSE;
            info->IsSuspicious = FALSE;
            info->TebBase = 0;
            info->StackBase = 0;
            info->StackLimit = 0;
            
            // Check if thread is hidden (not in CreateThread snapshot)
            // This requires comparing with PsGetNextProcessThread
            PETHREAD ValidatedThread = NULL;
            if (NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &ValidatedThread))) {
                if (ValidatedThread != Thread) {
                    info->IsHidden = TRUE;
                    info->IsSuspicious = TRUE;
                    Response->HiddenThreadCount++;
                }
                ObDereferenceObject(ValidatedThread);
            } else {
                info->IsHidden = TRUE;
                info->IsSuspicious = TRUE;
                Response->HiddenThreadCount++;
            }
            
            // Check CrossThreadFlags for suspicious flags
            // CrossThreadFlags offset: 0x6B4 (x64), 0x450 (x86)
            #ifdef _WIN64
                PULONG CrossThreadFlags = (PULONG)((PUCHAR)Thread + 0x6B4);
            #else
                PULONG CrossThreadFlags = (PULONG)((PUCHAR)Thread + 0x450);
            #endif
            
            if (MmIsAddressValid(CrossThreadFlags)) {
                if (*CrossThreadFlags & 0x200) { // PS_CROSS_THREAD_FLAGS_HIDE_FROM_DEBUGGER
                    info->IsSuspicious = TRUE;
                }
            }
            
            count++;
        }
        
        CurrentEntry = CurrentEntry->Flink;
    }

    Response->ThreadCount = count;

    ObDereferenceObject(Process);
    return STATUS_SUCCESS;
}

// Get VAD information for a process
NTSTATUS GetVADInformation(
    _In_ ULONG ProcessId,
    _In_ ULONG_PTR BaseAddress,
    _In_ ULONG MaxVadCount,
    _Inout_ PKAC_VAD_INFO_RESPONSE Response,
    _In_ ULONG BufferSize
)
{
    if (!Response || BufferSize < sizeof(KAC_VAD_INFO_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Response->VadCount = 0;
    Response->SuspiciousVadCount = 0;

    // VAD root is in EPROCESS->VadRoot
    // Offset varies: 0x658 (Win10 x64), 0x478 (Win10 x86)
    #ifdef _WIN64
        const ULONG_PTR VadRootOffset = 0x658;
    #else
        const ULONG_PTR VadRootOffset = 0x478;
    #endif

    // VadRoot is an RTL_AVL_TREE structure (single PVOID pointer to root node)
    PVOID* VadRootPtr = (PVOID*)((PUCHAR)Process + VadRootOffset);
    
    if (!MmIsAddressValid(VadRootPtr) || !(*VadRootPtr)) {
        ObDereferenceObject(Process);
        return STATUS_NOT_FOUND;
    }

    // Walk VAD tree (simplified - in-order traversal)
    // VAD node structure: _MMVAD
    // We'll do a simple stack-based traversal
    PVOID VadStack[256];
    ULONG StackTop = 0;
    VadStack[StackTop++] = *VadRootPtr;
    
    ULONG count = 0;
    while (StackTop > 0 && count < MaxVadCount) {
        PVOID VadNode = VadStack[--StackTop];
        
        if (!MmIsAddressValid(VadNode)) {
            continue;
        }

        // _MMVAD structure offsets (Windows 10 x64):
        // +0x000: Core (RTL_BALANCED_NODE)
        // +0x018: u (flags/type)
        // +0x020: StartingVpn
        // +0x028: EndingVpn
        
        PUCHAR VadPtr = (PUCHAR)VadNode;
        
        // RTL_BALANCED_NODE at offset 0
        PVOID* LeftChild = (PVOID*)(VadPtr + 0x00);
        PVOID* RightChild = (PVOID*)(VadPtr + 0x08);
        
        // StartingVpn/EndingVpn at offset 0x18, 0x20 (simplified)
        #ifdef _WIN64
            PULONG_PTR StartVpn = (PULONG_PTR)(VadPtr + 0x18);
            PULONG_PTR EndVpn = (PULONG_PTR)(VadPtr + 0x20);
        #else
            PULONG StartVpn = (PULONG)(VadPtr + 0x10);
            PULONG EndVpn = (PULONG)(VadPtr + 0x14);
        #endif
        
        if (MmIsAddressValid(StartVpn) && MmIsAddressValid(EndVpn)) {
            ULONG_PTR StartVpnVal = *StartVpn;
            ULONG_PTR EndVpnVal = *EndVpn;
            ULONG_PTR StartAddr = StartVpnVal << 12; // VPN to address
            ULONG_PTR EndAddr = (EndVpnVal << 12) | 0xFFF;
            SIZE_T Size = EndAddr - StartAddr + 1;
            
            // If BaseAddress specified, only return matching VAD
            if (BaseAddress == 0 || (BaseAddress >= StartAddr && BaseAddress <= EndAddr)) {
                PKAC_VAD_ENTRY entry = &Response->Vads[count];
                entry->StartingVpn = StartVpnVal;
                entry->EndingVpn = EndVpnVal;
                entry->StartingAddress = StartAddr;
                entry->EndingAddress = EndAddr;
                entry->SizeInBytes = Size;
                entry->Protection = 0; // Would need to parse VadFlags
                entry->VadType = 0;
                entry->IsPrivate = FALSE;
                entry->IsSuspicious = FALSE;
                entry->Flags = 0;
                
                // Check for suspicious characteristics
                if (Size > 100 * 1024 * 1024) { // >100MB
                    entry->IsSuspicious = TRUE;
                    Response->SuspiciousVadCount++;
                }
                
                count++;
                
                if (BaseAddress != 0) {
                    // Found specific VAD, stop
                    break;
                }
            }
        }
        
        // Push children to stack
        if (MmIsAddressValid(RightChild) && *RightChild && StackTop < 256) {
            VadStack[StackTop++] = *RightChild;
        }
        if (MmIsAddressValid(LeftChild) && *LeftChild && StackTop < 256) {
            VadStack[StackTop++] = *LeftChild;
        }
    }

    Response->VadCount = count;

    ObDereferenceObject(Process);
    return STATUS_SUCCESS;
}

// Get kernel callback information
NTSTATUS GetKernelCallbacks(
    _In_ ULONG CallbackType,
    _In_ ULONG MaxCallbackCount,
    _Inout_ PKAC_CALLBACK_INFO_RESPONSE Response,
    _In_ ULONG BufferSize
)
{
    if (!Response || BufferSize < sizeof(KAC_CALLBACK_INFO_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Response->CallbackCount = 0;
    Response->SuspiciousCallbackCount = 0;

    // Kernel callback arrays are not directly exposed
    // We would need to locate them via pattern scanning or hardcoded offsets
    // This is a simplified implementation that demonstrates the structure
    
    // For production, you'd need to:
    // 1. Find PspCreateProcessNotifyRoutine array (process notify)
    // 2. Find PspCreateThreadNotifyRoutine array (thread notify)
    // 3. Find PspLoadImageNotifyRoutine array (image notify)
    // 4. Walk array and collect non-NULL entries
    
    // Example for process notify callbacks (simplified):
    if (CallbackType == 0) { // ProcessNotify
        // PspCreateProcessNotifyRoutine is an array of EX_CALLBACK_ROUTINE_BLOCK structures
        // Maximum 64 entries on Windows 10
        // This is just a placeholder - real implementation needs pattern scanning
        
        // Return empty for now (would need kernel base + pattern scan)
        Response->CallbackCount = 0;
    }
    else if (CallbackType == 1) { // ThreadNotify
        Response->CallbackCount = 0;
    }
    else if (CallbackType == 2) { // ImageNotify
        Response->CallbackCount = 0;
    }
    else {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

// Validate if ETHREAD is in ThreadListHead
NTSTATUS ValidateEThread(
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId,
    _Inout_ PKAC_VALIDATE_ETHREAD_RESPONSE Response
)
{
    if (!Response) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Response, sizeof(KAC_VALIDATE_ETHREAD_RESPONSE));
    Response->ThreadExists = FALSE;
    Response->IsHidden = FALSE;
    Response->IsSuspicious = FALSE;

    // Lookup thread by ID
    PETHREAD Thread = NULL;
    NTSTATUS status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)ThreadId, &Thread);
    if (!NT_SUCCESS(status)) {
        return STATUS_NOT_FOUND;
    }

    Response->ThreadExists = TRUE;
    Response->ThreadInfo.ThreadId = ThreadId;

    // Check if thread belongs to process
    PEPROCESS ThreadProcess = PsGetThreadProcess(Thread);
    HANDLE ThreadProcessId = PsGetProcessId(ThreadProcess);
    
    if (HandleToULong(ThreadProcessId) != ProcessId) {
        ObDereferenceObject(Thread);
        return STATUS_SUCCESS; // Valid thread but wrong process
    }

    // Now walk the process's ThreadListHead to verify it's in the list
    PEPROCESS Process = NULL;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(Thread);
        return status;
    }

    #ifdef _WIN64
        const ULONG_PTR ThreadListHeadOffset = 0x5E0;
        const ULONG_PTR ThreadListEntryOffset = 0x6B8;
    #else
        const ULONG_PTR ThreadListHeadOffset = 0x428;
        const ULONG_PTR ThreadListEntryOffset = 0x450;
    #endif

    PLIST_ENTRY ThreadListHead = (PLIST_ENTRY)((PUCHAR)Process + ThreadListHeadOffset);
    PLIST_ENTRY CurrentEntry = ThreadListHead->Flink;

    BOOLEAN foundInList = FALSE;
    while (CurrentEntry != ThreadListHead) {
        PETHREAD CurrentThread = (PETHREAD)((PUCHAR)CurrentEntry - ThreadListEntryOffset);
        
        if (CurrentThread == Thread) {
            foundInList = TRUE;
            break;
        }
        
        CurrentEntry = CurrentEntry->Flink;
    }

    if (!foundInList) {
        Response->IsHidden = TRUE;
        Response->IsSuspicious = TRUE;
        Response->ThreadInfo.IsHidden = TRUE;
        Response->ThreadInfo.IsSuspicious = TRUE;
    }

    ObDereferenceObject(Process);
    ObDereferenceObject(Thread);

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID OblivionAC_EvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    WDFDEVICE device = WdfIoQueueGetDevice(Queue);
    PDEVICE_CONTEXT ctx = DeviceGetContext(device);

    if (IoControlCode == IOCTL_OBLIVIONAC_PEEK) {
        if (OutputBufferLength < sizeof(KAC_STATUS)) { status = STATUS_BUFFER_TOO_SMALL; }
        else {
            PKAC_STATUS outBuf = NULL; size_t outSize = 0;
            status = WdfRequestRetrieveOutputBuffer(Request, sizeof(KAC_STATUS), (PVOID*)&outBuf, &outSize);
            if (NT_SUCCESS(status)) {
                ExAcquireFastMutex(&ctx->Lock);
                outBuf->Events = ctx->Events;
                ctx->Events = 0; // consume
                outBuf->Reserved = 0;
                ExReleaseFastMutex(&ctx->Lock);
                WdfRequestSetInformation(Request, sizeof(KAC_STATUS));
            }
        }
    } else if (IoControlCode == IOCTL_OBLIVIONAC_SET_PROTECTED_PID) {
        if (InputBufferLength < sizeof(KAC_PROTECT_CFG)) { status = STATUS_BUFFER_TOO_SMALL; }
        else {
            PKAC_PROTECT_CFG inBuf = NULL; size_t inSize = 0;
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(KAC_PROTECT_CFG), (PVOID*)&inBuf, &inSize);
            if (NT_SUCCESS(status)) {
                ctx->ProtectedPid = inBuf->Pid;
                status = STATUS_SUCCESS;
                WdfRequestSetInformation(Request, 0);
            }
        }
    }
    // ===== PRIORITY 3: Stealth & Evasion Detection IOCTLs =====
    else if (IoControlCode == IOCTL_OBLIVIONAC_ENUM_ETHREAD) {
        // Enumerate ETHREAD structures for a process
        if (InputBufferLength < sizeof(KAC_ENUM_ETHREAD_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            PKAC_ENUM_ETHREAD_REQUEST inBuf = NULL;
            PKAC_ENUM_ETHREAD_RESPONSE outBuf = NULL;
            size_t inSize = 0, outSize = 0;
            
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(KAC_ENUM_ETHREAD_REQUEST), (PVOID*)&inBuf, &inSize);
            if (NT_SUCCESS(status)) {
                status = WdfRequestRetrieveOutputBuffer(Request, sizeof(KAC_ENUM_ETHREAD_RESPONSE), (PVOID*)&outBuf, &outSize);
                if (NT_SUCCESS(status)) {
                    // Call helper function to enumerate threads
                    status = EnumerateEThreads(inBuf->ProcessId, inBuf->MaxThreadCount, outBuf, (ULONG)outSize);
                    if (NT_SUCCESS(status)) {
                        WdfRequestSetInformation(Request, sizeof(KAC_ENUM_ETHREAD_RESPONSE) + 
                            (outBuf->ThreadCount - 1) * sizeof(KAC_ETHREAD_INFO));
                    }
                }
            }
        }
    }
    else if (IoControlCode == IOCTL_OBLIVIONAC_GET_VAD_INFO) {
        // Get VAD information for a process
        if (InputBufferLength < sizeof(KAC_VAD_INFO_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            PKAC_VAD_INFO_REQUEST inBuf = NULL;
            PKAC_VAD_INFO_RESPONSE outBuf = NULL;
            size_t inSize = 0, outSize = 0;
            
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(KAC_VAD_INFO_REQUEST), (PVOID*)&inBuf, &inSize);
            if (NT_SUCCESS(status)) {
                status = WdfRequestRetrieveOutputBuffer(Request, sizeof(KAC_VAD_INFO_RESPONSE), (PVOID*)&outBuf, &outSize);
                if (NT_SUCCESS(status)) {
                    // Call helper function to get VAD info
                    status = GetVADInformation(inBuf->ProcessId, inBuf->BaseAddress, inBuf->MaxVadCount, outBuf, (ULONG)outSize);
                    if (NT_SUCCESS(status)) {
                        WdfRequestSetInformation(Request, sizeof(KAC_VAD_INFO_RESPONSE) + 
                            (outBuf->VadCount - 1) * sizeof(KAC_VAD_ENTRY));
                    }
                }
            }
        }
    }
    else if (IoControlCode == IOCTL_OBLIVIONAC_GET_CALLBACKS) {
        // Get kernel callback information
        if (InputBufferLength < sizeof(KAC_CALLBACK_INFO_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            PKAC_CALLBACK_INFO_REQUEST inBuf = NULL;
            PKAC_CALLBACK_INFO_RESPONSE outBuf = NULL;
            size_t inSize = 0, outSize = 0;
            
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(KAC_CALLBACK_INFO_REQUEST), (PVOID*)&inBuf, &inSize);
            if (NT_SUCCESS(status)) {
                status = WdfRequestRetrieveOutputBuffer(Request, sizeof(KAC_CALLBACK_INFO_RESPONSE), (PVOID*)&outBuf, &outSize);
                if (NT_SUCCESS(status)) {
                    // Call helper function to get callback info
                    status = GetKernelCallbacks(inBuf->CallbackType, inBuf->MaxCallbackCount, outBuf, (ULONG)outSize);
                    if (NT_SUCCESS(status)) {
                        WdfRequestSetInformation(Request, sizeof(KAC_CALLBACK_INFO_RESPONSE) + 
                            (outBuf->CallbackCount - 1) * sizeof(KAC_CALLBACK_ENTRY));
                    }
                }
            }
        }
    }
    else if (IoControlCode == IOCTL_OBLIVIONAC_VALIDATE_ETHREAD) {
        // Validate if ETHREAD is in ThreadListHead
        if (InputBufferLength < sizeof(KAC_VALIDATE_ETHREAD_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            PKAC_VALIDATE_ETHREAD_REQUEST inBuf = NULL;
            PKAC_VALIDATE_ETHREAD_RESPONSE outBuf = NULL;
            size_t inSize = 0, outSize = 0;
            
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(KAC_VALIDATE_ETHREAD_REQUEST), (PVOID*)&inBuf, &inSize);
            if (NT_SUCCESS(status)) {
                status = WdfRequestRetrieveOutputBuffer(Request, sizeof(KAC_VALIDATE_ETHREAD_RESPONSE), (PVOID*)&outBuf, &outSize);
                if (NT_SUCCESS(status)) {
                    // Call helper function to validate thread
                    status = ValidateEThread(inBuf->ProcessId, inBuf->ThreadId, outBuf);
                    if (NT_SUCCESS(status)) {
                        WdfRequestSetInformation(Request, sizeof(KAC_VALIDATE_ETHREAD_RESPONSE));
                    }
                }
            }
        }
    }

    WdfRequestComplete(Request, status);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    // Load Parameters from registry
    LoadRegistryConfig(RegistryPath);
    // Register registry callback to detect tampering under our service key
    RegisterRegistryCallback(DriverObject, RegistryPath);
    // Record driver image path and expected hash
    LoadDriverImagePath(RegistryPath);
    LoadExpectedDriverHash(RegistryPath);
    // Check CI status and self-integrity (queue events until device add)
    CheckCodeIntegrityStatus();
    VerifySelfIntegrityIfConfigured();
    // Resolve KeQuerySystemTimePrecise if available
    {
        UNICODE_STRING fn; RtlInitUnicodeString(&fn, L"KeQuerySystemTimePrecise");
        g_pKeQuerySystemTimePrecise = (PFN_KeQuerySystemTimePrecise)MmGetSystemRoutineAddress(&fn);
    }

    WDF_DRIVER_CONFIG config; WDF_DRIVER_CONFIG_INIT(&config, OblivionAC_EvtDeviceAdd);
    config.EvtDriverUnload = NULL;

    NTSTATUS status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    return status;
}

_Use_decl_annotations_
EX_CALLBACK_FUNCTION OblivionAC_RegCallback
{
    UNREFERENCED_PARAMETER(Arg2);
    if (!g_Ctx) return STATUS_SUCCESS;
    REG_NOTIFY_CLASS cls = (REG_NOTIFY_CLASS)Reason;
    switch (cls) {
    case RegNtPreSetValueKey:
    case RegNtPreDeleteKey:
    case RegNtPreDeleteValueKey:
    case RegNtPreSetInformationKey:
    case RegNtPreRenameKey:
        SetEventFlag(g_Ctx, KAC_EVENT_REG_TAMPER);
        break;
    default:
        break;
    }
    return STATUS_SUCCESS;
}
