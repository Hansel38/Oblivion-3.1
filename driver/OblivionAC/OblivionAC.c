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
    UNREFERENCED_PARAMETER(ImageInfo);
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
    UnregisterObCallbacks();
    UnregisterRegistryCallback();
    FreeAllowLists();
    g_Ctx = NULL;
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
