#pragma once
#include <winioctl.h>

#define OBLIVIONAC_DEVICE_NAME      L"\\Device\\OblivionAC"
#define OBLIVIONAC_DOS_DEVICE_NAME  L"\\DosDevices\\OblivionAC"
#define OBLIVIONAC_USER_SYMLINK     L"\\\\.\\OblivionAC"

#define FILE_DEVICE_OBLIVION_AC  0x9876

#define IOCTL_OBLIVIONAC_PEEK             CTL_CODE(FILE_DEVICE_OBLIVION_AC, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OBLIVIONAC_SET_PROTECTED_PID CTL_CODE(FILE_DEVICE_OBLIVION_AC, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ===== PRIORITY 3: Stealth & Evasion Detection IOCTLs =====
#define IOCTL_OBLIVIONAC_ENUM_ETHREAD      CTL_CODE(FILE_DEVICE_OBLIVION_AC, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OBLIVIONAC_GET_VAD_INFO      CTL_CODE(FILE_DEVICE_OBLIVION_AC, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OBLIVIONAC_GET_CALLBACKS     CTL_CODE(FILE_DEVICE_OBLIVION_AC, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OBLIVIONAC_VALIDATE_ETHREAD  CTL_CODE(FILE_DEVICE_OBLIVION_AC, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Bitmask events from kernel to user
#define KAC_EVENT_DBK_DRIVER_DETECTED     0x00000001
#define KAC_EVENT_BLOCKED_HANDLE_RIGHTS   0x00000002
#define KAC_EVENT_SUSPICIOUS_IMAGE        0x00000004
#define KAC_EVENT_REG_TAMPER              0x00000008
#define KAC_EVENT_DRIVER_HASH_MISMATCH    0x00000010
#define KAC_EVENT_CI_TAMPER               0x00000020
#define KAC_EVENT_THREAD_ACTIVITY         0x00000040
// Time dilation / speedhack detected by kernel timer correlation
#define KAC_EVENT_TIME_DILATION           0x00000080
// Debugger-specific suspend attempt observed (SeDebugPrivilege or known debugger image)
#define KAC_EVENT_DEBUG_SUSPEND_ATTEMPT   0x00000100
// ===== PRIORITY 2.2.3: Kernel Driver Enhancement Events =====
// Suspicious device object creation detected (DBK/CEDRIVER patterns)
#define KAC_EVENT_SUSPICIOUS_DEVICE_OBJECT 0x00000200
// Suspicious driver object creation detected
#define KAC_EVENT_SUSPICIOUS_DRIVER_OBJECT 0x00000400
// DBK-characteristic IOCTL registration detected
#define KAC_EVENT_DBK_IOCTL_PATTERN        0x00000800
// Kernel driver load with suspicious characteristics
#define KAC_EVENT_SUSPICIOUS_DRIVER_LOAD   0x00001000
// ===== PRIORITY 3: Stealth & Evasion Detection Events =====
// Hidden ETHREAD detected (unlinked from ThreadListHead)
#define KAC_EVENT_HIDDEN_THREAD            0x00002000
// VAD tree manipulation detected
#define KAC_EVENT_VAD_MANIPULATION         0x00004000
// Kernel callback unhook detected
#define KAC_EVENT_CALLBACK_UNHOOK          0x00008000

typedef struct _KAC_STATUS
{
    ULONG Events;   // bitmask of KAC_EVENT_*
    ULONG Reserved; // future fields
} KAC_STATUS, *PKAC_STATUS;

typedef struct _KAC_PROTECT_CFG
{
    ULONG Pid; // protected process id
} KAC_PROTECT_CFG, *PKAC_PROTECT_CFG;

// ===== PRIORITY 3: Stealth & Evasion Detection Structures =====

// ETHREAD enumeration request
typedef struct _KAC_ENUM_ETHREAD_REQUEST
{
    ULONG ProcessId;
    ULONG MaxThreadCount;  // Max threads to return (prevents buffer overflow)
} KAC_ENUM_ETHREAD_REQUEST, *PKAC_ENUM_ETHREAD_REQUEST;

// Single ETHREAD info
typedef struct _KAC_ETHREAD_INFO
{
    ULONG ThreadId;
    ULONG_PTR StartAddress;
    ULONG_PTR Win32StartAddress;
    UCHAR State;           // Thread state (Running, Waiting, etc.)
    UCHAR WaitReason;
    BOOLEAN IsHidden;      // TRUE if unlinked from ThreadListHead
    BOOLEAN IsSuspicious;  // TRUE if suspicious characteristics
    ULONG_PTR TebBase;
    ULONG_PTR StackBase;
    ULONG_PTR StackLimit;
} KAC_ETHREAD_INFO, *PKAC_ETHREAD_INFO;

// ETHREAD enumeration response
typedef struct _KAC_ENUM_ETHREAD_RESPONSE
{
    ULONG ThreadCount;
    ULONG HiddenThreadCount;
    KAC_ETHREAD_INFO Threads[1]; // Variable-length array
} KAC_ENUM_ETHREAD_RESPONSE, *PKAC_ENUM_ETHREAD_RESPONSE;

// VAD information request
typedef struct _KAC_VAD_INFO_REQUEST
{
    ULONG ProcessId;
    ULONG_PTR BaseAddress;  // 0 = get all VADs, or specific address
    ULONG MaxVadCount;      // Max VADs to return
} KAC_VAD_INFO_REQUEST, *PKAC_VAD_INFO_REQUEST;

// Single VAD entry
typedef struct _KAC_VAD_ENTRY
{
    ULONG_PTR StartingVpn;  // Virtual Page Number
    ULONG_PTR EndingVpn;
    ULONG_PTR StartingAddress; // Actual address (VPN << PAGE_SHIFT)
    ULONG_PTR EndingAddress;
    SIZE_T SizeInBytes;
    ULONG Protection;       // PAGE_* flags
    ULONG VadType;         // PrivateMemory, Mapped, Image
    BOOLEAN IsPrivate;
    BOOLEAN IsSuspicious;  // Anomaly detected
    ULONG Flags;
} KAC_VAD_ENTRY, *PKAC_VAD_ENTRY;

// VAD information response
typedef struct _KAC_VAD_INFO_RESPONSE
{
    ULONG VadCount;
    ULONG SuspiciousVadCount;
    KAC_VAD_ENTRY Vads[1]; // Variable-length array
} KAC_VAD_INFO_RESPONSE, *PKAC_VAD_INFO_RESPONSE;

// Kernel callback information request
typedef struct _KAC_CALLBACK_INFO_REQUEST
{
    ULONG CallbackType;    // 0=ProcessNotify, 1=ThreadNotify, 2=ImageNotify
    ULONG MaxCallbackCount;
} KAC_CALLBACK_INFO_REQUEST, *PKAC_CALLBACK_INFO_REQUEST;

// Single callback entry
typedef struct _KAC_CALLBACK_ENTRY
{
    ULONG_PTR CallbackAddress;
    ULONG_PTR DriverBase;
    WCHAR DriverName[64];
    BOOLEAN IsHooked;      // TRUE if callback appears modified
    BOOLEAN IsUnhooked;    // TRUE if callback was removed
    BOOLEAN IsSuspicious;
    ULONG Index;           // Index in callback array
} KAC_CALLBACK_ENTRY, *PKAC_CALLBACK_ENTRY;

// Kernel callback information response
typedef struct _KAC_CALLBACK_INFO_RESPONSE
{
    ULONG CallbackCount;
    ULONG SuspiciousCallbackCount;
    KAC_CALLBACK_ENTRY Callbacks[1]; // Variable-length array
} KAC_CALLBACK_INFO_RESPONSE, *PKAC_CALLBACK_INFO_RESPONSE;

// ETHREAD validation request (check if thread is in ThreadListHead)
typedef struct _KAC_VALIDATE_ETHREAD_REQUEST
{
    ULONG ProcessId;
    ULONG ThreadId;
} KAC_VALIDATE_ETHREAD_REQUEST, *PKAC_VALIDATE_ETHREAD_REQUEST;

// ETHREAD validation response
typedef struct _KAC_VALIDATE_ETHREAD_RESPONSE
{
    BOOLEAN ThreadExists;
    BOOLEAN IsHidden;      // TRUE if not in ThreadListHead
    BOOLEAN IsSuspicious;
    KAC_ETHREAD_INFO ThreadInfo;
} KAC_VALIDATE_ETHREAD_RESPONSE, *PKAC_VALIDATE_ETHREAD_RESPONSE;

