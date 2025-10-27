#pragma once
#include <winioctl.h>

#define OBLIVIONAC_DEVICE_NAME      L"\\Device\\OblivionAC"
#define OBLIVIONAC_DOS_DEVICE_NAME  L"\\DosDevices\\OblivionAC"
#define OBLIVIONAC_USER_SYMLINK     L"\\\\.\\OblivionAC"

#define FILE_DEVICE_OBLIVION_AC  0x9876

#define IOCTL_OBLIVIONAC_PEEK             CTL_CODE(FILE_DEVICE_OBLIVION_AC, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OBLIVIONAC_SET_PROTECTED_PID CTL_CODE(FILE_DEVICE_OBLIVION_AC, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Bitmask events from kernel to user
#define KAC_EVENT_DBK_DRIVER_DETECTED   0x00000001
#define KAC_EVENT_BLOCKED_HANDLE_RIGHTS 0x00000002
#define KAC_EVENT_SUSPICIOUS_IMAGE      0x00000004

typedef struct _KAC_STATUS
{
    ULONG Events;   // bitmask of KAC_EVENT_*
    ULONG Reserved; // future fields
} KAC_STATUS, *PKAC_STATUS;

typedef struct _KAC_PROTECT_CFG
{
    ULONG Pid; // protected process id
} KAC_PROTECT_CFG, *PKAC_PROTECT_CFG;
