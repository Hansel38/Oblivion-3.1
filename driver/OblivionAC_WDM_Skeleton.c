#include <ntddk.h>
#include "../common/OblivionAC_ioctl.h"

#define DRIVER_TAG 'cAlO'

typedef struct _KAC_GLOBAL_CTX {
    ULONG Events;        // bitmask KAC_EVENT_*
    ULONG ProtectedPid;  // configured by user-mode
    FAST_MUTEX Lock;     // serialize updates at PASSIVE_LEVEL
} KAC_GLOBAL_CTX, *PKAC_GLOBAL_CTX;

static PKAC_GLOBAL_CTX g_Ctx = NULL;
static UNICODE_STRING g_SymLink;

DRIVER_UNLOAD DriverUnload;
_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH DispatchCreateClose;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH DispatchCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH DispatchDeviceControl;

static VOID CompleteIrp(_In_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Info)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

static NTSTATUS AllocateGlobal()
{
    if (g_Ctx) return STATUS_SUCCESS;
    PKAC_GLOBAL_CTX ctx = (PKAC_GLOBAL_CTX)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(KAC_GLOBAL_CTX), DRIVER_TAG);
    if (!ctx) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(ctx, sizeof(*ctx));
    ExInitializeFastMutex(&ctx->Lock);
    g_Ctx = ctx;
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = AllocateGlobal();
    if (!NT_SUCCESS(status)) return status;

    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, OBLIVIONAC_DEVICE_NAME);

    PDEVICE_OBJECT devObj = NULL;
    status = IoCreateDevice(DriverObject,
                            0, // no per-device extension for now
                            &devName,
                            FILE_DEVICE_OBLIVION_AC,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &devObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&g_SymLink, OBLIVIONAC_DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&g_SymLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(devObj);
        return status;
    }

    for (UINT32 i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) {
        DriverObject->MajorFunction[i] = DispatchCreateClose;
    }
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    devObj->Flags |= DO_BUFFERED_IO; // prefer METHOD_BUFFERED; safe default
    devObj->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE();
    if (g_SymLink.Buffer) {
        IoDeleteSymbolicLink(&g_SymLink);
        RtlZeroMemory(&g_SymLink, sizeof(g_SymLink));
    }
    if (DriverObject && DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
    if (g_Ctx) {
        ExFreePoolWithTag(g_Ctx, DRIVER_TAG);
        g_Ctx = NULL;
    }
}

NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    CompleteIrp(Irp, STATUS_SUCCESS, 0);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PAGED_CODE(); // ensure this runs at PASSIVE_LEVEL
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID sysBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen  = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR bytes = 0;

    if (!g_Ctx) {
        status = STATUS_DEVICE_NOT_READY;
        CompleteIrp(Irp, status, bytes);
        return status;
    }

    switch (code) {
    case IOCTL_OBLIVIONAC_PEEK: {
        // METHOD_BUFFERED expected: validate output buffer
        if (outLen < sizeof(KAC_STATUS) || sysBuf == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlZeroMemory(sysBuf, sizeof(KAC_STATUS));
        PKAC_STATUS st = (PKAC_STATUS)sysBuf;
        ExAcquireFastMutex(&g_Ctx->Lock);
        st->Events = g_Ctx->Events; // snapshot
        g_Ctx->Events = 0; // clear after read
        ExReleaseFastMutex(&g_Ctx->Lock);
        bytes = sizeof(KAC_STATUS);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_OBLIVIONAC_SET_PROTECTED_PID: {
        if (inLen < sizeof(KAC_PROTECT_CFG) || sysBuf == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PKAC_PROTECT_CFG cfg = (PKAC_PROTECT_CFG)sysBuf;
        // simple validation; do not deref PID here
        ExAcquireFastMutex(&g_Ctx->Lock);
        g_Ctx->ProtectedPid = cfg->Pid;
        ExReleaseFastMutex(&g_Ctx->Lock);
        status = STATUS_SUCCESS;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    CompleteIrp(Irp, status, bytes);
    return status;
}
