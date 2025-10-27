#pragma once
#include <ntddk.h>
#include <wdf.h>
#include "../../common/OblivionAC_ioctl.h"

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD OblivionAC_EvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP OblivionAC_EvtDriverContextCleanup;

EXTERN_C_END
