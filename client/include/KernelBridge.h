#pragma once
#include <windows.h>
#include <string>

class NetworkClient;

// Starts a background thread that communicates with the kernel AC driver (if present)
// and forwards events as detection reports with subtype "kernel".
void KernelBridge_Start(NetworkClient* netClient);

// Stops the background thread.
void KernelBridge_Stop();

// Get driver handle for direct IOCTL communication (for Priority 3 modules)
// Returns INVALID_HANDLE_VALUE if driver not available
HANDLE KernelBridge_GetDriverHandle();

// Check if kernel driver is available
bool KernelBridge_IsDriverAvailable();

