#pragma once
#include <windows.h>
#include <string>

class NetworkClient;

// Starts a background thread that communicates with the kernel AC driver (if present)
// and forwards events as detection reports with subtype "kernel".
void KernelBridge_Start(NetworkClient* netClient);

// Stops the background thread.
void KernelBridge_Stop();
