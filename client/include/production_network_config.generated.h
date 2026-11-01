#pragma once

// Deliberately unprovisioned. Release builds fail until deployment policy is
// generated from real endpoint and certificate-pin values. Empty defaults are
// fail-closed; they are not usable as a deployment configuration.
#define OBLIVION_PRODUCTION_NETWORK_CONFIG_READY 0
#define OBLIVION_PRODUCTION_SERVER_ENDPOINTS ""
#define OBLIVION_PRODUCTION_TLS_PIN_SHA256 ""
