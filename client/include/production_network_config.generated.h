#pragma once

// Deliberately unprovisioned. Release builds fail to compile until the deployment
// endpoint(s) and certificate pin(s) are generated from real production values.
#define OBLIVION_PRODUCTION_NETWORK_CONFIG_READY 0
#define OBLIVION_PRODUCTION_SERVER_ENDPOINTS ""
#define OBLIVION_PRODUCTION_TLS_PIN_SHA256 ""
