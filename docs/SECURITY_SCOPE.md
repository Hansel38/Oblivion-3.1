# Security implementation scope

## No kernel-mode anti-cheat

Oblivion 3.1 does not include, install, or require a kernel-mode anti-cheat
driver. Kernel drivers, Windows Driver Kit (WDK) projects, .sys binaries,
driver .inf packages, kernel callbacks, and kernel hooks are explicitly
outside the project scope.

Client protection remains user-mode. Existing process/handle inspection uses
user-mode APIs (including native Windows user-mode interfaces) and must not be
described as kernel-level protection. Such inspection is heuristic telemetry;
it cannot guarantee prevention of memory access by an administrator, kernel
driver, or hypervisor.

## Production security boundary

The Ragnarok client is untrusted. Client-side scanners and heartbeat status are
signals only. Game state, movement, skill timing, inventory, currency, damage,
and character statistics must be validated by the authoritative rAthena
map-server. The standalone Oblivion service does not replace those checks.

Production release provisioning still requires:
- Real SHA-256 hashes for every required packaged file.
- A signed integrity manifest and a protected signing key.
- A real TLS certificate/private key and pinned endpoint policy.
- A live smoke test and load test against the deployed package.
- rAthena-side gameplay validation before claiming gameplay anti-cheat coverage.

Do not ship production builds with placeholder hashes, development secrets,
or unprovisioned endpoint/certificate configuration.
