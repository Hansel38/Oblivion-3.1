# Oblivion Client Anti-Debug Guide

This document explains the anti-debug checks, configuration toggles, and logging to help operate and tune the shield safely.

## Checks Overview
- IsDebuggerPresent: Basic user-mode debugger presence.
- NtQueryInformationProcess (DebugPort): Detects attached debugger via non-zero debug port.
- INT3 Trap: Exception-based detection using a breakpoint.
- Hardware Breakpoints: Inspects DR0–DR7 via `GetThreadContext`.
- Kernel Debugger: Queries `SystemKernelDebuggerInformation`.
- Timing Anomalies: Adaptive baseline and multi-sample latency checks.
- API Hook Integrity: Verifies critical API addresses reside in their original modules.
- PEB Flags: Reads `BeingDebugged` and `NtGlobalFlag`.
- SEH Chain Integrity (x86): Validates SEH chain origin; whitelists our module.
- VEH Integrity: Two-phase probe (priority 1 then 0), avoids false positives.

## Decision Policy
- Default: Block only when 2 or more checks fire simultaneously.
- Strict Mode: Block on any single check.

## Environment Toggles
- `OBLIVION_ANTIDEBUG` (disable all checks)
  - Values: `0`, `false`, `off` → disabled; unset → enabled
- `OBLIVION_ANTIDEBUG_STRICT` (enable strict policy)
  - Values: `1`, `true`, `on` → strict; unset → consensus
- `OBLIVION_ANTIDEBUG_LOG` (enable logging)
  - Values: `1`, `true`, `on` → logs enabled; unset → disabled

## Logging
- File: `antidebug.log` next to the executable.
- Content: Timestamp + semicolon-separated signals (e.g., `HWBreakpoints;TimingAnomalies`).
- Extra entries:
  - `SEH suspicious module: <module>`
  - `SEH chain too deep`
  - `VEH suspicious: handler swallowed exceptions at all priorities`

## Suggested Operational Workflow
- Development:
  - Keep default consensus mode.
  - Enable logging during feature work: `OBLIVION_ANTIDEBUG_LOG=1`.
  - Avoid strict mode unless specifically testing.
- Production:
  - Use consensus mode by default.
  - Enable strict mode only if environment is controlled and performance stable.
  - Keep logging off for performance; enable temporarily for incident analysis.

## Tuning Hints
- If timing checks are noisy on specific machines/VMs, reduce the sensitivity by adjusting factor/margin in `CheckTimingAnomalies()`.
- If a trusted module triggers SEH/VEH flags, consider whitelisting by HMODULE equality (preferred) rather than path strings.

## Troubleshooting
- App closes unexpectedly:
  - Temporarily set `OBLIVION_ANTIDEBUG=0` to confirm anti-debug is the cause.
  - Enable `OBLIVION_ANTIDEBUG_LOG=1` to inspect which signals fired.
  - Revert toggles after investigation.

## Notes
- x64 SEH linked-list heuristics are disabled to avoid inaccuracies.
- VEH probe avoids SEH to comply with `/EHsc` and prevent object unwinding issues.
