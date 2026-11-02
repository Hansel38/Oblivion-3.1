#!/usr/bin/env python3
"""Regression checks for watchdog heartbeat progress during long scans."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    memory_header = read("client/include/memory_scanner.h")
    memory_source = read("client/src/memory_scanner.cpp")
    signature_header = read("client/include/digital_signature_validator.h")
    signature_source = read("client/src/digital_signature_validator.cpp")
    watcher_source = read("client/src/process_watcher.cpp")
    watchdog_source = read("client/src/anti_suspend.cpp")

    require("SetProgressCallback(std::function<void()> callback)" in memory_header,
            "MemoryScanner must expose a progress callback")
    require("SetProgressCallback(std::function<void()> callback)" in signature_header,
            "DigitalSignatureValidator must expose a progress callback")
    require("m_pMemoryScanner->SetProgressCallback(reportProgress)" in watcher_source,
            "ProcessWatcher must wire MemoryScanner progress to AntiSuspend")
    require("m_pDigitalSignatureValidator->SetProgressCallback(reportProgress)" in watcher_source,
            "ProcessWatcher must wire signature-scan progress to AntiSuspend")

    baseline_loop = memory_source.index("for (const auto& section : sections)")
    baseline_progress = memory_source.index("ReportProgress();", baseline_loop)
    require(baseline_progress < memory_source.index("baseline.rva = section.virtualAddress"),
            "MemoryScanner must report progress inside baseline section enumeration")

    verify_loop = memory_source.index("for (const auto& baseline : m_diskBaseline)")
    verify_progress = memory_source.index("ReportProgress();", verify_loop)
    require(verify_progress < memory_source.index("VirtualQuery(memoryAddr", verify_loop),
            "MemoryScanner must report progress inside runtime section verification")

    module_loop = signature_source.index("if (Module32FirstW(hSnapshot, &me32))")
    module_progress = signature_source.index("ReportProgress();", module_loop)
    trust_call = signature_source.index("IsModuleTrusted(", module_progress)
    require(module_progress < trust_call,
            "Signature scanner must report progress while enumerating modules")

    require("std::chrono::milliseconds(30000)" in watchdog_source,
            "Watchdog no-progress grace period should be 30 seconds")

    print("Scan progress / anti-suspend regression checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
