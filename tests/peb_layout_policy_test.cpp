#include "../common/peb_layout_policy.h"

#include <cstdint>
#include <iostream>

static_assert(Oblivion::Windows::kPebBeingDebuggedOffset == 0x02,
              "PEB BeingDebugged offset must remain architecture-independent");
static_assert(Oblivion::Windows::PebNtGlobalFlagOffset(4) == 0x68,
              "x86 PEB NtGlobalFlag offset mismatch");
static_assert(Oblivion::Windows::PebNtGlobalFlagOffset(8) == 0xBC,
              "x64 PEB NtGlobalFlag offset mismatch");
static_assert(Oblivion::Windows::PebNtGlobalFlagOffset(sizeof(void*)) != 0,
              "unsupported process pointer size");

int main() {
    using Oblivion::Windows::HasPebNtGlobalFlagDebugIndicators;

    if (HasPebNtGlobalFlagDebugIndicators(0)) {
        std::cerr << "zero NtGlobalFlag was incorrectly classified as debug evidence\n";
        return 1;
    }
    if (HasPebNtGlobalFlagDebugIndicators(0x08)) {
        std::cerr << "unrelated NtGlobalFlag bits were incorrectly classified\n";
        return 2;
    }
    if (!HasPebNtGlobalFlagDebugIndicators(0x10) ||
        !HasPebNtGlobalFlagDebugIndicators(0x20) ||
        !HasPebNtGlobalFlagDebugIndicators(0x40) ||
        !HasPebNtGlobalFlagDebugIndicators(0x70)) {
        std::cerr << "debug-heap NtGlobalFlag indicators were not recognized\n";
        return 3;
    }

    std::cout << "PEB architecture layout and debug-flag policy: PASS\n";
    return 0;
}
