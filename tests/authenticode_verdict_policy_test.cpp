#include "../common/authenticode_verdict_policy.h"

#include <cstdlib>
#include <iostream>

namespace {
void Expect(
    Oblivion::SignaturePolicy::WinTrustResultClass actual,
    Oblivion::SignaturePolicy::WinTrustResultClass expected,
    const char* description) {
    if (actual != expected) {
        std::cerr << "FAIL: " << description << '\n';
        std::exit(1);
    }
}
}

int main() {
    using Oblivion::SignaturePolicy::ClassifyWinTrustResult;
    using Oblivion::SignaturePolicy::WinTrustResultClass;

    Expect(ClassifyWinTrustResult(0u), WinTrustResultClass::Trusted,
        "ERROR_SUCCESS means signature verification succeeded");
    Expect(ClassifyWinTrustResult(0x80096010u), WinTrustResultClass::Rejected,
        "a bad image digest is a definite signature integrity failure");
    Expect(ClassifyWinTrustResult(0x800B0004u), WinTrustResultClass::Rejected,
        "an explicitly untrusted subject is not whitelisted");
    Expect(ClassifyWinTrustResult(0x800B010Cu), WinTrustResultClass::Rejected,
        "a revoked signer certificate is not whitelisted");
    Expect(ClassifyWinTrustResult(0x800B0111u), WinTrustResultClass::Rejected,
        "an explicitly distrusted signer is not whitelisted");
    Expect(ClassifyWinTrustResult(0x800B0100u), WinTrustResultClass::NoSignature,
        "absence of a signature is classified separately");
    Expect(ClassifyWinTrustResult(0x800B0109u), WinTrustResultClass::Inconclusive,
        "an untrusted root remains distinct from a proven content-integrity failure");
    Expect(ClassifyWinTrustResult(0x80092013u), WinTrustResultClass::Inconclusive,
        "offline revocation infrastructure is not misclassified as tampering");

    std::cout << "Authenticode verdict policy tests passed\n";
    return 0;
}
