#include "../common/module_trust_policy.h"

#include <cstdlib>
#include <iostream>

namespace {
void Expect(
    Oblivion::ModuleTrustPolicy::Decision actual,
    Oblivion::ModuleTrustPolicy::Decision expected,
    const char* description) {
    if (actual != expected) {
        std::cerr << "FAIL: " << description << '\n';
        std::exit(1);
    }
}
}

int main() {
    using Oblivion::ModuleTrustPolicy::Decision;
    using Oblivion::ModuleTrustPolicy::Evaluate;
    using Oblivion::ModuleTrustPolicy::SignatureEvidence;

    Expect(Evaluate(SignatureEvidence::TrustedPublisher, false, true), Decision::Trusted,
        "an explicitly trusted publisher is accepted everywhere");
    Expect(Evaluate(SignatureEvidence::ValidUntrustedPublisher, false, true), Decision::Untrusted,
        "an unknown signer outside a protected install directory is rejected");
    Expect(Evaluate(SignatureEvidence::ValidUntrustedPublisher, true, true), Decision::Trusted,
        "a valid Authenticode signature in a protected installation path can preserve compatibility");
    Expect(Evaluate(SignatureEvidence::ValidUntrustedPublisher, true, false), Decision::Untrusted,
        "a valid but unextractable signer identity is not trusted by path alone");
    Expect(Evaluate(SignatureEvidence::Unsigned, true, true), Decision::Untrusted,
        "the protected-directory compatibility rule never accepts unsigned modules");
    Expect(Evaluate(SignatureEvidence::InvalidSignature, true, true), Decision::Untrusted,
        "a bad or revoked signature is rejected even in a protected directory");
    Expect(Evaluate(SignatureEvidence::Inconclusive, false, true), Decision::Inconclusive,
        "an infrastructure error is distinct from a cheating verdict");

    std::cout << "Module signature trust policy tests passed\n";
    return 0;
}
