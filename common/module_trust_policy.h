#pragma once

namespace Oblivion::ModuleTrustPolicy {

enum class SignatureEvidence {
    TrustedPublisher,
    ValidUntrustedPublisher,
    Unsigned,
    InvalidSignature,
    Inconclusive
};

enum class Decision {
    Trusted,
    Untrusted,
    Inconclusive
};

constexpr Decision Evaluate(
    SignatureEvidence evidence,
    bool allowAnyValidSigner,
    bool publisherAvailable) noexcept {
    switch (evidence) {
    case SignatureEvidence::TrustedPublisher:
        return Decision::Trusted;
    case SignatureEvidence::ValidUntrustedPublisher:
        return allowAnyValidSigner && publisherAvailable
            ? Decision::Trusted
            : Decision::Untrusted;
    case SignatureEvidence::Unsigned:
    case SignatureEvidence::InvalidSignature:
        return Decision::Untrusted;
    case SignatureEvidence::Inconclusive:
    default:
        return Decision::Inconclusive;
    }
}

} // namespace Oblivion::ModuleTrustPolicy
