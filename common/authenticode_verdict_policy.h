#pragma once

#include <cstdint>
#include <cwctype>
#include <string>

namespace Oblivion::SignaturePolicy {

// Exact WinVerifyTrust status codes from the Windows SDK. This small policy
// header intentionally avoids Windows headers so classification has portable
// regression tests. WinVerifyTrust returns zero on success; do not use
// HRESULT SUCCEEDED/FAILED macros for this API.
constexpr std::uint32_t kTrustBadDigest = 0x80096010u;
constexpr std::uint32_t kTrustNoSignerCertificate = 0x80096002u;
constexpr std::uint32_t kTrustCounterSignerInvalid = 0x80096003u;
constexpr std::uint32_t kTrustCertificateSignatureInvalid = 0x80096004u;
constexpr std::uint32_t kTrustSubjectNotTrusted = 0x800B0004u;
constexpr std::uint32_t kTrustNoSignature = 0x800B0100u;
constexpr std::uint32_t kCertificateRevoked = 0x800B010Cu;
constexpr std::uint32_t kTrustExplicitDistrust = 0x800B0111u;

enum class WinTrustResultClass {
    Trusted,
    NoSignature,
    Rejected,
    Inconclusive
};

constexpr WinTrustResultClass ClassifyWinTrustResult(std::uint32_t status) noexcept {
    if (status == 0u) {
        return WinTrustResultClass::Trusted;
    }
    if (status == kTrustNoSignature) {
        return WinTrustResultClass::NoSignature;
    }

    switch (status) {
    case kTrustBadDigest:
    case kTrustNoSignerCertificate:
    case kTrustCounterSignerInvalid:
    case kTrustCertificateSignatureInvalid:
    case kTrustSubjectNotTrusted:
    case kCertificateRevoked:
    case kTrustExplicitDistrust:
        return WinTrustResultClass::Rejected;
    default:
        // Keep unknown provider/chain errors distinct from definite signature
        // failures to avoid banning legitimate applications on infrastructure errors.
        return WinTrustResultClass::Inconclusive;
    }
}


inline std::wstring NormalizePublisherName(std::wstring publisher) {
    auto isSpace = [](wchar_t ch) { return std::iswspace(static_cast<std::wint_t>(ch)) != 0; };
    while (!publisher.empty() && isSpace(publisher.front())) {
        publisher.erase(publisher.begin());
    }
    while (!publisher.empty() && isSpace(publisher.back())) {
        publisher.pop_back();
    }
    for (wchar_t& ch : publisher) {
        ch = static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(ch)));
    }
    return publisher;
}

inline bool IsExactPublisherMatch(
    const std::wstring& actual,
    const std::wstring& trusted) {
    const std::wstring normalizedActual = NormalizePublisherName(actual);
    const std::wstring normalizedTrusted = NormalizePublisherName(trusted);
    return !normalizedActual.empty() && normalizedActual == normalizedTrusted;
}

} // namespace Oblivion::SignaturePolicy
