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
constexpr std::uint32_t kTrustUntrustedRoot = 0x800B0109u;
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
    case kTrustUntrustedRoot:
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


inline bool IsExpectedPublisherMatch(
    const std::wstring& actual,
    const std::wstring& expected) {
    const std::wstring normalizedActual = NormalizePublisherName(actual);
    const std::wstring normalizedExpected = NormalizePublisherName(expected);
    if (normalizedActual.empty() || normalizedExpected.empty()) {
        return false;
    }
    if (normalizedActual == normalizedExpected) {
        return true;
    }

    // Some vendors include a legal entity suffix in the signer display name.
    // Accept only a complete known suffix; arbitrary appended text remains rejected.
    static const wchar_t* const kLegalSuffixes[] = {
        L", inc.", L" inc.", L", inc", L" inc",
        L", incorporated", L" incorporated",
        L", llc", L" llc",
        L", ltd.", L" ltd.", L", ltd", L" ltd",
        L", limited", L" limited",
        L", plc", L" plc",
        L", corp.", L" corp.",
        L", corporation", L" corporation",
        L", gmbh", L" gmbh",
        L", s.a.", L" s.a.", L", sa", L" sa",
        L", ag", L" ag", L", bv", L" bv", L", nv", L" nv",
        L", ab", L" ab", L", oy", L" oy"
    };
    for (const wchar_t* suffix : kLegalSuffixes) {
        const size_t suffixLength = std::char_traits<wchar_t>::length(suffix);
        if (normalizedActual.size() == normalizedExpected.size() + suffixLength &&
            normalizedActual.compare(0, normalizedExpected.size(), normalizedExpected) == 0 &&
            normalizedActual.compare(normalizedExpected.size(), suffixLength, suffix) == 0) {
            return true;
        }
    }
    return false;
}

} // namespace Oblivion::SignaturePolicy
