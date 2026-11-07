#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/select.h>
#include <sys/time.h>
#endif

namespace Oblivion {
namespace Tls {

inline std::string TrimAscii(const std::string& value) {
    const size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

inline std::string ToLowerAscii(const std::string& value) {
    std::string result = value;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

// Pin list is intentionally strict: one malformed pin invalidates the entire
// setting rather than silently weakening certificate identity verification.
inline bool ParseSha256PinList(
    const std::string& setting,
    std::vector<std::string>& pins,
    std::string& error) {
    pins.clear();
    error.clear();

    std::string token;
    auto appendToken = [&]() -> bool {
        if (token.empty()) return true;
        if (token.size() != 64 ||
            !std::all_of(token.begin(), token.end(), [](unsigned char c) {
                return std::isxdigit(c) != 0;
            })) {
            error = "each TLS SHA-256 certificate pin must be exactly 64 hexadecimal characters";
            return false;
        }
        const std::string normalized = ToLowerAscii(token);
        if (std::find(pins.begin(), pins.end(), normalized) == pins.end()) {
            pins.push_back(normalized);
        }
        token.clear();
        return true;
    };

    for (unsigned char c : setting) {
        if (c == ',' || c == ';' || std::isspace(c)) {
            if (!appendToken()) return false;
        } else {
            token.push_back(static_cast<char>(c));
        }
    }
    if (!appendToken()) return false;

    if (pins.empty()) {
        error = "TLS certificate pin is required";
        return false;
    }
    return true;
}

inline std::string CertificateSha256Pin(X509* certificate) {
    if (certificate == nullptr) return "";

    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digestLength = 0;
    if (X509_digest(certificate, EVP_sha256(), digest, &digestLength) != 1 ||
        digestLength != 32) {
        return "";
    }

    static const char* hex = "0123456789abcdef";
    std::string pin;
    pin.reserve(64);
    for (unsigned int i = 0; i < digestLength; ++i) {
        pin.push_back(hex[(digest[i] >> 4) & 0x0f]);
        pin.push_back(hex[digest[i] & 0x0f]);
    }
    return pin;
}

inline SSL_CTX* CreateClientContext(std::string& error) {
    error.clear();
    SSL_CTX* context = SSL_CTX_new(TLS_client_method());
    if (context == nullptr) {
        error = "SSL_CTX_new failed for TLS client";
        return nullptr;
    }

    if (SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) != 1) {
        error = "failed to require TLS 1.2 or newer";
        SSL_CTX_free(context);
        return nullptr;
    }

    SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    // Load the process-configured CA roots once into this context. Verification
    // below reuses this exact store, including SSL_CERT_FILE/SSL_CERT_DIR overrides.
    // A missing CA bundle does not disable explicitly pinned self-signed deployments;
    // it simply means CA-issued peers cannot be validated.
    (void)SSL_CTX_set_default_verify_paths(context);
    // Certificate identity is validated after the handshake so the explicitly
    // pinned self-signed leaf trust-anchor policy can be applied deliberately.
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    return context;
}

inline SSL_CTX* CreateServerContext(
    const std::string& certificateFile,
    const std::string& privateKeyFile,
    std::string& error) {
    error.clear();
    SSL_CTX* context = SSL_CTX_new(TLS_server_method());
    if (context == nullptr) {
        error = "SSL_CTX_new failed for TLS server";
        return nullptr;
    }

    SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    if (SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) != 1) {
        error = "failed to require TLS 1.2 or newer";
        SSL_CTX_free(context);
        return nullptr;
    }
    if (SSL_CTX_use_certificate_chain_file(context, certificateFile.c_str()) != 1) {
        error = "cannot load TLS certificate chain file: " + certificateFile;
        SSL_CTX_free(context);
        return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(context, privateKeyFile.c_str(), SSL_FILETYPE_PEM) != 1) {
        error = "cannot load TLS private key file: " + privateKeyFile;
        SSL_CTX_free(context);
        return nullptr;
    }
    if (SSL_CTX_check_private_key(context) != 1) {
        error = "TLS private key does not match the configured certificate";
        SSL_CTX_free(context);
        return nullptr;
    }
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    return context;
}

inline bool IsCryptographicallySelfSigned(X509* certificate) {
    if (certificate == nullptr ||
        X509_NAME_cmp(X509_get_issuer_name(certificate),
                      X509_get_subject_name(certificate)) != 0) {
        return false;
    }

    EVP_PKEY* publicKey = X509_get_pubkey(certificate);
    if (publicKey == nullptr) {
        return false;
    }
    const bool selfSigned = X509_verify(certificate, publicKey) == 1;
    EVP_PKEY_free(publicKey);
    return selfSigned;
}

// CA-issued certificates must validate to a root in the OpenSSL client trust store.
// A pinned self-signed leaf remains supported as an explicit private-PKI trust anchor.
inline bool VerifyPeerCertificateChain(
    SSL* session,
    X509* certificate,
    STACK_OF(X509)* peerChain,
    std::string& error) {
    error.clear();

    SSL_CTX* context = session == nullptr ? nullptr : SSL_get_SSL_CTX(session);
    X509_STORE* store = context == nullptr ? nullptr : SSL_CTX_get_cert_store(context);
    if (store == nullptr) {
        error = "TLS client context has no certificate trust store";
        return false;
    }

    X509_STORE_CTX* storeContext = X509_STORE_CTX_new();
    if (storeContext == nullptr) {
        error = "cannot allocate TLS certificate verification context";
        return false;
    }

    bool chainTrusted = false;
    long verificationError = X509_V_ERR_UNSPECIFIED;
    if (X509_STORE_CTX_init(storeContext, store, certificate, peerChain) == 1) {
        if (X509_STORE_CTX_set_purpose(storeContext, X509_PURPOSE_SSL_SERVER) == 1 &&
            X509_verify_cert(storeContext) == 1) {
            chainTrusted = true;
        } else {
            verificationError = X509_STORE_CTX_get_error(storeContext);
        }
    }
    X509_STORE_CTX_free(storeContext);

    if (chainTrusted) {
        return true;
    }
    if (IsCryptographicallySelfSigned(certificate)) {
        return true; // Exact leaf pin is the explicit trust anchor for this private deployment.
    }

    error = "TLS peer certificate chain is not trusted";
    if (verificationError != X509_V_ERR_UNSPECIFIED) {
        error += ": ";
        error += X509_verify_cert_error_string(verificationError);
    }
    return false;
}

inline bool VerifyPeerCertificate(
    SSL* session,
    const std::string& expectedHost,
    const std::vector<std::string>& allowedPins,
    std::string& error) {
    error.clear();
    if (session == nullptr || expectedHost.empty() || allowedPins.empty()) {
        error = "TLS verification inputs are incomplete";
        return false;
    }

    X509* certificate = SSL_get_peer_certificate(session);
    if (certificate == nullptr) {
        error = "TLS peer did not provide a certificate";
        return false;
    }

    bool valid = false;
    const int notBefore = X509_cmp_current_time(X509_get0_notBefore(certificate));
    const int notAfter = X509_cmp_current_time(X509_get0_notAfter(certificate));
    if (notBefore >= 0 || notAfter <= 0) {
        error = "TLS peer certificate is not currently valid";
        goto cleanup;
    }

    if (X509_check_purpose(certificate, X509_PURPOSE_SSL_SERVER, 0) != 1) {
        error = "TLS peer certificate is not valid for server authentication";
        goto cleanup;
    }

    {
        const bool looksLikeIp =
            expectedHost.find(':') != std::string::npos ||
            (!expectedHost.empty() &&
             std::all_of(expectedHost.begin(), expectedHost.end(), [](unsigned char c) {
                 return (c >= '0' && c <= '9') || c == '.';
             }));
        const int hostMatch = looksLikeIp
            ? X509_check_ip_asc(certificate, expectedHost.c_str(), 0)
            : X509_check_host(
                  certificate, expectedHost.c_str(), expectedHost.size(),
                  X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS |
                      X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
                  nullptr);
        if (hostMatch != 1) {
            error = "TLS peer certificate hostname/IP SAN does not match configured endpoint";
            goto cleanup;
        }
    }

    {
        const std::string fingerprint = CertificateSha256Pin(certificate);
        if (fingerprint.empty() ||
            std::find(allowedPins.begin(), allowedPins.end(), fingerprint) == allowedPins.end()) {
            error = "TLS peer certificate SHA-256 pin does not match configured pins";
            goto cleanup;
        }
    }

    if (!VerifyPeerCertificateChain(
            session, certificate, SSL_get_peer_cert_chain(session), error)) {
        goto cleanup;
    }

    valid = true;

cleanup:
    X509_free(certificate);
    return valid;
}


inline bool WaitForHandshakeIo(
    int socketDescriptor,
    int sslError,
    std::chrono::steady_clock::time_point deadline) {
    if (sslError != SSL_ERROR_WANT_READ && sslError != SSL_ERROR_WANT_WRITE) {
        return false;
    }

    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return false;
    const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);

    fd_set readSet;
    fd_set writeSet;
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    if (sslError == SSL_ERROR_WANT_READ) FD_SET(socketDescriptor, &readSet);
    else FD_SET(socketDescriptor, &writeSet);

    timeval timeout{};
    timeout.tv_sec = static_cast<long>(remaining.count() / 1000000);
    timeout.tv_usec = static_cast<long>(remaining.count() % 1000000);
#ifdef _WIN32
    const int ready = select(0, &readSet, &writeSet, nullptr, &timeout);
#else
    const int ready = select(socketDescriptor + 1, &readSet, &writeSet, nullptr, &timeout);
#endif
    return ready > 0;
}

inline bool PerformHandshake(
    SSL* session,
    int socketDescriptor,
    bool serverSide,
    std::string& error) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (true) {
        const int result = serverSide ? SSL_accept(session) : SSL_connect(session);
        if (result == 1) {
            return true;
        }

        const int sslError = SSL_get_error(session, result);
        if (!WaitForHandshakeIo(socketDescriptor, sslError, deadline)) {
            error = (std::chrono::steady_clock::now() >= deadline)
                ? "TLS handshake exceeded its 5-second deadline"
                : "TLS handshake failed";
            return false;
        }
    }
}

inline SSL* Connect(
    SSL_CTX* context,
    int socketDescriptor,
    const std::string& expectedHost,
    const std::vector<std::string>& allowedPins,
    std::string& error) {
    error.clear();
    if (context == nullptr || socketDescriptor < 0) {
        error = "TLS client context or socket is invalid";
        return nullptr;
    }

    SSL* session = SSL_new(context);
    if (session == nullptr) {
        error = "SSL_new failed for TLS client session";
        return nullptr;
    }
    if (SSL_set_fd(session, socketDescriptor) != 1) {
        error = "SSL_set_fd failed for TLS client session";
        SSL_free(session);
        return nullptr;
    }

    const bool looksLikeIp =
        expectedHost.find(':') != std::string::npos ||
        (!expectedHost.empty() &&
         std::all_of(expectedHost.begin(), expectedHost.end(), [](unsigned char c) {
             return (c >= '0' && c <= '9') || c == '.';
         }));
    if (!looksLikeIp && SSL_set_tlsext_host_name(session, expectedHost.c_str()) != 1) {
        error = "failed to set TLS SNI hostname";
        SSL_free(session);
        return nullptr;
    }

    if (!PerformHandshake(session, socketDescriptor, false, error)) {
        SSL_free(session);
        return nullptr;
    }

    if (!VerifyPeerCertificate(session, expectedHost, allowedPins, error)) {
        SSL_free(session);
        return nullptr;
    }

    return session;
}

inline SSL* Accept(SSL_CTX* context, int socketDescriptor, std::string& error) {
    error.clear();
    if (context == nullptr || socketDescriptor < 0) {
        error = "TLS server context or socket is invalid";
        return nullptr;
    }

    SSL* session = SSL_new(context);
    if (session == nullptr) {
        error = "SSL_new failed for TLS server session";
        return nullptr;
    }
    if (SSL_set_fd(session, socketDescriptor) != 1) {
        error = "SSL_set_fd failed for TLS server session";
        SSL_free(session);
        return nullptr;
    }
    if (!PerformHandshake(session, socketDescriptor, true, error)) {
        SSL_free(session);
        return nullptr;
    }
    return session;
}

} // namespace Tls
} // namespace Oblivion
