// server.cpp - OblivionServer console application
// Listens for detection reports from OblivionClient DLL

#include <iostream>
#include <string>
#include <fstream>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <thread>
#include <mutex>
#include <vector>
#include <algorithm>
#include <unordered_map>

#define SECURITY_WIN32
#include <sspi.h>
#include <schannel.h>

// Optional RapidJSON (header-only). If not available, we fallback to naive parsing.
#if defined(__has_include)
#  if __has_include(<rapidjson/document.h>)
#    define HAVE_RAPIDJSON 1
#    include <rapidjson/document.h>
#    include <rapidjson/error/en.h>
#  else
#    define HAVE_RAPIDJSON 0
#  endif
#else
#  define HAVE_RAPIDJSON 0
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")

// Configuration
int g_serverPort = 4000;
bool g_running = true;
bool g_enableHmacAuth = false;
bool g_enableTls = false; // enable Schannel TLS
std::string g_hmacSecret;
std::string g_tlsCertSubject; // subject common name used to locate cert in store
static std::mutex g_logFileMutex;

// New: control-plane policy for SIGPACK
static bool g_sigpackRequireTls = false;
static bool g_sigpackRequireHmac = false;

static bool g_tlsRequiredForHmac = true; // rule: when HMAC is enabled, TLS must be on
static std::vector<std::string> g_protectedModulePrefixes = {"rro.exe", "game.exe"};
static std::vector<std::string> g_protectedModuleBaseNames = {"rro.exe"};
static std::string g_escalationLogFile = "escalations.csv";
// Rate limiting
static DWORD g_rateLimitWindowMs = 10000; // 10s
static int   g_rateLimitMaxMsgs  = 60;    // 60 messages per window per IP
static bool  g_rateLimitCloseOnExceed = true;
static DWORD g_rateLimitBanMs = 60000; // 60s temporary ban
static int   g_rateLimitStrikesBeforeBan = 3;

struct RateBucket { ULONGLONG windowStart = 0; int count = 0; };
static std::mutex g_rateMx;
static std::unordered_map<std::string, RateBucket> g_rateByIp;
static std::unordered_map<std::string, RateBucket> g_rateByHwid;
static std::unordered_map<std::string, RateBucket> g_rateByHwidSubtype;
static std::unordered_map<std::string, int> g_rateStrikes; // key -> strikes
static std::unordered_map<std::string, ULONGLONG> g_rateBanUntil; // key -> ban until tick

// ================= Signature pack state =================
struct SigItem { std::string name; std::string bytes; int weight = 1; };
static std::mutex g_sigMx;
static int g_sigpackVersion = 0;
static std::vector<SigItem> g_sigpack;
static ULONGLONG g_sigpackLastLoadTick = 0;

// Small helpers
static std::string Trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    size_t e = s.find_last_not_of(" \t\r\n");
    if (b == std::string::npos) return std::string();
    return s.substr(b, e - b + 1);
}
static bool ParseInt(const std::string& v, int& out) {
    try { out = std::stoi(Trim(v)); return true; } catch (...) { return false; }
}
static bool ParseBool(const std::string& v, bool& out) {
    std::string t = Trim(v);
    if (t == "true" || t == "True" || t == "TRUE") { out = true; return true; }
    if (t == "false" || t == "False" || t == "FALSE") { out = false; return true; }
    return false;
}
static bool ParseStringLiteral(const std::string& v, std::string& out) {
    std::string t = Trim(v);
    if (t.size() >= 2 && t.front() == '"' && t.back() == '"') { out = t.substr(1, t.size()-2); return true; }
    return false;
}

// Forward decl for int parser only
static bool JsonGetInt(const std::string& json, const std::string& key, int& out);
// Forward decl for SIGPACK handler used in ProcessLine
static bool HandleSigpackRequest(const std::string& line, SOCKET s);

// Add naive integer JSON extractor
static bool JsonGetInt(const std::string& json, const std::string& key, int& out)
{
    std::string pat = "\"" + key + "\"";
    size_t pos = json.find(pat);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos);
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) ++pos;
    size_t start = pos;
    while (pos < json.size() && (json[pos] == '-' || (json[pos] >= '0' && json[pos] <= '9'))) ++pos;
    if (start == pos) return false;
    try { out = std::stoi(json.substr(start, pos - start)); return true; } catch (...) { return false; }
}


// New: simple quoted string extractor (distinct name)
static std::string JGetQ(const std::string& json, const std::string& key)
{
    std::string pat = "\"" + key + "\"";
    size_t pos = json.find(pat);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos);
    if (pos == std::string::npos) return "";
    ++pos;
    std::string out; bool esc=false;
    for (; pos < json.size(); ++pos) {
        char c = json[pos];
        if (esc) { out.push_back(c); esc=false; continue; }
        if (c=='\\') { esc=true; continue; }
        if (c=='"') break;
        out.push_back(c);
    }
    return out;
}

static bool IsBanned(const std::string& key, ULONGLONG now)
{
    auto it = g_rateBanUntil.find(key);
    return (it != g_rateBanUntil.end() && now < it->second);
}

static void OnLimitedStrike(const std::string& key, ULONGLONG now)
{
    int& s = g_rateStrikes[key];
    if (++s >= g_rateLimitStrikesBeforeBan) {
        g_rateBanUntil[key] = now + g_rateLimitBanMs;
        s = 0; // reset after ban
    }
}

static bool TouchBucket(std::unordered_map<std::string, RateBucket>& map, const std::string& key)
{
    if (key.empty()) return false;
    ULONGLONG now = GetTickCount64();
    auto& b = map[key];
    if (b.windowStart == 0 || now - b.windowStart >= g_rateLimitWindowMs) { b.windowStart = now; b.count = 0; }
    ++b.count;
    return b.count > g_rateLimitMaxMsgs;
}

static bool ShouldRateLimit(const std::string& clientIp, const std::string& json)
{
    std::string hwid = JGetQ(json, "hwid");
    std::string subtype = JGetQ(json, "subtype");
    ULONGLONG now = GetTickCount64();

    std::lock_guard<std::mutex> _g(g_rateMx);
    // Ban checks
    if (IsBanned(clientIp, now)) return true;
    if (!hwid.empty() && IsBanned(hwid, now)) return true;
    std::string hsKey;
    if (!hwid.empty() && !subtype.empty()) { hsKey = hwid + ":" + subtype; if (IsBanned(hsKey, now)) return true; }

    bool limited = false;
    if (TouchBucket(g_rateByIp, clientIp)) { limited = true; OnLimitedStrike(clientIp, now); }
    if (TouchBucket(g_rateByHwid, hwid)) { limited = true; OnLimitedStrike(hwid, now); }
    if (!hsKey.empty() && TouchBucket(g_rateByHwidSubtype, hsKey)) { limited = true; OnLimitedStrike(hsKey, now); }

    return limited;
}

static std::vector<std::string> SplitSemicolon(const std::string& s)
{
    std::vector<std::string> out; std::string cur;
    for (size_t i=0;i<=s.size();++i){ char c = (i<s.size()? s[i] : ';'); if (c==';'){ if(!cur.empty()){ out.push_back(cur); cur.clear(); } } else cur.push_back(c);}    
    return out;
}

static std::string ToLower(const std::string& s){ std::string t=s; for(auto& c:t) c=(char)tolower((unsigned char)c); return t; }

static bool StartsWithInsensitive(const std::string& s, const std::string& p) {
    if (s.size() < p.size()) return false;
    for (size_t i=0;i<p.size();++i) {
        char a = (char)tolower((unsigned char)s[i]);
        char b = (char)tolower((unsigned char)p[i]);
        if (a != b) return false;
    }
    return true;
}

static std::string BasenameInsensitive(const std::string& path)
{
    std::string t = ToLower(path);
    size_t pos = t.find_last_of("/");
    size_t pos2 = t.find_last_of("\\");

    // Check if the separators are found
    if (pos == std::string::npos && pos2 == std::string::npos) {
        return t; // No separators found, return the entire string
    }

    // Determine the position of the last separator
    size_t p = (pos == std::string::npos) ? pos2 : (pos2 == std::string::npos) ? pos : (pos > pos2 ? pos : pos2);

    return t.substr(p + 1); // Extract the basename after the last separator
}

static bool IsProtectedModule(const std::string& modulePath)
{
    std::string modLower = ToLower(modulePath);
    std::string base = BasenameInsensitive(modulePath);
    // full/path or folder prefixes
    for (auto& pre : g_protectedModulePrefixes) {
        std::string preLower = ToLower(pre);
        if (StartsWithInsensitive(modLower, preLower) || StartsWithInsensitive(base, preLower)) return true;
    }
    // exact basename list (case-insensitive)
    for (auto& bn : g_protectedModuleBaseNames) {
        if (base == ToLower(bn)) return true;
    }
    return false;
}

// Logging helpers
std::string GetTimestamp()
{
    time_t now = time(nullptr);
    char buffer[26];
    ctime_s(buffer, sizeof(buffer), &now);
    std::string timestamp(buffer);
    if (!timestamp.empty() && timestamp.back() == '\n') {
        timestamp.pop_back();
    }
    return timestamp;
}

static void RotateLogIfNeeded()
{
    const char* logPath = "server_log.txt";
    const char* bakPath = "server_log_old.txt";

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (GetFileAttributesExA(logPath, GetFileExInfoStandard, &fad)) {
        ULONGLONG size = (static_cast<ULONGLONG>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
        const ULONGLONG maxBytes = 5ull * 1024ull * 1024ull; // 5 MB
        if (size >= maxBytes) {
            DeleteFileA(bakPath);
            MoveFileExA(logPath, bakPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);
        }
    }
}

void LogMessage(const std::string& message)
{
    RotateLogIfNeeded();

    std::cout << "[" << GetTimestamp() << "] " << message << std::endl;

    std::ofstream logFile("server_log.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << GetTimestamp() << "] " << message << std::endl;
        logFile.close();
    }
}

// HMAC helper
static bool HmacSha256(const BYTE* key, DWORD keyLen, const BYTE* data, DWORD dataLen, std::string& outHex)
{
    HCRYPTPROV hProv{}; HCRYPTHASH hHash{}; HCRYPTKEY hKey{};
    HMAC_INFO info{}; info.HashAlgid = CALG_SHA_256;

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;

    struct {
        BLOBHEADER hdr; DWORD keyLen; BYTE key[512];
    } blob{};
    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.reserved = 0;
    blob.hdr.aiKeyAlg = CALG_RC2;
    blob.keyLen = keyLen;
    if (keyLen > sizeof(blob.key)) { CryptReleaseContext(hProv,0); return false; }
    memcpy(blob.key, key, keyLen);

    if (!CryptImportKey(hProv, (BYTE*)&blob, sizeof(BLOBHEADER)+sizeof(DWORD)+keyLen, 0, CRYPT_IPSEC_HMAC_KEY, &hKey)) { CryptReleaseContext(hProv,0); return false; }
    if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash)) { CryptDestroyKey(hKey); CryptReleaseContext(hProv,0); return false; }
    if (!CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&info, 0)) { CryptDestroyHash(hHash); CryptDestroyKey(hKey); CryptReleaseContext(hProv,0); return false; }
    if (!CryptHashData(hHash, data, dataLen, 0)) { CryptDestroyHash(hHash); CryptDestroyKey(hKey); CryptReleaseContext(hProv,0); return false; }

    BYTE digest[32]{}; DWORD dlen = sizeof(digest);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, digest, &dlen, 0)) { CryptDestroyHash(hHash); CryptDestroyKey(hKey); CryptReleaseContext(hProv,0); return false; }

    static const char* hex = "0123456789abcdef";
    outHex.resize(dlen*2);
    for (DWORD i=0;i<dlen;++i) { outHex[2*i] = hex[(digest[i]>>4)&0xF]; outHex[2*i+1] = hex[digest[i]&0xF]; }

    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv,0);
    return true;
}

// ===================== Schannel TLS helpers =====================
class TlsServerSession {
public:
    explicit TlsServerSession(SOCKET s) : m_sock(s) { ZeroMemory(&m_cred, sizeof(m_cred)); ZeroMemory(&m_ctx, sizeof(m_ctx)); ZeroMemory(&m_sizes, sizeof(m_sizes)); }
    ~TlsServerSession() { Cleanup(); }

    bool InitCredentials(const std::string& subjectCn) {
        std::wstring ws;
        if (!subjectCn.empty()) {
            int len = MultiByteToWideChar(CP_UTF8, 0, subjectCn.c_str(), (int)subjectCn.size(), nullptr, 0);
            ws.resize(len);
            MultiByteToWideChar(CP_UTF8, 0, subjectCn.c_str(), (int)subjectCn.size(), &ws[0], len);
        }
        PCCERT_CONTEXT pCert = nullptr;
        // Try LocalMachine then CurrentUser
        HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, L"MY");
        if (hStore) {
            pCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, ws.empty()? L"" : ws.c_str(), nullptr);
            CertCloseStore(hStore, 0);
        }
        if (!pCert) {
            hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG, L"MY");
            if (hStore) {
                pCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING, 0, ws.empty()? CERT_FIND_ANY : CERT_FIND_SUBJECT_STR, ws.empty()? L"" : ws.c_str(), nullptr);
                CertCloseStore(hStore, 0);
            }
        }
        if (!pCert) {
            LogMessage("TLS: Server certificate not found. Check tls_cert_subject and certificate store.");
            return false;
        }

        SCHANNEL_CRED schCred{};
        schCred.dwVersion = SCHANNEL_CRED_VERSION;
        schCred.cCreds = 1;
        schCred.paCred = &pCert;
        schCred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
        schCred.dwFlags = SCH_USE_STRONG_CRYPTO | SCH_CRED_NO_DEFAULT_CREDS;

        TimeStamp ts{};
        SECURITY_STATUS ss = AcquireCredentialsHandleW(nullptr, const_cast<wchar_t*>(UNISP_NAME_W), SECPKG_CRED_INBOUND, nullptr, &schCred, nullptr, nullptr, &m_cred, &ts);
        CertFreeCertificateContext(pCert);
        if (ss != SEC_E_OK) {
            LogMessage("TLS: AcquireCredentialsHandle failed: " + std::to_string(ss));
            return false;
        }
        m_haveCred = true;
        return true;
    }

    bool Handshake() {
        if (!m_haveCred) return false;
        SECURITY_STATUS ss;
        DWORD ctxAttr = 0;
        std::vector<char> inBuf;
        bool haveCtx = false;

        while (true) {
            SecBuffer inSec[2];
            inSec[0].BufferType = SECBUFFER_TOKEN;
            inSec[0].pvBuffer = inBuf.empty()? nullptr : inBuf.data();
            inSec[0].cbBuffer = (unsigned long)inBuf.size();
            inSec[1].BufferType = SECBUFFER_EMPTY;
            inSec[1].pvBuffer = nullptr;
            inSec[1].cbBuffer = 0;
            SecBufferDesc inDesc{ SECBUFFER_VERSION, 2, inSec };

            SecBuffer outSec[1];
            outSec[0].BufferType = SECBUFFER_TOKEN;
            outSec[0].pvBuffer = nullptr; // let SSPI allocate
            outSec[0].cbBuffer = 0;
            SecBufferDesc outDesc{ SECBUFFER_VERSION, 1, outSec };

            ss = AcceptSecurityContext(&m_cred, haveCtx? &m_ctx : nullptr, inBuf.empty()? nullptr : &inDesc,
                                       ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM | ASC_REQ_ALLOCATE_MEMORY,
                                       SECURITY_NATIVE_DREP, haveCtx? nullptr : &m_ctx, &outDesc, &ctxAttr, nullptr);

            haveCtx = true;

            if (outSec[0].pvBuffer && outSec[0].cbBuffer) {
                int sent = send(m_sock, (const char*)outSec[0].pvBuffer, (int)outSec[0].cbBuffer, 0);
                (void)sent;
                FreeContextBuffer(outSec[0].pvBuffer);
                outSec[0].pvBuffer = nullptr;
            }

            if (ss == SEC_E_OK) {
                // handshake done
                SECURITY_STATUS q = QueryContextAttributes(&m_ctx, SECPKG_ATTR_STREAM_SIZES, &m_sizes);
                if (q != SEC_E_OK) {
                    LogMessage("TLS: QueryContextAttributes failed: " + std::to_string(q));
                    return false;
                }
                m_tlsReady = true;
                return true;
            } else if (ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE) {
                // need more data
                char tmp[8192];
                int rec = recv(m_sock, tmp, sizeof(tmp), 0);
                if (rec <= 0) { LogMessage("TLS: recv during handshake failed"); return false; }
                // append or manage extra
                if (ss == SEC_E_INCOMPLETE_MESSAGE) {
                    inBuf.insert(inBuf.end(), tmp, tmp+rec);
                } else {
                    // If there is extra in previous call, it would be in inSec[1] as SECBUFFER_EXTRA. Handle it.
                    if (inSec[1].BufferType == SECBUFFER_EXTRA && inSec[1].cbBuffer > 0) {
                        size_t extra = inSec[1].cbBuffer;
                        // keep last 'extra' bytes
                        if (inBuf.size() > extra) {
                            std::vector<char> carry(extra);
                            memcpy(carry.data(), (char*)inSec[1].pvBuffer + (inSec[0].cbBuffer - extra), extra);
                            inBuf.assign(carry.begin(), carry.end());
                        }
                    } else {
                        inBuf.clear();
                    }
                    inBuf.insert(inBuf.end(), tmp, tmp+rec);
                }
                continue;
            } else if (ss == SEC_I_COMPLETE_AND_CONTINUE || ss == SEC_I_COMPLETE_NEEDED) {
                CompleteAuthToken(&m_ctx, &outDesc);
                continue;
            } else {
                LogMessage("TLS: AcceptSecurityContext failed: " + std::to_string(ss));
                return false;
            }
        }
    }

    // Receive CRLF-terminated line through TLS; returns false on connection close/error
    bool RecvLine(std::string& outLine) {
        if (!m_tlsReady) return false;
        while (true) {
            // Check if we already have a full line in decrypted buffer
            auto it = std::search(m_decrypted.begin(), m_decrypted.end(), crlf, crlf+2);
            if (it != m_decrypted.end()) {
                outLine.assign(m_decrypted.begin(), it);
                m_decrypted.erase(m_decrypted.begin(), it + 2);
                return true;
            }
            // Need more data: read encrypted and decrypt
            char enc[8192];
            int rec = recv(m_sock, enc, sizeof(enc), 0);
            if (rec <= 0) return false;
            m_encrypted.insert(m_encrypted.end(), enc, enc+rec);
            // decrypt loop
            while (!m_encrypted.empty()) {
                SecBuffer inSec[4];
                inSec[0].BufferType = SECBUFFER_DATA;
                inSec[0].pvBuffer = m_encrypted.data();
                inSec[0].cbBuffer = (unsigned long)m_encrypted.size();
                inSec[1].BufferType = SECBUFFER_EMPTY;
                inSec[2].BufferType = SECBUFFER_EMPTY;
                inSec[3].BufferType = SECBUFFER_EMPTY;
                SecBufferDesc inDesc{ SECBUFFER_VERSION, 4, inSec };

                SECURITY_STATUS ss = DecryptMessage(&m_ctx, &inDesc, 0, nullptr);
                if (ss == SEC_E_INCOMPLETE_MESSAGE) break; // need more encrypted bytes
                if (ss == SEC_I_CONTEXT_EXPIRED) return false;
                if (ss != SEC_E_OK && ss != SEC_I_RENEGOTIATE) { LogMessage("TLS: DecryptMessage failed: " + std::to_string(ss)); return false; }

                // Extract application data
                for (int i=0;i<4;++i) {
                    if (inSec[i].BufferType == SECBUFFER_DATA && inSec[i].cbBuffer) {
                        char* p = (char*)inSec[i].pvBuffer;
                        m_decrypted.insert(m_decrypted.end(), p, p + inSec[i].cbBuffer);
                    }
                }
                // Handle extra (unused encrypted) bytes
                size_t extraBytes = 0; void* extraPtr = nullptr;
                for (int i=0;i<4;++i) {
                    if (inSec[i].BufferType == SECBUFFER_EXTRA) { extraBytes = inSec[i].cbBuffer; extraPtr = inSec[i].pvBuffer; break; }
                }
                if (extraBytes > 0 && extraPtr) {
                    std::vector<char> carry(extraBytes);
                    memcpy(carry.data(), extraPtr, extraBytes);
                    m_encrypted.assign(carry.begin(), carry.end());
                } else {
                    m_encrypted.clear();
                }

                if (ss == SEC_I_RENEGOTIATE) {
                    // Simplified: ignore renegotiation for now
                    LogMessage("TLS: Renegotiation requested - not supported in this minimal server.");
                    return false;
                }
            }
        }
    }

    bool Send(const char* data, size_t len) {
        if (!m_tlsReady) return false;
        size_t total = m_sizes.cbHeader + len + m_sizes.cbTrailer;
        std::vector<char> buf(total);
        char* pHdr = buf.data();
        char* pData = pHdr + m_sizes.cbHeader;
        memcpy(pData, data, len);
        SecBuffer sec[4];
        sec[0].BufferType = SECBUFFER_STREAM_HEADER; sec[0].pvBuffer = pHdr; sec[0].cbBuffer = m_sizes.cbHeader;
        sec[1].BufferType = SECBUFFER_DATA;          sec[1].pvBuffer = pData; sec[1].cbBuffer = (unsigned long)len;
        sec[2].BufferType = SECBUFFER_STREAM_TRAILER; sec[2].pvBuffer = pData + len; sec[2].cbBuffer = m_sizes.cbTrailer;
        sec[3].BufferType = SECBUFFER_EMPTY;         sec[3].pvBuffer = nullptr; sec[3].cbBuffer = 0;
        SecBufferDesc desc{ SECBUFFER_VERSION, 4, sec };
        SECURITY_STATUS ss = EncryptMessage(&m_ctx, 0, &desc, 0);
        if (ss != SEC_E_OK) { LogMessage("TLS: EncryptMessage failed: " + std::to_string(ss)); return false; }
        size_t toSend = sec[0].cbBuffer + sec[1].cbBuffer + sec[2].cbBuffer;
        size_t sent = 0;
        while (sent < toSend) {
            int s = send(m_sock, buf.data() + sent, (int)(toSend - sent), 0);
            if (s <= 0) return false;
            sent += s;
        }
        return true;
    }

    void Cleanup() {
        if (m_tlsReady) {
            ApplyControlToken(&m_ctx, nullptr); // no-op here
        }
        if (m_haveCred || m_tlsReady) {
            DeleteSecurityContext(&m_ctx);
        }
        if (m_haveCred) {
            FreeCredentialHandle(&m_cred);
        }
        m_tlsReady = false; m_haveCred = false;
        m_encrypted.clear(); m_decrypted.clear();
    }

private:
    SOCKET m_sock;
    CredHandle m_cred{};
    CtxtHandle m_ctx{};
    SecPkgContext_StreamSizes m_sizes{};
    bool m_haveCred = false;
    bool m_tlsReady = false;
    std::vector<char> m_encrypted;
    std::vector<char> m_decrypted;
    const char crlf[2] = {'\r','\n'};
};

// CSV writer for reports
static void AppendCsv(const std::string& json, bool hmacOk)
{
#if HAVE_RAPIDJSON
    struct ParsedDetection { int version=0,pid=0,indicators=0; std::string subtype,process,reason,hwid,clientVersion; };
    auto TryParseWithRapidJson = [](const std::string& j, ParsedDetection& out)->bool{
        rapidjson::Document d; d.Parse(j.c_str()); if (d.HasParseError()||!d.IsObject()) return false;
        if (d.HasMember("version")&&d["version"].IsInt()) out.version=d["version"].GetInt();
        if (d.HasMember("pid")&&d["pid"].IsInt()) out.pid=d["pid"].GetInt();
        if (d.HasMember("indicators")&&d["indicators"].IsInt()) out.indicators=d["indicators"].GetInt();
        if (d.HasMember("subtype")&&d["subtype"].IsString()) out.subtype=d["subtype"].GetString();
        if (d.HasMember("process")&&d["process"].IsString()) out.process=d["process"].GetString();
        if (d.HasMember("reason")&&d["reason"].IsString()) out.reason=d["reason"].GetString();
        if (d.HasMember("hwid")&&d["hwid"].IsString()) out.hwid=d["hwid"].GetString();
        if (d.HasMember("client_version")&&d["client_version"].IsString()) out.clientVersion=d["client_version"].GetString();
        return true;
    };
    ParsedDetection pr{}; bool ok = TryParseWithRapidJson(json, pr);
    std::string subtype = ok ? pr.subtype : JGetQ(json, "subtype");
    std::string process = ok ? pr.process : JGetQ(json, "process");
    std::string reason  = ok ? pr.reason  : JGetQ(json, "reason");
    std::string hwid    = ok ? pr.hwid    : JGetQ(json, "hwid");
    std::string clientv = ok ? pr.clientVersion : JGetQ(json, "client_version");
    int pid = ok ? pr.pid : 0; if (!ok) JsonGetInt(json, "pid", pid);
    int indicators = ok ? pr.indicators : 0; if (!ok) JsonGetInt(json, "indicators", indicators);
#else
    std::string subtype = JGetQ(json, "subtype");
    std::string process = JGetQ(json, "process");
    std::string reason  = JGetQ(json, "reason");
    std::string hwid    = JGetQ(json, "hwid");
    std::string clientv = JGetQ(json, "client_version");
    int pid = 0; JsonGetInt(json, "pid", pid);
    int indicators = 0; JsonGetInt(json, "indicators", indicators);
#endif

    std::lock_guard<std::mutex> _g(g_logFileMutex);
    std::ofstream f("reports.csv", std::ios::app);
    if (f.is_open()) {
        f << GetTimestamp() << ',' << pid << ',' << '"' << process << '"' << ',' << subtype << ',' << indicators << ',' << (hmacOk?"OK":"FAIL") << ',' << hwid << ',' << '"' << reason << '"' << ',' << clientv << "\n";
        f.close();
    }
}

static void SetConsoleColorBySubtype(const std::string& subtype)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE; // default white
    if (subtype == "process") attr = FOREGROUND_RED | FOREGROUND_INTENSITY;
    else if (subtype == "overlay") attr = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    else if (subtype == "antidebug") attr = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY; // magenta
    else if (subtype == "injection") attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // yellow
    else if (subtype == "sigcheck") attr = FOREGROUND_BLUE | FOREGROUND_INTENSITY; // blue
    else if (subtype == "antisuspend") attr = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY; // cyan
    else if (subtype == "hijackedthread") attr = FOREGROUND_RED | FOREGROUND_GREEN; // dim yellow
    else if (subtype == "iathook") attr = FOREGROUND_INTENSITY; // bright white
    else if (subtype == "integrity") attr = FOREGROUND_GREEN | FOREGROUND_INTENSITY; // bright green
    else if (subtype == "memsig") attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; // yellow
    SetConsoleTextAttribute(h, attr);
}

static void ResetConsoleColor()
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// Load signatures from sigpack.txt (optional). Format:
//   VER <n>
//   NAME:<name>[@<w>] BYTES:<AA BB ?? CC>
// Empty or missing file leaves pack empty.
static void LoadSigPackIfNeeded()
{
    std::lock_guard<std::mutex> _g(g_sigMx);
    ULONGLONG now = GetTickCount64();
    if (g_sigpackLastLoadTick != 0 && (now - g_sigpackLastLoadTick) < 5000) return; // at most every 5s
    g_sigpackLastLoadTick = now;

    std::ifstream f("sigpack.txt");
    if (!f.is_open()) return;

    int newVer = 0; std::vector<SigItem> newPack; std::string line;
    while (std::getline(f, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;
        if (line.rfind("VER", 0) == 0) {
            int v = 0; if (sscanf_s(line.c_str(), "VER %d", &v) == 1) newVer = v; continue;
        }
        size_t pName = line.find("NAME:");
        size_t pBytes = line.find("BYTES:");
        if (pName == std::string::npos || pBytes == std::string::npos) continue;
        std::string name = Trim(line.substr(pName + 5, pBytes - (pName + 5)));
        std::string bytes = Trim(line.substr(pBytes + 6));
        int w = 1;
        size_t at = name.find('@');
        if (at != std::string::npos) { ParseInt(name.substr(at+1), w); name = name.substr(0, at); }
        newPack.push_back(SigItem{name, bytes, w});
    }
    f.close();
    if (!newPack.empty()) { g_sigpack = std::move(newPack); if (newVer > 0) g_sigpackVersion = newVer; }
}

static void SendSigpackResponse(SOCKET s)
{
    LoadSigPackIfNeeded();
    std::lock_guard<std::mutex> _g(g_sigMx);
    std::string hdr = std::string("SIGPACK VER ") + std::to_string(g_sigpackVersion) + "\r\n";
    send(s, hdr.c_str(), (int)hdr.size(), 0);
    for (auto& it : g_sigpack) {
        std::string line = std::string("NAME:") + it.name + "@" + std::to_string(it.weight) + " BYTES:" + it.bytes + "\r\n";
        send(s, line.c_str(), (int)line.size(), 0);
    }
    const char* end = "END\r\n"; send(s, end, 5, 0);
}

static void SendSigpackResponseTls(class TlsServerSession& sess)
{
    LoadSigPackIfNeeded();
    std::lock_guard<std::mutex> _g(g_sigMx);
    std::string hdr = std::string("SIGPACK VER ") + std::to_string(g_sigpackVersion) + "\r\n";
    sess.Send(hdr.c_str(), hdr.size());
    for (auto& it : g_sigpack) {
        std::string line = std::string("NAME:") + it.name + "@" + std::to_string(it.weight) + " BYTES:" + it.bytes + "\r\n";
        sess.Send(line.c_str(), line.size());
    }
    const char* end = "END\r\n"; sess.Send(end, 5);
}

// =================== Parsing/printing ===================
#if HAVE_RAPIDJSON
struct ParsedDetection {
    int version = 0;
    int pid = 0;
    int indicators = 0;
    std::string subtype;
    std::string process;
    std::string reason;
    std::string hwid;
    std::string clientVersion;
};

static bool TryParseWithRapidJson(const std::string& json, ParsedDetection& out)
{
    rapidjson::Document d;
    d.Parse(json.c_str());
    if (d.HasParseError() || !d.IsObject()) return false;
    if (d.HasMember("version") && d["version"].IsInt()) out.version = d["version"].GetInt();
    if (d.HasMember("pid") && d["pid"].IsInt()) out.pid = d["pid"].GetInt();
    if (d.HasMember("indicators") && d["indicators"].IsInt()) out.indicators = d["indicators"].GetInt();
    if (d.HasMember("subtype") && d["subtype"].IsString()) out.subtype = d["subtype"].GetString();
    if (d.HasMember("process") && d["process"].IsString()) out.process = d["process"].GetString();
    if (d.HasMember("reason") && d["reason"].IsString()) out.reason = d["reason"].GetString();
    if (d.HasMember("hwid") && d["hwid"].IsString()) out.hwid = d["hwid"].GetString();
    if (d.HasMember("client_version") && d["client_version"].IsString()) out.clientVersion = d["client_version"].GetString();
    return true;
}
#endif

static void PrintParsedDetection(const std::string& json, bool hmacOk)
{
#if HAVE_RAPIDJSON
    ParsedDetection pr{};
    if (TryParseWithRapidJson(json, pr)) {
        SetConsoleColorBySubtype(pr.subtype);
        LogMessage(std::string("[DETECTION v") + std::to_string(pr.version) + "] subtype=" + pr.subtype + ", pid=" + std::to_string(pr.pid) + ", process='" + pr.process + "'" + (pr.hwid.empty()? "" : std::string(", hwid=") + pr.hwid) + (pr.clientVersion.empty()? "" : std::string(", client=") + pr.clientVersion) + ", indicators=" + std::to_string(pr.indicators) + (hmacOk? " [HMAC=OK]" : (g_enableHmacAuth? " [HMAC=FAIL]" : "")));
        ResetConsoleColor();
        LogMessage(std::string("[REASON] ") + pr.reason);
        AppendCsv(json, hmacOk);
        return;
    }
#endif
    // Fallback
    std::string subtype = JGetQ(json, "subtype");
    std::string process = JGetQ(json, "process");
    std::string reason  = JGetQ(json, "reason");
    std::string hwid    = JGetQ(json, "hwid");
    std::string clientv = JGetQ(json, "client_version");
    int pid = 0; JsonGetInt(json, "pid", pid);
    int version = 0; JsonGetInt(json, "version", version);
    int indicators = 0; JsonGetInt(json, "indicators", indicators);

    if (!subtype.empty()) {
        SetConsoleColorBySubtype(subtype);
        LogMessage(std::string("[DETECTION v") + std::to_string(version) + "] subtype=" + subtype + ", pid=" + std::to_string(pid) + ", process='" + process + "'" + (hwid.empty()? "" : std::string(", hwid=") + hwid) + (clientv.empty()? "" : std::string(", client=") + clientv) + ", indicators=" + std::to_string(indicators) + (hmacOk? " [HMAC=OK]" : (g_enableHmacAuth? " [HMAC=FAIL]" : "")));
        ResetConsoleColor();
        LogMessage(std::string("[REASON] ") + reason);
    } else {
        LogMessage("Detection report received:");
        LogMessage(json);
    }

    AppendCsv(json, hmacOk);
}

// Common line processor for both TLS/plain sockets
static void ProcessLine(SOCKET clientSocket, const std::string& line, std::string& pendingMac)
{
    // SIGPACK command path (no HMAC auth; separate control plane). Keep it simple and optional.
    if (HandleSigpackRequest(line, clientSocket)) {
        return;
    }

    // Authorization header?
    if (line.rfind("Auth:", 0) == 0) {
        const std::string prefix = "Auth: HMAC-SHA256 ";
        if (line.rfind(prefix, 0) == 0) {
            pendingMac = Trim(line.substr(prefix.size()));
        } else {
            pendingMac.clear();
        }
        return; // wait for JSON line
    }

    bool accepted = true;
    bool hmacOk = true;
    if (g_enableHmacAuth && !g_hmacSecret.empty()) {
        if (!pendingMac.empty()) {
            std::string calc;
            if (HmacSha256(reinterpret_cast<const BYTE*>(g_hmacSecret.data()), (DWORD)g_hmacSecret.size(), reinterpret_cast<const BYTE*>(line.data()), (DWORD)line.size(), calc)) {
                auto tolower_str = [](std::string s){ for (auto& c : s) c = (char)tolower((unsigned char)c); return s; };
                hmacOk = tolower_str(calc) == tolower_str(pendingMac);
            } else {
                hmacOk = false;
            }
        } else {
            hmacOk = false;
        }
        pendingMac.clear();
        accepted = hmacOk;
    }

    if (accepted) {
        PrintParsedDetection(line, hmacOk);
    } else {
        LogMessage("Rejected message due to invalid HMAC");
    }
}

void HandleClient(SOCKET clientSocket, const std::string& clientIp)
{
    std::string pendingMac;

    if (g_enableHmacAuth && g_tlsRequiredForHmac && !g_enableTls) {
        LogMessage("Policy: HMAC enabled but TLS is disabled. Closing connection.");
        closesocket(clientSocket);
        return;
    }

    if (g_enableTls) {
        LogMessage("TLS enabled, starting Schannel handshake...");
        TlsServerSession sess(clientSocket);
        if (!sess.InitCredentials(g_tlsCertSubject) || !sess.Handshake()) {
            LogMessage("TLS handshake failed; closing connection.");
            closesocket(clientSocket);
            return;
        }
        LogMessage("TLS handshake complete.");

        std::string line;
        while (sess.RecvLine(line)) {
            // Capture Auth header for subsequent line (SIGPACK or JSON)
            if (line.rfind("Auth:", 0) == 0) {
                const std::string prefix = "Auth: HMAC-SHA256 ";
                if (line.rfind(prefix, 0) == 0) pendingMac = Trim(line.substr(prefix.size())); else pendingMac.clear();
                continue;
            }

            // SIGPACK control-plane
            if (line.rfind("SIGPACK", 0) == 0) {
                if (g_sigpackRequireHmac && g_enableHmacAuth) {
                    if (pendingMac.empty()) { const char* err = "ERR HMAC_REQUIRED\r\n"; sess.Send(err, strlen(err)); continue; }
                    std::string calc; if (!HmacSha256((const BYTE*)g_hmacSecret.data(), (DWORD)g_hmacSecret.size(), (const BYTE*)line.data(), (DWORD)line.size(), calc)) { const char* err = "ERR HMAC_FAILED\r\n"; sess.Send(err, strlen(err)); continue; }
                    auto tolower_str = [](std::string s){ for (auto& c:s) c=(char)tolower((unsigned char)c); return s; };
                    if (tolower_str(calc) != tolower_str(pendingMac)) { const char* err = "ERR HMAC_BAD\r\n"; sess.Send(err, strlen(err)); continue; }
                }
                SendSigpackResponseTls(sess);
                const char* ack = "ok\r\n"; sess.Send(ack, 4);
                continue;
            }

            if (ShouldRateLimit(clientIp, line)) {
                LogMessage(std::string("Rate limit exceeded (HWID/subtype/IP) for ") + clientIp + (g_rateLimitCloseOnExceed? ", closing." : ", dropping."));
                if (g_rateLimitCloseOnExceed) { closesocket(clientSocket); return; }
                continue;
            }
            ProcessLine(clientSocket, line, pendingMac);
            const char* ack = "ok\r\n";
            sess.Send(ack, 4);
        }
        closesocket(clientSocket);
        return;
    }

    // Plain (non-TLS) path
    char buffer[8192]; int bytesReceived; std::string acc;
    while ((bytesReceived = recv(clientSocket, buffer, sizeof(buffer)-1, 0)) > 0) {
        buffer[bytesReceived] = '\0'; acc.append(buffer, bytesReceived);
        size_t pos; while ((pos = acc.find("\r\n")) != std::string::npos) {
            std::string line = acc.substr(0, pos); acc.erase(0, pos + 2);

            // Capture Auth header for next SIGPACK/JSON line
            if (line.rfind("Auth:", 0) == 0) {
                const std::string prefix = "Auth: HMAC-SHA256 ";
                if (line.rfind(prefix, 0) == 0) pendingMac = Trim(line.substr(prefix.size())); else pendingMac.clear();
                continue;
            }

            // SIGPACK control-plane
            if (line.rfind("SIGPACK", 0) == 0) {
                if (g_sigpackRequireTls) {
                    const char* err = "ERR TLS_REQUIRED\r\n"; send(clientSocket, err, (int)strlen(err), 0); continue;
                }
                if (g_sigpackRequireHmac && g_enableHmacAuth) {
                    if (pendingMac.empty()) { const char* err = "ERR HMAC_REQUIRED\r\n"; send(clientSocket, err, (int)strlen(err), 0); continue; }
                    std::string calc; if (!HmacSha256((const BYTE*)g_hmacSecret.data(), (DWORD)g_hmacSecret.size(), (const BYTE*)line.data(), (DWORD)line.size(), calc)) { const char* err = "ERR HMAC_FAILED\r\n"; send(clientSocket, err, (int)strlen(err), 0); continue; }
                    auto tolower_str = [](std::string s){ for (auto& c:s) c=(char)tolower((unsigned char)c); return s; };
                    if (tolower_str(calc) != tolower_str(pendingMac)) { const char* err = "ERR HMAC_BAD\r\n"; send(clientSocket, err, (int)strlen(err), 0); continue; }
                }
                SendSigpackResponse(clientSocket);
                const char* ack = "ok\r\n"; send(clientSocket, ack, 4, 0);
                continue;
            }

            if (line.rfind("Auth:", 0) != 0) {
                if (ShouldRateLimit(clientIp, line)) {
                    LogMessage(std::string("Rate limit exceeded (HWID/subtype/IP) for ") + clientIp + (g_rateLimitCloseOnExceed? ", closing." : ", dropping."));
                    if (g_rateLimitCloseOnExceed) { closesocket(clientSocket); return; }
                    continue;
                }
            }
            ProcessLine(clientSocket, line, pendingMac);
            if (line.rfind("Auth:", 0) == 0) continue;
            const char* ack = "ok\r\n"; send(clientSocket, ack, 4, 0);
        }
    }

    if (!acc.empty()) {
        // process remaining tail similarly
        if (acc.rfind("SIGPACK", 0) == 0) {
            if (g_sigpackRequireTls) { const char* err = "ERR TLS_REQUIRED\r\n"; send(clientSocket, err, (int)strlen(err), 0); closesocket(clientSocket); return; }
            if (g_sigpackRequireHmac && g_enableHmacAuth) {
                if (pendingMac.empty()) { const char* err = "ERR HMAC_REQUIRED\r\n"; send(clientSocket, err, (int)strlen(err), 0); closesocket(clientSocket); return; }
                std::string calc; if (!HmacSha256((const BYTE*)g_hmacSecret.data(), (DWORD)g_hmacSecret.size(), (const BYTE*)acc.data(), (DWORD)acc.size(), calc)) { const char* err = "ERR HMAC_FAILED\r\n"; send(clientSocket, err, (int)strlen(err), 0); closesocket(clientSocket); return; }
                auto tolower_str = [](std::string s){ for (auto& c:s) c=(char)tolower((unsigned char)c); return s; };
                if (tolower_str(calc) != tolower_str(pendingMac)) { const char* err = "ERR HMAC_BAD\r\n"; send(clientSocket, err, (int)strlen(err), 0); closesocket(clientSocket); return; }
            }
            SendSigpackResponse(clientSocket);
            const char* ack = "ok\r\n"; send(clientSocket, ack, 4, 0);
            closesocket(clientSocket);
            return;
        }
        if (ShouldRateLimit(clientIp, acc)) {
            LogMessage(std::string("Rate limit exceeded (HWID/subtype/IP) for ") + clientIp + (g_rateLimitCloseOnExceed? ", closing." : ", dropping."));
            if (g_rateLimitCloseOnExceed) { closesocket(clientSocket); return; }
        }
        ProcessLine(clientSocket, acc, pendingMac);
        const char* ack = "ok\r\n"; send(clientSocket, ack, 4, 0);
    }

    closesocket(clientSocket);
}

bool LoadConfig()
{
    std::ifstream f("server_config.json");
    if (!f.is_open()) return false;
    std::string line;
    bool any = false;
    while (std::getline(f, line)) {
        auto c = line.find(':');
        if (c == std::string::npos) continue;
        std::string key = Trim(line.substr(0, c));
        std::string val = line.substr(c + 1);
        if (!val.empty() && val.back() == ',') val.pop_back();
        if (key.size() >= 2 && key.front() == '"' && key.back() == '"') key = key.substr(1, key.size()-2);
        if (key == "server_port") { int v; if (ParseInt(val, v)) { g_serverPort = v; any = true; } }
        else if (key == "enable_hmac_auth") { bool b; if (ParseBool(val, b)) { g_enableHmacAuth = b; any = true; } }
        else if (key == "hmac_secret") { std::string s; if (ParseStringLiteral(val, s)) { g_hmacSecret = s; any = true; } }
        else if (key == "enable_tls") { bool b; if (ParseBool(val, b)) { g_enableTls = b; any = true; } }
        else if (key == "tls_cert_subject") { std::string s; if (ParseStringLiteral(val, s)) { g_tlsCertSubject = s; any = true; } }
        else if (key == "require_tls_for_hmac") { bool b; if (ParseBool(val, b)) { g_tlsRequiredForHmac = b; any = true; } }
        else if (key == "sigpack_require_tls") { bool b; if (ParseBool(val, b)) { g_sigpackRequireTls = b; any = true; } }
        else if (key == "sigpack_require_hmac") { bool b; if (ParseBool(val, b)) { g_sigpackRequireHmac = b; any = true; } }
        else if (key == "protected_modules") { std::string s; if (ParseStringLiteral(val, s)) { auto list = SplitSemicolon(s); if (!list.empty()) { g_protectedModulePrefixes = std::move(list); } any = true; } }
        else if (key == "protected_module_basenames") { std::string s; if (ParseStringLiteral(val, s)) { auto list = SplitSemicolon(s); if (!list.empty()) { g_protectedModuleBaseNames = std::move(list); } any = true; } }
        else if (key == "escalation_log_file") { std::string s; if (ParseStringLiteral(val, s)) { g_escalationLogFile = s; any = true; } }
        else if (key == "rate_limit_window_ms") { int v; if (ParseInt(val, v)) { g_rateLimitWindowMs = (DWORD)v; any = true; } }
        else if (key == "rate_limit_max_messages") { int v; if (ParseInt(val, v)) { g_rateLimitMaxMsgs = v; any = true; } }
        else if (key == "rate_limit_close_on_exceed") { bool b; if (ParseBool(val, b)) { g_rateLimitCloseOnExceed = b; any = true; } }
        else if (key == "rate_limit_ban_ms") { int v; if (ParseInt(val, v)) { g_rateLimitBanMs = (DWORD)v; any = true; } }
        else if (key == "rate_limit_strikes_before_ban") { int v; if (ParseInt(val, v)) { g_rateLimitStrikesBeforeBan = v; any = true; } }
    }
    f.close();
    return any;
}

int main()
{
    std::cout << "========================================" << std::endl;
    std::cout << "  Oblivion AntiCheat Server" << std::endl;
    std::cout << "========================================" << std::endl;

    LoadConfig();

    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        return 1;
    }

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr = { 0 };
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(static_cast<u_short>(g_serverPort));

    if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    LogMessage("Server started on port " + std::to_string(g_serverPort) + (g_enableHmacAuth? " (HMAC enabled)" : "") + (g_enableTls? " (TLS)" : ""));
    std::cout << "Waiting for client connections...\n(Press Ctrl+C to stop)\n" << std::endl;

    while (g_running) {
        sockaddr_in clientAddr = { 0 };
        int clientAddrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET) {
            continue;
        }

        char clientIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, INET_ADDRSTRLEN);
        LogMessage(std::string("Client connected from ") + clientIp);
        std::string ipStr(clientIp);

        std::thread([clientSocket, ipStr]() { HandleClient(clientSocket, ipStr); }).detach();
    }

    closesocket(listenSocket);
    WSACleanup();

    LogMessage("Server stopped.");
    return 0;
}

// Stub kept for backward compatibility with ProcessLine; main SIGPACK handling is in HandleClient loops
static bool HandleSigpackRequest(const std::string& /*line*/, SOCKET /*s*/)
{
    return false;
}
