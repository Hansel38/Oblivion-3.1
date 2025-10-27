#include "../pch.h"
#include "SignaturePackManager.h"
#include "NetworkClient.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

static bool RecvCrlfLine(SOCKET s, std::string& out)
{
    out.clear();
    char buf[1024]; std::string acc;
    for (;;) {
        int r = recv(s, buf, sizeof(buf),0);
        if (r <=0) return false;
        acc.append(buf, r);
        size_t p = acc.find("\r\n");
        if (p != std::string::npos) {
            out = acc.substr(0, p);
            // retain extra? protocol here is line-oriented, so we drop rest
            return true;
        }
        if (acc.size() > (1<<20)) return false;
    }
}

static bool HmacSha256(const BYTE* key, DWORD keyLen, const BYTE* data, DWORD dataLen, std::string& outHex)
{
    HCRYPTPROV hProv{}; HCRYPTHASH hHash{}; HCRYPTKEY hKey{};
    HMAC_INFO info{}; info.HashAlgid = CALG_SHA_256;

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;

    struct { BLOBHEADER hdr; DWORD keyLen; BYTE key[512]; } blob{};
    blob.hdr.bType = PLAINTEXTKEYBLOB; blob.hdr.bVersion = CUR_BLOB_VERSION; blob.hdr.reserved =0; blob.hdr.aiKeyAlg = CALG_RC2;
    blob.keyLen = keyLen; if (keyLen > sizeof(blob.key)) { CryptReleaseContext(hProv,0); return false; }
    memcpy(blob.key, key, keyLen);

    if (!CryptImportKey(hProv, (BYTE*)&blob, sizeof(BLOBHEADER)+sizeof(DWORD)+keyLen,0, CRYPT_IPSEC_HMAC_KEY, &hKey)) { CryptReleaseContext(hProv,0); return false; }
    if (!CryptCreateHash(hProv, CALG_HMAC, hKey,0, &hHash)) { CryptDestroyKey(hKey); CryptReleaseContext(hProv,0); return false; }
    if (!CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&info,0)) { CryptDestroyHash(hHash); CryptDestroyKey(hKey); CryptReleaseContext(hProv,0); return false; }
    if (!CryptHashData(hHash, data, dataLen,0)) { CryptDestroyHash(hHash); CryptDestroyKey(hKey); CryptReleaseContext(hProv,0); return false; }

    BYTE digest[32]{}; DWORD dlen = sizeof(digest);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, digest, &dlen,0)) { CryptDestroyHash(hHash); CryptDestroyKey(hKey); CryptReleaseContext(hProv,0); return false; }

    static const char* hex = "0123456789abcdef";
    outHex.resize(dlen*2);
    for (DWORD i=0;i<dlen;++i) { outHex[2*i] = hex[(digest[i]>>4)&0xF]; outHex[2*i+1] = hex[digest[i]&0xF]; }

    CryptDestroyHash(hHash); CryptDestroyKey(hKey); CryptReleaseContext(hProv,0);
    return true;
}

SignaturePackManager::SignaturePackManager(const std::string& serverIp, int serverPort, ClientConfig* cfg)
    : m_serverIp(serverIp), m_serverPort(serverPort), m_cfg(cfg)
{
}

SignaturePackManager::~SignaturePackManager()
{
    Stop();
}

void SignaturePackManager::Start(DWORD intervalMs)
{
    Stop();
    m_intervalMs = intervalMs ? intervalMs :60000;
    m_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_thread = CreateThread(nullptr,0, ThreadProc, this,0, nullptr);
}

void SignaturePackManager::Stop()
{
    if (m_thread) {
        if (m_stopEvent) SetEvent(m_stopEvent);
        WaitForSingleObject(m_thread,3000);
        CloseHandle(m_thread);
        m_thread = nullptr;
    }
    if (m_stopEvent) { CloseHandle(m_stopEvent); m_stopEvent = nullptr; }
}

DWORD WINAPI SignaturePackManager::ThreadProc(LPVOID ctx)
{
    static_cast<SignaturePackManager*>(ctx)->RunLoop();
    return 0;
}

void SignaturePackManager::RunLoop()
{
    while (WaitForSingleObject(m_stopEvent, m_intervalMs) == WAIT_TIMEOUT) {
        PollOnce();
    }
}

bool SignaturePackManager::PollOnce()
{
    // Connect to server and request the signature pack using a simple line protocol
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons((u_short)m_serverPort);
    inet_pton(AF_INET, m_serverIp.c_str(), &addr.sin_addr);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) { closesocket(sock); return false; }

    // Build request line without CRLF for HMAC
    char lineBuf[64]; _snprintf_s(lineBuf, _TRUNCATE, "SIGPACK GET %d", m_currentVersion);
    std::string line(lineBuf);

    // Optionally send HMAC header if enabled in config
    if (m_cfg && m_cfg->enableHmacAuth && !m_cfg->hmacSecret.empty()) {
        std::string mac;
        if (HmacSha256(reinterpret_cast<const BYTE*>(m_cfg->hmacSecret.data()), (DWORD)m_cfg->hmacSecret.size(), reinterpret_cast<const BYTE*>(line.data()), (DWORD)line.size(), mac)) {
            std::string auth = std::string("Auth: HMAC-SHA256 ") + mac + "\r\n";
            if (send(sock, auth.c_str(), (int)auth.size(),0) <=0) { closesocket(sock); return false; }
        }
    }

    // Send request line + CRLF
    std::string req = line + "\r\n";
    if (send(sock, req.c_str(), (int)req.size(),0) <=0) { closesocket(sock); return false; }

    // Expect response: SIGPACK VER <n>\r\n followed by items and END\r\n
    std::string lineResp;
    if (!RecvCrlfLine(sock, lineResp)) { closesocket(sock); return false; }
    int newVer =0;
    if (sscanf_s(lineResp.c_str(), "SIGPACK VER %d", &newVer) !=1) { closesocket(sock); return false; }

    if (newVer <= m_currentVersion) { closesocket(sock); return true; }

    std::wstring memSig; // will build semicolon-delimited string

    while (RecvCrlfLine(sock, lineResp)) {
        if (lineResp == "END") break;
        size_t pName = lineResp.find("NAME:");
        size_t pBytes = lineResp.find("BYTES:");
        if (pName == std::string::npos || pBytes == std::string::npos) continue;
        std::string name = lineResp.substr(pName +5, pBytes - (pName +5));
        std::string bytes = lineResp.substr(pBytes +6);
        auto trim = [](std::string s){ size_t b = s.find_first_not_of(" \t"); size_t e = s.find_last_not_of(" \t"); if (b==std::string::npos) return std::string(); return s.substr(b, e-b+1); };
        auto collapse = [](std::string s){ std::string r; r.reserve(s.size()); for(char c: s){ if (c!='\r' && c!='\n' && c!='\t') r.push_back(c);} return r; };
        name = trim(name); bytes = trim(collapse(bytes));
        std::wstring wname(name.begin(), name.end());
        std::wstring wbytes(bytes.begin(), bytes.end());
        if (!memSig.empty()) memSig.push_back(L';');
        memSig += wname; memSig.push_back(L'='); memSig += wbytes;
    }

    closesocket(sock);

    if (!memSig.empty() && m_cfg) {
        m_cfg->memorySignatures = memSig;
        m_cfg->enableMemorySignatureScanner = true;
        m_cfg->memorySignatureThreshold =1; // fast rollout uses1
        m_currentVersion = newVer;
    }

    return true;
}
