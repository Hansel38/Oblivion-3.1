#include "../pch.h"
#include "NetworkClient.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

NetworkClient::NetworkClient()
    : m_serverPort(0), m_initialized(false)
{
}

NetworkClient::~NetworkClient()
{
    Close();
}

bool NetworkClient::Initialize(const std::string& serverIp, int serverPort)
{
    m_serverIp = serverIp;
    m_serverPort = serverPort;

    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        return false;
    }

    m_initialized = true;
    return true;
}

static bool HmacSha256(const BYTE* key, DWORD keyLen, const BYTE* data, DWORD dataLen, std::string& outHex)
{
    HCRYPTPROV hProv{}; HCRYPTHASH hHash{}; HCRYPTKEY hKey{};
    HMAC_INFO info{}; info.HashAlgid = CALG_SHA_256;

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;

    // Build key blob for HMAC
    struct {
        BLOBHEADER hdr; DWORD keyLen; BYTE key[512];
    } blob{};
    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.reserved = 0;
    blob.hdr.aiKeyAlg = CALG_RC2; // algorithm ignored for PLAINTEXTKEYBLOB HMAC key import
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

static bool SendOnceAndAck(const std::string& ip, int port, const std::string& payload, const std::string& hmacSecret)
{
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return false;
    }

    DWORD timeout = 3000; 
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    sockaddr_in serverAddr = { 0 };
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    std::string msg;
    if (!hmacSecret.empty()) {
        std::string mac;
        if (HmacSha256(reinterpret_cast<const BYTE*>(hmacSecret.data()), (DWORD)hmacSecret.size(), reinterpret_cast<const BYTE*>(payload.data()), (DWORD)payload.size(), mac)) {
            msg = std::string("Auth: HMAC-SHA256 ") + mac + "\r\n";
        }
    }
    msg += payload + "\r\n";

    int sent = send(sock, msg.c_str(), static_cast<int>(msg.length()), 0);
    if (sent <= 0) { closesocket(sock); return false; }

    char ack[8] = {0};
    int r = recv(sock, ack, sizeof(ack)-1, 0);
    closesocket(sock);
    if (r <= 0) return false;
    return std::string(ack).find("ok") != std::string::npos;
}

bool NetworkClient::SendMessage(const std::string& jsonMessage)
{
    if (!m_initialized) {
        return false;
    }

    const int attempts = 2;
    for (int i = 0; i < attempts; ++i) {
        if (SendOnceAndAck(m_serverIp, m_serverPort, jsonMessage, m_hmacSecret)) return true;
        Sleep(500);
    }
    return false;
}

void NetworkClient::Close()
{
    if (m_initialized) {
        WSACleanup();
        m_initialized = false;
    }
}
