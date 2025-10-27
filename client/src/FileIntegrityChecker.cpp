#include "../pch.h"
#include "FileIntegrityChecker.h"
#include <wincrypt.h>
#include <fstream>
#include <vector>
#include <algorithm>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

static std::string ToHex(const BYTE* data, size_t len)
{
    static const char* hex = "0123456789abcdef";
    std::string s; s.resize(len*2);
    for (size_t i=0;i<len;++i) { s[2*i] = hex[(data[i]>>4)&0xF]; s[2*i+1] = hex[data[i]&0xF]; }
    return s;
}

bool FileIntegrityChecker::ComputeSHA256File(const std::wstring& path, std::string& outHex)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return false;
    HCRYPTPROV hProv{}; HCRYPTHASH hHash{};
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { CryptReleaseContext(hProv,0); return false; }
    std::vector<char> buf(64*1024);
    while (f) {
        f.read(buf.data(), buf.size());
        std::streamsize got = f.gcount();
        if (got > 0) CryptHashData(hHash, reinterpret_cast<BYTE*>(buf.data()), (DWORD)got, 0);
    }
    BYTE digest[32]{}; DWORD dlen=sizeof(digest);
    bool ok = !!CryptGetHashParam(hHash, HP_HASHVAL, digest, &dlen, 0);
    CryptDestroyHash(hHash); CryptReleaseContext(hProv,0);
    if (!ok) return false;
    outHex = ToHex(digest, dlen);
    return true;
}

bool FileIntegrityChecker::RunOnceScan(IntegrityFinding& out)
{
    out = IntegrityFinding{};
    for (const auto& it : m_items) {
        const auto& path = it.first; const auto& expected = it.second;
        std::string hex;
        if (!ComputeSHA256File(path, hex)) continue; // if file missing, skip; we can extend later
        int score = 0;
        if (!expected.empty() && _stricmp(expected.c_str(), hex.c_str()) != 0) score += 2; // mismatch strong
        if (expected.empty()) score += 1; // no baseline provided: weak indicator only if we need it
        if (score > 0) {
            out.path = path;
            out.expectedHex = expected;
            out.actualHex = hex;
            out.indicators = score;
            return true;
        }
    }
    return false;
}
