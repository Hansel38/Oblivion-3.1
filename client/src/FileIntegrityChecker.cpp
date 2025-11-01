#include "../pch.h"
#include "FileIntegrityChecker.h"
#include <wincrypt.h>
#include <Psapi.h>
#include <fstream>
#include <vector>
#include <algorithm>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

static std::string ToHex(const BYTE* data, size_t len)
{
    static const char* hex = "0123456789abcdef";
    std::string s; s.resize(len*2);
    for (size_t i=0;i<len;++i) { s[2*i] = hex[(data[i]>>4)&0xF]; s[2*i+1] = hex[data[i]&0xF]; }
    return s;
}

static bool MapFileImage(const std::wstring& path, std::unique_ptr<BYTE[]>& outBuf, size_t& outSize)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    HANDLE mm = CreateFileMappingW(h, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    CloseHandle(h);
    if (!mm) return false;
    PBYTE view = (PBYTE)MapViewOfFile(mm, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(mm);
    if (!view) return false;
    auto dos = (PIMAGE_DOS_HEADER)view;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) { UnmapViewOfFile(view); return false; }
    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)view + dos->e_lfanew);
    size_t sz = nt->OptionalHeader.SizeOfImage;
    std::unique_ptr<BYTE[]> buf(new BYTE[sz]);
    memcpy(buf.get(), view, sz);
    UnmapViewOfFile(view);
    outBuf = std::move(buf); outSize = sz; return true;
}

static bool CompareTextSection(HMODULE mod, const std::wstring& diskPath)
{
    if (!mod) return false;
    PBYTE base = (PBYTE)mod;
    auto dos = (PIMAGE_DOS_HEADER)base; if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    std::unique_ptr<BYTE[]> fileImg; size_t fileSz=0;
    if (!MapFileImage(diskPath, fileImg, fileSz)) return false;
    PBYTE fbase = fileImg.get();
    auto fdos = (PIMAGE_DOS_HEADER)fbase; auto fnt = (PIMAGE_NT_HEADERS)(fbase + fdos->e_lfanew);

    // Find .text sections in both
    PIMAGE_SECTION_HEADER secM = IMAGE_FIRST_SECTION(nt);
    for (UINT i=0;i<nt->FileHeader.NumberOfSections;++i,++secM) {
        char name[9] = {0}; memcpy(name, secM->Name, 8);
        if (strcmp(name, ".text") == 0) {
            DWORD vsize = secM->Misc.VirtualSize;
            DWORD rva = secM->VirtualAddress;
            if (rva + vsize > nt->OptionalHeader.SizeOfImage) vsize = nt->OptionalHeader.SizeOfImage - rva;
            BYTE* memText = base + rva;

            // locate matching section in file image at same RVA
            PIMAGE_SECTION_HEADER secF = IMAGE_FIRST_SECTION(fnt);
            for (UINT j=0;j<fnt->FileHeader.NumberOfSections;++j,++secF) {
                char fname[9] = {0}; memcpy(fname, secF->Name, 8);
                if (strcmp(fname, ".text") == 0) {
                    DWORD frva = secF->VirtualAddress;
                    if (frva == rva) {
                        BYTE* fileText = fbase + frva;
                        DWORD fsize = secF->Misc.VirtualSize;
                        DWORD cmp = std::min<DWORD>(vsize, fsize);
                        return memcmp(memText, fileText, cmp) == 0;
                    }
                }
            }
            // fallback: compare by section name only
            PIMAGE_SECTION_HEADER secF2 = IMAGE_FIRST_SECTION(fnt);
            for (UINT j=0;j<fnt->FileHeader.NumberOfSections;++j,++secF2) {
                char fname[9] = {0}; memcpy(fname, secF2->Name, 8);
                if (strcmp(fname, ".text") == 0) {
                    BYTE* fileText = fbase + secF2->VirtualAddress;
                    DWORD fsize = secF2->Misc.VirtualSize;
                    DWORD cmp = std::min<DWORD>(vsize, fsize);
                    return memcmp(memText, fileText, cmp) == 0;
                }
            }
            break;
        }
    }
    return false;
}

static std::wstring ToLower(const std::wstring& s){ std::wstring r=s; std::transform(r.begin(), r.end(), r.begin(), ::towlower); return r; }

static std::wstring Basename(const std::wstring& path)
{
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return path;
    return path.substr(pos+1);
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

        // If this item refers to an image we might have loaded, compare memory vs disk
        std::wstring lowerPath = ToLower(path);
        if (lowerPath.size() > 4) {
            std::wstring ext = lowerPath.substr(lowerPath.size()-4);
            if (ext == L".exe" || ext == L".dll") {
                // try find loaded module by basename
                HMODULE mods[1024]; DWORD needed=0;
                if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
                    size_t count = needed/sizeof(HMODULE);
                    std::wstring wantBase = ToLower(Basename(lowerPath));
                    for (size_t i=0;i<count;++i) {
                        wchar_t modPath[MAX_PATH]{}; if (!GetModuleFileNameW(mods[i], modPath, MAX_PATH)) continue;
                        std::wstring modBase = ToLower(Basename(modPath));
                        if (modBase == wantBase) {
                            if (!CompareTextSection(mods[i], path)) {
                                score += 2; // memory drift from disk
                            }
                            break;
                        }
                    }
                }
            }
        }
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
