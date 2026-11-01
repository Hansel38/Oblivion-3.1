#include "pch.h"
#include "secret_obf.h"
#include "win_path_utils.h"
#include <vector>
#include <windows.h>

// Obfuscation ringan untuk shared secret. Hindari menyimpan literal string.

namespace Oblivion {
    std::string GetClientSecret() {
        static std::string cached;
        if (!cached.empty()) {
            return cached;
        }

        // 1) Coba ambil dari environment variable (runtime configurable)
        //    Set dengan nama OBLIVION_SECRET untuk override tanpa recompile
        wchar_t envBuf[256] = {0};
        DWORD envLen = GetEnvironmentVariableW(L"OBLIVION_SECRET", envBuf, 255);
        if (envLen > 0 && envLen < 255) {
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, envBuf, (int)envLen, NULL, 0, NULL, NULL);
            if (size_needed > 0) {
                std::string envSecret(size_needed, '\0');
                WideCharToMultiByte(CP_UTF8, 0, envBuf, (int)envLen, &envSecret[0], size_needed, NULL, NULL);
                cached = envSecret;
                return cached;
            }
        }

        // 2) Coba load dari file berdampingan (secret.dat) untuk produksi
        //    File berisi bytes yang sudah di-XOR (encoded) agar tidak terlihat literal
        std::wstring secretPathW;
        const std::wstring executablePath = Oblivion::WinPath::GetModulePath(nullptr);
        if (!executablePath.empty()) {
            const size_t lastSlash = executablePath.find_last_of(L"\\/");
            if (lastSlash != std::wstring::npos) {
                secretPathW = executablePath.substr(0, lastSlash + 1) + L"secret.dat";
            }
        }

        // Do not fall back to the process working directory if module path
        // resolution fails; only load a secret located beside the executable.
        HANDLE hFile = secretPathW.empty()
            ? INVALID_HANDLE_VALUE
            : CreateFileW(secretPathW.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize > 0 && fileSize < 1024) {
                std::vector<unsigned char> encoded(fileSize);
                DWORD readBytes = 0;
                if (ReadFile(hFile, encoded.data(), fileSize, &readBytes, NULL) && readBytes == fileSize) {
                    std::string secret;
                    secret.reserve(fileSize);
                    for (size_t i = 0; i < encoded.size(); ++i) {
                        unsigned char key = (unsigned char)(0x5A + ((i * 7) % 0x3F));
                        secret += (char)(encoded[i] ^ key);
                    }
                    CloseHandle(hFile);
                    cached = secret;
                    return cached;
                }
            }
            CloseHandle(hFile);
        }

        // No built-in shared-secret fallback: missing deployment credentials must fail closed.
        return cached;
    }
}
