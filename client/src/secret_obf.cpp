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

        // 1) Read the environment secret using its reported length. Never silently
        // fall back to secret.dat when a configured environment value is malformed.
        const DWORD requiredChars = GetEnvironmentVariableW(L"OBLIVION_SECRET", nullptr, 0);
        if (requiredChars > 0) {
            std::vector<wchar_t> envBuffer(static_cast<size_t>(requiredChars), L'\0');
            const DWORD envLen = GetEnvironmentVariableW(
                L"OBLIVION_SECRET", envBuffer.data(), requiredChars);
            if (envLen == 0 || envLen >= requiredChars) {
                cached.clear();
                return cached;
            }
            const int sizeNeeded = WideCharToMultiByte(
                CP_UTF8, WC_ERR_INVALID_CHARS, envBuffer.data(), static_cast<int>(envLen),
                nullptr, 0, nullptr, nullptr);
            if (sizeNeeded <= 0) {
                cached.clear();
                return cached;
            }
            std::string envSecret(static_cast<size_t>(sizeNeeded), '\0');
            const int converted = WideCharToMultiByte(
                CP_UTF8, WC_ERR_INVALID_CHARS, envBuffer.data(), static_cast<int>(envLen),
                &envSecret[0], sizeNeeded, nullptr, nullptr);
            if (converted != sizeNeeded) {
                cached.clear();
                return cached;
            }
            cached = envSecret;
            return cached;
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

        // No embedded development secret. An unconfigured client remains
        // unauthenticated and cannot establish an authenticated session.
        cached.clear();
        return cached;
    }
}
