#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include "secret_obf.h"
#if defined(_WIN32)
#include <windows.h>
#else
#include <limits.h>
#include <unistd.h>
#endif

// Obfuscation ringan untuk shared secret. Hindari menyimpan literal string.
// PENTING: Algoritma HARUS SAMA dengan client side!

namespace OblivionServer {
    std::string GetServerSecret() {
        static std::string cached;
        if (!cached.empty()) return cached;

        // 1) Environment variable override
        // Aman: gunakan _dupenv_s di Windows
    #if defined(_WIN32)
        char* envSecret = nullptr;
        size_t envLen = 0;
        if (_dupenv_s(&envSecret, &envLen, "OBLIVION_SECRET") == 0 && envSecret != nullptr) {
            // MSVC envLen includes the terminating NUL; do not append it to the key.
            if (envLen > 1) {
                cached.assign(envSecret);
            }
            std::free(envSecret);
            if (!cached.empty()) {
                return cached;
            }
        }
    #else
        const char* envSecret = getenv("OBLIVION_SECRET");
        if (envSecret && *envSecret) {
            cached = std::string(envSecret);
            return cached;
        }
    #endif

        // 2) File-based secret (secret.dat) encoded dengan XOR agar tidak muncul literal
        //    Lokasi: berdampingan dengan server executable
        std::string secret;
#if defined(_WIN32)
        wchar_t pathBuf[MAX_PATH] = {0};
        DWORD sz = GetModuleFileNameW(NULL, pathBuf, MAX_PATH);
        std::wstring exeDir;
        if (sz > 0) {
            exeDir.assign(pathBuf, sz);
            size_t lastSlash = exeDir.find_last_of(L"\\/");
            if (lastSlash != std::wstring::npos) exeDir = exeDir.substr(0, lastSlash + 1);
        }
        std::wstring secretPathW = exeDir + L"secret.dat";
        HANDLE hFile = CreateFileW(secretPathW.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize > 0 && fileSize < 1024) {
                std::vector<unsigned char> encoded(fileSize);
                DWORD readBytes = 0;
                if (ReadFile(hFile, encoded.data(), fileSize, &readBytes, NULL) && readBytes == fileSize) {
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
#else
        // Resolve secret.dat beside the executable only. If executable-path
        // resolution fails, do not fall back to the process working directory.
        char executablePath[PATH_MAX] = {0};
        std::string executableDir;
        const ssize_t pathLength = readlink("/proc/self/exe", executablePath, sizeof(executablePath) - 1);
        if (pathLength > 0 && static_cast<size_t>(pathLength) < sizeof(executablePath) - 1) {
            executablePath[pathLength] = '\0';
            const std::string fullPath(executablePath);
            const size_t slash = fullPath.find_last_of('/');
            if (slash != std::string::npos) {
                executableDir = fullPath.substr(0, slash + 1);
            }
        }

        FILE* f = nullptr;
        if (!executableDir.empty()) {
            const std::string secretPath = executableDir + "secret.dat";
            f = std::fopen(secretPath.c_str(), "rb");
        }
        if (f) {
            bool readOk = false;
            if (std::fseek(f, 0, SEEK_END) == 0) {
                const long fileSize = std::ftell(f);
                if (fileSize > 0 && fileSize < 1024 && std::fseek(f, 0, SEEK_SET) == 0) {
                    std::vector<unsigned char> encoded(static_cast<size_t>(fileSize));
                    readOk = std::fread(encoded.data(), 1, encoded.size(), f) == encoded.size();
                    if (readOk) {
                        secret.reserve(encoded.size());
                        for (size_t i = 0; i < encoded.size(); ++i) {
                            const unsigned char key = static_cast<unsigned char>(0x5A + ((i * 7) % 0x3F));
                            secret.push_back(static_cast<char>(encoded[i] ^ key));
                        }
                    }
                }
            }
            std::fclose(f);
            if (readOk && !secret.empty()) {
                cached = secret;
                return cached;
            }
        }
#endif

        // 3) Fallback development value jika tidak ada konfigurasi
        const char* devDefault = "DEV_SECRET_NOT_SET";
        size_t len = strlen(devDefault);
        std::vector<unsigned char> encoded(len);
        for (size_t i = 0; i < len; ++i) {
            unsigned char key = (unsigned char)(0x5A + ((i * 7) % 0x3F));
            encoded[i] = (unsigned char)(devDefault[i] ^ key);
        }
        secret.reserve(len);
        for (size_t i = 0; i < len; ++i) {
            unsigned char key = (unsigned char)(0x5A + ((i * 7) % 0x3F));
            secret += (char)(encoded[i] ^ key);
        }

        cached = secret;
        return cached;
    }
}
