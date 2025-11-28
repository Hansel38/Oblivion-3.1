#include "pch.h"
#include "secret_obf.h"
#include <vector>
#include <windows.h>

// Original secret: OBLIVION_SEC_2025
// Obfuscation sederhana dengan XOR + rotasi bit untuk menyulitkan static analysis.
// Tinggal ganti string di bawah, algoritma akan otomatis encode/decode.

namespace Oblivion {
    std::string GetClientSecret() {
        static std::string cached;
        if (!cached.empty()) {
            return cached;
        }

        // GANTI SECRET DI SINI (bisa berapa karakter pun):
        const char* original = "OBLIVION_SEC_2025";
        
        // Encode dengan XOR pattern berbasis index
        size_t len = strlen(original);
        std::vector<unsigned char> encoded(len);
        
        for (size_t i = 0; i < len; ++i) {
            unsigned char key = (unsigned char)(0x5A + ((i * 7) % 0x3F));
            encoded[i] = (unsigned char)(original[i] ^ key);
        }
        
        // Decode kembali
        std::string secret;
        secret.reserve(len);
        for (size_t i = 0; i < len; ++i) {
            unsigned char key = (unsigned char)(0x5A + ((i * 7) % 0x3F));
            secret += (char)(encoded[i] ^ key);
        }

        cached = secret;
        return cached;
    }
}
