#include "../common/heartbeat_auth.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

int main() {
    const std::string payload = Oblivion::Protocol::BuildPongAuthPayload(
        42, 1700000000123ULL, 1700000000000ULL, 987654321ULL,
        "1|1", "TEST-HWID-0123456789");
    const std::string expectedPayload =
        "42:1700000000123:1700000000000:987654321:1|1:TEST-HWID-0123456789";
    if (payload != expectedPayload) {
        std::cerr << "PONG authentication payload does not match the protocol contract\n";
        return 1;
    }

    // Golden vector detects field omission, reordering, delimiter drift and
    // inconsistent serialization between client and server implementations.
    const std::string key = "oblivion-test-session-key";
    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digestLength = 0;
    if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char*>(payload.data()),
             payload.size(), digest, &digestLength) == nullptr || digestLength != 32U) {
        std::cerr << "Unable to calculate the test HMAC\n";
        return 2;
    }

    std::ostringstream encoded;
    encoded << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digestLength; ++i) {
        encoded << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }
    if (encoded.str() != "af9639a703f11195153d91e5448a5a9e00a96c25ce54a2f1f1374d7decdd8b8b") {
        std::cerr << "HMAC does not match the golden protocol vector\n";
        return 3;
    }

    const std::string alteredStatus = Oblivion::Protocol::BuildPongAuthPayload(
        42, 1700000000123ULL, 1700000000000ULL, 987654321ULL,
        "0|1", "TEST-HWID-0123456789");
    const std::string alteredTimestamp = Oblivion::Protocol::BuildPongAuthPayload(
        42, 1700000000124ULL, 1700000000000ULL, 987654321ULL,
        "1|1", "TEST-HWID-0123456789");
    if (alteredStatus == payload || alteredTimestamp == payload) {
        std::cerr << "PONG authentication payload does not bind all security fields\n";
        return 4;
    }

    std::cout << "Heartbeat authentication contract: PASS\n";
    return 0;
}
