#pragma once

#include <cstdint>
#include <string>

namespace Oblivion {
namespace Protocol {

// Canonical heartbeat PONG authentication payload. Changes here are wire
// protocol changes and must be deployed to client and servers together.
inline std::string BuildPongAuthPayload(
    std::uint64_t sequence,
    std::uint64_t clientTimestamp,
    std::uint64_t serverTimestamp,
    std::uint64_t nonce,
    const std::string& status,
    const std::string& hwid) {
    return std::to_string(sequence) + ":" +
           std::to_string(clientTimestamp) + ":" +
           std::to_string(serverTimestamp) + ":" +
           std::to_string(nonce) + ":" +
           status + ":" + hwid;
}

} // namespace Protocol
} // namespace Oblivion
