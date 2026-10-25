#pragma once

#include <cstdint>
#include <optional>
#include <string>

// Sends a game packet to the server through the game's own network stack
// (BatchedNetworkPeer::sendPacket), above batching/compression/encryption and
// independent of RakNet/NetherNet.
namespace packet_send {

// Locate and hook sendPacket (RTTI vtable lookup, signature fallback).
void init();

enum class State { Searching, Ready, Failed };
State state();

// Send token to the server in a DebugInfoPacket once the player is in-world in
// session session_id. Replaces any token still pending.
void queue_token(uint64_t session_id, const std::string& token);

struct Result {
    uint64_t session_id = 0;
    bool ok = false;
};

// Outcome of the last queued token, once it was sent.
std::optional<Result> poll_result();

} // namespace packet_send
