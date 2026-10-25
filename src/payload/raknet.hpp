#pragma once

#include <winsock2.h>

#include <cstddef>
#include <cstdint>

// RakNet (UDP) parsing for session start, the joined hostname and disconnects.
namespace raknet {

// Any outgoing datagram; detects Open Connection Requests.
void on_send(const sockaddr* to, const uint8_t* data, size_t len);

// Datagram to/from the current RakNet server.
void on_session_datagram(SOCKET s, bool inbound, const uint8_t* data, size_t len);

} // namespace raknet
