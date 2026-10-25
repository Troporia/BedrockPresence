#pragma once

#include <winsock2.h>

#include <cstddef>
#include <cstdint>

// NetherNet (WebRTC) detection. Joining by address starts with plain HTTP on the
// game port ("POST /v1/join/<networkId>"), then ICE/DTLS/SCTP over UDP.
namespace nethernet {

// Outgoing TCP data; detects the join request.
void on_tcp_send(SOCKET s, const uint8_t* data, size_t len);

// Datagram to/from the current NetherNet server.
void on_session_datagram(SOCKET s, bool inbound, const uint8_t* data, size_t len);

} // namespace nethernet
