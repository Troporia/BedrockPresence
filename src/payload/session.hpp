#pragma once

#include <winsock2.h>

#include <cstdint>
#include <optional>
#include <string>

// The game's current server connection, as seen from Winsock traffic.
namespace session {

enum class Transport { RakNet, NetherNet };

// Where a hostname came from; higher wins.
enum class HostSource { Ip = 0, Dns = 1, Exact = 2 };

// Player identity from the Login packet (RakNet; empty fields when unknown).
struct Identity {
    std::string client_random_id; // int64 as decimal text
    std::string self_signed_id;
    std::string xuid;
    std::string uuid;
    std::string username;
};

struct Info {
    uint64_t id = 0;
    Transport transport = Transport::RakNet;
    std::string ip;
    uint16_t game_port = 0;
    std::string host;   // what the player joined (domain or IP)
    bool host_final = false; // host will not change any more
    bool confirmed = false;  // the server answered; not just an attempt
    Identity identity; // client_random_id also from clientId.txt (NetherNet)
};

// Read clientId.txt once, off the game's network threads.
void init();

// RakNet Open Connection Request 1/2 (id 0x05/0x07) sent to server.
void raknet_open_request(const sockaddr* server, uint8_t id);

// NetherNet "POST /v1/join/..." sent to server over TCP; host from the Host header.
void nethernet_join(const sockaddr* server, const std::string& host_header);

// Fast check: is this datagram peer the current server? Fills transport when true.
bool matches(const sockaddr* peer, Transport* transport);

// Datagram to or from the current server (after matches()).
void traffic(bool inbound);

// The server answered with real connection traffic; s is the socket carrying it.
void confirm(SOCKET s);

// Better hostname found (Login ServerAddress, Host header).
void set_host(const std::string& host, HostSource source);

// ClientRandomId/SelfSignedId from the Login packet.
void set_identity(const Identity& identity);

// The connection ended (disconnect packet, socket closed, ...).
void end(const char* reason);

// Socket closed by the game.
void socket_closed(SOCKET s);

// Timeouts; call periodically.
void tick();

// Id of the confirmed session, 0 when none. Lock-free.
uint64_t active_id();

std::optional<Info> current();

} // namespace session
