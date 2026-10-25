#pragma once

#include <winsock2.h>

#include <cstdint>
#include <string>

// Remembers which hostnames the game resolved to which addresses, so a server
// joined by domain can be reached by that same domain.
namespace dns_cache {

// Record one resolved address. port is 0 when the lookup had no service/port.
void record(const std::string& host, const sockaddr* resolved);

// Newest hostname that resolved to this address, preferring lookups that also
// named the same port. Empty when the address was never resolved (joined by IP).
std::string lookup(const sockaddr* server);

} // namespace dns_cache
