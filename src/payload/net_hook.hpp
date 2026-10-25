#pragma once

// Winsock and resolver hooks feeding session/raknet/nethernet/dns_cache.
namespace net_hook {

// Create and enable the hooks. MH_Initialize must have been called.
bool install();

// Call on threads that make our own network calls (presence link), so their
// sockets and lookups are not mistaken for the game's.
void mark_internal_thread();

} // namespace net_hook
