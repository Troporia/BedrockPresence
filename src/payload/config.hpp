#pragma once

#include <string>

#include <nlohmann/json.hpp>

// Settings from config.json next to the DLL (created with defaults on first run).
namespace config {

void load();

int port();                    // presence TCP port on the game server host
std::string default_client_id(); // Discord application id when a message has none
int disconnect_timeout_ms();   // no traffic from the server for this long = disconnected
int retry_interval_ms();       // wait between presence connection attempts
int popup_after_failures();    // consecutive failed attempts before the warning popup
bool debug_log();
std::string send_packet_class(); // RTTI class whose vtable holds sendPacket
int send_packet_vtable_index(); // sendPacket vtable slot
std::string send_packet_signature(); // fallback byte pattern for sendPacket
bool tls();                    // encrypt the presence link (TLS 1.2)
bool tls_verify();             // check the certificate against system trust + hostname
std::string tls_pin_sha256();  // accept exactly this certificate (self-signed)
// {"client_id", "elapsed", "idle": activity, "server": activity}: shown while no
// server activity is (menus, singleplayer, servers without presence).
const nlohmann::json& default_presence();

} // namespace config
