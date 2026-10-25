#pragma once

#include <string>

#include <nlohmann/json.hpp>

// Discord Rich Presence over the local IPC pipe (\\.\pipe\discord-ipc-N).
// All pipe I/O runs on one background thread; these calls only queue.
namespace discord {

void start();

// Show activity under the Discord application client_id. A different client_id
// than the current one reconnects with that id.
void set_activity(const std::string& client_id, const nlohmann::json& activity);

void clear();

} // namespace discord
