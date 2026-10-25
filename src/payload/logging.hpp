#pragma once

#include <string>

// Logging to the debugger (view with DebugView), prefixed "bedrock-presence: ".
namespace logging {

// Where the log file went (empty when no location was writable).
std::string log_path();

void set_debug(bool enabled);
bool debug_enabled();

// Always logged.
void info(const char* fmt, ...);

// Logged only when "debug_log" is true in config.json.
void debug(const char* fmt, ...);

} // namespace logging
