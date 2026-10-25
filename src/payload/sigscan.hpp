#pragma once

#include <cstdint>

// Scan the given module's executable memory for a byte pattern.
// Pattern is IDA-style, space separated, "??" for wildcards, e.g. "41 57 ?? 48".
// Returns the address of the first match, or nullptr.
uint8_t* find_pattern(const char* module_name, const char* pattern);
