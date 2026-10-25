#include "sigscan.hpp"

#include <windows.h>

#include <psapi.h>

#include <optional>
#include <vector>

namespace {

struct Pattern {
    std::vector<uint8_t> bytes;
    std::vector<bool> mask; // true = compare, false = wildcard
};

Pattern parse(const char* p)
{
    Pattern out;
    while (*p)
    {
        if (*p == ' ')
        {
            ++p;
            continue;
        }
        if (p[0] == '?')
        {
            out.bytes.push_back(0);
            out.mask.push_back(false);
            p += (p[1] == '?') ? 2 : 1;
        }
        else
        {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9')
                    return c - '0';
                if (c >= 'a' && c <= 'f')
                    return c - 'a' + 10;
                if (c >= 'A' && c <= 'F')
                    return c - 'A' + 10;
                return 0;
            };
            out.bytes.push_back(static_cast<uint8_t>((hex(p[0]) << 4) | hex(p[1])));
            out.mask.push_back(true);
            p += 2;
        }
    }
    return out;
}

} // namespace

uint8_t* find_pattern(const char* module_name, const char* pattern)
{
    HMODULE mod = GetModuleHandleA(module_name);
    if (!mod)
        return nullptr;
    MODULEINFO info{};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &info, sizeof(info)))
        return nullptr;

    Pattern pat = parse(pattern);
    if (pat.bytes.empty())
        return nullptr;

    auto* base = static_cast<uint8_t*>(info.lpBaseOfDll);
    size_t size = info.SizeOfImage;
    size_t n = pat.bytes.size();

    for (size_t i = 0; i + n <= size; ++i)
    {
        bool ok = true;
        for (size_t j = 0; j < n; ++j)
        {
            if (pat.mask[j] && base[i + j] != pat.bytes[j])
            {
                ok = false;
                break;
            }
        }
        if (ok)
            return base + i;
    }
    return nullptr;
}
