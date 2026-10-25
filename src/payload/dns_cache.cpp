#include "dns_cache.hpp"

#include <windows.h>

#include <deque>
#include <mutex>

#include "addr.hpp"
#include "logging.hpp"

namespace dns_cache {
namespace {

struct Entry {
    std::string host;
    sockaddr_storage address{};
    uint64_t tick = 0;
};

constexpr size_t kMaxEntries = 128;
constexpr uint64_t kMaxAgeMs = 5 * 60 * 1000;
constexpr uint64_t kAmbiguousMs = 10 * 1000;

std::mutex g_mutex;
std::deque<Entry> g_entries; // oldest first

} // namespace

void record(const std::string& host, const sockaddr* resolved)
{
    if (host.empty() || !addr::is_ip(resolved) || addr::is_ip_literal(host))
        return;
    Entry e;
    e.host = host;
    memcpy(&e.address, resolved, addr::length(resolved));
    e.tick = GetTickCount64();
    std::lock_guard<std::mutex> lock(g_mutex);
    g_entries.push_back(std::move(e));
    while (g_entries.size() > kMaxEntries)
        g_entries.pop_front();
}

std::string lookup(const sockaddr* server)
{
    uint64_t now = GetTickCount64();
    uint16_t port = addr::port(server);
    std::lock_guard<std::mutex> lock(g_mutex);

    const Entry* exact = nullptr; // same ip and port
    const Entry* loose = nullptr; // same ip, lookup had no port
    for (auto it = g_entries.rbegin(); it != g_entries.rend(); ++it)
    {
        if (now - it->tick > kMaxAgeMs)
            break;
        const auto* a = reinterpret_cast<const sockaddr*>(&it->address);
        if (!addr::same_ip(a, server))
            continue;
        uint16_t p = addr::port(a);
        if (p == port && !exact)
            exact = &*it;
        else if (p == 0 && !loose)
            loose = &*it;
    }
    const Entry* best = exact ? exact : loose;
    if (!best)
        return {};

    // Several names on the same address (play./test. on one proxy) resolved
    // recently: the newest is still the best guess, but say so.
    for (const auto& e : g_entries)
    {
        if (&e != best && e.host != best->host && best->tick - e.tick < kAmbiguousMs &&
            addr::same_ip(reinterpret_cast<const sockaddr*>(&e.address), server))
        {
            logging::info("hostname for %s is ambiguous (%s, %s), using %s",
                          addr::ip_string(server).c_str(), e.host.c_str(), best->host.c_str(),
                          best->host.c_str());
            break;
        }
    }
    return best->host;
}

} // namespace dns_cache
