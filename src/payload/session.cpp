#include "session.hpp"

#include <windows.h>

#include <atomic>
#include <cctype>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <shared_mutex>

#include "addr.hpp"
#include "config.hpp"
#include "dns_cache.hpp"
#include "logging.hpp"

namespace fs = std::filesystem;

namespace session {
namespace {

// A connection that never gets real traffic (server offline, wrong address)
// is dropped after this long.
constexpr uint64_t kConfirmTimeoutMs = 20000;
// RakNet: wait this long for the Login packet's ServerAddress before falling
// back to the DNS name.
constexpr uint64_t kHostWaitMs = 3000;

struct State {
    bool active = false;
    uint64_t id = 0;
    Transport transport = Transport::RakNet;
    sockaddr_storage server{};
    std::string ip;
    uint16_t game_port = 0;
    std::string host;
    HostSource host_source = HostSource::Ip;
    bool confirmed = false;
    uint64_t start_tick = 0;
    SOCKET socket = INVALID_SOCKET;
    Identity identity;
};

std::shared_mutex g_mutex;
State g_state;
uint64_t g_next_id = 1;
std::atomic<uint64_t> g_active_id{0};
std::atomic<uint64_t> g_last_in{0};
std::atomic<uint64_t> g_last_out{0};

// Whether this process is Minecraft Preview, which keeps its data apart from release.
bool is_preview()
{
    wchar_t exe[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (!n || n >= MAX_PATH)
        return false;
    std::wstring path(exe, n);
    for (wchar_t& c : path)
        c = static_cast<wchar_t>(towlower(c));
    return path.find(L"preview") != std::wstring::npos || path.find(L"beta") != std::wstring::npos;
}

// Bedrock keeps the ClientRandomId it puts in the Login packet in clientId.txt
// (games/com.mojang/minecraftpe), per edition. Needed for NetherNet, whose Login is encrypted.
std::string client_id_file()
{
    static std::string cached = [] {
        wchar_t appdata[MAX_PATH] = {};
        DWORD n = GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH);
        if (!n || n >= MAX_PATH)
            return std::string();
        std::error_code ec;
        bool preview = is_preview();
        fs::path users = fs::path(appdata) / (preview ? L"Minecraft Bedrock Preview" : L"Minecraft Bedrock") / L"Users";
        logging::info("edition: %s", preview ? "preview" : "release");
        fs::path best;
        fs::file_time_type best_time{};
        for (const auto& user : fs::directory_iterator(users, ec))
        {
            fs::path p = user.path() / L"games" / L"com.mojang" / L"minecraftpe" / L"clientId.txt";
            if (!fs::exists(p, ec))
                continue;
            auto t = fs::last_write_time(p, ec);
            if (best.empty() || t > best_time)
            {
                best = p;
                best_time = t;
            }
        }
        std::string id;
        if (!best.empty())
        {
            std::ifstream in(best);
            std::getline(in, id);
            while (!id.empty() && (id.back() == '\r' || id.back() == ' '))
                id.pop_back();
        }
        logging::info("clientId.txt: %s", id.empty() ? "not found" : id.c_str());
        return id;
    }();
    return cached;
}

const char* name(Transport t)
{
    return t == Transport::RakNet ? "RakNet" : "NetherNet";
}

void end_locked(const char* reason)
{
    if (!g_state.active)
        return;
    logging::info("session %llu ended: %s", g_state.id, reason);
    g_state = State{};
    g_active_id = 0;
}

void begin_locked(Transport t, const sockaddr* server, std::string host, HostSource source)
{
    end_locked("new connection");
    g_state.active = true;
    g_state.id = g_next_id++;
    g_state.transport = t;
    memcpy(&g_state.server, server, addr::length(server));
    g_state.ip = addr::ip_string(server);
    g_state.game_port = addr::port(server);
    g_state.start_tick = GetTickCount64();
    g_last_in = 0;
    g_last_out = g_state.start_tick;

    if (source < HostSource::Dns)
    {
        std::string dns = dns_cache::lookup(server);
        if (!dns.empty())
        {
            host = dns;
            source = HostSource::Dns;
        }
    }
    if (host.empty())
        host = g_state.ip;
    g_state.host = host;
    g_state.host_source = source;
    g_state.identity.client_random_id = client_id_file();
    logging::info("session %llu: %s connect to %s:%u (host %s)", g_state.id, name(t),
                  g_state.ip.c_str(), g_state.game_port, host.c_str());
}

} // namespace

void init()
{
    client_id_file();
}

void raknet_open_request(const sockaddr* server, uint8_t id)
{
    std::unique_lock lock(g_mutex);
    bool same = g_state.active && g_state.transport == Transport::RakNet &&
                addr::same_endpoint(reinterpret_cast<const sockaddr*>(&g_state.server), server);
    // OCR1/OCR2 are retried during one handshake; only a fresh OCR1 after an
    // established connection to the same server means a reconnect.
    if (same && !(id == 0x05 && g_state.confirmed))
        return;
    if (id != 0x05 && !same)
        return; // stray OCR2 without OCR1: ignore
    begin_locked(Transport::RakNet, server, {}, HostSource::Ip);
}

void nethernet_join(const sockaddr* server, const std::string& host_header)
{
    std::string host = addr::strip_port(host_header);
    std::unique_lock lock(g_mutex);
    begin_locked(Transport::NetherNet, server, host,
                 host.empty() ? HostSource::Ip : HostSource::Exact);
}

bool matches(const sockaddr* peer, Transport* transport)
{
    if (!addr::is_ip(peer))
        return false;
    std::shared_lock lock(g_mutex);
    if (!g_state.active)
        return false;
    const auto* server = reinterpret_cast<const sockaddr*>(&g_state.server);
    // NetherNet media runs on an ICE port, not the game port: match the IP only.
    bool hit = g_state.transport == Transport::RakNet ? addr::same_endpoint(server, peer)
                                                      : addr::same_ip(server, peer);
    if (hit && transport)
        *transport = g_state.transport;
    return hit;
}

void traffic(bool inbound)
{
    (inbound ? g_last_in : g_last_out) = GetTickCount64();
}

void confirm(SOCKET s)
{
    {
        std::shared_lock lock(g_mutex);
        if (!g_state.active || (g_state.confirmed && g_state.socket == s))
            return;
    }
    std::unique_lock lock(g_mutex);
    if (!g_state.active)
        return;
    g_state.socket = s;
    if (!g_state.confirmed)
    {
        g_state.confirmed = true;
        g_active_id = g_state.id;
        logging::info("session %llu: connected", g_state.id);
    }
}

void set_identity(const Identity& identity)
{
    std::unique_lock lock(g_mutex);
    if (!g_state.active)
        return;
    const std::string& file_id = g_state.identity.client_random_id;
    if (!file_id.empty())
        logging::info(file_id == identity.client_random_id
                          ? "clientId.txt matches Login ClientRandomId"
                          : "clientId.txt (%s) differs from Login ClientRandomId (%s)",
                      file_id.c_str(), identity.client_random_id.c_str());
    std::string fallback_id = file_id;
    g_state.identity = identity;
    if (g_state.identity.client_random_id.empty())
        g_state.identity.client_random_id = fallback_id;
}

void set_host(const std::string& host, HostSource source)
{
    std::string h = addr::strip_port(host);
    if (h.empty())
        return;
    std::unique_lock lock(g_mutex);
    if (!g_state.active || source < g_state.host_source)
        return;
    if (h != g_state.host)
        logging::info("session %llu: host %s", g_state.id, h.c_str());
    g_state.host = h;
    g_state.host_source = source;
}

void end(const char* reason)
{
    std::unique_lock lock(g_mutex);
    end_locked(reason);
}

void socket_closed(SOCKET s)
{
    {
        std::shared_lock lock(g_mutex);
        if (!g_state.active || g_state.socket != s)
            return;
    }
    end("socket closed");
}

void tick()
{
    uint64_t now = GetTickCount64();
    std::unique_lock lock(g_mutex);
    if (!g_state.active)
        return;
    if (!g_state.confirmed)
    {
        if (now - g_state.start_tick > kConfirmTimeoutMs)
            end_locked("server never answered");
        return;
    }
    // Inbound is the real signal; if the game reads with overlapped I/O we never
    // see it, so fall back to our own sends (the game keeps sending while connected).
    uint64_t last = g_last_in ? g_last_in.load() : g_last_out.load();
    uint64_t timeout = static_cast<uint64_t>(config::disconnect_timeout_ms());
    if (last && now > last && now - last > timeout)
        end_locked("timed out");
}

uint64_t active_id()
{
    return g_active_id;
}

std::optional<Info> current()
{
    std::shared_lock lock(g_mutex);
    if (!g_state.active)
        return std::nullopt;
    Info i;
    i.id = g_state.id;
    i.transport = g_state.transport;
    i.ip = g_state.ip;
    i.game_port = g_state.game_port;
    i.host = g_state.host;
    i.host_final = g_state.host_source == HostSource::Exact ||
                   GetTickCount64() - g_state.start_tick > kHostWaitMs;
    i.confirmed = g_state.confirmed;
    i.identity = g_state.identity;
    return i;
}

} // namespace session
