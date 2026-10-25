#include "link.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <ctime>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "config.hpp"
#include "discord_ipc.hpp"
#include "logging.hpp"
#include "net_hook.hpp"
#include "packet_send.hpp"
#include "session.hpp"
#include "tls.hpp"

namespace presence_link {
namespace {

using Json = nlohmann::json;

constexpr int kConnectTimeoutMs = 5000;
constexpr int kTickMs = 200;
constexpr size_t kMaxLine = 16 * 1024;
constexpr size_t kMaxToken = 256;

struct State {
    uint64_t session_id = 0;
    std::string buffer;
    uint64_t next_attempt = 0;
    int failures = 0;
    bool popup_shown = false;
    bool presence_set = false;
    bool token_pending = false;
};

State g;
Connection g_conn;

// What Discord shows when the server does not drive it (config default_presence).
enum class Shown { Nothing, Idle, Server, Remote };
struct DefaultState {
    Shown shown = Shown::Nothing;
    Shown mode = Shown::Nothing; // last default mode, for its start time
    uint64_t session_id = 0;
    std::string host;
    int64_t since = 0;
};
DefaultState g_default;

std::wstring wide(const std::string& s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n > 0 ? n - 1 : 0, L'\0');
    if (n > 1)
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

void popup(const std::string& target, int attempts)
{
    std::wstring text = L"Could not connect to presence server " + wide(target) + L" (" +
                        std::to_wstring(attempts) + L" attempts).\nRetrying every " +
                        std::to_wstring(config::retry_interval_ms() / 1000) + L" seconds.";
    // Own thread: a modal box must never stall the game or the link.
    std::thread([text] {
        MessageBoxW(nullptr, text.c_str(), L"Bedrock Presence",
                    MB_OK | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND);
    }).detach();
}

// Server activity gone; update_default() puts the default (or nothing) back.
void clear_presence()
{
    g.presence_set = false;
}

void replace_placeholders(Json& j, const std::string& host)
{
    if (j.is_string())
    {
        std::string s = j.get<std::string>();
        for (size_t pos; (pos = s.find("{host}")) != std::string::npos;)
            s.replace(pos, 6, host);
        j = s;
    }
    else if (j.is_structured())
        for (auto& v : j)
            replace_placeholders(v, host);
}

// Default activity while no server activity is shown: "idle" without a server
// connection (menus, singleplayer, unsupported joins), "server" on a server
// that does not send one (falls back to "idle" when not configured).
void update_default(const std::optional<session::Info>& info)
{
    if (g.presence_set)
    {
        g_default.shown = Shown::Remote;
        return;
    }
    bool on_server = info && info->confirmed;
    Shown mode = on_server ? Shown::Server : Shown::Idle;
    uint64_t session_id = on_server ? info->id : 0;
    std::string host = on_server ? info->host : std::string();
    if (g_default.shown == mode && g_default.session_id == session_id && g_default.host == host)
        return;

    if (g_default.mode != mode || g_default.session_id != session_id)
        g_default.since = static_cast<int64_t>(time(nullptr));
    bool had_activity = g_default.shown != Shown::Nothing;
    g_default.shown = mode;
    g_default.mode = mode;
    g_default.session_id = session_id;
    g_default.host = host;

    const Json& cfg = config::default_presence();
    std::string client_id = cfg.value("client_id", std::string());
    if (client_id.empty())
        client_id = config::default_client_id();
    Json activity = cfg.value(on_server ? "server" : "idle", Json());
    if (!activity.is_object() && on_server)
        activity = cfg.value("idle", Json());
    if (client_id.empty() || !activity.is_object() || activity.empty())
    {
        if (had_activity)
            discord::clear();
        return;
    }
    replace_placeholders(activity, host);
    if (cfg.value("elapsed", true) && !activity.contains("timestamps"))
        activity["timestamps"] = Json{{"start", g_default.since}};
    discord::set_activity(client_id, activity);
}

void close_link(const char* reason)
{
    if (g_conn.is_open())
        logging::info("presence link closed: %s", reason);
    g_conn.close();
    g.buffer.clear();
    clear_presence();
}

bool send_line(const Json& j)
{
    return g_conn.write(j.dump(-1, ' ', false, Json::error_handler_t::replace) + "\n");
}

// Resolve host fresh (a proxy may point the name elsewhere than the game
// address) and connect with a timeout. Returns INVALID_SOCKET on failure.
SOCKET open(const std::string& host, int port)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    std::string service = std::to_string(port);
    if (getaddrinfo(host.c_str(), service.c_str(), &hints, &res) != 0)
    {
        logging::info("presence link: cannot resolve %s", host.c_str());
        return INVALID_SOCKET;
    }
    SOCKET result = INVALID_SOCKET;
    for (addrinfo* ai = res; ai && result == INVALID_SOCKET; ai = ai->ai_next)
    {
        SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;
        u_long nonblocking = 1;
        ioctlsocket(s, FIONBIO, &nonblocking);
        connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        fd_set wr, ex;
        FD_ZERO(&wr);
        FD_ZERO(&ex);
        FD_SET(s, &wr);
        FD_SET(s, &ex);
        timeval tv{kConnectTimeoutMs / 1000, (kConnectTimeoutMs % 1000) * 1000};
        if (select(0, nullptr, &wr, &ex, &tv) == 1 && FD_ISSET(s, &wr))
        {
            nonblocking = 0;
            ioctlsocket(s, FIONBIO, &nonblocking);
            BOOL nodelay = TRUE;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay),
                       sizeof(nodelay));
            result = s;
        }
        else
            closesocket(s);
    }
    freeaddrinfo(res);
    return result;
}

void attempt(const session::Info& info)
{
    const std::string& host = info.host;
    int port = config::port();
    std::string target = host + ":" + std::to_string(port);
    if (SOCKET s = open(host, port); s != INVALID_SOCKET)
    {
        g_conn.attach(s);
        if (config::tls() &&
            !g_conn.start_tls(host, config::tls_verify(), config::tls_pin_sha256()))
            g_conn.close();
    }
    if (!g_conn.is_open())
    {
        g.failures++;
        g.next_attempt = GetTickCount64() + config::retry_interval_ms();
        logging::info("presence link to %s failed (%d in a row)", target.c_str(), g.failures);
        if (g.failures >= config::popup_after_failures() && !g.popup_shown)
        {
            g.popup_shown = true;
            popup(target, g.failures);
        }
        return;
    }
    logging::info("presence link connected to %s%s", target.c_str(), config::tls() ? " (TLS)" : "");
    g.failures = 0;
    g.popup_shown = false;
    Json hello{{"type", "hello"},
               {"version", 1},
               {"host", info.host},
               {"game_port", info.game_port},
               {"transport", info.transport == session::Transport::RakNet ? "raknet" : "nethernet"}};
    // Lets the server map this link to the player (from the Login packet).
    const auto& id = info.identity;
    for (const auto& [key, value] : {std::pair{"client_random_id", &id.client_random_id},
                                     std::pair{"self_signed_id", &id.self_signed_id},
                                     std::pair{"xuid", &id.xuid},
                                     std::pair{"uuid", &id.uuid},
                                     std::pair{"username", &id.username}})
        if (!value->empty())
            hello[key] = *value;
    send_line(hello);
}

void handle_message(const std::string& line)
{
    Json msg = Json::parse(line, nullptr, false);
    if (!msg.is_object())
    {
        logging::info("presence link: ignoring invalid JSON");
        return;
    }
    std::string type = msg.value("type", std::string());
    if (type == "activity")
    {
        std::string client_id = msg.value("client_id", config::default_client_id());
        if (client_id.empty() || !msg["activity"].is_object())
        {
            logging::info("presence link: activity needs client_id and an activity object");
            return;
        }
        discord::set_activity(client_id, msg["activity"]);
        g.presence_set = true;
        g_default.shown = Shown::Remote;
    }
    else if (type == "clear")
        clear_presence();
    else if (type == "token")
    {
        std::string token = msg.value("token", std::string());
        if (token.empty() || token.size() > kMaxToken)
            send_line(Json{{"type", "token_error"}, {"reason", "invalid token"}});
        else if (packet_send::state() == packet_send::State::Failed)
            send_line(Json{{"type", "token_error"},
                           {"reason", "send hook unavailable (see bedrock_presence.log)"}});
        else
        {
            packet_send::queue_token(g.session_id, token);
            g.token_pending = true;
        }
    }
    else
        logging::debug("presence link: unknown message type '%s'", type.c_str());
}

// Wrong field types make json accessors throw; never let that reach the game.
void handle(const std::string& line)
{
    try
    {
        handle_message(line);
    }
    catch (const std::exception& e)
    {
        logging::info("presence link: bad message: %s", e.what());
    }
}

// Read whatever arrived within timeout_ms. false = connection gone.
bool pump(int timeout_ms)
{
    fd_set rd;
    FD_ZERO(&rd);
    FD_SET(g_conn.socket(), &rd);
    timeval tv{0, timeout_ms * 1000};
    int r = select(0, &rd, nullptr, nullptr, &tv);
    if (r < 0)
        return false;
    if (r == 0)
        return true;
    if (!g_conn.read(g.buffer))
        return false;
    size_t nl;
    while ((nl = g.buffer.find('\n')) != std::string::npos)
    {
        std::string line = g.buffer.substr(0, nl);
        g.buffer.erase(0, nl + 1);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            handle(line);
    }
    return g.buffer.size() <= kMaxLine;
}

} // namespace

void run()
{
    net_hook::mark_internal_thread();
    for (;;)
    {
        session::tick();
        auto info = session::current();
        try
        {
            update_default(info);
        }
        catch (const std::exception& e)
        {
            logging::info("default presence: %s", e.what());
        }

        if (!info || !info->confirmed)
        {
            if (g.session_id)
            {
                close_link("left the server");
                g = State{};
            }
            Sleep(kTickMs);
            continue;
        }

        if (info->id != g.session_id)
        {
            close_link("new server session");
            g = State{};
            g.session_id = info->id;
        }

        if (!g_conn.is_open())
        {
            if (info->host_final && GetTickCount64() >= g.next_attempt)
                attempt(*info);
            else
                Sleep(kTickMs);
            continue;
        }

        if (auto r = packet_send::poll_result(); r && r->session_id == g.session_id)
        {
            send_line(Json{{"type", "token_sent"}});
            g.token_pending = false;
        }
        else if (g.token_pending && packet_send::state() == packet_send::State::Failed)
        {
            send_line(Json{{"type", "token_error"},
                           {"reason", "send hook unavailable (see bedrock_presence.log)"}});
            g.token_pending = false;
        }

        if (!pump(kTickMs))
        {
            close_link("server closed the connection");
            g.next_attempt = GetTickCount64() + config::retry_interval_ms();
        }
    }
}

} // namespace presence_link
