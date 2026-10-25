#include "discord_ipc.hpp"

#include <windows.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>

#include "logging.hpp"

namespace discord {
namespace {

using Json = nlohmann::json;

enum Opcode : uint32_t { Handshake = 0, Frame = 1, Close = 2, Ping = 3, Pong = 4 };

struct Desired {
    std::string client_id;
    Json activity;
};

std::mutex g_mutex;
std::condition_variable g_cv;
bool g_changed = false;
std::optional<Desired> g_desired; // nullopt = no activity

// Presence thread only.
HANDLE g_pipe = INVALID_HANDLE_VALUE;
std::string g_client_id;
uint64_t g_nonce = 0;

void close_pipe()
{
    if (g_pipe != INVALID_HANDLE_VALUE)
        CloseHandle(g_pipe);
    g_pipe = INVALID_HANDLE_VALUE;
    g_client_id.clear();
}

bool write_frame(uint32_t op, const Json& payload)
{
    std::string body = payload.dump(-1, ' ', false, Json::error_handler_t::replace);
    std::string frame(8, '\0');
    uint32_t len = static_cast<uint32_t>(body.size());
    memcpy(frame.data(), &op, 4);
    memcpy(frame.data() + 4, &len, 4);
    frame += body;
    DWORD written = 0;
    return WriteFile(g_pipe, frame.data(), static_cast<DWORD>(frame.size()), &written, nullptr) &&
           written == frame.size();
}

bool read_exact(void* buf, DWORD n)
{
    auto* p = static_cast<char*>(buf);
    while (n)
    {
        DWORD got = 0;
        if (!ReadFile(g_pipe, p, n, &got, nullptr) || got == 0)
            return false;
        p += got;
        n -= got;
    }
    return true;
}

// Read one frame if one arrives within timeout_ms. false on timeout or a broken pipe
// (broken also closes the pipe).
bool read_frame(uint32_t& op, Json& payload, int timeout_ms)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;)
    {
        DWORD avail = 0;
        if (!PeekNamedPipe(g_pipe, nullptr, 0, nullptr, &avail, nullptr))
        {
            close_pipe();
            return false;
        }
        if (avail >= 8)
            break;
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    uint32_t header[2];
    if (!read_exact(header, sizeof(header)) || header[1] > 64 * 1024)
    {
        close_pipe();
        return false;
    }
    op = header[0];
    std::string body(header[1], '\0');
    if (header[1] && !read_exact(body.data(), header[1]))
    {
        close_pipe();
        return false;
    }
    payload = Json::parse(body, nullptr, false);
    return true;
}

// Handle anything Discord sent (responses, errors, pings).
void drain()
{
    uint32_t op;
    Json payload;
    while (g_pipe != INVALID_HANDLE_VALUE && read_frame(op, payload, 0))
    {
        if (op == Ping)
            write_frame(Pong, payload);
        else if (op == Close)
        {
            logging::info("Discord closed the connection: %s", payload.dump(-1, ' ', false, Json::error_handler_t::replace).c_str());
            close_pipe();
        }
        else if (payload.is_object() && payload.value("evt", Json()) == "ERROR")
            logging::info("Discord error: %s", payload.dump(-1, ' ', false, Json::error_handler_t::replace).c_str());
    }
}

bool connect(const std::string& client_id)
{
    close_pipe();
    for (int i = 0; i < 10; ++i)
    {
        std::wstring name = L"\\\\.\\pipe\\discord-ipc-" + std::to_wstring(i);
        g_pipe = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                             0, nullptr);
        if (g_pipe != INVALID_HANDLE_VALUE)
            break;
    }
    if (g_pipe == INVALID_HANDLE_VALUE)
    {
        logging::debug("Discord is not running (no IPC pipe)");
        return false;
    }
    if (!write_frame(Handshake, Json{{"v", 1}, {"client_id", client_id}}))
    {
        close_pipe();
        return false;
    }
    uint32_t op;
    Json payload;
    if (!read_frame(op, payload, 5000) || op != Frame || !payload.is_object() ||
        payload.value("evt", Json()) != "READY")
    {
        logging::info("Discord handshake failed (client_id %s): %s", client_id.c_str(),
                      payload.dump(-1, ' ', false, Json::error_handler_t::replace).c_str());
        close_pipe();
        return false;
    }
    g_client_id = client_id;
    logging::info("connected to Discord (client_id %s)", client_id.c_str());
    return true;
}

bool send_activity(const Json* activity)
{
    Json args{{"pid", GetCurrentProcessId()}};
    if (activity)
        args["activity"] = *activity;
    Json cmd{{"cmd", "SET_ACTIVITY"}, {"args", args}, {"nonce", std::to_string(++g_nonce)}};
    if (write_frame(Frame, cmd))
        return true;
    close_pipe();
    return false;
}

// Bring Discord in line with the desired state. false = retry later.
bool apply(const std::optional<Desired>& desired)
{
    if (!desired)
    {
        if (g_pipe != INVALID_HANDLE_VALUE)
            send_activity(nullptr);
        return true;
    }
    if (g_pipe != INVALID_HANDLE_VALUE && g_client_id != desired->client_id)
    {
        send_activity(nullptr);
        close_pipe();
    }
    if (g_pipe == INVALID_HANDLE_VALUE && !connect(desired->client_id))
        return false;
    return send_activity(&desired->activity);
}

void worker()
{
    bool dirty = false;
    std::optional<Desired> desired;
    for (;;)
    {
        {
            std::unique_lock<std::mutex> lock(g_mutex);
            g_cv.wait_for(lock, std::chrono::seconds(dirty ? 15 : 2), [] { return g_changed; });
            if (g_changed)
            {
                desired = g_desired;
                g_changed = false;
                dirty = true;
            }
        }
        bool had_pipe = g_pipe != INVALID_HANDLE_VALUE;
        drain();
        // Discord restarted or dropped us: show the activity again once it is back.
        if (had_pipe && g_pipe == INVALID_HANDLE_VALUE && desired)
            dirty = true;
        if (dirty)
            dirty = !apply(desired);
    }
}

void post(std::optional<Desired> d)
{
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_desired = std::move(d);
        g_changed = true;
    }
    g_cv.notify_one();
}

} // namespace

void start()
{
    std::thread(worker).detach();
}

void set_activity(const std::string& client_id, const nlohmann::json& activity)
{
    post(Desired{client_id, activity});
}

void clear()
{
    post(std::nullopt);
}

} // namespace discord
