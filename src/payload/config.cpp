#include "config.hpp"

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>

namespace fs = std::filesystem;

namespace config {
namespace {

using Json = nlohmann::json;

int g_port = 9514;
std::string g_default_client_id;
int g_disconnect_timeout_ms = 10000;
int g_retry_interval_ms = 30000;
int g_popup_after_failures = 3;
bool g_debug_log = false;
std::string g_send_packet_class = "BatchedNetworkPeer";
int g_send_packet_vtable_index = 1;
std::string g_send_packet_signature;
bool g_tls = false;
bool g_tls_verify = true;
std::string g_tls_pin_sha256;
Json g_default_presence = Json::object();

// Directory of this DLL (where the injector and config.json sit).
fs::path dll_dir()
{
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&dll_dir), &self);
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(self, path, MAX_PATH);
    return fs::path(path).parent_path();
}

} // namespace

void load()
{
    Json j{{"port", 9514},
           {"default_client_id", ""},
           {"disconnect_timeout_ms", 10000},
           {"retry_interval_ms", 30000},
           {"popup_after_failures", 3},
           {"debug_log", false},
           {"send_packet_class", "BatchedNetworkPeer"},
           {"send_packet_vtable_index", 1},
           {"send_packet_signature", ""},
           {"tls", false},
           {"tls_verify", true},
           {"tls_pin_sha256", ""},
           {"default_presence",
            {{"client_id", ""},
             {"elapsed", true},
             {"idle", {{"details", "In the menus"}}},
             {"server", {{"details", "Playing multiplayer"}}}}}};

    fs::path path = dll_dir() / L"config.json";
    std::error_code ec;
    if (fs::exists(path, ec))
    {
        try
        {
            std::ifstream in(path);
            j.merge_patch(Json::parse(in, nullptr, true, true));
        }
        catch (...)
        {
        }
    }
    else
    {
        std::ofstream out(path);
        out << j.dump(2);
    }

    auto num = [&](const char* key, int fallback) {
        const auto& v = j[key];
        return v.is_number_integer() ? v.get<int>() : fallback;
    };
    auto str = [&](const char* key) {
        const auto& v = j[key];
        return v.is_string() ? v.get<std::string>() : std::string();
    };

    g_port = num("port", 9514);
    g_default_client_id = str("default_client_id");
    g_disconnect_timeout_ms = num("disconnect_timeout_ms", 10000);
    g_retry_interval_ms = num("retry_interval_ms", 30000);
    g_popup_after_failures = num("popup_after_failures", 3);
    auto flag = [&](const char* key, bool fallback) {
        const auto& v = j[key];
        return v.is_boolean() ? v.get<bool>() : fallback;
    };
    g_send_packet_class = str("send_packet_class");
    if (g_send_packet_class.empty())
        g_send_packet_class = "BatchedNetworkPeer";
    g_send_packet_vtable_index = num("send_packet_vtable_index", 1);
    g_send_packet_signature = str("send_packet_signature");
    g_debug_log = flag("debug_log", false);
    g_tls = flag("tls", false);
    g_tls_verify = flag("tls_verify", true);
    g_tls_pin_sha256 = str("tls_pin_sha256");
    g_default_presence = j["default_presence"].is_object() ? j["default_presence"] : Json::object();
}

int port()
{
    return g_port;
}

std::string default_client_id()
{
    return g_default_client_id;
}

int disconnect_timeout_ms()
{
    return g_disconnect_timeout_ms;
}

int retry_interval_ms()
{
    return g_retry_interval_ms;
}

int popup_after_failures()
{
    return g_popup_after_failures;
}

bool debug_log()
{
    return g_debug_log;
}

std::string send_packet_class()
{
    return g_send_packet_class;
}

int send_packet_vtable_index()
{
    return g_send_packet_vtable_index;
}

std::string send_packet_signature()
{
    return g_send_packet_signature;
}

bool tls()
{
    return g_tls;
}

bool tls_verify()
{
    return g_tls_verify;
}

std::string tls_pin_sha256()
{
    return g_tls_pin_sha256;
}

const Json& default_presence()
{
    return g_default_presence;
}

} // namespace config
