#include "packet_send.hpp"

#include <windows.h>

#include <atomic>
#include <cstring>
#include <mutex>
#include <string_view>
#include <thread>
#include <vector>

#include "MinHook.h"
#include <nlohmann/json.hpp>

#include "config.hpp"
#include "logging.hpp"
#include "session.hpp"
#include "sigscan.hpp"

namespace packet_send {
namespace {

constexpr uint32_t kPlayerAuthInput = 144;
constexpr uint32_t kDebugInfoPacket = 155;
// NetworkPeer::Reliability::ReliableOrdered, Compressibility::Compressible.
constexpr int kReliableOrdered = 1;
constexpr int kCompressible = 0;

// The game's std::string (MSVC x64 layout), spelled out so this DLL does not
// depend on being built with the same standard library.
struct GameString {
    union {
        char inline_buf[16];
        const char* heap;
    };
    size_t size;
    size_t capacity; // > 15 means the text lives at heap

    std::string_view view() const { return {capacity > 15 ? heap : inline_buf, size}; }
};
static_assert(sizeof(GameString) == 32);

// Points at text (which must stay alive and be null-terminated while in use).
GameString make_game_string(const std::string& text)
{
    GameString g{};
    g.size = text.size();
    if (text.size() < 16)
    {
        memcpy(g.inline_buf, text.c_str(), text.size() + 1);
        g.capacity = 15;
    }
    else
    {
        g.heap = text.c_str();
        g.capacity = text.size();
    }
    return g;
}

// virtual void BatchedNetworkPeer::sendPacket(const std::string& data,
//     NetworkPeer::Reliability, Compressibility); data = VarUInt header + payload.
using SendPacket = void (*)(void* self, const GameString* data, int reliability, int compressibility);

SendPacket g_original = nullptr;
std::atomic<State> g_state{State::Searching};

std::atomic<uint64_t> g_in_world_session{0}; // session in which PlayerAuthInput was seen
std::atomic<bool> g_pending{false};
std::mutex g_mutex;
uint64_t g_pending_session = 0;
std::string g_pending_token;
std::optional<Result> g_result;
std::atomic<int> g_logged_packets{0};

void write_varuint(std::string& out, uint64_t v)
{
    while (v >= 0x80)
    {
        out.push_back(static_cast<char>((v & 0x7F) | 0x80));
        v >>= 7;
    }
    out.push_back(static_cast<char>(v));
}

bool read_varuint(std::string_view s, uint32_t& v)
{
    v = 0;
    for (size_t i = 0; i < s.size() && i < 5; ++i)
    {
        uint8_t b = static_cast<uint8_t>(s[i]);
        v |= static_cast<uint32_t>(b & 0x7F) << (7 * i);
        if (!(b & 0x80))
            return true;
    }
    return false;
}

// DebugInfoPacket: zigzag VarLong uniqueEntityId, VarUInt-length string data.
std::string debug_info_packet(const std::string& data)
{
    std::string p;
    write_varuint(p, kDebugInfoPacket); // header: id, sub-client ids 0
    write_varuint(p, 0);                // zigzag(0)
    write_varuint(p, data.size());
    p += data;
    return p;
}

void detour(void* self, const GameString* data, int reliability, int compressibility)
{
    g_original(self, data, reliability, compressibility);

    uint32_t header = 0;
    if (!data || !read_varuint(data->view(), header))
        return;
    uint32_t id = header & 0x3FF;
    if (logging::debug_enabled() && g_logged_packets.fetch_add(1) < 5)
        logging::debug("sendPacket id %u (reliability %d, compressibility %d)", id, reliability,
                       compressibility);

    uint64_t sid = session::active_id();
    if (id == kPlayerAuthInput && sid && g_in_world_session.load() != sid)
        g_in_world_session = sid;

    // Inject on the game's own network thread, right after one of its packets,
    // and only once the player is in-world so the handshake/login is done.
    if (!g_pending.load() || sid == 0 || g_in_world_session.load() != sid)
        return;
    std::string token;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_pending || g_pending_session != sid)
            return;
        token = std::move(g_pending_token);
        g_pending = false;
    }
    std::string packet = debug_info_packet(nlohmann::json{{"presence_token", token}}.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
    GameString game_packet = make_game_string(packet);
    g_original(self, &game_packet, kReliableOrdered, kCompressible);
    logging::info("sent presence token in DebugInfoPacket");
    std::lock_guard<std::mutex> lock(g_mutex);
    g_result = Result{sid, true};
}

struct Region {
    uint8_t* base;
    size_t size;
};

// Committed, readable pages of the module. Protected game builds keep some
// pages inaccessible (decrypted on first use), so never touch those.
std::vector<Region> readable_regions(HMODULE module)
{
    std::vector<Region> out;
    auto* base = reinterpret_cast<uint8_t*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    uint8_t* end = base + nt->OptionalHeader.SizeOfImage;
    constexpr DWORD readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    for (uint8_t* p = base; p < end;)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(p, &mbi, sizeof(mbi)) || mbi.RegionSize == 0)
            break;
        auto* rb = static_cast<uint8_t*>(mbi.BaseAddress);
        uint8_t* re = rb + mbi.RegionSize;
        if (re > end)
            re = end;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & readable) && !(mbi.Protect & PAGE_GUARD))
        {
            if (!out.empty() && out.back().base + out.back().size == rb)
                out.back().size += re - rb;
            else
                out.push_back({rb, static_cast<size_t>(re - rb)});
        }
        p = re;
    }
    return out;
}

// Log RTTI class names containing "NetworkPeer" (helps when the configured
// class is missing after a game update).
void log_peer_classes(const std::vector<Region>& regions)
{
    constexpr std::string_view prefix = ".?AV";
    int logged = 0;
    size_t total_names = 0, total_bytes = 0;
    for (const auto& r : regions)
    {
        total_bytes += r.size;
        for (size_t i = 0; i + prefix.size() < r.size; ++i)
            total_names += memcmp(r.base + i, prefix.data(), prefix.size()) == 0;
    }
    logging::info("scanned %zu readable region(s), %zu MiB, %zu RTTI class name(s)", regions.size(),
                  total_bytes >> 20, total_names);
    for (const auto& r : regions)
    {
        for (size_t i = 0; i + prefix.size() < r.size && logged < 30; ++i)
        {
            if (memcmp(r.base + i, prefix.data(), prefix.size()) != 0)
                continue;
            size_t n = 0;
            while (i + n < r.size && n < 128 && r.base[i + n] >= 0x20 && r.base[i + n] < 0x7F)
                ++n;
            std::string_view name(reinterpret_cast<const char*>(r.base + i), n);
            if (name.find("NetworkPeer") != std::string_view::npos)
            {
                logging::info("RTTI class: %.*s", static_cast<int>(name.size()), name.data());
                ++logged;
            }
            i += n;
        }
    }
    if (logged == 0)
        logging::info("no RTTI class names with NetworkPeer found (RTTI stripped?)");
}

// MSVC x64 RTTI: TypeDescriptor{vftable, spare, name} -> CompleteObjectLocator
// {signature=1, offset, cdOffset, typeDescriptor RVA, classDescriptor RVA, self RVA}
// -> vtable[-1] points at the locator.
void** find_vtable(HMODULE module, const std::string& mangled, bool diagnose)
{
    auto* base = reinterpret_cast<uint8_t*>(module);
    auto regions = readable_regions(module);

    std::vector<uint32_t> type_rvas;
    for (const auto& r : regions)
    {
        for (size_t i = 0; i + mangled.size() + 1 <= r.size; ++i)
        {
            if (r.base[i] == '.' && memcmp(r.base + i, mangled.data(), mangled.size()) == 0 &&
                r.base[i + mangled.size()] == 0 && r.base + i >= base + 16)
                type_rvas.push_back(static_cast<uint32_t>(r.base + i - 16 - base));
        }
    }
    if (type_rvas.empty())
    {
        if (diagnose)
        {
            logging::info("RTTI name %s not found", mangled.c_str());
            log_peer_classes(regions);
        }
        return nullptr;
    }

    int locators = 0;
    for (const auto& r : regions)
    {
        for (size_t i = (4 - reinterpret_cast<uintptr_t>(r.base) % 4) % 4; i + 24 <= r.size; i += 4)
        {
            const auto* col = reinterpret_cast<const uint32_t*>(r.base + i);
            uint32_t self_rva = static_cast<uint32_t>(r.base + i - base);
            if (col[0] != 1 || col[1] != 0 || col[5] != self_rva)
                continue;
            bool match = false;
            for (uint32_t rva : type_rvas)
                match |= col[3] == rva;
            if (!match)
                continue;
            ++locators;
            uintptr_t col_addr = reinterpret_cast<uintptr_t>(col);
            for (const auto& v : regions)
            {
                for (size_t j = (8 - reinterpret_cast<uintptr_t>(v.base) % 8) % 8; j + 16 <= v.size; j += 8)
                {
                    if (*reinterpret_cast<const uintptr_t*>(v.base + j) == col_addr)
                        return reinterpret_cast<void**>(v.base + j + 8);
                }
            }
        }
    }
    if (diagnose)
        logging::info("RTTI %s: %zu type descriptor(s), %d object locator(s), no vtable",
                      mangled.c_str(), type_rvas.size(), locators);
    return nullptr;
}

bool hook_vtable(void** vtable, int index)
{
    void** slot = vtable + index;
    DWORD old = 0;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old))
        return false;
    g_original = reinterpret_cast<SendPacket>(*slot);
    *slot = reinterpret_cast<void*>(&detour);
    VirtualProtect(slot, sizeof(void*), old, &old);
    return true;
}

bool hook_signature(const std::string& signature)
{
    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring_view path(exe);
    std::wstring name(path.substr(path.find_last_of(L"\\/") + 1));
    char module[MAX_PATH] = {};
    WideCharToMultiByte(CP_UTF8, 0, name.c_str(), -1, module, sizeof(module), nullptr, nullptr);
    uint8_t* target = find_pattern(module, signature.c_str());
    if (!target)
        return false;
    return MH_CreateHook(target, reinterpret_cast<LPVOID>(&detour),
                         reinterpret_cast<LPVOID*>(&g_original)) == MH_OK &&
           MH_EnableHook(target) == MH_OK;
}

bool try_hook(HMODULE game, bool diagnose)
{
    std::string signature = config::send_packet_signature();
    if (!signature.empty())
    {
        bool ok = hook_signature(signature);
        if (diagnose || ok)
            logging::info("sendPacket via signature: %s", ok ? "hooked" : "not found");
        if (ok)
            return true;
    }
    std::string mangled = ".?AV" + config::send_packet_class() + "@@";
    void** vtable = find_vtable(game, mangled, diagnose);
    int index = config::send_packet_vtable_index();
    if (!vtable || index < 0 || !hook_vtable(vtable, index))
        return false;
    logging::info("%s vtable at +0x%llx, sendPacket slot %d -> +0x%llx", mangled.c_str(),
                  static_cast<unsigned long long>(reinterpret_cast<uint8_t*>(vtable) -
                                                  reinterpret_cast<uint8_t*>(game)),
                  index,
                  static_cast<unsigned long long>(reinterpret_cast<uint8_t*>(g_original) -
                                                  reinterpret_cast<uint8_t*>(game)));
    return true;
}

} // namespace

void init()
{
    // Retry in the background: parts of a protected binary may only become
    // readable once the game has run for a while.
    std::thread([] {
        HMODULE game = GetModuleHandleW(nullptr);
        constexpr int kAttempts = 24;
        for (int i = 0; i < kAttempts; ++i)
        {
            bool last = i == kAttempts - 1;
            if (try_hook(game, i == 0 || last))
            {
                g_state = State::Ready;
                return;
            }
            if (!last)
                Sleep(5000);
        }
        g_state = State::Failed;
        logging::info("sendPacket hook unavailable; token relay disabled");
    }).detach();
}

State state()
{
    return g_state;
}

void queue_token(uint64_t session_id, const std::string& token)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_pending_session = session_id;
    g_pending_token = token;
    g_result.reset();
    g_pending = true;
}

std::optional<Result> poll_result()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    auto r = g_result;
    g_result.reset();
    return r;
}

} // namespace packet_send
