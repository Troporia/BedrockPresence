#include "raknet.hpp"

#include <windows.h>

#include <bcrypt.h>

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <miniz.h>
#include <nlohmann/json.hpp>

#include "logging.hpp"
#include "session.hpp"

namespace raknet {
namespace {

constexpr uint8_t kOfflineMagic[16] = {0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE,
                                       0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78};
constexpr uint8_t kOpenConnectionRequest1 = 0x05;
constexpr uint8_t kOpenConnectionRequest2 = 0x07;
constexpr uint8_t kDisconnectNotification = 0x15;
constexpr uint8_t kGamePacket = 0xFE;

// Stop looking for the Login packet after this long into a session.
constexpr uint64_t kLoginSniffMs = 15000;
constexpr uint32_t kMaxSplitCount = 512;
constexpr size_t kMaxSplitBytes = 4 * 1024 * 1024;

// Outgoing split-packet reassembly, only while looking for the Login packet.
struct Split {
    uint32_t count = 0;
    uint32_t received = 0;
    size_t bytes = 0;
    std::vector<std::string> parts;
};

std::mutex g_login_mutex;
uint64_t g_login_session = 0;   // session the state below belongs to
uint64_t g_login_start = 0;
bool g_login_done = false;
std::map<uint16_t, Split> g_splits;

struct Reader {
    const uint8_t* p;
    size_t left;

    bool take(size_t n, const uint8_t** out = nullptr)
    {
        if (left < n)
            return false;
        if (out)
            *out = p;
        p += n;
        left -= n;
        return true;
    }
    bool u8(uint8_t& v)
    {
        const uint8_t* b;
        if (!take(1, &b))
            return false;
        v = b[0];
        return true;
    }
    bool u16be(uint16_t& v)
    {
        const uint8_t* b;
        if (!take(2, &b))
            return false;
        v = static_cast<uint16_t>(b[0] << 8 | b[1]);
        return true;
    }
    bool u32be(uint32_t& v)
    {
        const uint8_t* b;
        if (!take(4, &b))
            return false;
        v = static_cast<uint32_t>(b[0]) << 24 | b[1] << 16 | b[2] << 8 | b[3];
        return true;
    }
};

std::string base64url_decode(const std::string& in)
{
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z')
            return c - 'A';
        if (c >= 'a' && c <= 'z')
            return c - 'a' + 26;
        if (c >= '0' && c <= '9')
            return c - '0' + 52;
        if (c == '-' || c == '+')
            return 62;
        if (c == '_' || c == '/')
            return 63;
        return -1;
    };
    std::string out;
    uint32_t buf = 0;
    int bits = 0;
    for (char c : in)
    {
        int v = val(c);
        if (v < 0)
            break;
        buf = buf << 6 | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

struct LoginClaims {
    std::string server_address;
    std::string client_random_id; // int64 as decimal text
    std::string self_signed_id;
    std::string xuid;
    std::string uuid;
    std::string username;
    bool from_token = false; // identity from the newer "Token" JWT (preferred)
};

// UUID.nameUUIDFromBytes(bytes): MD5, version 3 (how servers derive the player
// UUID from the token's xid).
std::string name_uuid(const std::string& name)
{
    uint8_t h[16] = {};
    if (!BCRYPT_SUCCESS(BCryptHash(BCRYPT_MD5_ALG_HANDLE, nullptr, 0,
                                   reinterpret_cast<PUCHAR>(const_cast<char*>(name.data())),
                                   static_cast<ULONG>(name.size()), h, sizeof(h))))
        return {};
    h[6] = (h[6] & 0x0F) | 0x30;
    h[8] = (h[8] & 0x3F) | 0x80;
    char out[37];
    snprintf(out, sizeof(out),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", h[0], h[1],
             h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]);
    return out;
}

std::string json_str(const nlohmann::json& j, const char* key)
{
    return j.contains(key) && j[key].is_string() ? j[key].get<std::string>() : std::string();
}

// Identity: chain JWT "extraData" {XUID, identity, displayName}, or the newer
// token JWT {xid, xname} with uuid = nameUUIDFromBytes(xid).
void identity_in_json(const nlohmann::json& j, LoginClaims& out)
{
    if (j.contains("xid") && j["xid"].is_string())
    {
        out.xuid = json_str(j, "xid");
        out.username = json_str(j, "xname");
        out.uuid = name_uuid(out.xuid);
        out.from_token = true;
    }
    else if (!out.from_token && j.contains("extraData") && j["extraData"].is_object())
    {
        const auto& e = j["extraData"];
        out.xuid = json_str(e, "XUID");
        out.uuid = json_str(e, "identity");
        out.username = json_str(e, "displayName");
    }
}

bool claims_in_json(const nlohmann::json& j, LoginClaims& out)
{
    if (!j.contains("ServerAddress") || !j["ServerAddress"].is_string())
        return false;
    out.server_address = j["ServerAddress"].get<std::string>();
    const auto& rid = j.contains("ClientRandomId") ? j["ClientRandomId"] : nlohmann::json();
    if (rid.is_number_integer())
        out.client_random_id = rid.is_number_unsigned() ? std::to_string(rid.get<uint64_t>())
                                                        : std::to_string(rid.get<int64_t>());
    if (j.contains("SelfSignedId") && j["SelfSignedId"].is_string())
        out.self_signed_id = j["SelfSignedId"].get<std::string>();
    return true;
}

// The Login packet carries JWTs (base64url "eyJ..." segments): identity JWTs
// (chain or token) and the client data JWT, whose payload holds "ServerAddress"
// (what the player typed to join) plus the ClientRandomId/SelfSignedId the server
// also sees, used to map the presence link.
bool find_login_claims(const uint8_t* data, size_t len, LoginClaims& out)
{
    bool found = false;
    std::string_view text(reinterpret_cast<const char*>(data), len);
    auto is_token = [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '-' || c == '_' || c == '.';
    };
    for (size_t pos = text.find("eyJ"); pos != std::string_view::npos; pos = text.find("eyJ", pos + 3))
    {
        size_t end = pos;
        while (end < text.size() && is_token(text[end]))
            ++end;
        std::string jwt(text.substr(pos, end - pos));
        size_t seg_start = 0;
        while (seg_start <= jwt.size())
        {
            size_t dot = jwt.find('.', seg_start);
            std::string seg = jwt.substr(seg_start, dot == std::string::npos ? std::string::npos
                                                                              : dot - seg_start);
            std::string decoded = base64url_decode(seg);
            if (!decoded.empty() && decoded.front() == '{')
            {
                auto j = nlohmann::json::parse(decoded, nullptr, false);
                if (j.is_object())
                {
                    identity_in_json(j, out);
                    found |= claims_in_json(j, out);
                }
            }
            if (dot == std::string::npos)
                break;
            seg_start = dot + 1;
        }
        pos = end > pos + 3 ? end - 3 : pos;
    }
    return found;
}

// Game packet body after 0xFE: compression id (0x00 zlib/deflate, 0x01 snappy,
// 0xFF none) then the batch. Login is sent before encryption is enabled.
void inspect_game_packet(const uint8_t* data, size_t len)
{
    if (len < 2)
        return;
    LoginClaims claims;
    bool found = false;
    uint8_t algo = data[0];
    if (algo == 0xFF)
        found = find_login_claims(data + 1, len - 1, claims);
    else if (algo == 0x00)
    {
        size_t out_len = 0;
        void* out = tinfl_decompress_mem_to_heap(data + 1, len - 1, &out_len, 0);
        if (out)
        {
            found = find_login_claims(static_cast<const uint8_t*>(out), out_len, claims);
            mz_free(out);
        }
    }
    if (!found)
        return;
    logging::info("Login ServerAddress: %s, ClientRandomId: %s, user %s (xuid %s, uuid %s)",
                  claims.server_address.c_str(), claims.client_random_id.c_str(),
                  claims.username.c_str(), claims.xuid.c_str(), claims.uuid.c_str());
    g_login_done = true;
    g_splits.clear();
    session::set_identity({claims.client_random_id, claims.self_signed_id, claims.xuid, claims.uuid,
                           claims.username});
    session::set_host(claims.server_address, session::HostSource::Exact);
}

// Caller holds g_login_mutex.
void login_frame(bool split, uint32_t count, uint16_t id, uint32_t index, const uint8_t* body,
                 size_t len)
{
    if (!split)
    {
        if (len && body[0] == kGamePacket)
            inspect_game_packet(body + 1, len - 1);
        return;
    }
    if (count == 0 || count > kMaxSplitCount || index >= count)
        return;
    Split& s = g_splits[id];
    if (s.count == 0)
    {
        s.count = count;
        s.parts.resize(count);
    }
    if (s.count != count || !s.parts[index].empty() || len == 0)
        return;
    s.parts[index].assign(reinterpret_cast<const char*>(body), len);
    s.received++;
    s.bytes += len;
    if (s.bytes > kMaxSplitBytes)
    {
        g_splits.erase(id);
        return;
    }
    if (s.received < s.count)
        return;
    std::string whole;
    whole.reserve(s.bytes);
    for (const auto& part : s.parts)
        whole += part;
    g_splits.erase(id);
    if (!whole.empty() && static_cast<uint8_t>(whole[0]) == kGamePacket)
        inspect_game_packet(reinterpret_cast<const uint8_t*>(whole.data()) + 1, whole.size() - 1);
}

} // namespace

void on_send(const sockaddr* to, const uint8_t* data, size_t len)
{
    if (len < 17 || (data[0] != kOpenConnectionRequest1 && data[0] != kOpenConnectionRequest2))
        return;
    if (memcmp(data + 1, kOfflineMagic, sizeof(kOfflineMagic)) != 0)
        return;
    session::raknet_open_request(to, data[0]);
}

void on_session_datagram(SOCKET s, bool inbound, const uint8_t* data, size_t len)
{
    if (len < 4)
        return;
    uint8_t flags = data[0];
    // Frame set: valid bit set, not an ACK (0x40) or NACK (0x20).
    if (!(flags & 0x80) || (flags & 0x60))
        return;
    session::confirm(s);

    uint64_t sid = session::active_id();
    bool sniff = false;
    std::unique_lock<std::mutex> lock(g_login_mutex, std::defer_lock);
    if (!inbound)
    {
        lock.lock();
        if (g_login_session != sid)
        {
            g_login_session = sid;
            g_login_start = GetTickCount64();
            g_login_done = false;
            g_splits.clear();
        }
        sniff = !g_login_done && GetTickCount64() - g_login_start < kLoginSniffMs;
        if (!sniff)
            lock.unlock();
    }

    Reader r{data + 4, len - 4}; // flags + 24-bit sequence number
    while (r.left)
    {
        uint8_t fflags;
        uint16_t bits;
        if (!r.u8(fflags) || !r.u16be(bits))
            return;
        uint8_t reliability = fflags >> 5;
        bool split = fflags & 0x10;
        size_t body_len = (bits + 7) / 8;
        bool reliable = reliability == 2 || reliability == 3 || reliability == 4 ||
                        reliability == 6 || reliability == 7;
        bool sequenced = reliability == 1 || reliability == 4;
        bool ordered = sequenced || reliability == 3 || reliability == 7;
        if (reliable && !r.take(3))
            return;
        if (sequenced && !r.take(3))
            return;
        if (ordered && !r.take(4))
            return;
        uint32_t split_count = 0, split_index = 0;
        uint16_t split_id = 0;
        if (split && (!r.u32be(split_count) || !r.u16be(split_id) || !r.u32be(split_index)))
            return;
        const uint8_t* body;
        if (!r.take(body_len, &body))
            return;

        if (!split && body_len && body[0] == kDisconnectNotification)
        {
            if (lock.owns_lock())
                lock.unlock();
            session::end(inbound ? "server sent disconnect" : "client sent disconnect");
            return;
        }
        if (sniff && !g_login_done)
            login_frame(split, split_count, split_id, split_index, body, body_len);
    }
}

} // namespace raknet
