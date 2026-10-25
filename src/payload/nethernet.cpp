#include "nethernet.hpp"

#include <cstring>
#include <string>
#include <string_view>

#include "logging.hpp"
#include "session.hpp"

namespace nethernet {
namespace {

// Join request paths: /v1/join/<networkId> (1.26.50) and /v1/play.
constexpr std::string_view kJoinPrefixes[] = {"POST /v1/join/", "POST /v1/play"};
// DTLS record header: content type, then version 0xFEFD (DTLS 1.2) or 0xFEFF (1.0).
constexpr uint8_t kDtlsAlert = 21;
constexpr uint8_t kDtlsApplicationData = 23;

bool is_dtls(const uint8_t* data, size_t len, uint8_t content_type)
{
    return len >= 13 && data[0] == content_type && data[1] == 0xFE &&
           (data[2] == 0xFD || data[2] == 0xFF);
}

std::string header_value(std::string_view request, std::string_view name)
{
    size_t head_end = request.find("\r\n\r\n");
    std::string_view head = request.substr(0, head_end);
    size_t pos = head.find("\r\n");
    while (pos != std::string_view::npos)
    {
        size_t line_start = pos + 2;
        size_t line_end = head.find("\r\n", line_start);
        std::string_view line = head.substr(line_start, line_end == std::string_view::npos
                                                            ? std::string_view::npos
                                                            : line_end - line_start);
        if (line.size() > name.size() && line[name.size()] == ':' &&
            _strnicmp(line.data(), name.data(), name.size()) == 0)
        {
            std::string_view value = line.substr(name.size() + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
                value.remove_prefix(1);
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
                value.remove_suffix(1);
            return std::string(value);
        }
        pos = line_end;
    }
    return {};
}

} // namespace

void on_tcp_send(SOCKET s, const uint8_t* data, size_t len)
{
    std::string_view head(reinterpret_cast<const char*>(data), len);
    bool join = false;
    for (std::string_view prefix : kJoinPrefixes)
        join |= head.substr(0, prefix.size()) == prefix;
    if (!join)
        return;
    sockaddr_storage peer{};
    int peer_len = sizeof(peer);
    if (getpeername(s, reinterpret_cast<sockaddr*>(&peer), &peer_len) != 0)
        return;
    std::string_view request(reinterpret_cast<const char*>(data), len);
    std::string host = header_value(request, "Host");
    logging::debug("NetherNet join request, Host: %s", host.c_str());
    session::nethernet_join(reinterpret_cast<const sockaddr*>(&peer), host);
}

void on_session_datagram(SOCKET s, bool inbound, const uint8_t* data, size_t len)
{
    if (is_dtls(data, len, kDtlsApplicationData))
        session::confirm(s);
    else if (is_dtls(data, len, kDtlsAlert))
        session::end(inbound ? "server closed DTLS" : "client closed DTLS");
}

} // namespace nethernet
