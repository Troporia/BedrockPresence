#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdint>
#include <cstring>
#include <string>

// Helpers for IPv4/IPv6 socket addresses.
namespace addr {

inline bool is_ip(const sockaddr* a)
{
    return a && (a->sa_family == AF_INET || a->sa_family == AF_INET6);
}

inline uint16_t port(const sockaddr* a)
{
    if (a->sa_family == AF_INET)
        return ntohs(reinterpret_cast<const sockaddr_in*>(a)->sin_port);
    if (a->sa_family == AF_INET6)
        return ntohs(reinterpret_cast<const sockaddr_in6*>(a)->sin6_port);
    return 0;
}

// IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) compare equal to plain IPv4.
inline bool v4_of(const sockaddr* a, in_addr& out)
{
    if (a->sa_family == AF_INET)
    {
        out = reinterpret_cast<const sockaddr_in*>(a)->sin_addr;
        return true;
    }
    if (a->sa_family == AF_INET6)
    {
        const auto* b = reinterpret_cast<const sockaddr_in6*>(a)->sin6_addr.s6_addr;
        static const uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
        if (memcmp(b, prefix, 12) == 0)
        {
            memcpy(&out, b + 12, 4);
            return true;
        }
    }
    return false;
}

inline bool same_ip(const sockaddr* a, const sockaddr* b)
{
    in_addr x{}, y{};
    bool ax = v4_of(a, x), by = v4_of(b, y);
    if (ax || by)
        return ax && by && x.s_addr == y.s_addr;
    if (a->sa_family != AF_INET6 || b->sa_family != AF_INET6)
        return false;
    return memcmp(&reinterpret_cast<const sockaddr_in6*>(a)->sin6_addr,
                  &reinterpret_cast<const sockaddr_in6*>(b)->sin6_addr, sizeof(in6_addr)) == 0;
}

inline bool same_endpoint(const sockaddr* a, const sockaddr* b)
{
    return same_ip(a, b) && port(a) == port(b);
}

inline std::string ip_string(const sockaddr* a)
{
    char buf[INET6_ADDRSTRLEN] = {};
    in_addr v4{};
    if (v4_of(a, v4))
        inet_ntop(AF_INET, &v4, buf, sizeof(buf));
    else if (a->sa_family == AF_INET6)
        inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(a)->sin6_addr, buf, sizeof(buf));
    return buf;
}

inline int length(const sockaddr* a)
{
    return a->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
}

// "play.example.org:19132" -> "play.example.org", "[::1]:19132" -> "::1".
inline std::string strip_port(std::string host)
{
    if (!host.empty() && host.front() == '[')
    {
        auto end = host.find(']');
        return end == std::string::npos ? host.substr(1) : host.substr(1, end - 1);
    }
    auto colon = host.find(':');
    if (colon != std::string::npos && host.find(':', colon + 1) == std::string::npos)
        host.resize(colon);
    return host;
}

inline bool is_ip_literal(const std::string& s)
{
    in_addr v4{};
    in6_addr v6{};
    return inet_pton(AF_INET, s.c_str(), &v4) == 1 || inet_pton(AF_INET6, s.c_str(), &v6) == 1;
}

} // namespace addr
