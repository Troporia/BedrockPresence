#include "net_hook.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <string>
#include <vector>

#include "MinHook.h"

#include "addr.hpp"
#include "dns_cache.hpp"
#include "logging.hpp"
#include "nethernet.hpp"
#include "raknet.hpp"
#include "session.hpp"

namespace net_hook {
namespace {

thread_local bool t_internal = false;

using sendto_t = int(WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
using WSASendTo_t = int(WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const sockaddr*, int,
                                 LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using recvfrom_t = int(WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);
using WSARecvFrom_t = int(WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, sockaddr*, LPINT,
                                   LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using send_t = int(WSAAPI*)(SOCKET, const char*, int, int);
using WSASend_t = int(WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using closesocket_t = int(WSAAPI*)(SOCKET);
using getaddrinfo_t = INT(WSAAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
using GetAddrInfoW_t = INT(WSAAPI*)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
using GetAddrInfoExW_t = INT(WSAAPI*)(PCWSTR, PCWSTR, DWORD, LPGUID, const ADDRINFOEXW*,
                                      PADDRINFOEXW*, timeval*, LPOVERLAPPED,
                                      LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);

sendto_t o_sendto;
WSASendTo_t o_WSASendTo;
recvfrom_t o_recvfrom;
WSARecvFrom_t o_WSARecvFrom;
send_t o_send;
WSASend_t o_WSASend;
closesocket_t o_closesocket;
getaddrinfo_t o_getaddrinfo;
GetAddrInfoW_t o_GetAddrInfoW;
GetAddrInfoExW_t o_GetAddrInfoExW;

std::string utf8(PCWSTR w)
{
    if (!w)
        return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1)
        return {};
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

// Flatten WSABUFs (only done for datagrams to/from the server).
std::vector<uint8_t> gather(LPWSABUF bufs, DWORD count, size_t limit)
{
    std::vector<uint8_t> out;
    for (DWORD i = 0; i < count && out.size() < limit; ++i)
    {
        size_t n = bufs[i].len;
        if (n > limit - out.size())
            n = limit - out.size();
        out.insert(out.end(), reinterpret_cast<uint8_t*>(bufs[i].buf),
                   reinterpret_cast<uint8_t*>(bufs[i].buf) + n);
    }
    return out;
}

void on_datagram(SOCKET s, bool inbound, const sockaddr* peer, const uint8_t* data, size_t len)
{
    if (t_internal || !data || !addr::is_ip(peer))
        return;
    if (!inbound)
        raknet::on_send(peer, data, len);
    session::Transport transport;
    if (!session::matches(peer, &transport))
        return;
    session::traffic(inbound);
    if (transport == session::Transport::RakNet)
        raknet::on_session_datagram(s, inbound, data, len);
    else
        nethernet::on_session_datagram(s, inbound, data, len);
}

void on_wsabufs(SOCKET s, bool inbound, const sockaddr* peer, LPWSABUF bufs, DWORD count,
                size_t len)
{
    if (t_internal || !bufs || count == 0 || !addr::is_ip(peer))
        return;
    if (count == 1 || bufs[0].len >= len)
    {
        on_datagram(s, inbound, peer, reinterpret_cast<uint8_t*>(bufs[0].buf),
                    len < bufs[0].len ? len : bufs[0].len);
        return;
    }
    auto flat = gather(bufs, count, len);
    on_datagram(s, inbound, peer, flat.data(), flat.size());
}

int WSAAPI h_sendto(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
{
    if (len > 0)
        on_datagram(s, false, to, reinterpret_cast<const uint8_t*>(buf), len);
    return o_sendto(s, buf, len, flags, to, tolen);
}

int WSAAPI h_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent, DWORD flags,
                       const sockaddr* to, int tolen, LPWSAOVERLAPPED ov,
                       LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    size_t total = 0;
    for (DWORD i = 0; bufs && i < count; ++i)
        total += bufs[i].len;
    on_wsabufs(s, false, to, bufs, count, total);
    return o_WSASendTo(s, bufs, count, sent, flags, to, tolen, ov, cr);
}

int WSAAPI h_recvfrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)
{
    int r = o_recvfrom(s, buf, len, flags, from, fromlen);
    if (r > 0 && from)
        on_datagram(s, true, from, reinterpret_cast<const uint8_t*>(buf), r);
    return r;
}

int WSAAPI h_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD received, LPDWORD flags,
                         sockaddr* from, LPINT fromlen, LPWSAOVERLAPPED ov,
                         LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    int r = o_WSARecvFrom(s, bufs, count, received, flags, from, fromlen, ov, cr);
    // Only completed-now receives have data; pending overlapped ones are skipped
    // (session falls back to outbound traffic for its timeout).
    if (r == 0 && received && *received > 0 && from)
        on_wsabufs(s, true, from, bufs, count, *received);
    return r;
}

int WSAAPI h_send(SOCKET s, const char* buf, int len, int flags)
{
    if (!t_internal && len > 0)
        nethernet::on_tcp_send(s, reinterpret_cast<const uint8_t*>(buf), len);
    return o_send(s, buf, len, flags);
}

int WSAAPI h_WSASend(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent, DWORD flags,
                     LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    if (!t_internal && bufs && count > 0 && bufs[0].len > 0)
        nethernet::on_tcp_send(s, reinterpret_cast<const uint8_t*>(bufs[0].buf), bufs[0].len);
    return o_WSASend(s, bufs, count, sent, flags, ov, cr);
}

int WSAAPI h_closesocket(SOCKET s)
{
    if (!t_internal)
    {
        session::socket_closed(s);
    }
    return o_closesocket(s);
}

template <typename AddrInfo>
void record_results(const std::string& host, const AddrInfo* res)
{
    for (const AddrInfo* ai = res; ai; ai = ai->ai_next)
        if (ai->ai_addr)
            dns_cache::record(host, ai->ai_addr);
}

INT WSAAPI h_getaddrinfo(PCSTR node, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* res)
{
    INT r = o_getaddrinfo(node, service, hints, res);
    if (r == 0 && !t_internal && node && res)
        record_results<ADDRINFOA>(node, *res);
    return r;
}

INT WSAAPI h_GetAddrInfoW(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* res)
{
    INT r = o_GetAddrInfoW(node, service, hints, res);
    if (r == 0 && !t_internal && node && res)
        record_results<ADDRINFOW>(utf8(node), *res);
    return r;
}

INT WSAAPI h_GetAddrInfoExW(PCWSTR name, PCWSTR service, DWORD ns, LPGUID nsp,
                            const ADDRINFOEXW* hints, PADDRINFOEXW* res, timeval* timeout,
                            LPOVERLAPPED ov, LPLOOKUPSERVICE_COMPLETION_ROUTINE cr, LPHANDLE handle)
{
    INT r = o_GetAddrInfoExW(name, service, ns, nsp, hints, res, timeout, ov, cr, handle);
    // Asynchronous lookups (ov set) fill *res later; only synchronous ones are seen.
    if (r == 0 && !ov && !t_internal && name && res)
        record_results<ADDRINFOEXW>(utf8(name), *res);
    return r;
}

template <typename T>
bool hook(const wchar_t* module, const char* name, T detour, T* original)
{
    MH_STATUS st = MH_CreateHookApi(module, name, reinterpret_cast<LPVOID>(detour),
                                    reinterpret_cast<LPVOID*>(original));
    if (st != MH_OK)
    {
        logging::info("hook %s failed: %s", name, MH_StatusToString(st));
        return false;
    }
    return true;
}

} // namespace

bool install()
{
    LoadLibraryW(L"ws2_32.dll");
    bool ok = true;
    ok &= hook(L"ws2_32", "sendto", &h_sendto, &o_sendto);
    ok &= hook(L"ws2_32", "WSASendTo", &h_WSASendTo, &o_WSASendTo);
    ok &= hook(L"ws2_32", "recvfrom", &h_recvfrom, &o_recvfrom);
    ok &= hook(L"ws2_32", "WSARecvFrom", &h_WSARecvFrom, &o_WSARecvFrom);
    ok &= hook(L"ws2_32", "send", &h_send, &o_send);
    ok &= hook(L"ws2_32", "WSASend", &h_WSASend, &o_WSASend);
    ok &= hook(L"ws2_32", "closesocket", &h_closesocket, &o_closesocket);
    ok &= hook(L"ws2_32", "getaddrinfo", &h_getaddrinfo, &o_getaddrinfo);
    ok &= hook(L"ws2_32", "GetAddrInfoW", &h_GetAddrInfoW, &o_GetAddrInfoW);
    ok &= hook(L"ws2_32", "GetAddrInfoExW", &h_GetAddrInfoExW, &o_GetAddrInfoExW);
    MH_STATUS st = MH_EnableHook(MH_ALL_HOOKS);
    if (st != MH_OK)
    {
        logging::info("enabling hooks failed: %s", MH_StatusToString(st));
        return false;
    }
    return ok;
}

void mark_internal_thread()
{
    t_internal = true;
}

} // namespace net_hook
