#include <winsock2.h>

#include <windows.h>

#include "MinHook.h"

#include "config.hpp"
#include "discord_ipc.hpp"
#include "link.hpp"
#include "logging.hpp"
#include "net_hook.hpp"
#include "packet_send.hpp"
#include "session.hpp"

namespace {

DWORD WINAPI start(LPVOID)
{
    config::load();
    logging::set_debug(config::debug_log());

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
    {
        logging::info("MinHook init failed: %s", MH_StatusToString(st));
        return 0;
    }
    session::init();
    if (!net_hook::install())
        logging::info("some network hooks failed; detection may be incomplete");
    packet_send::init();
    discord::start();
    logging::info("loaded (presence port %d), log file: %s", config::port(),
                  logging::log_path().empty() ? "none writable" : logging::log_path().c_str());
    presence_link::run();
    return 0;
}

} // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
        if (HANDLE thread = CreateThread(nullptr, 0, start, nullptr, 0, nullptr))
            CloseHandle(thread);
    }
    return TRUE;
}
