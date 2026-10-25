#include "logging.hpp"

#include <windows.h>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <share.h>
#include <mutex>
#include <string>
#include <vector>

namespace logging {
namespace {

std::atomic<bool> g_debug{false};
std::mutex g_file_mutex;

std::wstring g_log_path;

// bedrock_presence.log, truncated on each injection. Next to the DLL when the
// game may write there, else %LOCALAPPDATA%\BedrockPresence, else %TEMP%.
FILE* log_file()
{
    static FILE* file = [] {
        std::vector<std::wstring> dirs;
        HMODULE self = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&log_file), &self);
        wchar_t path[MAX_PATH] = {};
        GetModuleFileNameW(self, path, MAX_PATH);
        std::wstring dll(path);
        dirs.push_back(dll.substr(0, dll.find_last_of(L"\\/") + 1));
        if (DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", path, MAX_PATH); n && n < MAX_PATH)
        {
            std::wstring dir = std::wstring(path) + L"\\BedrockPresence\\";
            CreateDirectoryW(dir.c_str(), nullptr);
            dirs.push_back(dir);
        }
        if (DWORD n = GetTempPathW(MAX_PATH, path); n && n < MAX_PATH)
            dirs.push_back(path);
        for (const auto& dir : dirs)
        {
            std::wstring p = dir + L"bedrock_presence.log";
            if (FILE* f = _wfsopen(p.c_str(), L"w", _SH_DENYWR))
            {
                g_log_path = p;
                return f;
            }
        }
        return static_cast<FILE*>(nullptr);
    }();
    return file;
}

void emit(const char* fmt, va_list args)
{
    char buf[1024] = "bedrock-presence: ";
    size_t prefix = strlen(buf);
    vsnprintf(buf + prefix, sizeof(buf) - prefix - 2, fmt, args);
    strcat_s(buf, "\n");
    OutputDebugStringA(buf);

    SYSTEMTIME t;
    GetLocalTime(&t);
    std::lock_guard<std::mutex> lock(g_file_mutex);
    if (FILE* f = log_file())
    {
        fprintf(f, "%02d:%02d:%02d.%03d %s", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds,
                buf + prefix);
        fflush(f);
    }
}

} // namespace

std::string log_path()
{
    log_file();
    std::string out(g_log_path.size() * 3 + 1, '\0');
    int n = WideCharToMultiByte(CP_UTF8, 0, g_log_path.c_str(), -1, out.data(),
                                static_cast<int>(out.size()), nullptr, nullptr);
    out.resize(n > 0 ? n - 1 : 0);
    return out;
}

void set_debug(bool enabled)
{
    g_debug = enabled;
}

bool debug_enabled()
{
    return g_debug;
}

void info(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    emit(fmt, args);
    va_end(args);
}

void debug(const char* fmt, ...)
{
    if (!g_debug)
        return;
    va_list args;
    va_start(args, fmt);
    emit(fmt, args);
    va_end(args);
}

} // namespace logging
