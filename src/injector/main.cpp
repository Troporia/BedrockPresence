#include <windows.h>

#include <aclapi.h>
#include <appmodel.h>

#ifndef PACKAGE_FAMILY_NAME_MAX_LENGTH
#define PACKAGE_FAMILY_NAME_MAX_LENGTH 64
#endif
#include <sddl.h>
#include <tlhelp32.h>

#include <filesystem>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr wchar_t kGameExe[] = L"Minecraft.Windows.exe";

int fail(const char* what)
{
    std::cerr << what << " failed (error " << GetLastError() << ")\n";
    return 1;
}

DWORD find_process(const wchar_t* name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    PROCESSENTRY32W entry{sizeof(entry)};
    DWORD pid = 0;
    for (BOOL ok = Process32FirstW(snap, &entry); ok; ok = Process32NextW(snap, &entry))
    {
        if (_wcsicmp(entry.szExeFile, name) == 0)
        {
            pid = entry.th32ProcessID;
            break;
        }
    }
    CloseHandle(snap);
    return pid;
}

bool has_module(DWORD pid, const std::wstring& module_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return false;
    MODULEENTRY32W entry{sizeof(entry)};
    bool found = false;
    for (BOOL ok = Module32FirstW(snap, &entry); ok; ok = Module32NextW(snap, &entry))
    {
        if (_wcsicmp(entry.szModule, module_name.c_str()) == 0)
        {
            found = true;
            break;
        }
    }
    CloseHandle(snap);
    return found;
}

// Packaged processes can only load DLLs that ALL APPLICATION PACKAGES may read.
bool grant_app_packages(const fs::path& path, DWORD permissions)
{
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-15-2-1", &sid))
        return false;

    PACL old_dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL new_dacl = nullptr;
    bool ok = false;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr,
                              nullptr, &old_dacl, nullptr, &sd) == ERROR_SUCCESS)
    {
        EXPLICIT_ACCESSW access{};
        access.grfAccessPermissions = permissions;
        access.grfAccessMode = GRANT_ACCESS;
        access.grfInheritance = NO_INHERITANCE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        access.Trustee.ptstrName = static_cast<LPWSTR>(sid);
        if (SetEntriesInAclW(1, &access, old_dacl, &new_dacl) == ERROR_SUCCESS)
        {
            ok = SetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
                                       DACL_SECURITY_INFORMATION, nullptr, nullptr, new_dacl,
                                       nullptr) == ERROR_SUCCESS;
        }
    }
    LocalFree(new_dacl);
    LocalFree(sd);
    LocalFree(sid);
    return ok;
}

// The sandboxed game cannot create files next to the DLL: create config.json (from
// config.example.json) and the log file here and let the game read/write just those.
void prepare_files(const fs::path& dir)
{
    std::error_code ec;
    fs::path config = dir / L"config.json";
    fs::path example = dir / L"config.example.json";
    if (!fs::exists(config, ec) && fs::exists(example, ec))
        fs::copy_file(example, config, ec);
    fs::path log = dir / L"bedrock_presence.log";
    if (!fs::exists(log, ec))
        CloseHandle(CreateFileW(log.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL, nullptr));
    for (const auto& f : {config, log})
        if (fs::exists(f, ec) && !grant_app_packages(f, GENERIC_READ | GENERIC_WRITE))
            std::wcerr << L"Warning: could not grant the game access to " << f.wstring() << L"\n";
}

std::wstring env(const wchar_t* name)
{
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(name, buf, MAX_PATH);
    return n && n < MAX_PATH ? std::wstring(buf) : std::wstring();
}

// The DLL writes bedrock_presence.log next to itself, else in %LOCALAPPDATA% or
// %TEMP%; for a packaged game those may be redirected into the package folder.
void report_log(DWORD pid, const fs::path& dll_dir)
{
    std::vector<fs::path> candidates{dll_dir / L"bedrock_presence.log"};
    fs::path local = env(L"LOCALAPPDATA");
    fs::path temp = env(L"TEMP");
    if (!local.empty())
        candidates.push_back(local / L"BedrockPresence" / L"bedrock_presence.log");
    if (!temp.empty())
        candidates.push_back(temp / L"bedrock_presence.log");

    if (HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid))
    {
        wchar_t family[PACKAGE_FAMILY_NAME_MAX_LENGTH + 1] = {};
        UINT32 len = PACKAGE_FAMILY_NAME_MAX_LENGTH + 1;
        if (GetPackageFamilyName(p, &len, family) == ERROR_SUCCESS && !local.empty())
        {
            fs::path pkg = local / L"Packages" / family;
            candidates.push_back(pkg / L"LocalCache" / L"Local" / L"BedrockPresence" / L"bedrock_presence.log");
            candidates.push_back(pkg / L"AC" / L"Temp" / L"bedrock_presence.log");
            candidates.push_back(pkg / L"LocalCache" / L"Local" / L"Temp" / L"bedrock_presence.log");
        }
        CloseHandle(p);
    }

    for (int i = 0; i < 20; ++i)
    {
        for (const auto& c : candidates)
        {
            std::error_code ec;
            if (fs::exists(c, ec))
            {
                std::wcout << L"Log: " << c.wstring() << L"\n";
                return;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    std::wcout << L"Log file not found. Looked in:\n";
    for (const auto& c : candidates)
        std::wcout << L"  " << c.wstring() << L"\n";
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    fs::path dll = argc > 1 ? fs::absolute(argv[1]) : fs::path(self).parent_path() / L"bedrock_presence.dll";
    if (!fs::exists(dll))
    {
        std::wcerr << L"DLL not found: " << dll.wstring() << L"\n";
        return 1;
    }

    DWORD pid = find_process(kGameExe);
    if (pid == 0)
    {
        std::wcerr << kGameExe << L" is not running\n";
        return 1;
    }
    std::wcout << L"Found " << kGameExe << L" (pid " << pid << L")\n";

    if (has_module(pid, dll.filename().wstring()))
    {
        std::wcout << L"Already injected\n";
        report_log(pid, dll.parent_path());
        return 0;
    }

    if (!grant_app_packages(dll, GENERIC_READ | GENERIC_EXECUTE))
        std::wcerr << L"Warning: could not grant ALL APPLICATION PACKAGES read on the DLL\n";
    prepare_files(dll.parent_path());

    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                     PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                 FALSE, pid);
    if (!process)
        return fail("OpenProcess");

    const std::wstring dll_path = dll.wstring();
    const size_t bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote)
        return fail("VirtualAllocEx");
    if (!WriteProcessMemory(process, remote, dll_path.c_str(), bytes, nullptr))
        return fail("WriteProcessMemory");

    auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
    HANDLE thread = CreateRemoteThread(process, nullptr, 0, load_library, remote, 0, nullptr);
    if (!thread)
        return fail("CreateRemoteThread");
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    CloseHandle(process);

    if (!has_module(pid, dll.filename().wstring()))
    {
        std::wcerr << L"LoadLibraryW ran but the DLL is not loaded in the game\n";
        return 1;
    }
    std::wcout << L"Injected " << dll_path << L"\n";
    report_log(pid, dll.parent_path());
    return 0;
}
