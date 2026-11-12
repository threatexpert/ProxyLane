#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include "../../src/ProxyLaneHook/RundllHost.h"

static int Attach(DWORD pid, const wchar_t* pipe, const wchar_t* hook)
{
    HANDLE target = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    ProcessArchitecture::ProcessInfo architecture;
    if (!target) return 10;
    BOOL queried = ProcessArchitecture::Query(target, architecture);
    CloseHandle(target);
    if (!queried) return 11;
    const wchar_t* folder = ProcessArchitecture::SystemRundllDirectory(architecture);
    if (!folder) return 12;
    wchar_t windows[MAX_PATH];
    if (!GetWindowsDirectoryW(windows, MAX_PATH)) return 13;
    wchar_t command[2048];
    swprintf_s(command, L"\"%s\\%s\\rundll32.exe\" \"%s\",AttachTo --pid=%lu --tid=0 --pipe=%s",
        windows, folder, hook, pid, pipe);
    RundllHost::Attributes attributes;
    if (!attributes.Initialize(architecture)) return 14;
    PROCESS_INFORMATION process = {};
    if (!RundllHost::Create(architecture, command, attributes, process))
    { fwprintf(stderr, L"rundll32: %lu\n", GetLastError()); return 15; }
    DWORD code = 0;
    if (WaitForSingleObject(process.hProcess, 20000) != WAIT_OBJECT_0)
        TerminateProcess(process.hProcess, 16);
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    return code == 0xff01 ? 0 : 17;
}

static int Traffic()
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa)) return 20;
    SOCKET connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connection == INVALID_SOCKET) return 21;
    DWORD timeout = 10000;
    setsockopt(connection, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
    setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));
    sockaddr_in address = {};
    address.sin_family = AF_INET; address.sin_port = htons(39093);
    address.sin_addr.s_addr = htonl(0xcb00710a); // Documentation-only IP, served by test SOCKS server.
    int result = 0;
    u_long nonblocking = 1;
    ioctlsocket(connection, FIONBIO, &nonblocking);
    if (connect(connection, reinterpret_cast<sockaddr*>(&address), sizeof(address)))
    {
        if (WSAGetLastError() != WSAEWOULDBLOCK) result = 22;
        else
        {
            fd_set writeSet, errorSet;
            FD_ZERO(&writeSet); FD_ZERO(&errorSet);
            FD_SET(connection, &writeSet); FD_SET(connection, &errorSet);
            timeval limit = { 1, 0 };
            int error = 0, size = sizeof(error);
            if (select(0, NULL, &writeSet, &errorSet, &limit) <= 0 ||
                getsockopt(connection, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) || error)
                result = 22;
        }
    }
    nonblocking = 0;
    ioctlsocket(connection, FIONBIO, &nonblocking);
    if (!result && send(connection, "PING", 4, 0) != 4) result = 23;
    if (!result)
    {
        char response[4]; int received = 0;
        while (received < 4)
        {
            int size = recv(connection, response + received, 4 - received, 0);
            if (size <= 0) break;
            received += size;
        }
        if (received != 4 || memcmp(response, "PONG", 4)) result = 24;
    }
    closesocket(connection); WSACleanup();
    return result;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 5 && wcscmp(argv[1], L"--attach") == 0)
        return Attach(wcstoul(argv[2], NULL, 10), argv[3], argv[4]);
    int first = 1;
    bool attachment = false;
    bool kernelBase = false;
    if (argc > 1 && wcscmp(argv[1], L"--wait") == 0)
    {
        attachment = true;
        ++first;
    }
    if (argc > first && wcscmp(argv[first], L"--kernelbase") == 0)
    {
        kernelBase = true;
        ++first;
    }
    if (argc <= first) return 3;
    const wchar_t* report = argv[first++];
    ProcessArchitecture::ProcessInfo actual;
    int result = 0;
    if (!ProcessArchitecture::Query(GetCurrentProcess(), actual) ||
        actual.process != ProcessArchitecture::CurrentModule()) result = 4;
    FARPROC publicEntries[2] = {};
    BYTE publicBefore[2][32] = {};
    bool publicEntriesUnchanged = false;
    const bool checkPublicEntries = attachment && !result &&
        (actual.native == ProcessArchitecture::X86 || actual.native == ProcessArchitecture::X64);
    if (attachment)
    {
        // Snapshot before injection and signal readiness to the runner. On
        // native Intel, attaching PL must leave both public exports untouched.
        if (checkPublicEntries)
        {
            const wchar_t* providers[] = { L"kernel32.dll", L"kernelbase.dll" };
            for (int i = 0; i < 2; ++i)
            {
                HMODULE provider = GetModuleHandleW(providers[i]);
                publicEntries[i] = provider ? GetProcAddress(provider, "CreateProcessW") : NULL;
                if (publicEntries[i]) memcpy(publicBefore[i], reinterpret_cast<const void*>(publicEntries[i]), sizeof(publicBefore[i]));
            }
            if (!publicEntries[0]) return 34;
        }
        FILE* ready = NULL;
        if (_wfopen_s(&ready, (std::wstring(report) + L".ready").c_str(), L"wt") || !ready) return 35;
        fputs("READY\n", ready);
        fclose(ready);
        // Do no network I/O before the runner has attached and releases us.
        if (getchar() != 'G') return 2;
    }
    const wchar_t* hook = ProcessArchitecture::HookFileName(ProcessArchitecture::CurrentModule());
    HMODULE loaded = NULL;
    // Injection is queued asynchronously; wait for the expected module before testing traffic.
    for (int i = 0; i < 200 && !loaded; ++i)
    { loaded = GetModuleHandleW(hook); if (!loaded) Sleep(25); }
    if (!loaded) result = 5;
    wchar_t loadedPath[32768] = {};
    if (loaded) GetModuleFileNameW(loaded, loadedPath, _countof(loadedPath));
    if (!result)
    {
        // A queued loader / loaded DLL is not yet an initialized Hook. Exercise
        // actual traffic with a bounded connect timeout until attachment settles.
        for (int attempt = 0; attempt < (attachment ? 10 : 1); ++attempt)
        {
            result = Traffic();
            if (!result) break;
            Sleep(100);
        }
    }
    if (!result && checkPublicEntries)
    {
        publicEntriesUnchanged = true;
        for (int i = 0; i < 2; ++i)
            if (publicEntries[i] && memcmp(publicBefore[i], reinterpret_cast<const void*>(publicEntries[i]), sizeof(publicBefore[i])))
                publicEntriesUnchanged = false;
        if (!publicEntriesUnchanged) result = 36;
    }
    if (!result && first < argc)
    {
        std::wstring command = L"\"" + std::wstring(argv[first++]) + L"\" " +
            (kernelBase ? L"--kernelbase " : L"") + L"\"" + report + L".child\"";
        for (; first < argc; ++first) command += L" \"" + std::wstring(argv[first]) + L"\"";
        STARTUPINFOW startup = { sizeof(startup) };
        PROCESS_INFORMATION process = {};
        auto create = kernelBase ? reinterpret_cast<decltype(&::CreateProcessW)>(
            GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "CreateProcessW")) : CreateProcessW;
        if (!create) return 30;
        if (kernelBase)
        {
            // Failed public creation must restore the per-thread nesting guard
            // and preserve the Windows error before the next successful launch.
            std::wstring missing = std::wstring(report) + L".missing.exe";
            if (create(missing.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process))
            { TerminateProcess(process.hProcess, 31); return 31; }
            if (GetLastError() != ERROR_FILE_NOT_FOUND) return 32;
        }
        if (!create(NULL, &command[0], NULL, NULL, FALSE,
            CREATE_NO_WINDOW | (kernelBase ? CREATE_SUSPENDED : 0),
            NULL, NULL, &startup, &process)) result = 6;
        else
        {
            if (kernelBase && ResumeThread(process.hThread) != 1)
            { TerminateProcess(process.hProcess, 33); result = 33; }
            DWORD code = 0;
            if (WaitForSingleObject(process.hProcess, 30000) != WAIT_OBJECT_0)
                TerminateProcess(process.hProcess, 7);
            if (!GetExitCodeProcess(process.hProcess, &code) || code) result = 8;
            CloseHandle(process.hThread); CloseHandle(process.hProcess);
        }
    }
    FILE* output = NULL;
    const std::wstring temporary = std::wstring(report) + L".tmp";
    if (_wfopen_s(&output, temporary.c_str(), L"wt, ccs=UTF-8") || !output) return 9;
    fwprintf(output, L"%s machine=%u hook=%s error=%d public_entries_unchanged=%d\n", result ? L"FAIL" : L"PASS",
        static_cast<unsigned>(actual.process), loadedPath, result, publicEntriesUnchanged ? 1 : 0);
    fclose(output);
    if (!MoveFileExW(temporary.c_str(), report, MOVEFILE_REPLACE_EXISTING)) return 9;
    return result;
}
