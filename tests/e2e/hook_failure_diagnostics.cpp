// Run against the actual Hook DLL in a separate, test-owned process per case.
#include "../../src/ProxyLaneHook/structinfo.h"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>

static HANDLE pipeHandle;
static const char* testCase;
static bool observed = false;
static DWORD observedError = 0;

static bool ReadExact(void* buffer, DWORD size)
{
    BYTE* at = static_cast<BYTE*>(buffer);
    while (size) {
        DWORD got = 0;
        if (!ReadFile(pipeHandle, at, size, &got, NULL) || !got) return false;
        at += got; size -= got;
    }
    return true;
}

static bool WriteExact(const void* buffer, DWORD size)
{
    DWORD sent = 0;
    return WriteFile(pipeHandle, buffer, size, &sent, NULL) && sent == size;
}

static bool Accept()
{
    return ConnectNamedPipe(pipeHandle, NULL) || GetLastError() == ERROR_PIPE_CONNECTED;
}

static DWORD WINAPI Serve(void*)
{
    if (!Accept()) return 1;
    PRCPipeDataHead header = {};
    if (!ReadExact(&header, sizeof(header)) || header.action != PRCPD_GET_SETTINGS_INFO) return 2;
    const bool startup = !std::strcmp(testCase, "startup");
    if (startup) {
        ProxySettingsInfo settings = {};
        header.action = PRCPD_REPLY; header.flag = 1; header.dataSize = sizeof(settings);
        if (!WriteExact(&header, sizeof(header)) || !WriteExact(&settings, sizeof(settings))) return 3;
        if (!ReadExact(&header, sizeof(header)) || header.action != PRCPD_GETSTARTUPINFO) return 4;
    }
    if (!std::strcmp(testCase, "broken-pipe")) {
        // No reply: the client must preserve ERROR_BROKEN_PIPE across reconnect.
        DisconnectNamedPipe(pipeHandle);
    } else {
        // A malformed reply must report ERROR_INVALID_DATA, not a stale LastError.
        header.action = PRCPD_REPLY; header.flag = 0; header.dataSize = 0;
        if (!WriteExact(&header, sizeof(header))) return 5;
        FlushFileBuffers(pipeHandle);
        DisconnectNamedPipe(pipeHandle);
    }
    if (!Accept()) return 6;
    if (!ReadExact(&header, sizeof(header)) || header.action != PRCPD_Logtext ||
        header.dataSize < 8 || header.dataSize > 8192) return 7;
    std::vector<BYTE> payload(header.dataSize);
    if (!ReadExact(&payload[0], header.dataSize)) return 8;
    HookLogtext* log = reinterpret_cast<HookLogtext*>(&payload[0]);
    if (log->dwProcessId != GetCurrentProcessId() || log->len < 2 ||
        log->len != static_cast<int>(header.dataSize - 8)) return 9;
    const WCHAR* detail = log->str;
    if (wcsncmp(detail, L"[ProxyLane.Hook.v1] ", 20) != 0) return 10;
    WCHAR path[MAX_PATH] = {};
    GetModuleFileNameW(NULL, path, MAX_PATH);
    const WCHAR* name = wcsrchr(path, L'\\'); name = name ? name + 1 : path;
    const WCHAR* code = wcsstr(detail, L"error=");
    if (!code) return 10;
    const DWORD expected = wcstoul(code + 6, NULL, 10);
    if (!std::strcmp(testCase, "broken-pipe")) {
        // ReadFile may see either state depending on whether the read was pending.
        if (expected != ERROR_BROKEN_PIPE && expected != ERROR_PIPE_NOT_CONNECTED) return 10;
    } else if (expected != ERROR_INVALID_DATA) return 10;
    WCHAR errorText[64]; swprintf_s(errorText, L"error=%lu (0x%08lX)", expected, expected);
    if (!wcsstr(detail, name) || !wcsstr(detail, L"module=PRC") || !wcsstr(detail, errorText) ||
        !wcsstr(detail, startup ? L"stage=read-startup-info" : L"stage=read-proxy-settings") ||
        !wcsstr(detail, startup ? L"API=GetPRCStartupInfo" : L"API=PRCGetProxySettingsInfo")) return 10;
    wprintf(L"%s\n", detail);
    HookWSockResult result = {};
    if (!ReadExact(&header, sizeof(header)) || header.action != PRCPD_HOOKWSOCK_RESULT ||
        header.dataSize != sizeof(result) || !ReadExact(&result, sizeof(result)) ||
        result.dwProcessId != GetCurrentProcessId() || !result.processCreateTime || result.err != expected) return 11;
    observed = true;
    observedError = expected;
    return 0;
}

int main(int argc, char** argv)
{
    if (argc != 3) return 1;
    testCase = argv[2];
    HMODULE hook = LoadLibraryA(argv[1]);
    if (!hook) return 2;
    typedef BOOL (WINAPI *Install)(LPCSTR);
    Install install = reinterpret_cast<Install>(GetProcAddress(hook, "gp_HookWinsock"));
    if (!install) return 3;
    char name[128]; sprintf_s(name, "\\\\.\\pipe\\PLHookFailureTest-%lu", GetCurrentProcessId());
    pipeHandle = CreateNamedPipeA(name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
        1, 8192, 8192, 5000, NULL);
    if (pipeHandle == INVALID_HANDLE_VALUE) return 4;
    HANDLE worker = CreateThread(NULL, 0, Serve, NULL, 0, NULL);
    if (!worker) return 5;
    SetLastError(12345);
    BOOL installed = install(name);
    DWORD error = GetLastError();
    if (WaitForSingleObject(worker, 10000) != WAIT_OBJECT_0) return 6;
    DWORD serverResult = 99;
    GetExitCodeThread(worker, &serverResult);
    CloseHandle(worker); CloseHandle(pipeHandle);
    if (installed || error != observedError || serverResult || !observed) {
        fprintf(stderr, "installed=%d error=%lu server=%lu observed=%d\n", installed, error, serverResult, observed);
        return 7;
    }
    puts("Hook failure text and status delivered over the legacy pipe protocol");
    return 0;
}
