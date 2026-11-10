#pragma once
#include <tlhelp32.h>

// A running PL instance can automatically inject this test process as a child.
// Remove hooks only from this test process, before creating any test threads or
// sockets. Unhooking only our imported DLL misses another copy at another path.
static void IsolateTestProcess() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    Check(snapshot != INVALID_HANDLE_VALUE, "enumerate own test modules");
    MODULEENTRY32W entry = {sizeof(entry)};
    std::vector<HMODULE> hooks;
    for (BOOL more = Module32FirstW(snapshot, &entry); more; more = Module32NextW(snapshot, &entry)) {
        if (!_wcsicmp(entry.szModule, L"ProxyLaneHook64.dll") || !_wcsicmp(entry.szModule, L"ProxyLaneHook32.dll"))
            hooks.push_back(entry.hModule);
    }
    CloseHandle(snapshot);
    for (auto module : hooks) {
        typedef BOOL (WINAPI* Unhook)();
        auto unhook = (Unhook)GetProcAddress(module, "gp_UnhookWinsock");
        Check(unhook != NULL, "find own-process unhook entry");
        // Our imported DLL may be loaded without having installed hooks yet.
        Check(unhook() || GetLastError() == ERROR_NOT_FOUND, "remove ambient hook from own test process");
    }
}
