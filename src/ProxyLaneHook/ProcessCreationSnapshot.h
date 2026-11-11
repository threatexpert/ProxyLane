#pragma once
#include "structinfo.h"

// Sender-side only. No process is opened: the caller snapshots itself with
// its pseudo handle. Safe with the XP build's /Zc:threadSafeInit- setting.
inline HookProcessSnapshot CurrentCreationSender()
{
    static HookProcessSnapshot cached = {};
    static LONG state = 0;
    if (InterlockedCompareExchange(&state, 2, 2) == 2) return cached;
    const DWORD error = GetLastError();
    HookProcessSnapshot value = {};
    value.dwProcessId = GetCurrentProcessId();
    FILETIME c = {}, e = {}, k = {}, u = {};
    if (GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u))
        value.processCreateTime = (ULONGLONG(c.dwHighDateTime) << 32) | c.dwLowDateTime;
    GetModuleFileNameW(NULL, value.szAppPath, _countof(value.szAppPath));
    value.szAppPath[_countof(value.szAppPath)-1] = L'\0';
    // Concurrent first callers can collect their own copy without waiting.
    if (InterlockedCompareExchange(&state, 1, 0) == 0) {
        cached = value;
        InterlockedExchange(&state, 2);
    }
    SetLastError(error);
    return value;
}

inline HookProcessCreationNotice MakeProcessCreationNotice(const HookNewProcessInfo& child)
{
    HookProcessCreationNotice notice = {};
    notice.child = child;
    notice.parent = CurrentCreationSender();
    return notice;
}
