#pragma once
#include <windows.h>

// Fixed-width identity also used in the optional v4 command reply.
struct AutomationProcessIdentity
{
    DWORD pid;
    FILETIME created;
};
static_assert(sizeof(AutomationProcessIdentity) == 12, "command identity layout");

inline void SetAutomationProcessIdentity(AutomationProcessIdentity* identity, DWORD pid, ULONGLONG created)
{
    if (!identity) return;
    identity->pid = pid;
    identity->created.dwLowDateTime = static_cast<DWORD>(created);
    identity->created.dwHighDateTime = static_cast<DWORD>(created >> 32);
}

// Best effort by explicit product policy: an inaccessible, vanished or reused
// PID means no wait. Never wait on a process whose identity cannot be verified.
inline HANDLE OpenAutomationProcess(const AutomationProcessIdentity& identity)
{
    if (!identity.pid || (!identity.created.dwLowDateTime && !identity.created.dwHighDateTime)) return NULL;
    HANDLE process = OpenProcess(SYNCHRONIZE | 0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, FALSE, identity.pid);
    if (!process) process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, identity.pid); // XP
    if (!process) return NULL;
    FILETIME created, exited, kernel, user;
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user) || CompareFileTime(&created, &identity.created)) {
        CloseHandle(process); return NULL;
    }
    return process;
}

inline DWORD WaitForAutomationProcess(const AutomationProcessIdentity& identity)
{
    HANDLE process = OpenAutomationProcess(identity);
    if (!process) return 0; // Launch succeeded; the exit status is unavailable.
    DWORD code = 0;
    // Wait first: 259 is also a legitimate final exit code.
    if (WaitForSingleObject(process, INFINITE) == WAIT_OBJECT_0) GetExitCodeProcess(process, &code);
    CloseHandle(process);
    return code;
}
