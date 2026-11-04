#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

// Local diagnostic state only: the existing PRC text/result wire formats stay intact.
struct HookFailureDiagnostics
{
    DWORD error;
    const char* stage;
    const char* module;
    const char* api;

    void Set(DWORD code, const char* where, const char* dll, const char* function)
    {
        error = code;
        stage = where;
        module = dll;
        api = function;
    }

    void Format(WCHAR* output, size_t count, LPCWSTR processPath, DWORD processId) const
    {
        LPCWSTR name = wcsrchr(processPath, L'\\');
        name = name ? name + 1 : processPath;
        WCHAR description[512] = {};
        if (error)
            FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, error, 0, description, _countof(description), NULL);
        for (WCHAR* p = description; *p; ++p)
            if (*p == L'\r' || *p == L'\n') *p = L' ';
        _snwprintf_s(output, count, _TRUNCATE,
            L"[ProxyLane.Hook.v1] %s (%lu) | stage=%hs | module=%hs | API=%hs | error=%lu (0x%08lX) | %s",
            name[0] ? name : L"Unknown", processId, stage ? stage : "unknown",
            module ? module : "n/a", api ? api : "n/a", error, error,
            error ? (description[0] ? description : L"No system error description")
                  : L"No error code supplied by the failing operation");
    }
};
