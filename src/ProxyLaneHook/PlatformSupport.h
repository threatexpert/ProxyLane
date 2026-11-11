#pragma once
#include <windows.h>

// Only identifies the NT 5.x boundary; this is not a promise that every newer
// Windows version supports every optional module. GetVersionEx is XP-safe,
// and the newer-Windows compatibility version (6.2) is sufficient here.
inline bool ProxyIsLegacyWindows()
{
    static const bool legacy = [] {
        OSVERSIONINFOW version = {}; version.dwOSVersionInfoSize = sizeof(version);
        return GetVersionExW(&version) && version.dwMajorVersion < 6;
    }();
    return legacy;
}

// These modules run in the proxy host, not in the injected target process.
// A 32-bit target can still use them through a 64-bit proxy host.
inline bool ProxySupportsOptionalModules()
{
#ifdef _WIN64
    return !ProxyIsLegacyWindows();
#else
    return false;
#endif
}
