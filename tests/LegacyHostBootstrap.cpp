// Exercise the real 32-bit UI on an x64 test machine. Only skip forwarding
// to the native host; production sources/binaries are unchanged.
#include "../src/ProxyLane/stdafx.h"
#include "../src/ProxyLane/ProxyLane.h"
#include "../src/ProxyLane/Page3.h"
namespace ProcessArchitecture {
inline BOOL QueryLegacyHost(HANDLE process, ProcessInfo& info)
{
    if (!Query(process, info)) return FALSE;
    if (process == GetCurrentProcess()) info.native = info.process;
    return TRUE;
}
}
#define Query QueryLegacyHost
#include "../src/ProxyLane/ProxyLane.cpp"
#undef Query
