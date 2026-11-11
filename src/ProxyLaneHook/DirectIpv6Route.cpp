#include "stdafx.h"
#include "DirectIpv6Route.h"
#include <iphlpapi.h>
#include <netioapi.h>

namespace
{
    typedef DWORD (WINAPI *GetBestRoute2Proc)(NET_LUID*, NET_IFINDEX,
        const SOCKADDR_INET*, const SOCKADDR_INET*, ULONG,
        MIB_IPFORWARD_ROW2*, SOCKADDR_INET*);

    GetBestRoute2Proc LoadRouteQuery()
    {
        // Resolve dynamically to preserve startup compatibility with Windows XP.
        WCHAR path[MAX_PATH];
        const UINT length = GetSystemDirectoryW(path, _countof(path));
        const WCHAR suffix[] = L"\\iphlpapi.dll";
        if (!length || length + _countof(suffix) > _countof(path))
            return NULL;
        CopyMemory(path + length, suffix, sizeof(suffix));
        HMODULE module = LoadLibraryW(path);
        if (!module) return NULL;
        GetBestRoute2Proc query = reinterpret_cast<GetBestRoute2Proc>(
            GetProcAddress(module, "GetBestRoute2"));
        if (!query) FreeLibrary(module);
        // A successful function pointer and its module live together until exit.
        return query;
    }
}

DWORD DirectIpv6Route::QuerySystemRoute(const _SockAddr& destination)
{
    static GetBestRoute2Proc query = LoadRouteQuery();
    if (!query) return ERROR_NOT_SUPPORTED;
    SOCKADDR_INET target = {};
    CopyMemory(&target.Ipv6, &destination, sizeof(target.Ipv6));
    SOCKADDR_INET source = {};
    MIB_IPFORWARD_ROW2 route = {};
    // Use the service's network context and normal source/interface selection,
    // matching the upstream socket. Never cache route results across connections.
    return query(NULL, 0, NULL, &target, 0, &route, &source);
}
