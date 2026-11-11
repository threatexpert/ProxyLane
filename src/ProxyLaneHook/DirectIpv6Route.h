#pragma once
#include "structinfo.h"

namespace DirectIpv6Route
{
    typedef DWORD (*Query)(const _SockAddr& destination);
    DWORD QuerySystemRoute(const _SockAddr& destination);

    inline bool NeedsQuery(const PRCClient& client)
    {
        if (client.sType != SOCK_STREAM ||
            (client.szDomainName[0] && !client.HasProxyDestination()))
            return false;
        const _SockAddr& destination = client.GetProxyDestination();
        if (!destination.IsIPv6() || destination.IsIPv4Mapped() ||
            destination.IsLoopback() || destination.IsAny())
            return false;
        const SOCKADDR_IN6* address = reinterpret_cast<const SOCKADDR_IN6*>(&destination);
        // An ambiguous link-local interface must not be treated as absent routing.
        return !IN6_IS_ADDR_MULTICAST(&address->sin6_addr) &&
            (!IN6_IS_ADDR_LINKLOCAL(&address->sin6_addr) || address->sin6_scope_id != 0);
    }

    inline bool ShouldReject(const PRCClient& client, ProxyInfo& route,
        Query query = QuerySystemRoute)
    {
        return route.GetProxyType() == PROXYTYPE_NOPROXY && NeedsQuery(client) &&
            query && query(client.GetProxyDestination()) == ERROR_NETWORK_UNREACHABLE;
    }
}
