#include "../src/ProxyLaneHook/DirectIpv6Route.h"
#include <stdio.h>
#include <stdlib.h>
#include <initializer_list>

static DWORD result;
static int calls;
static _SockAddr observed;
static DWORD Query(const _SockAddr& destination)
{
    ++calls;
    observed = destination;
    return result;
}
static void Check(bool ok, const char* message)
{
    if (!ok) { printf("FAIL %s\n", message); exit(1); }
}
int DirectIpv6RouteTestsMain()
{
    PRCClient client = {};
    client.sType = SOCK_STREAM;
    client.dstAddr.SetIP("2001:db8:1234:5678:9abc:def0:1234:5678");
    client.dstAddr.SetPort(443);
    ProxyInfo route = {};
    const DWORD results[] = {NO_ERROR, ERROR_NETWORK_UNREACHABLE, ERROR_ACCESS_DENIED,
        ERROR_INVALID_PARAMETER, ERROR_FILE_NOT_FOUND, ERROR_NOT_SUPPORTED, ERROR_NOT_FOUND,
        ERROR_HOST_UNREACHABLE, ERROR_TIMEOUT, WSAENETUNREACH};
    for (DWORD code : results) {
        result = code; calls = 0;
        PRCClient before = client;
        Check(DirectIpv6Route::ShouldReject(client, route, Query) == (code == 1231), "only Win32 1231 rejects");
        Check(calls == 1 && memcmp(&client, &before, sizeof(client)) == 0 &&
            memcmp(&observed, &client.dstAddr, sizeof(observed)) == 0, "query exact target without mutation");
    }
    result = 1231;
    for (const TCHAR* type : {TEXT("SOCKS5"), TEXT("HTTP10"), TEXT("HTTP11"), TEXT("SOCKS4")}) {
        route.strProxyType = type; calls = 0;
        Check(!DirectIpv6Route::ShouldReject(client, route, Query) && calls == 0, "remote proxy never queried");
    }
    route.strProxyType = TEXT("NOPROXY");
    for (const char* address : {"127.0.0.1", "::ffff:192.0.2.1", "::1", "::", "fe80::1", "ff02::1"}) {
        client.dstAddr.SetIP(address); calls = 0;
        Check(!DirectIpv6Route::ShouldReject(client, route, Query) && calls == 0, "excluded destination");
    }
    client.dstAddr.SetIP("fe80::1");
    reinterpret_cast<SOCKADDR_IN6*>(&client.dstAddr)->sin6_scope_id = 7;
    Check(DirectIpv6Route::ShouldReject(client, route, Query), "explicit link-local scope queried");
    Check(reinterpret_cast<SOCKADDR_IN6*>(&observed)->sin6_scope_id == 7, "scope preserved");
    client.dstAddr.SetIP("fd00::1");
    strcpy_s(client.szDomainName, "example.invalid"); calls = 0;
    Check(!DirectIpv6Route::ShouldReject(client, route, Query) && calls == 0, "hostname identity excluded");
    client.routingFlags = PRC_CLIENT_FLAG_DNS_REDIRECT;
    client.proxyDstAddr.SetIP("2001:db8::2");
    Check(DirectIpv6Route::ShouldReject(client, route, Query) &&
        observed == client.proxyDstAddr, "query effective upstream destination");
    client.sType = SOCK_DGRAM; calls = 0;
    Check(!DirectIpv6Route::ShouldReject(client, route, Query) && calls == 0, "UDP untouched");
    client.sType = SOCK_STREAM; calls = 0;
    result = 1231; Check(DirectIpv6Route::ShouldReject(client, route, Query), "unreachable now");
    result = 0; Check(!DirectIpv6Route::ShouldReject(client, route, Query) && calls == 2, "no stale negative cache");
    Check(!DirectIpv6Route::ShouldReject(client, route, NULL), "unavailable API preserves flow");
    puts("Direct IPv6 route gating, error matrix, scope, remote proxies and network changes passed");
    return 0;
}
