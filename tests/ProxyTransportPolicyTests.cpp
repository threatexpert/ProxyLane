#include <assert.h>
#include <iostream>

#include "ProxyTransportPolicy.h"

int main()
{
	assert(!ProxyTransportPolicy::SupportsGoncTlsPsk(PROXYTYPE_NOPROXY));
	assert(!ProxyTransportPolicy::SupportsGoncTlsPsk(PROXYTYPE_SOCKS4));
	assert(!ProxyTransportPolicy::SupportsGoncTlsPsk(PROXYTYPE_SOCKS4A));
	assert(ProxyTransportPolicy::SupportsGoncTlsPsk(PROXYTYPE_SOCKS5));
	assert(ProxyTransportPolicy::SupportsGoncTlsPsk(PROXYTYPE_HTTP10));
	assert(ProxyTransportPolicy::SupportsGoncTlsPsk(PROXYTYPE_HTTP11));

	assert(ProxyTransportPolicy::SupportsUdpProxy(PROXYTYPE_SOCKS5));
	assert(!ProxyTransportPolicy::SupportsUdpProxy(PROXYTYPE_HTTP10));
	assert(!ProxyTransportPolicy::SupportsUdpProxy(PROXYTYPE_HTTP11));

	ProxyInfo profile = {};
	profile.strProxyType = TEXT("HTTP11");
	profile.reserved = PROXY_TRANSPORT_GONC_TLS_PSK;
	profile.strTransportPsk = TEXT("test-psk");
	assert(ProxyTransportPolicy::UsesGoncTlsPsk(&profile));
	ProxyInfo direct = profile;
	ProxyTransportPolicy::UseDirectConnection(direct);
	assert(direct.GetProxyType() == PROXYTYPE_NOPROXY);
	assert(direct.reserved == PROXY_TRANSPORT_PLAIN);
	for (size_t i = 0; i < sizeof(direct.strTransportPsk.szbuf); ++i)
		assert(direct.strTransportPsk.szbuf[i] == 0);
	assert(profile.reserved == PROXY_TRANSPORT_GONC_TLS_PSK);
	assert(strcmp(profile.strTransportPsk.szbuf, "test-psk") == 0);
	assert(ProxyTransportPolicy::UsesGoncTlsPsk(&profile));
	// A legacy/custom settings provider may leave TLS metadata on a direct route.
	direct.reserved = PROXY_TRANSPORT_GONC_TLS_PSK;
	assert(!ProxyTransportPolicy::UsesGoncTlsPsk(&direct));
	assert(!ProxyTransportPolicy::UsesGoncTlsPsk(NULL));
	profile.reserved = PROXY_TRANSPORT_PLAIN;
	assert(!ProxyTransportPolicy::UsesGoncTlsPsk(&profile));

	std::cout << "Proxy transport policy tests passed" << std::endl;
	return 0;
}
