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

	std::cout << "Proxy transport policy tests passed" << std::endl;
	return 0;
}
