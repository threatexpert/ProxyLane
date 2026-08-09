#pragma once

#include "structinfo.h"

namespace ProxyTransportPolicy
{
	inline bool SupportsGoncTlsPsk(int proxyType)
	{
		return proxyType == PROXYTYPE_SOCKS5 ||
			proxyType == PROXYTYPE_HTTP10 ||
			proxyType == PROXYTYPE_HTTP11;
	}

	inline bool SupportsUdpProxy(int proxyType)
	{
		return proxyType == PROXYTYPE_SOCKS5;
	}
}
