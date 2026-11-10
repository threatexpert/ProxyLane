#pragma once

#include "structinfo.h"

namespace ProxyTransportPolicy
{
	// Normalize the per-connection copy; the saved proxy profile stays intact.
	inline void UseDirectConnection(ProxyInfo& info)
	{
		info.strProxyType = TEXT("");
		info.reserved = PROXY_TRANSPORT_PLAIN;
        info.sshAuth = 0;
        info.strSshKeyDigest.szbuf[0] = 0;
        SecureZeroMemory(info.strSshKeyFile.szbuf, sizeof(info.strSshKeyFile.szbuf));
		SecureZeroMemory(info.strTransportPsk.szbuf, sizeof(info.strTransportPsk.szbuf));
	}

	inline bool UsesGoncTlsPsk(LPProxyInfo info)
	{
		return info && info->GetProxyType() != PROXYTYPE_NOPROXY &&
			info->reserved == PROXY_TRANSPORT_GONC_TLS_PSK;
	}

	inline bool SupportsGoncTlsPsk(int proxyType)
	{
		return proxyType == PROXYTYPE_SOCKS5 ||
			proxyType == PROXYTYPE_HTTP10 ||
			proxyType == PROXYTYPE_HTTP11;
	}

	inline bool SupportsUdpProxy(int proxyType)
	{
		// Direct routes still pass through the local UDP relay and monitor.
		return proxyType == PROXYTYPE_NOPROXY || proxyType == PROXYTYPE_SOCKS5;
	}
}
