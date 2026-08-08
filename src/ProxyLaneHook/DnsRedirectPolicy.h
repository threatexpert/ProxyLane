#pragma once

#include "structinfo.h"

namespace DnsRedirectPolicy
{
	inline BOOL IsPrivateDnsAddress(const _SockAddr& address)
	{
		if (address.IsIPv4() || address.IsIPv4Mapped())
		{
			DWORD ipv4 = address.GetdwIP();
			const BYTE *bytes = reinterpret_cast<const BYTE *>(&ipv4);
			return bytes[0] == 10 ||
				(bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
				(bytes[0] == 192 && bytes[1] == 168) ||
				(bytes[0] == 169 && bytes[1] == 254);
		}
		if (address.IsIPv6() && address.GetAddr6())
		{
			const BYTE *bytes = address.GetAddr6()->u.Byte;
			return (bytes[0] & 0xfe) == 0xfc ||
				(bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80);
		}
		return FALSE;
	}

	inline BOOL IsValidPublicResolver(const _SockAddr& address)
	{
		if (address.IsAny() || address.IsLoopback() ||
			address.IsIPv4Mapped() || IsPrivateDnsAddress(address))
			return FALSE;
		if (address.IsIPv4() || address.IsIPv4Mapped())
		{
			DWORD ipv4 = address.GetdwIP();
			const BYTE *bytes = reinterpret_cast<const BYTE *>(&ipv4);
			return bytes[0] < 224;
		}
		if (address.IsIPv6() && address.GetAddr6())
			return address.GetAddr6()->u.Byte[0] != 0xff;
		return FALSE;
	}

	inline BOOL ShouldRedirect(const PRCClient& client,
		const ProxySettingsInfo& settings, ProxyInfo& proxy)
	{
		return settings.nDNSOption == PSI_DNSOPT_REMOTE &&
			settings.bRedirectPrivateDNS &&
			proxy.GetProxyType() != PROXYTYPE_NOPROXY &&
			client.dstAddr.GetPort() == 53 &&
			client.szDomainName[0] == '\0' &&
			IsPrivateDnsAddress(client.dstAddr) &&
			IsValidPublicResolver(settings.redirectDNSAddr);
	}

	inline BOOL Apply(PRCClient& client, const ProxySettingsInfo& settings,
		ProxyInfo& proxy)
	{
		client.routingFlags &= ~PRC_CLIENT_FLAG_DNS_REDIRECT;
		client.proxyDstAddr.Clear();
		if (!ShouldRedirect(client, settings, proxy))
			return FALSE;
		client.proxyDstAddr = settings.redirectDNSAddr;
		client.proxyDstAddr.SetPort(53);
		client.routingFlags |= PRC_CLIENT_FLAG_DNS_REDIRECT;
		return TRUE;
	}
}
