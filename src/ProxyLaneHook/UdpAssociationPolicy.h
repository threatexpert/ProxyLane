#pragma once

#include <winsock2.h>
#include <string.h>

namespace UdpAssociationPolicy
{
	struct Destination
	{
		BOOL hasDomain;
		const char *domain;
		ADDRESS_FAMILY family;
		DWORD ipv4;
		BYTE ipv6[16];
		WORD port;
	};

	inline BOOL IsSameDestination(const Destination &left,
		const Destination &right)
	{
		if (left.hasDomain != right.hasDomain || left.port != right.port)
			return FALSE;
		if (left.hasDomain)
			return left.domain && right.domain &&
				_stricmp(left.domain, right.domain) == 0;
		if (left.family != right.family)
			return FALSE;
		return left.family == AF_INET6
			? memcmp(left.ipv6, right.ipv6, sizeof(left.ipv6)) == 0
			: left.ipv4 == right.ipv4;
	}

	inline BOOL CanShareAssociation(const Destination &left,
		const Destination &right)
	{
		if (IsSameDestination(left, right))
			return TRUE;

		// An IPv4 SOCKS5 UDP reply identifies an IP address and port, not the
		// original domain. Two different routes on the same remote port are
		// ambiguous whenever either route was addressed by domain.
		if (left.port == right.port && (left.hasDomain || right.hasDomain))
			return FALSE;
		return TRUE;
	}

	inline BOOL ShouldEnterDormant(DWORD now, DWORD lastActivity,
		DWORD idleTimeout, BOOL hasPendingWork)
	{
		return !hasPendingWork &&
			(DWORD)(now - lastActivity) >= idleTimeout;
	}
}
