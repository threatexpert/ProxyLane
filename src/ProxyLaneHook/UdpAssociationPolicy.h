#pragma once

#include <winsock2.h>
#include <string.h>

namespace UdpAssociationPolicy
{
	enum UpstreamState
	{
		UPSTREAM_ROUTE_RESERVED = 0,
		UPSTREAM_ASSOCIATING,
		UPSTREAM_READY,
		UPSTREAM_RECONNECT_WAIT,
		UPSTREAM_DORMANT,
		UPSTREAM_CLOSING
	};

	enum CapabilityState
	{
		CAPABILITY_UNKNOWN = 0,
		CAPABILITY_SUPPORTED,
		CAPABILITY_UNSUPPORTED,
		CAPABILITY_TEMPORARILY_UNAVAILABLE
	};

	struct CapabilityCircuit
	{
		CapabilityState state;
		DWORD consecutiveFailures;
		DWORD blockedUntil;
		DWORD suppressedAttempts;

		CapabilityCircuit() { Reset(); }

		void Reset()
		{
			state = CAPABILITY_UNKNOWN;
			consecutiveFailures = 0;
			blockedUntil = 0;
			suppressedAttempts = 0;
		}

		BOOL CanAttempt(DWORD now)
		{
			if (state == CAPABILITY_TEMPORARILY_UNAVAILABLE &&
				(LONG)(now - blockedUntil) >= 0)
			{
				state = CAPABILITY_UNKNOWN;
				consecutiveFailures = 0;
				blockedUntil = 0;
			}
			return state != CAPABILITY_UNSUPPORTED &&
				state != CAPABILITY_TEMPORARILY_UNAVAILABLE;
		}

		BOOL ReportFailure(DWORD now, BOOL permanent,
			DWORD threshold = 3, DWORD cooldown = 60 * 1000)
		{
			if (permanent)
			{
				state = CAPABILITY_UNSUPPORTED;
				blockedUntil = 0;
				return TRUE;
			}
			if (state == CAPABILITY_UNSUPPORTED)
				return TRUE;
			if (++consecutiveFailures < threshold)
			{
				state = CAPABILITY_UNKNOWN;
				return FALSE;
			}
			state = CAPABILITY_TEMPORARILY_UNAVAILABLE;
			blockedUntil = now + cooldown;
			return TRUE;
		}

		void ReportSuccess()
		{
			state = CAPABILITY_SUPPORTED;
			consecutiveFailures = 0;
			blockedUntil = 0;
		}
	};

	inline BOOL ShouldActivateUpstream(UpstreamState state)
	{
		return state == UPSTREAM_ROUTE_RESERVED ||
			state == UPSTREAM_DORMANT;
	}

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

	inline BOOL IsMdnsDestination(ADDRESS_FAMILY family, DWORD ipv4,
		const BYTE *ipv6, WORD port)
	{
		if (port != 5353)
			return FALSE;
		if (family == AF_INET)
		{
			const BYTE *bytes = reinterpret_cast<const BYTE *>(&ipv4);
			return bytes[0] == 224 && bytes[1] == 0 &&
				bytes[2] == 0 && bytes[3] == 251;
		}
		static const BYTE mdns6[16] = {
			0xff, 0x02, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0xfb
		};
		return family == AF_INET6 && ipv6 &&
			memcmp(ipv6, mdns6, sizeof(mdns6)) == 0;
	}
}
