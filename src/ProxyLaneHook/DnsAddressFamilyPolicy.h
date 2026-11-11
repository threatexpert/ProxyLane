#pragma once

#include <winsock2.h>

namespace DnsAddressFamilyPolicy
{
	enum Decision
	{
		KEEP_REQUESTED_FAMILY = 0,
		FORCE_IPV4,
		REJECT_IPV6
	};

	inline Decision Decide(int requestedFamily, bool blockIPv6)
	{
		// FakeIP lookups default to IPv4. Preserve explicit IPv6 requests
		// unless the application's IPv6 policy rejects them.
		if (requestedFamily == AF_UNSPEC)
			return FORCE_IPV4;
		if (requestedFamily == AF_INET6 && blockIPv6)
			return REJECT_IPV6;
		return KEEP_REQUESTED_FAMILY;
	}
}
