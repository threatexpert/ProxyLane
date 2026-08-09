#pragma once

#include "structinfo.h"

namespace Ipv6BlockPolicy
{
	inline BOOL ShouldBlock(const _SockAddr& destination)
	{
		if (!destination.IsIPv6() || !destination.GetAddr6())
			return FALSE;
		const IN6_ADDR *address = destination.GetAddr6();
		return !IN6_IS_ADDR_LOOPBACK(address) &&
			!IN6_IS_ADDR_V4MAPPED(address);
	}
}
