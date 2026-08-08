#pragma once

#include <stddef.h>
#include <string.h>

namespace UdpPayloadPolicy
{
	static const size_t MAX_IPV4_UDP_PAYLOAD = 65507;
	static const size_t SOCKS5_IPV4_HEADER_SIZE = 10;
	static const size_t SOCKS5_IPV6_HEADER_SIZE = 22;

	inline size_t Socks5HeaderSize(const char *domain)
	{
		if (!domain || !domain[0])
			return SOCKS5_IPV4_HEADER_SIZE;
		size_t domainLength = strlen(domain);
		if (domainLength > 255)
			return MAX_IPV4_UDP_PAYLOAD + 1;
		return 7 + domainLength;
	}

	inline size_t MaxPayload(BOOL usesSocks5, const char *domain,
		BOOL isIPv6 = FALSE)
	{
		if (!usesSocks5)
			return MAX_IPV4_UDP_PAYLOAD;
		size_t headerSize = isIPv6 ? SOCKS5_IPV6_HEADER_SIZE : Socks5HeaderSize(domain);
		return headerSize <= MAX_IPV4_UDP_PAYLOAD
			? MAX_IPV4_UDP_PAYLOAD - headerSize : 0;
	}

	inline BOOL IsAllowed(size_t payloadLength, BOOL usesSocks5,
		const char *domain, BOOL isIPv6 = FALSE)
	{
		return payloadLength <= MaxPayload(usesSocks5, domain, isIPv6);
	}
}
