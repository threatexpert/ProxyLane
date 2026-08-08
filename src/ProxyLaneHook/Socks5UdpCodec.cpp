#ifndef SOCKS5_CODEC_STANDALONE
#include "stdafx.h"
#endif
#include "Socks5UdpCodec.h"

void CSocks5UdpCodec::DecodedPacket::Clear()
{
	ZeroMemory(this, sizeof(*this));
}

int CSocks5UdpCodec::EncodeIPv4(BYTE *output, int outputCapacity,
	const SOCKADDR_IN *destination, const void *payload, int payloadLength)
{
	const int headerLength = 10;
	if (!output || !destination || payloadLength < 0 ||
		(payloadLength && !payload) || outputCapacity < headerLength + payloadLength)
		return SOCKET_ERROR;

	ZeroMemory(output, headerLength);
	output[3] = 0x01;
	CopyMemory(output + 4, &destination->sin_addr.s_addr, 4);
	CopyMemory(output + 8, &destination->sin_port, 2);
	if (payloadLength)
		CopyMemory(output + headerLength, payload, payloadLength);
	return headerLength + payloadLength;
}

int CSocks5UdpCodec::EncodeIPv6(BYTE *output, int outputCapacity,
	const SOCKADDR_IN6 *destination, const void *payload, int payloadLength)
{
	const int headerLength = 22;
	if (!output || !destination || payloadLength < 0 ||
		(payloadLength && !payload) || outputCapacity < headerLength + payloadLength)
		return SOCKET_ERROR;

	ZeroMemory(output, headerLength);
	output[3] = 0x04;
	CopyMemory(output + 4, &destination->sin6_addr, 16);
	CopyMemory(output + 20, &destination->sin6_port, 2);
	if (payloadLength)
		CopyMemory(output + headerLength, payload, payloadLength);
	return headerLength + payloadLength;
}

int CSocks5UdpCodec::EncodeDomain(BYTE *output, int outputCapacity,
	LPCSTR domain, USHORT port, const void *payload, int payloadLength)
{
	if (!output || !domain || payloadLength < 0 || (payloadLength && !payload))
		return SOCKET_ERROR;

	const size_t domainLength = strlen(domain);
	if (!domainLength || domainLength > 255)
		return SOCKET_ERROR;
	const int headerLength = 7 + (int)domainLength;
	if (outputCapacity < headerLength + payloadLength)
		return SOCKET_ERROR;

	ZeroMemory(output, 5);
	output[3] = 0x03;
	output[4] = (BYTE)domainLength;
	CopyMemory(output + 5, domain, domainLength);
	const USHORT networkPort = htons(port);
	CopyMemory(output + 5 + domainLength, &networkPort, 2);
	if (payloadLength)
		CopyMemory(output + headerLength, payload, payloadLength);
	return headerLength + payloadLength;
}

BOOL CSocks5UdpCodec::Decode(const BYTE *packet, int packetLength, DecodedPacket *decoded)
{
	if (!packet || !decoded || packetLength < 4)
		return FALSE;

	decoded->Clear();
	if (packet[0] != 0 || packet[1] != 0 || packet[2] != 0)
		return FALSE; // RFC 1928 fragmentation is deliberately unsupported.

	int headerLength = 0;
	decoded->source.sin_family = AF_INET;
	if (packet[3] == 0x01)
	{
		headerLength = 10;
		if (packetLength < headerLength)
			return FALSE;
		CopyMemory(&decoded->source.sin_addr.s_addr, packet + 4, 4);
		CopyMemory(&decoded->source.sin_port, packet + 8, 2);
		decoded->sourceLength = sizeof(decoded->source);
	}
	else if (packet[3] == 0x03)
	{
		if (packetLength < 7)
			return FALSE;
		const int domainLength = packet[4];
		headerLength = 7 + domainLength;
		if (!domainLength || packetLength < headerLength)
			return FALSE;
		CopyMemory(decoded->domain, packet + 5, domainLength);
		decoded->domain[domainLength] = '\0';
		CopyMemory(&decoded->source.sin_port, packet + 5 + domainLength, 2);
		decoded->sourceLength = sizeof(decoded->source);
	}
	else if (packet[3] == 0x04)
	{
		headerLength = 22;
		if (packetLength < headerLength)
			return FALSE;
		decoded->source6.sin6_family = AF_INET6;
		CopyMemory(&decoded->source6.sin6_addr, packet + 4, 16);
		CopyMemory(&decoded->source6.sin6_port, packet + 20, 2);
		decoded->sourceLength = sizeof(decoded->source6);
	}
	else
	{
		return FALSE;
	}

	decoded->payload = packet + headerLength;
	decoded->payloadLength = packetLength - headerLength;
	return TRUE;
}
