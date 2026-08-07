#pragma once

#include <winsock2.h>

class CSocks5UdpCodec
{
public:
	enum { MAX_HEADER_SIZE = 262 };

	struct DecodedPacket
	{
		SOCKADDR_IN source;
		char domain[256];
		const BYTE *payload;
		int payloadLength;

		void Clear();
		BOOL HasDomain() const { return domain[0] != '\0'; }
	};

	static int EncodeIPv4(BYTE *output, int outputCapacity,
		const SOCKADDR_IN *destination, const void *payload, int payloadLength);
	static int EncodeDomain(BYTE *output, int outputCapacity,
		LPCSTR domain, USHORT port, const void *payload, int payloadLength);
	static BOOL Decode(const BYTE *packet, int packetLength, DecodedPacket *decoded);
};
