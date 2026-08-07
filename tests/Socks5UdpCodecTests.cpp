#include <assert.h>
#include <string.h>
#include "Socks5UdpCodec.h"

static void TestIPv4RoundTrip()
{
	BYTE packet[128];
	SOCKADDR_IN destination;
	ZeroMemory(&destination, sizeof(destination));
	destination.sin_family = AF_INET;
	destination.sin_addr.s_addr = inet_addr("8.8.8.8");
	destination.sin_port = htons(443);
	const char payload[] = "quic";

	int packetLength = CSocks5UdpCodec::EncodeIPv4(packet, sizeof(packet),
		&destination, payload, sizeof(payload) - 1);
	assert(packetLength == 14);

	CSocks5UdpCodec::DecodedPacket decoded;
	assert(CSocks5UdpCodec::Decode(packet, packetLength, &decoded));
	assert(!decoded.HasDomain());
	assert(decoded.source.sin_addr.s_addr == destination.sin_addr.s_addr);
	assert(decoded.source.sin_port == destination.sin_port);
	assert(decoded.payloadLength == sizeof(payload) - 1);
	assert(memcmp(decoded.payload, payload, sizeof(payload) - 1) == 0);
}

static void TestDomainRoundTrip()
{
	BYTE packet[256];
	const char payload[] = "dns";
	int packetLength = CSocks5UdpCodec::EncodeDomain(packet, sizeof(packet),
		"example.com", 53, payload, sizeof(payload) - 1);
	assert(packetLength > 0);

	CSocks5UdpCodec::DecodedPacket decoded;
	assert(CSocks5UdpCodec::Decode(packet, packetLength, &decoded));
	assert(decoded.HasDomain());
	assert(strcmp(decoded.domain, "example.com") == 0);
	assert(decoded.source.sin_port == htons(53));
	assert(decoded.payloadLength == sizeof(payload) - 1);
}

static void TestMalformedPackets()
{
	BYTE fragmented[] = { 0, 0, 1, 1, 0, 0, 0, 0, 0, 0 };
	BYTE truncatedDomain[] = { 0, 0, 0, 3, 10, 'a' };
	CSocks5UdpCodec::DecodedPacket decoded;
	assert(!CSocks5UdpCodec::Decode(fragmented, sizeof(fragmented), &decoded));
	assert(!CSocks5UdpCodec::Decode(truncatedDomain, sizeof(truncatedDomain), &decoded));
}

int main()
{
	TestIPv4RoundTrip();
	TestDomainRoundTrip();
	TestMalformedPackets();
	return 0;
}
