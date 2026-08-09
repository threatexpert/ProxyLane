#include <assert.h>
#include <string.h>
#include <thread>
#include <vector>
#include "Socks5UdpCodec.h"
#include "InetCompat.h"

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

static void TestIPv6RoundTrip()
{
	SOCKADDR_IN6 destination = { 0 };
	destination.sin6_family = AF_INET6;
	destination.sin6_port = htons(443);
	assert(ProxyInetPtonA(AF_INET6, "2001:db8::1234", &destination.sin6_addr) == 1);
	const char payload[] = "ipv6-payload";
	BYTE packet[256];
	int packetLength = CSocks5UdpCodec::EncodeIPv6(packet, sizeof(packet),
		&destination, payload, sizeof(payload));
	assert(packetLength == 22 + sizeof(payload));
	assert(packet[3] == 4);
	CSocks5UdpCodec::DecodedPacket decoded;
	assert(CSocks5UdpCodec::Decode(packet, packetLength, &decoded));
	assert(decoded.sourceLength == sizeof(SOCKADDR_IN6));
	assert(decoded.source6.sin6_family == AF_INET6);
	assert(decoded.source6.sin6_port == destination.sin6_port);
	assert(IN6_ARE_ADDR_EQUAL(&decoded.source6.sin6_addr,
		&destination.sin6_addr));
	assert(decoded.payloadLength == sizeof(payload));
	assert(memcmp(decoded.payload, payload, sizeof(payload)) == 0);
}

static void TestMalformedPackets()
{
	BYTE fragmented[] = { 0, 0, 1, 1, 0, 0, 0, 0, 0, 0 };
	BYTE truncatedDomain[] = { 0, 0, 0, 3, 10, 'a' };
	CSocks5UdpCodec::DecodedPacket decoded;
	assert(!CSocks5UdpCodec::Decode(fragmented, sizeof(fragmented), &decoded));
	assert(!CSocks5UdpCodec::Decode(truncatedDomain, sizeof(truncatedDomain), &decoded));
}

static void TestPayloadBoundaries()
{
	const int sizes[] = { 0, 1, 512, 1200, 1472, 16384, 65497 };
	SOCKADDR_IN destination = {};
	destination.sin_family = AF_INET;
	destination.sin_addr.s_addr = inet_addr("1.2.3.4");
	destination.sin_port = htons(443);
	for (int index = 0; index < (int)(sizeof(sizes) / sizeof(sizes[0])); ++index)
	{
		std::vector<BYTE> payload(sizes[index], (BYTE)index);
		std::vector<BYTE> packet(sizes[index] + 10);
		int encoded = CSocks5UdpCodec::EncodeIPv4(packet.data(),
			(int)packet.size(), &destination,
			payload.empty() ? NULL : payload.data(), (int)payload.size());
		assert(encoded == sizes[index] + 10);
		CSocks5UdpCodec::DecodedPacket decoded;
		assert(CSocks5UdpCodec::Decode(packet.data(), encoded, &decoded));
		assert(decoded.payloadLength == sizes[index]);
	}
}

static void TestMaximumDomainAndConcurrentUse()
{
	char domain[256];
	memset(domain, 'a', 255);
	domain[255] = '\0';
	BYTE packet[300];
	assert(CSocks5UdpCodec::EncodeDomain(packet, sizeof(packet), domain, 53,
		NULL, 0) == 262);

	std::vector<std::thread> workers;
	for (int worker = 0; worker < 16; ++worker)
	{
		workers.push_back(std::thread([worker]() {
			for (int iteration = 0; iteration < 1000; ++iteration)
			{
				BYTE localPacket[64];
				SOCKADDR_IN target = {};
				target.sin_family = AF_INET;
				target.sin_addr.s_addr = htonl(0x0A000001 + worker);
				target.sin_port = htons((USHORT)(1000 + worker));
				int encoded = CSocks5UdpCodec::EncodeIPv4(localPacket,
					sizeof(localPacket), &target, &iteration, sizeof(iteration));
				CSocks5UdpCodec::DecodedPacket decoded;
				assert(CSocks5UdpCodec::Decode(localPacket, encoded, &decoded));
				assert(decoded.source.sin_port == target.sin_port);
			}
		}));
	}
	for (size_t index = 0; index < workers.size(); ++index)
		workers[index].join();
}

int main()
{
	TestIPv4RoundTrip();
	TestDomainRoundTrip();
	TestIPv6RoundTrip();
	TestMalformedPackets();
	TestPayloadBoundaries();
	TestMaximumDomainAndConcurrentUse();
	return 0;
}
