#include <windows.h>
#include <assert.h>
#include "UdpAssociationPolicy.h"

using UdpAssociationPolicy::Destination;

static Destination Domain(const char *name, WORD port)
{
	Destination destination;
	ZeroMemory(&destination, sizeof(destination));
	destination.hasDomain = TRUE;
	destination.domain = name;
	destination.family = AF_INET;
	destination.port = port;
	return destination;
}

static Destination IPv4(DWORD address, WORD port)
{
	Destination destination;
	ZeroMemory(&destination, sizeof(destination));
	destination.family = AF_INET;
	destination.ipv4 = address;
	destination.port = port;
	return destination;
}

int main()
{
	assert(UdpAssociationPolicy::ShouldActivateUpstream(
		UdpAssociationPolicy::UPSTREAM_ROUTE_RESERVED));
	assert(UdpAssociationPolicy::ShouldActivateUpstream(
		UdpAssociationPolicy::UPSTREAM_DORMANT));
	assert(!UdpAssociationPolicy::ShouldActivateUpstream(
		UdpAssociationPolicy::UPSTREAM_ASSOCIATING));
	assert(!UdpAssociationPolicy::ShouldActivateUpstream(
		UdpAssociationPolicy::UPSTREAM_READY));
	assert(!UdpAssociationPolicy::ShouldActivateUpstream(
		UdpAssociationPolicy::UPSTREAM_RECONNECT_WAIT));
	assert(!UdpAssociationPolicy::ShouldActivateUpstream(
		UdpAssociationPolicy::UPSTREAM_CLOSING));

	assert(UdpAssociationPolicy::IsSameDestination(
		Domain("dns.example", 53), Domain("DNS.EXAMPLE", 53)));
	assert(UdpAssociationPolicy::CanShareAssociation(
		Domain("dns.example", 53), Domain("DNS.EXAMPLE", 53)));

	assert(!UdpAssociationPolicy::CanShareAssociation(
		Domain("dns-a.example", 53), Domain("dns-b.example", 53)));
	assert(!UdpAssociationPolicy::CanShareAssociation(
		Domain("dns.example", 443), IPv4(0x01020304, 443)));

	assert(UdpAssociationPolicy::CanShareAssociation(
		Domain("dns-a.example", 53), Domain("dns-b.example", 443)));
	assert(UdpAssociationPolicy::CanShareAssociation(
		IPv4(0x01020304, 53), IPv4(0x05060708, 53)));

	assert(!UdpAssociationPolicy::ShouldEnterDormant(4999, 0, 5000, FALSE));
	assert(UdpAssociationPolicy::ShouldEnterDormant(5000, 0, 5000, FALSE));
	assert(!UdpAssociationPolicy::ShouldEnterDormant(6000, 0, 5000, TRUE));
	assert(UdpAssociationPolicy::ShouldEnterDormant(
		0x00000020, 0xfffffff0, 0x30, FALSE));

	DWORD mdns4 = 0;
	BYTE *mdns4Bytes = reinterpret_cast<BYTE *>(&mdns4);
	mdns4Bytes[0] = 224;
	mdns4Bytes[1] = 0;
	mdns4Bytes[2] = 0;
	mdns4Bytes[3] = 251;
	BYTE mdns6[16] = { 0xff, 0x02 };
	mdns6[15] = 0xfb;
	assert(UdpAssociationPolicy::IsMdnsDestination(AF_INET, mdns4, NULL, 5353));
	assert(UdpAssociationPolicy::IsMdnsDestination(AF_INET6, 0, mdns6, 5353));
	assert(!UdpAssociationPolicy::IsMdnsDestination(AF_INET, mdns4, NULL, 53));
	mdns4Bytes[3] = 250;
	assert(!UdpAssociationPolicy::IsMdnsDestination(AF_INET, mdns4, NULL, 5353));

	UdpAssociationPolicy::CapabilityCircuit circuit;
	assert(circuit.CanAttempt(100));
	assert(!circuit.ReportFailure(100, FALSE));
	assert(!circuit.ReportFailure(101, FALSE));
	assert(circuit.ReportFailure(102, FALSE));
	assert(!circuit.CanAttempt(103));
	assert(circuit.CanAttempt(60102));
	circuit.ReportSuccess();
	assert(circuit.state == UdpAssociationPolicy::CAPABILITY_SUPPORTED);
	assert(circuit.ReportFailure(70000, TRUE));
	assert(!circuit.CanAttempt(0xffffffff));
	circuit.Reset();
	assert(circuit.ReportFailure(0xfffffff0, FALSE, 1, 0x30));
	assert(!circuit.CanAttempt(0x00000010));
	assert(circuit.CanAttempt(0x00000020));
	return 0;
}
