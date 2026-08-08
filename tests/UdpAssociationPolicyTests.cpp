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
	return 0;
}
