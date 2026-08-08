#include <windows.h>
#include <assert.h>
#include <string.h>
#include "DnsRedirectPolicy.h"

static _SockAddr Address(const char *text, WORD port = 53)
{
	_SockAddr address;
	address.Clear();
	assert(address.SetIP(text));
	address.SetPort(port);
	return address;
}

static ProxyInfo Socks5Proxy()
{
	ProxyInfo proxy;
	ZeroMemory(&proxy, sizeof(proxy));
	strcpy_s(proxy.strProxyType.szbuf, "SOCKS5");
	return proxy;
}

static ProxySettingsInfo RemoteSettings()
{
	ProxySettingsInfo settings;
	ZeroMemory(&settings, sizeof(settings));
	settings.nDNSOption = PSI_DNSOPT_REMOTE;
	settings.bRedirectPrivateDNS = TRUE;
	settings.redirectDNSAddr = Address("8.8.8.8", 0);
	return settings;
}

int main()
{
	assert(DnsRedirectPolicy::IsPrivateDnsAddress(Address("10.1.2.3")));
	assert(DnsRedirectPolicy::IsPrivateDnsAddress(Address("172.16.0.1")));
	assert(DnsRedirectPolicy::IsPrivateDnsAddress(Address("172.31.255.254")));
	assert(!DnsRedirectPolicy::IsPrivateDnsAddress(Address("172.32.0.1")));
	assert(DnsRedirectPolicy::IsPrivateDnsAddress(Address("192.168.50.1")));
	assert(DnsRedirectPolicy::IsPrivateDnsAddress(Address("169.254.1.1")));
	assert(DnsRedirectPolicy::IsPrivateDnsAddress(Address("fd00::53")));
	assert(DnsRedirectPolicy::IsPrivateDnsAddress(Address("fe80::1")));
	assert(DnsRedirectPolicy::IsPrivateDnsAddress(Address("::ffff:192.168.50.1")));
	assert(!DnsRedirectPolicy::IsPrivateDnsAddress(Address("8.8.8.8")));
	assert(!DnsRedirectPolicy::IsPrivateDnsAddress(Address("2001:4860:4860::8888")));

	assert(DnsRedirectPolicy::IsValidPublicResolver(Address("8.8.8.8")));
	assert(DnsRedirectPolicy::IsValidPublicResolver(
		Address("2001:4860:4860::8888")));
	assert(!DnsRedirectPolicy::IsValidPublicResolver(Address("127.0.0.1")));
	assert(!DnsRedirectPolicy::IsValidPublicResolver(Address("192.168.1.1")));
	assert(!DnsRedirectPolicy::IsValidPublicResolver(Address("::ffff:8.8.8.8")));
	assert(!DnsRedirectPolicy::IsValidPublicResolver(Address("ff02::1")));

	PRCClient client;
	client.zero();
	client.sType = SOCK_DGRAM;
	client.dstAddr = Address("192.168.50.1");
	ProxySettingsInfo settings = RemoteSettings();
	ProxyInfo proxy = Socks5Proxy();
	assert(DnsRedirectPolicy::Apply(client, settings, proxy));
	assert(client.dstAddr == Address("192.168.50.1"));
	assert(client.GetProxyDestination() == Address("8.8.8.8"));

	client.zero();
	client.dstAddr = Address("192.168.50.1", 54);
	assert(!DnsRedirectPolicy::Apply(client, settings, proxy));

	client.zero();
	client.dstAddr = Address("192.168.50.1");
	strcpy_s(client.szDomainName, "resolver.example");
	assert(!DnsRedirectPolicy::Apply(client, settings, proxy));

	client.zero();
	client.dstAddr = Address("192.168.50.1");
	settings.nDNSOption = PSI_DNSOPT_LOCAL;
	assert(!DnsRedirectPolicy::Apply(client, settings, proxy));

	settings = RemoteSettings();
	ZeroMemory(&proxy, sizeof(proxy));
	assert(!DnsRedirectPolicy::Apply(client, settings, proxy));

	return 0;
}
