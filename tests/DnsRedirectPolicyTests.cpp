#include <windows.h>
#include <assert.h>
#include <string.h>
#include "DnsRedirectPolicy.h"
#include "DohPolicy.h"

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
    for (const char* ip : {"192.168.1.1", "8.8.8.8", "fd00::53", "2001:4860:4860::8888"}) {
        assert(DohPolicy::DnsDestination(Address(ip)));
        assert(!DohPolicy::DnsDestination(Address(ip, 853)));
    }
    for (const char* ip : {"127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.251", "ff02::fb"})
        assert(!DohPolicy::DnsDestination(Address(ip)));
    PRCClient dnsClient = {}; dnsClient.dstAddr = Address("8.8.8.8");
    ProxyInfo dnsProxy = Socks5Proxy();
    assert(!DohPolicy::Intercept(dnsClient, dnsProxy));
    dnsProxy.dohEnabled = 1;
    assert(DohPolicy::Intercept(dnsClient, dnsProxy));
    dnsClient.dstAddr = Address("127.255.0.1"); strcpy_s(dnsClient.szDomainName, "resolver.example");
    assert(DohPolicy::Intercept(dnsClient, dnsProxy));
    dnsProxy.strProxyType = TEXT("NOPROXY");
    assert(!DohPolicy::Intercept(dnsClient, dnsProxy));
    std::vector<_SockAddr> bootstrap;
    assert(DohPolicy::Parse("https://resolver.example:8443/dns-query", "1.1.1.1, 2001:4860:4860::8888", false, bootstrap));
    assert(bootstrap.size() == 2 && bootstrap[0].GetPort() == 8443 && bootstrap[1].IsIPv6());
    assert(!DohPolicy::Parse("http://resolver.example/dns-query", "1.1.1.1", false, bootstrap));
    assert(!DohPolicy::Parse("https://resolver.example/dns-query", "", false, bootstrap));
    assert(!DohPolicy::Parse("https://resolver.example/dns-query", "resolver.example", false, bootstrap));
    assert(!DohPolicy::Parse("https://user:pass@resolver.example/dns-query", "1.1.1.1", false, bootstrap));
    assert(!DohPolicy::Parse("https://resolver.example:65536/dns-query", "1.1.1.1", false, bootstrap));
    assert(!DohPolicy::Parse("https://resolver.example/dns-query#fragment", "1.1.1.1", false, bootstrap));
    assert(!DohPolicy::Parse("https://resolver.example/dns-query", "::1", true, bootstrap));
    assert(!DohPolicy::Parse("https://resolver.example/dns-query", "0.0.0.0", false, bootstrap));
    assert(!DohPolicy::Parse("https://resolver.example/dns-query", "224.0.0.1", false, bootstrap));
    assert(!DohPolicy::Parse("https://resolver.example/dns-query", "::ffff:1.1.1.1", false, bootstrap));

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
