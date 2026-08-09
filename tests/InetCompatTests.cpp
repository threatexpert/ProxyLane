#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "InetCompat.h"
#include "structinfo.h"

static void TestIPv4WithoutCallerStartup()
{
	IN_ADDR address = { 0 };
	assert(ProxyInetPtonA(AF_INET, "192.0.2.15", &address) == 1);
	CHAR text[INET_ADDRSTRLEN] = { 0 };
	assert(ProxyInetNtopA(AF_INET, &address, text, sizeof(text)) == text);
	assert(strcmp(text, "192.0.2.15") == 0);
}

static void TestIPv6WithoutCallerStartup()
{
	IN6_ADDR address = { 0 };
	assert(ProxyInetPtonA(AF_INET6, "2001:db8::1234", &address) == 1);

	CHAR text[INET6_ADDRSTRLEN] = { 0 };
	assert(ProxyInetNtopA(AF_INET6, &address, text, sizeof(text)) == text);
	assert(strcmp(text, "2001:db8::1234") == 0);

	WCHAR wideText[INET6_ADDRSTRLEN] = { 0 };
	assert(ProxyInetNtopW(AF_INET6, &address, wideText,
		sizeof(wideText) / sizeof(wideText[0])) == wideText);
	assert(wcscmp(wideText, L"2001:db8::1234") == 0);
}

static void TestInvalidInputs()
{
	IN_ADDR address4 = { 0 };
	IN6_ADDR address6 = { 0 };
	assert(ProxyInetPtonA(AF_INET, "example.com", &address4) == 0);
	assert(ProxyInetPtonA(AF_INET, "192.0.2.15:53", &address4) == 0);
	assert(ProxyInetPtonA(AF_INET6, "[2001:db8::1]:53", &address6) == 0);
	assert(ProxyInetPtonA(AF_INET6, "2001:db8::zz", &address6) == 0);
}

static void TestLoopbackAddressRanges()
{
	_SockAddr address;
	address.Clear();
	address.SetIP("127.0.0.1");
	assert(address.IsLoopback());
	address.SetIP("127.255.0.1");
	assert(address.IsLoopback());
	address.SetIP("126.255.0.1");
	assert(!address.IsLoopback());
	address.SetIP("::1");
	assert(address.IsLoopback());
	address.SetIP("::2");
	assert(!address.IsLoopback());
}

int main()
{
	TestIPv4WithoutCallerStartup();
	TestIPv6WithoutCallerStartup();
	TestInvalidInputs();
	TestLoopbackAddressRanges();
	printf("Inet compatibility tests passed\n");
	return 0;
}
