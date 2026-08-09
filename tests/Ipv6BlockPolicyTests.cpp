#include <windows.h>
#include <assert.h>
#include "Ipv6BlockPolicy.h"

static _SockAddr Address(const char *text)
{
	_SockAddr address;
	address.Clear();
	assert(address.SetIP(text));
	return address;
}

int main()
{
	assert(Ipv6BlockPolicy::ShouldBlock(Address("2001:db8::1")));
	assert(Ipv6BlockPolicy::ShouldBlock(Address("fe80::1")));
	assert(!Ipv6BlockPolicy::ShouldBlock(Address("::1")));
	assert(!Ipv6BlockPolicy::ShouldBlock(Address("127.0.0.1")));
	assert(!Ipv6BlockPolicy::ShouldBlock(Address("192.0.2.1")));
	assert(!Ipv6BlockPolicy::ShouldBlock(Address("::ffff:192.0.2.1")));
	return 0;
}
