#include <winsock2.h>
#include <assert.h>
#include "DnsAddressFamilyPolicy.h"

int main()
{
	using namespace DnsAddressFamilyPolicy;

	assert(Decide(AF_UNSPEC, false) == KEEP_REQUESTED_FAMILY);
	assert(Decide(AF_INET, false) == KEEP_REQUESTED_FAMILY);
	assert(Decide(AF_INET6, false) == KEEP_REQUESTED_FAMILY);

	assert(Decide(AF_UNSPEC, true) == FORCE_IPV4);
	assert(Decide(AF_INET, true) == KEEP_REQUESTED_FAMILY);
	assert(Decide(AF_INET6, true) == REJECT_IPV6);
	assert(Decide(AF_BTH, true) == KEEP_REQUESTED_FAMILY);
	return 0;
}
