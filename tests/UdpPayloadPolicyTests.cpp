#include <winsock2.h>

#include "../src/ProxyLaneHook/UdpPayloadPolicy.h"

#include <assert.h>
#include <iostream>
#include <string>

int main()
{
	assert(UdpPayloadPolicy::MaxPayload(FALSE, NULL) == 65507);
	assert(UdpPayloadPolicy::IsAllowed(65507, FALSE, NULL));
	assert(UdpPayloadPolicy::MaxPayload(TRUE, NULL) == 65497);
	assert(UdpPayloadPolicy::IsAllowed(65497, TRUE, NULL));
	assert(!UdpPayloadPolicy::IsAllowed(65498, TRUE, NULL));
	assert(UdpPayloadPolicy::MaxPayload(TRUE, "a.test") == 65494);
	assert(UdpPayloadPolicy::IsAllowed(65494, TRUE, "a.test"));
	assert(!UdpPayloadPolicy::IsAllowed(65495, TRUE, "a.test"));
	std::string longestDomain(255, 'a');
	assert(UdpPayloadPolicy::MaxPayload(TRUE, longestDomain.c_str()) == 65245);
	std::string invalidDomain(256, 'a');
	assert(UdpPayloadPolicy::MaxPayload(TRUE, invalidDomain.c_str()) == 0);
	std::cout << "UDP payload policy tests passed" << std::endl;
	return 0;
}
