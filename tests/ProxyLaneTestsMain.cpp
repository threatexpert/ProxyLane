#include <iostream>

int Socks5UdpCodecTestsMain();
int BoundedLogQueueTestsMain();
int UdpAssociationPolicyTestsMain();
int UdpPayloadPolicyTestsMain();
int DnsRedirectPolicyTestsMain();
int ProxyTransportPolicyTestsMain();
int InetCompatTestsMain();
int Ipv6BlockPolicyTestsMain();
int DnsAddressFamilyPolicyTestsMain();
int DnsNamePolicyTestsMain();
int DnsQueryPolicyTestsMain();
int DeferredMitigationPolicyTestsMain();
int AppContainerPipeAccessTestsMain();
int ProcessActionsTestsMain();
int ScopedProcessSuspensionTestsMain();

int main()
{
	if (Socks5UdpCodecTestsMain() != 0)
		return 1;
	if (BoundedLogQueueTestsMain() != 0)
		return 1;
	if (UdpAssociationPolicyTestsMain() != 0)
		return 1;
	if (UdpPayloadPolicyTestsMain() != 0)
		return 1;
	if (DnsRedirectPolicyTestsMain() != 0)
		return 1;
	if (ProxyTransportPolicyTestsMain() != 0)
		return 1;
	if (InetCompatTestsMain() != 0)
		return 1;
	if (Ipv6BlockPolicyTestsMain() != 0)
		return 1;
	if (DnsAddressFamilyPolicyTestsMain() != 0)
		return 1;
	if (DnsNamePolicyTestsMain() != 0)
		return 1;
	if (DnsQueryPolicyTestsMain() != 0)
		return 1;
	if (DeferredMitigationPolicyTestsMain() != 0)
		return 1;
	if (AppContainerPipeAccessTestsMain() != 0)
		return 1;
	if (ProcessActionsTestsMain() != 0)
		return 1;
	if (ScopedProcessSuspensionTestsMain() != 0)
		return 1;
	std::cout << "ProxyLane tests passed" << std::endl;
	return 0;
}
