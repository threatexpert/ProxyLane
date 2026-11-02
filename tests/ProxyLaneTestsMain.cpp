#include <iostream>
#include <cstring>

int Socks5UdpCodecTestsMain();
int BoundedLogQueueTestsMain();
int MonitorLogFormatTestsMain();
int ProfileShareCodecTestsMain();
int UdpAssociationPolicyTestsMain();
int UdpPayloadPolicyTestsMain();
int DnsRedirectPolicyTestsMain();
int ProxyTransportPolicyTestsMain();
int InetCompatTestsMain();
int Ipv6BlockPolicyTestsMain();
int DirectIpv6RouteTestsMain();
int DnsAddressFamilyPolicyTestsMain();
int DnsNamePolicyTestsMain();
int DnsQueryPolicyTestsMain();
int DeferredMitigationPolicyTestsMain();
int AppContainerPipeAccessTestsMain();
int ProcessActionsTestsMain();
int AsyncSnapshotTestsMain();
int ProcessRegistryTestsMain();
int BrowserLaunchWatchTestsMain();
int UdpBlockLogLimiterTestsMain();
int UdpBlockLogProbe(const char* output);
int ExitProcessCleanupTestsMain();
int ScopedProcessSuspensionTestsMain();
int TrafficStatisticsTestsMain();
int ConfigLocationPolicyTestsMain();

int DetourHooksTestsMain();

int DetourHooksTestCase(const char* name);

int main(int argc, char** argv)
{
    if (ProfileShareCodecTestsMain() != 0) return 1;
	if (argc == 3 && std::strcmp(argv[1], "--udp-block-probe") == 0)
		return UdpBlockLogProbe(argv[2]);
    if (MonitorLogFormatTestsMain() != 0) return 1;
	if (argc == 3 && std::strcmp(argv[1], "--detours-case") == 0)
		return DetourHooksTestCase(argv[2]);
	if (DetourHooksTestsMain() != 0) return 1;
	if (ConfigLocationPolicyTestsMain() != 0) return 1;
	if (TrafficStatisticsTestsMain() != 0)
		return 1;
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
	if (DirectIpv6RouteTestsMain() != 0) return 1;
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
	if (AsyncSnapshotTestsMain() != 0) return 1;
	if (ProcessActionsTestsMain() != 0)
		return 1;
	if (ProcessRegistryTestsMain() != 0)
		return 1;
	if (BrowserLaunchWatchTestsMain() != 0) return 1;
	if (UdpBlockLogLimiterTestsMain() != 0)
		return 1;
	if (ExitProcessCleanupTestsMain() != 0)
		return 1;
	if (ScopedProcessSuspensionTestsMain() != 0)
		return 1;
	std::cout << "ProxyLane tests passed" << std::endl;
	return 0;
}
