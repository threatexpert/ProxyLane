#include <iostream>

int Socks5UdpCodecTestsMain();
int BoundedLogQueueTestsMain();

int main()
{
	if (Socks5UdpCodecTestsMain() != 0)
		return 1;
	if (BoundedLogQueueTestsMain() != 0)
		return 1;
	std::cout << "ProxyLane tests passed" << std::endl;
	return 0;
}
