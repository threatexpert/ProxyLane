#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <fstream>
#include <string>

// Run only as an explicitly launched, injected child of the GUI E2E fixture.
int UdpBlockLogProbe(const char* output)
{
	WSADATA data;
	if (WSAStartup(MAKEWORD(2, 2), &data)) return 1;
	bool passed = true;
	std::ofstream progress(std::string(output) + ".progress");
	progress << "started" << std::endl;
	// Injection bootstrap is asynchronous. The fixture supplies its own pipe;
	// the idempotent exported entry waits for hook installation before probing.
	std::string pipe;
	for (int i = 0; i < 1000 && pipe.empty(); ++i)
	{
		std::ifstream input(std::string(output) + ".pipe");
		std::getline(input, pipe);
		if (pipe.empty()) Sleep(10);
	}
#ifdef _WIN64
	HMODULE hook = GetModuleHandleW(L"ProxyLaneHook64.dll");
#else
	HMODULE hook = GetModuleHandleW(L"ProxyLaneHook32.dll");
#endif
	typedef BOOL (WINAPI* EnableHook)(LPCSTR);
	EnableHook enable = hook ? reinterpret_cast<EnableHook>(GetProcAddress(hook, "gp_HookWinsock")) : NULL;
	if (pipe.empty() || !enable || !enable(pipe.c_str()))
	{
		std::ofstream file(output); file << "FAIL hook initialization";
		return 1;
	}
	SOCKADDR_IN target = {};
	target.sin_family = AF_INET;
	target.sin_addr.s_addr = htonl(0xc000020a);
	char payload = 'x';
	WSABUF buffer = { 1, &payload };
	for (int api = 0; api < 5; ++api)
	{
		progress << "API " << api << std::endl;
		SOCKET socketHandle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		target.sin_port = htons(static_cast<u_short>(12000 + api));
		DWORD sent = 0;
		int result = 0;
		if (api == 0) result = connect(socketHandle, (SOCKADDR*)&target, sizeof(target));
		if (api == 1) result = WSAConnect(socketHandle, (SOCKADDR*)&target, sizeof(target), NULL, NULL, NULL, NULL);
		if (api == 2) result = sendto(socketHandle, &payload, 1, 0, (SOCKADDR*)&target, sizeof(target));
		if (api == 3) result = WSASendTo(socketHandle, &buffer, 1, &sent, 0, (SOCKADDR*)&target, sizeof(target), NULL, NULL);
		if (api == 4)
		{
			GUID id = WSAID_WSASENDMSG;
			LPFN_WSASENDMSG sendMessage = NULL;
			DWORD returned = 0;
			if (WSAIoctl(socketHandle, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id),
				&sendMessage, sizeof(sendMessage), &returned, NULL, NULL) || !sendMessage)
			{ passed = false; closesocket(socketHandle); continue; }
			WSAMSG message = {};
			message.name = (SOCKADDR*)&target; message.namelen = sizeof(target);
			message.lpBuffers = &buffer; message.dwBufferCount = 1;
			result = sendMessage(socketHandle, &message, 0, &sent, NULL, NULL);
		}
		const int error = WSAGetLastError();
		progress << "API result=" << result << " error=" << error << std::endl;
		passed = passed && result == SOCKET_ERROR && error == WSAEACCES;
		closesocket(socketHandle);
	}
	progress << "flood" << std::endl;
	// Socket recreation does not reset destination cooldown; suppression must
	// still leave the same WSAEACCES result on every attempt.
	target.sin_port = htons(12002);
	SOCKET flood = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	for (int i = 0; i < 1000; ++i)
	{
		int result = sendto(flood, &payload, 1, 0, (SOCKADDR*)&target, sizeof(target));
		passed = passed && result == SOCKET_ERROR && WSAGetLastError() == WSAEACCES;
		if (i % 100 == 0) progress << "flood " << i << std::endl;
	}
	closesocket(flood);
	SOCKET ipv6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	progress << "IPv6" << std::endl;
	SOCKADDR_IN6 target6 = {};
	target6.sin6_family = AF_INET6; target6.sin6_port = htons(12005);
	target6.sin6_addr.u.Byte[0] = 0x20; target6.sin6_addr.u.Byte[1] = 1;
	target6.sin6_addr.u.Byte[2] = 0x0d; target6.sin6_addr.u.Byte[3] = 0xb8;
	target6.sin6_addr.u.Byte[15] = 1;
	int result = sendto(ipv6, &payload, 1, 0, (SOCKADDR*)&target6, sizeof(target6));
	int error = WSAGetLastError();
	progress << "IPv6 result=" << result << " error=" << error << std::endl;
	passed = passed && result == SOCKET_ERROR && error == WSAEACCES;
	closesocket(ipv6);
	// Loopback remains usable and must never produce a UDP-disabled log.
	SOCKET local = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	progress << "loopback" << std::endl;
	SOCKADDR_IN address = {}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	passed = passed && bind(local, (SOCKADDR*)&address, sizeof(address)) == 0;
	int size = sizeof(address); getsockname(local, (SOCKADDR*)&address, &size);
	DWORD timeout = 1000; setsockopt(local, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	passed = passed && sendto(local, &payload, 1, 0, (SOCKADDR*)&address, sizeof(address)) == 1;
	char received = 0;
	passed = passed && recv(local, &received, 1, 0) == 1 && received == payload;
	closesocket(local);
	Sleep(5200);
	progress << "cooldown" << std::endl;
	SOCKET last = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	result = sendto(last, &payload, 1, 0, (SOCKADDR*)&target, sizeof(target));
	passed = passed && result == SOCKET_ERROR && WSAGetLastError() == WSAEACCES;
	closesocket(last);
	std::ofstream file(output); file << (passed ? "PASS" : "FAIL");
	WSACleanup();
	return passed ? 0 : 1;
}
