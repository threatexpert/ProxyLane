// Run against socks5_udp_server.go and TCP/UDP endpoints that double payloads.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include "../../src/ProxyLaneHook/ProxyModule.h"

static void Require(BOOL result, const char* operation)
{
	if (!result)
	{
		fprintf(stderr, "%s failed (Win32=%lu, Winsock=%d)\n", operation,
			GetLastError(), WSAGetLastError());
		exit(1);
	}
}

class Settings : public IProxySettings
{
public:
	int port;
	BOOL GetProxySettings(LPProxySettingsInfo settings)
	{
		ZeroMemory(settings, sizeof(*settings));
		settings->bHookTCP = settings->bHookUDP = TRUE;
		return TRUE;
	}
	BOOL GetProxyInfo(const LPPRCClient, LPProxyInfo proxy)
	{
		ZeroMemory(proxy, sizeof(*proxy));
		proxy->strProxyType = TEXT("SOCKS5");
		proxy->strProxyHost = TEXT("127.0.0.1");
		proxy->nProxyPort = port;
		return TRUE;
	}
};

static void Transfer(int type, int port, int length)
{
	SOCKET sock = socket(AF_INET, type, 0);
	Require(sock != INVALID_SOCKET, "socket");
	DWORD timeout = 10000;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
	sockaddr_in target = { 0 };
	target.sin_family = AF_INET;
	target.sin_addr.s_addr = inet_addr("203.0.113.10");
	target.sin_port = htons(static_cast<u_short>(port));
	Require(connect(sock, (sockaddr*)&target, sizeof(target)) == 0, "connect");
	std::vector<char> data(length, 'x');
	int position = 0;
	while (position < length)
	{
		int sent = send(sock, &data[position], length - position, 0);
		Require(sent > 0, "send");
		position += sent;
	}
	std::vector<char> reply(length * 2);
	position = 0;
	while (position < length * 2)
	{
		int received = recv(sock, &reply[position], length * 2 - position, 0);
		Require(received > 0, "recv");
		position += received;
	}
	for (size_t i = 0; i < reply.size(); ++i)
		Require(reply[i] == 'x', "payload integrity");
	closesocket(sock);
}

static void VerifyTotals(IProxyReceptionCentre* centre, ULONGLONG expected)
{
	ULONGLONG upload = 0, download = 0;
	for (int i = 0; i < 100; ++i)
	{
		centre->GetTrafficTotals(upload, download);
		if (upload == expected && download == expected * 2)
			break;
		Sleep(10);
	}
	printf("upload=%I64u download=%I64u expected=%I64u/%I64u\n",
		upload, download, expected, expected * 2);
	Require(upload == expected && download == expected * 2, "exact traffic totals");
}

static void RunClient(const char* pipe, int port, int type, int length)
{
	char executable[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, executable, sizeof(executable));
	char command[MAX_PATH * 3];
	sprintf_s(command, "\"%s\" --child \"%s\" %d %d %d", executable, pipe, port, type, length);
	STARTUPINFOA startup = { sizeof(startup) };
	PROCESS_INFORMATION process = { 0 };
	Require(CreateProcessA(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
		NULL, NULL, &startup, &process), "start client");
	DWORD wait = WaitForSingleObject(process.hProcess, 15000);
	if (wait != WAIT_OBJECT_0)
		TerminateProcess(process.hProcess, 1);
	DWORD code = 1;
	GetExitCodeProcess(process.hProcess, &code);
	CloseHandle(process.hThread);
	CloseHandle(process.hProcess);
	Require(wait == WAIT_OBJECT_0 && code == 0, "client completed");
}

int main(int argc, char** argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc == 6 && strcmp(argv[1], "--child") == 0)
	{
		WSADATA wsa;
		Require(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "client WSAStartup");
		Require(gp_HookWinsock(argv[2]), "client hook");
		Transfer(atoi(argv[4]), atoi(argv[3]), atoi(argv[5]));
		Require(gp_UnhookWinsock(), "client unhook");
		WSACleanup();
		return 0;
	}
	if (argc != 3)
		return 2;
	WSADATA wsa;
	Require(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "WSAStartup");
	Settings settings;
	settings.port = atoi(argv[1]);
	IGlobalProxy* proxy = GetGlobalProxyInstance();
	Require(proxy != NULL, "global proxy");
	proxy->GetSettingsInstance()->AddInstance(&settings);
	Require(proxy->EnableProxy(), "enable");
	IProxyReceptionCentre* centre = proxy->GetPRCInstance();
	char pipe[MAX_PATH] = { 0 };
	Require(centre->GetPRCPipeName(pipe, sizeof(pipe)), "pipe name");
	VerifyTotals(centre, 0);
	RunClient(pipe, atoi(argv[2]), SOCK_STREAM, 65537);
	VerifyTotals(centre, 65537);
	// Each new UDP socket queues its first datagram until association completes.
	RunClient(pipe, atoi(argv[2]), SOCK_DGRAM, 777);
	VerifyTotals(centre, 65537 + 777);
	RunClient(pipe, atoi(argv[2]), SOCK_DGRAM, 113);
	VerifyTotals(centre, 65537 + 777 + 113);
	Require(proxy->DisableProxy(), "disable");
	Require(proxy->EnableProxy(), "restart");
	VerifyTotals(proxy->GetPRCInstance(), 0);
	Require(proxy->DisableProxy(), "disable after restart");
	settings.Detach();
	ReleaseGlobalProxyInstance();
	WSACleanup();
	puts("TCP/UDP traffic totals and restart passed");
	return 0;
}
