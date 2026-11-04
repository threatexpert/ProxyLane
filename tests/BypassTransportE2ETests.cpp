// Local-only PRC regression: preserve a hostname alongside a fake destination,
// then verify that a direct route resolves it without loading proxy encryption.
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include "../src/ProxyLaneHook/ProxyModule.h"

static void Check(bool ok, const char* message)
{
	if (!ok)
	{
		printf("FAIL %s (error %d)\n", message, WSAGetLastError());
		exit(2);
	}
}

class Settings : public IProxySettings
{
public:
	ProxyInfo info;
	BOOL GetProxySettings(LPProxySettingsInfo settings) override
	{
		ZeroMemory(settings, sizeof(*settings));
		settings->bHookTCP = TRUE;
		return TRUE;
	}
	BOOL GetProxyInfo(const LPPRCClient, LPProxyInfo result) override
	{
		*result = info;
		return TRUE;
	}
};

class Log : public IProxyLog
{
public:
	LONG failed = 0, direct = 0;
	ConnectionStage failureStage = STAGE_ALLOCATE;
	DWORD failureError = 0;
	LONG proxyFailures = 0;
	DWORD failurePid = 0;
	std::wstring failureTarget;
	void LogText(LPCWSTR) override {}
	void LogNewProxyTask(const LPPRCClient) override {}
	BOOL ShouldInjectNewProcess(LPHookNewProcessInfo) override { return TRUE; }
	void OnHookWsock(LPHookWSockResult) override {}
	void OnHookLogtext(LPHookLogtext) override {}
	void OnChildInjectionResult(LPHookNewProcessInfo, BOOL) override {}
	void OnConnectionEvent(ConnectionEvent event, const LPPRCClient, LPCWSTR) override
	{
		if (event == ROUTE_DIRECT) ++direct;
	}
	void OnConnectionFailure(const LPPRCClient, LPCWSTR,
		ConnectionStage stage, DWORD error) override
	{
		failureStage = stage;
		failureError = error;
		++failed;
	}
	void OnProxyFailure(const LPPRCClient client, LPCWSTR, LPCWSTR target,
		BOOL, DWORD error, LPCWSTR) override
	{
		++proxyFailures;
		failurePid = client->dwPid;
		failureTarget = target;
		failureError = error;
	}
};

static void Write(HANDLE pipe, const void* data, DWORD size)
{
	DWORD transferred;
	Check(WriteFile(pipe, data, size, &transferred, NULL) && transferred == size, "pipe write");
}

static void Read(HANDLE pipe, void* data, DWORD size)
{
	DWORD transferred;
	Check(ReadFile(pipe, data, size, &transferred, NULL) && transferred == size, "pipe read");
}

static bool Run(int domain, DWORD transport, const TCHAR* type, const TCHAR* psk,
	bool expectedFailure, int timeoutMode = 0)
{
	Settings settings;
	ZeroMemory(&settings.info, sizeof(settings.info));
	settings.info.strProxyType = type;
	settings.info.reserved = transport;
	settings.info.strTransportPsk = psk;
	Log log;
	IGlobalProxy* proxy = GetGlobalProxyInstance();
	Check(proxy != NULL, "global proxy");
	proxy->GetSettingsInstance()->AddInstance(&settings);
	proxy->GetLogInstance()->AddInstance(&log);
	Check(proxy->EnableProxy() != FALSE, "enable proxy");

	const bool literalIPv6 = domain == 3;
	const bool byName = domain == 1 || domain == 2;
	SOCKET listener = socket(literalIPv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
	_SockAddr local = {};
	Check(local.SetIP(literalIPv6 ? "::1" : "127.0.0.1") != FALSE, "listener IP");
	Check(bind(listener, &local, local.Size()) == 0 &&
		listen(listener, 1) == 0, "listen");
	int len = sizeof(local);
	Check(getsockname(listener, (sockaddr*)&local, &len) == 0, "listener address");
	if (timeoutMode >= 2)
	{
		settings.info.strProxyType = timeoutMode == 2 ? TEXT("SOCKS5") : TEXT("HTTP11");
		settings.info.strProxyHost = TEXT("127.0.0.1");
		settings.info.nProxyPort = local.GetPort();
	}
	SOCKET client = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in source = {};
	source.sin_family = AF_INET;
	source.sin_addr.s_addr = inet_addr("127.0.0.1");
	Check(bind(client, (sockaddr*)&source, sizeof(source)) == 0, "client bind");
	len = sizeof(source);
	Check(getsockname(client, (sockaddr*)&source, &len) == 0, "client address");

	char name[MAX_PATH];
	Check(proxy->GetPRCInstance()->GetPRCPipeName(name, sizeof(name)) != FALSE, "pipe name");
	HANDLE pipe = CreateFileA(name, GENERIC_READ | FILE_WRITE_DATA,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	Check(pipe != INVALID_HANDLE_VALUE, "pipe open");
	PRCPipeDataHead header = {};
	header.action = PRCPD_GETSTARTUPINFO;
	Write(pipe, &header, sizeof(header));
	Read(pipe, &header, sizeof(header));
	Check(header.flag == 1 && header.dataSize == sizeof(PRCINFO), "startup header");
	PRCINFO startup;
	Read(pipe, &startup, sizeof(startup));
	PRCClient registration;
	registration.zero();
	registration.dwPid = GetCurrentProcessId();
	registration.dwTid = GetCurrentThreadId();
	registration.sType = SOCK_STREAM;
	registration.s = client;
	registration.socketGeneration = 1;
	FILETIME created, exited, kernel, user;
	Check(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user) != FALSE,
		"process identity");
	registration.processCreateTime = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
	registration.srcAddr = source;
	registration.dstAddr.SetIP(literalIPv6 ? "::1" : byName ? "127.255.0.1" : "127.0.0.1");
	if (domain == 2)
	{
		sockaddr_in6 fake = {};
		fake.sin6_family = AF_INET6;
		fake.sin6_addr.u.Byte[0] = 0xfd;
		fake.sin6_addr.u.Byte[15] = 1;
		registration.dstAddr.Set((sockaddr*)&fake, sizeof(fake));
	}
	registration.dstAddr.SetPort((WORD)local.GetPort());
	if (byName) strcpy_s(registration.szDomainName, "localhost");
	header.action = PRCPD_REGISTERCLIENT;
	header.flag = 0;
	header.dataSize = sizeof(registration);
	Write(pipe, &header, sizeof(header));
	Write(pipe, &registration, sizeof(registration));
	Read(pipe, &header, sizeof(header));
	Check(header.flag == 1 && header.dataSize == 0, "register");
	CloseHandle(pipe);
	startup.tcpaddr.SetIP("127.0.0.1");
	Check(connect(client, &startup.tcpaddr, startup.tcpaddr.Size()) == 0, "connect PRC");
	fd_set ready;
	FD_ZERO(&ready);
	FD_SET(listener, &ready);
	timeval timeout = { 2, 0 };
	bool echo = false;
	bool timedOut = false;
	if (select(0, &ready, NULL, NULL, &timeout) > 0)
	{
		SOCKET accepted = accept(listener, NULL, NULL);
		Check(accepted != INVALID_SOCKET, "accept");
		DWORD receiveTimeout = 2000;
		setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&receiveTimeout, sizeof(receiveTimeout));
		setsockopt(accepted, SOL_SOCKET, SO_RCVTIMEO, (char*)&receiveTimeout, sizeof(receiveTimeout));
		if (timeoutMode == 3)
		{
			std::string request;
			while (request.find("\r\n\r\n") == std::string::npos)
			{
				char buffer[512];
				int count = recv(accepted, buffer, sizeof(buffer), 0);
				Check(count > 0 && request.size() < 4096, "HTTP CONNECT request");
				request.append(buffer, count);
			}
			Check(request.find("CONNECT localhost:") == 0, "HTTP CONNECT domain target");
			const char reply[] = "HTTP/1.1 200 Connection established\r\n\r\n";
			Check(send(accepted, reply, sizeof(reply) - 1, 0) == sizeof(reply) - 1,
				"HTTP CONNECT success");
		}
		if (timeoutMode == 1 || timeoutMode == 3)
		{
			puts("Waiting 17s on an established, idle connection...");
			Sleep(17000);
		}
		char value = 0;
		if (timeoutMode == 2)
		{
			// Accept TCP but never answer the SOCKS greeting: the real PRC
			// connection deadline must close the client and report its target.
			receiveTimeout = 22000;
			setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&receiveTimeout, sizeof(receiveTimeout));
			DWORD started = GetTickCount();
			int result = recv(client, &value, 1, 0);
			DWORD elapsed = GetTickCount() - started;
			timedOut = (result == 0 || (result == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET)) &&
				elapsed >= 14000 && elapsed < 21000;
		}
		else
			echo = send(client, "x", 1, 0) == 1 && recv(accepted, &value, 1, 0) == 1 && value == 'x' &&
				send(accepted, "y", 1, 0) == 1 && recv(client, &value, 1, 0) == 1 && value == 'y';
		closesocket(accepted);
	}
	closesocket(client);
	closesocket(listener);
	Check(proxy->DisableProxy() != FALSE, "disable proxy");
	// Disable joins the worker; only read callback state after it has stopped.
	wchar_t expectedTarget[80];
	swprintf_s(expectedTarget, L"localhost:%d", local.GetPort());
	const bool passed = timeoutMode == 2
		? timedOut && log.proxyFailures == 1 && log.failureError == WSAETIMEDOUT &&
			log.failurePid == GetCurrentProcessId() && log.failureTarget == expectedTarget
		: expectedFailure
		? !echo && log.failed == 1 && log.direct == 0 &&
			log.failureStage == IProxyLog::STAGE_TRANSPORT && log.failureError == WSAEINVAL
		: echo && log.failed == 0 && log.proxyFailures == 0 && log.direct == (timeoutMode == 3 ? 0 : 1);
	if (timeoutMode) printf("%s timeout scenario %d, reports=%ld, target=%ls\n",
		passed ? "PASS" : "FAIL", timeoutMode, log.proxyFailures, log.failureTarget.c_str());
	printf("%s: %s transport=%lu type=%s echo=%d failures=%ld stage=%d error=%lu\n",
		passed ? "PASS" : "FAIL", literalIPv6 ? "literal IPv6" : domain == 2 ? "fake IPv6 + hostname" : domain ? "fake IPv4 + hostname" : "IP",
		transport, settings.info.strProxyType.szbuf, echo, log.failed, log.failureStage, log.failureError);
	settings.Detach();
	log.Detach();
	ReleaseGlobalProxyInstance();
	return passed;
}

static void RunIpv6RouteChecks()
{
	_SockAddr target = {};
	Check(target.SetIP("2001:db8::1") != FALSE, "IPv6 route test address");
	SOCKADDR_INET destination = {}, source = {};
	CopyMemory(&destination.Ipv6, &target, sizeof(destination.Ipv6));
	MIB_IPFORWARD_ROW2 route = {};
	DWORD routeError = GetBestRoute2(NULL, 0, NULL, &destination, 0, &route, &source);
	if (routeError != ERROR_NETWORK_UNREACHABLE)
	{
		printf("SKIP real no-route test: system returned %lu, expected 1231\n", routeError);
		return;
	}
	class TargetSettings : public Settings
	{
	public:
		BOOL GetProxyInfo(const LPPRCClient client, LPProxyInfo result) override
		{
			ZeroMemory(result, sizeof(*result));
			// Emulate final target routing: port 444 stays remote, all others direct.
			result->strProxyType = client->dstAddr.GetPort() == 444 ? TEXT("SOCKS5") : TEXT("NOPROXY");
			return TRUE;
		}
	} settings;
	Log log;
	IGlobalProxy* proxy = GetGlobalProxyInstance();
	Check(proxy != NULL, "route global proxy");
	proxy->GetSettingsInstance()->AddInstance(&settings);
	proxy->GetLogInstance()->AddInstance(&log);
	Check(proxy->EnableProxy() != FALSE, "route enable proxy");
	char name[MAX_PATH];
	Check(proxy->GetPRCInstance()->GetPRCPipeName(name, sizeof(name)) != FALSE, "route pipe name");
	HANDLE pipe = CreateFileA(name, GENERIC_READ | FILE_WRITE_DATA,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	Check(pipe != INVALID_HANDLE_VALUE, "route pipe open");
	PRCClient client = {};
	client.dwPid = GetCurrentProcessId();
	client.dwTid = GetCurrentThreadId();
	client.sType = SOCK_STREAM;
	client.s = socket(AF_INET6, SOCK_STREAM, 0);
	client.socketGeneration = 1;
	client.dstAddr = target;
	FILETIME created, exited, kernel, user;
	Check(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user) != FALSE, "route identity");
	client.processCreateTime = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
	for (int i = 0; i < 3; ++i)
	{
		client.dstAddr.SetPort(i == 1 ? 444 : 443);
		PRCPipeDataHead header = {};
		header.action = PRCPD_REGISTERCLIENT;
		header.dataSize = sizeof(client);
		Write(pipe, &header, sizeof(header));
		Write(pipe, &client, sizeof(client));
		Read(pipe, &header, sizeof(header));
		if (i == 1) Check(header.flag == 1 && header.dataSize == 0, "remote proxy registration unaffected");
		else
		{
			Check(header.flag == 0 && header.dataSize == sizeof(DWORD), "direct route failure response");
			DWORD error;
			Read(pipe, &error, sizeof(error));
			Check(error == WSAENETUNREACH, "1231 maps to 10051; pipe remains reusable");
		}
	}
	CloseHandle(pipe);
	closesocket(client.s);
	Check(gp_HookWinsock(name) != FALSE, "install hook for route probe");
	target.SetPort(443);
	for (int api = 0; api < 3; ++api)
	{
		SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		Check(s != INVALID_SOCKET, "route probe socket");
		int result;
		if (api == 0) result = connect(s, &target, target.Size());
		else if (api == 1) result = WSAConnect(s, &target, target.Size(), NULL, NULL, NULL, NULL);
		else
		{
			SOCKADDR_IN6 local = {};
			local.sin6_family = AF_INET6;
			Check(bind(s, (sockaddr*)&local, sizeof(local)) == 0, "ConnectEx bind");
			GUID id = WSAID_CONNECTEX;
			LPFN_CONNECTEX connectEx = NULL;
			DWORD bytes = 0;
			Check(WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id),
				&connectEx, sizeof(connectEx), &bytes, NULL, NULL) == 0, "ConnectEx lookup");
			OVERLAPPED overlapped = {};
			result = connectEx(s, &target, target.Size(), NULL, 0, &bytes, &overlapped) ? 0 : SOCKET_ERROR;
		}
		const int error = WSAGetLastError();
		Check(result == SOCKET_ERROR && error == WSAENETUNREACH, "hook immediately returns network unreachable");
		closesocket(s);
	}
	Check(gp_UnhookWinsock() != FALSE, "unhook route probe");
	Check(proxy->DisableProxy() != FALSE, "route disable proxy");
	Check(log.failed == 5 && log.failureStage == IProxyLog::STAGE_IPV6_ROUTE &&
		log.failureError == WSAENETUNREACH && log.direct == 0, "route failure logging before local redirect");
	settings.Detach();
	log.Detach();
	ReleaseGlobalProxyInstance();
	puts("PASS real 1231 route: final NOPROXY, remote proxy exclusion, reusable pipe, connect/WSAConnect/ConnectEx => 10051");
}

int main()
{
	setvbuf(stdout, NULL, _IONBF, 0);
	WSADATA wsa;
	Check(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "Winsock");
	RunIpv6RouteChecks();
	bool passed = true;
	for (int domain = 0; domain <= 3; ++domain)
	{
		passed &= Run(domain, PROXY_TRANSPORT_PLAIN, TEXT(""), TEXT(""), false);
		passed &= Run(domain, PROXY_TRANSPORT_GONC_TLS_PSK, TEXT(""), TEXT("test-psk"), false);
		passed &= Run(domain, PROXY_TRANSPORT_GONC_TLS_PSK, TEXT(""), TEXT(""), false);
	}
	passed &= Run(true, PROXY_TRANSPORT_GONC_TLS_PSK, TEXT("HTTP11"), TEXT(""), true);
	passed &= Run(true, PROXY_TRANSPORT_GONC_TLS_PSK, TEXT("SOCKS4"), TEXT("test-psk"), true);
	passed &= Run(true, PROXY_TRANSPORT_PLAIN, TEXT(""), TEXT(""), false, 1);
	passed &= Run(true, PROXY_TRANSPORT_PLAIN, TEXT(""), TEXT(""), false, 2);
	passed &= Run(true, PROXY_TRANSPORT_PLAIN, TEXT(""), TEXT(""), false, 3);
	WSACleanup();
	return passed ? 0 : 1;
}
