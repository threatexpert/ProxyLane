// Local-only PRC regression: preserve a hostname alongside a fake destination,
// then verify that a direct route resolves it without loading proxy encryption.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
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
	bool expectedFailure)
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

	SOCKET listener = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in local = {};
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = inet_addr("127.0.0.1");
	Check(bind(listener, (sockaddr*)&local, sizeof(local)) == 0 &&
		listen(listener, 1) == 0, "listen");
	int len = sizeof(local);
	Check(getsockname(listener, (sockaddr*)&local, &len) == 0, "listener address");
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
	registration.dstAddr.SetIP(domain ? "127.255.0.1" : "127.0.0.1");
	if (domain == 2)
	{
		sockaddr_in6 fake = {};
		fake.sin6_family = AF_INET6;
		fake.sin6_addr.u.Byte[0] = 0xfd;
		fake.sin6_addr.u.Byte[15] = 1;
		registration.dstAddr.Set((sockaddr*)&fake, sizeof(fake));
	}
	registration.dstAddr.SetPort(ntohs(local.sin_port));
	if (domain) strcpy_s(registration.szDomainName, "localhost");
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
	if (select(0, &ready, NULL, NULL, &timeout) > 0)
	{
		SOCKET accepted = accept(listener, NULL, NULL);
		Check(accepted != INVALID_SOCKET, "accept");
		DWORD receiveTimeout = 2000;
		setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&receiveTimeout, sizeof(receiveTimeout));
		setsockopt(accepted, SOL_SOCKET, SO_RCVTIMEO, (char*)&receiveTimeout, sizeof(receiveTimeout));
		char value = 0;
		echo = send(client, "x", 1, 0) == 1 && recv(accepted, &value, 1, 0) == 1 && value == 'x' &&
			send(accepted, "y", 1, 0) == 1 && recv(client, &value, 1, 0) == 1 && value == 'y';
		closesocket(accepted);
	}
	closesocket(client);
	closesocket(listener);
	Check(proxy->DisableProxy() != FALSE, "disable proxy");
	// Disable joins the worker; only read callback state after it has stopped.
	const bool passed = expectedFailure
		? !echo && log.failed == 1 && log.direct == 0 &&
			log.failureStage == IProxyLog::STAGE_TRANSPORT && log.failureError == WSAEINVAL
		: echo && log.failed == 0 && log.direct == 1;
	printf("%s: %s transport=%lu type=%s echo=%d failures=%ld stage=%d error=%lu\n",
		passed ? "PASS" : "FAIL", domain == 2 ? "fake IPv6 + hostname" : domain ? "fake IPv4 + hostname" : "IP",
		transport, settings.info.strProxyType.szbuf, echo, log.failed, log.failureStage, log.failureError);
	settings.Detach();
	log.Detach();
	ReleaseGlobalProxyInstance();
	return passed;
}

int main()
{
	setvbuf(stdout, NULL, _IONBF, 0);
	WSADATA wsa;
	Check(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "Winsock");
	bool passed = true;
	for (int domain = 0; domain <= 2; ++domain)
	{
		passed &= Run(domain, PROXY_TRANSPORT_PLAIN, TEXT(""), TEXT(""), false);
		passed &= Run(domain, PROXY_TRANSPORT_GONC_TLS_PSK, TEXT(""), TEXT("test-psk"), false);
		passed &= Run(domain, PROXY_TRANSPORT_GONC_TLS_PSK, TEXT(""), TEXT(""), false);
	}
	passed &= Run(true, PROXY_TRANSPORT_GONC_TLS_PSK, TEXT("HTTP11"), TEXT(""), true);
	passed &= Run(true, PROXY_TRANSPORT_GONC_TLS_PSK, TEXT("SOCKS4"), TEXT("test-psk"), true);
	WSACleanup();
	return passed ? 0 : 1;
}
