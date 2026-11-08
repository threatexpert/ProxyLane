// Local-only proxy chain regression: route a PRC connection through chains of
// in-process proxies (SOCKS5 and HTTP CONNECT, up to eight hops) to an echo
// server, check that a single upstream keeps its one-layer path, and check
// the tester's per-hop failure reporting.
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <thread>
#include <mutex>
#include <vector>
#include <memory>
#include <algorithm>
#include "../src/ProxyLaneHook/ProxyModule.h"

static void Check(bool ok, const char* message)
{
	if (!ok)
	{
		printf("FAIL %s (error %d)\n", message, WSAGetLastError());
		exit(2);
	}
}

static bool RecvAll(SOCKET s, void* data, int size)
{
	char* p = (char*)data;
	while (size > 0)
	{
		int n = recv(s, p, size, 0);
		if (n <= 0) return false;
		p += n;
		size -= n;
	}
	return true;
}

static bool SendAll(SOCKET s, const void* data, int size)
{
	const char* p = (const char*)data;
	while (size > 0)
	{
		int n = send(s, p, size, 0);
		if (n <= 0) return false;
		p += n;
		size -= n;
	}
	return true;
}

static SOCKET ConnectTo(const std::string& host, const std::string& port)
{
	addrinfo hints = {}, *result = NULL;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0)
		return INVALID_SOCKET;
	SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(s, result->ai_addr, (int)result->ai_addrlen) != 0)
	{
		closesocket(s);
		s = INVALID_SOCKET;
	}
	freeaddrinfo(result);
	return s;
}

// One listening server on 127.0.0.1: a SOCKS5 or HTTP CONNECT proxy, or an
// echo target. Connections are served one at a time on the server's thread.
class Server
{
public:
	enum Kind { SOCKS5, HTTP, ECHO };
	explicit Server(Kind kind) : m_kind(kind) {}
	~Server() { Stop(); }

	bool reject = false;
	std::string user, pass;

	WORD Start()
	{
		m_listener = socket(AF_INET, SOCK_STREAM, 0);
		sockaddr_in local = {};
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = inet_addr("127.0.0.1");
		Check(bind(m_listener, (sockaddr*)&local, sizeof(local)) == 0 &&
			listen(m_listener, 4) == 0, "server listen");
		int len = sizeof(local);
		Check(getsockname(m_listener, (sockaddr*)&local, &len) == 0, "server address");
		m_port = ntohs(local.sin_port);
		m_thread = std::thread([this]() { Run(); });
		return m_port;
	}

	void Stop()
	{
		if (!m_thread.joinable()) return;
		m_stop = true;
		m_thread.join();
		closesocket(m_listener);
	}

	std::string Target() { std::lock_guard<std::mutex> lock(m_lock); return m_target; }
	int Accepted() const { return m_accepted; }
	WORD Port() const { return m_port; }

private:
	void Run()
	{
		while (!m_stop)
		{
			fd_set ready;
			FD_ZERO(&ready);
			FD_SET(m_listener, &ready);
			timeval wait = { 0, 100000 };
			if (select(0, &ready, NULL, NULL, &wait) <= 0) continue;
			SOCKET s = accept(m_listener, NULL, NULL);
			if (s == INVALID_SOCKET) continue;
			++m_accepted;
			SOCKET upstream = INVALID_SOCKET;
			if (m_kind == ECHO) Relay(s, INVALID_SOCKET);
			else if (m_kind == SOCKS5 ? Socks(s, upstream) : Http(s, upstream)) Relay(s, upstream);
			closesocket(s);
			if (upstream != INVALID_SOCKET) closesocket(upstream);
		}
	}

	void Record(const std::string& target)
	{
		std::lock_guard<std::mutex> lock(m_lock);
		m_target = target;
	}

	bool Socks(SOCKET s, SOCKET& upstream)
	{
		unsigned char buf[512];
		if (!RecvAll(s, buf, 2) || buf[0] != 5 || !RecvAll(s, buf + 2, buf[1])) return false;
		const bool offersPassword = memchr(buf + 2, 2, buf[1]) != NULL;
		if (!user.empty())
		{
			unsigned char choice[] = { 5, (unsigned char)(offersPassword ? 2 : 0xff) };
			if (!SendAll(s, choice, 2) || !offersPassword) return false;
			unsigned char head[2];
			if (!RecvAll(s, head, 2)) return false;
			std::string u(head[1], '\0');
			if (head[1] && !RecvAll(s, &u[0], head[1])) return false;
			unsigned char plen;
			if (!RecvAll(s, &plen, 1)) return false;
			std::string p(plen, '\0');
			if (plen && !RecvAll(s, &p[0], plen)) return false;
			const bool ok = u == user && p == pass;
			unsigned char status[] = { 1, (unsigned char)(ok ? 0 : 1) };
			if (!SendAll(s, status, 2) || !ok) return false;
		}
		else
		{
			unsigned char choice[] = { 5, 0 };
			if (!SendAll(s, choice, 2)) return false;
		}

		if (!RecvAll(s, buf, 4) || buf[0] != 5 || buf[1] != 1) return false;
		std::string host;
		if (buf[3] == 1)
		{
			unsigned char ip[4];
			if (!RecvAll(s, ip, 4)) return false;
			char text[16];
			sprintf_s(text, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
			host = text;
		}
		else if (buf[3] == 3)
		{
			unsigned char len;
			if (!RecvAll(s, &len, 1)) return false;
			host.assign(len, '\0');
			if (!RecvAll(s, &host[0], len)) return false;
		}
		else return false;
		unsigned char portBytes[2];
		if (!RecvAll(s, portBytes, 2)) return false;
		const std::string port = std::to_string((portBytes[0] << 8) | portBytes[1]);
		Record(host + ":" + port);

		unsigned char reply[10] = { 5, 0, 0, 1 };
		if (!reject) upstream = ConnectTo(host, port);
		if (upstream == INVALID_SOCKET)
		{
			reply[1] = 5; // connection refused
			SendAll(s, reply, sizeof(reply));
			return false;
		}
		return SendAll(s, reply, sizeof(reply));
	}

	bool Http(SOCKET s, SOCKET& upstream)
	{
		std::string request;
		while (request.find("\r\n\r\n") == std::string::npos)
		{
			char buffer[512];
			int n = recv(s, buffer, sizeof(buffer), 0);
			if (n <= 0 || request.size() > 4096) return false;
			request.append(buffer, n);
		}
		if (request.compare(0, 8, "CONNECT ") != 0) return false;
		const size_t end = request.find(' ', 8);
		const std::string target = request.substr(8, end - 8);
		Record(target);
		const size_t colon = target.rfind(':');
		if (!reject) upstream = ConnectTo(target.substr(0, colon), target.substr(colon + 1));
		if (upstream == INVALID_SOCKET)
		{
			const char refused[] = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
			SendAll(s, refused, sizeof(refused) - 1);
			return false;
		}
		const char ok[] = "HTTP/1.1 200 Connection established\r\n\r\n";
		return SendAll(s, ok, sizeof(ok) - 1);
	}

	// Copies both ways until either side closes; with no upstream, echoes.
	void Relay(SOCKET a, SOCKET b)
	{
		char buffer[4096];
		while (!m_stop)
		{
			fd_set ready;
			FD_ZERO(&ready);
			FD_SET(a, &ready);
			if (b != INVALID_SOCKET) FD_SET(b, &ready);
			timeval wait = { 0, 100000 };
			if (select(0, &ready, NULL, NULL, &wait) <= 0) continue;
			if (FD_ISSET(a, &ready))
			{
				int n = recv(a, buffer, sizeof(buffer), 0);
				if (n <= 0 || !SendAll(b == INVALID_SOCKET ? a : b, buffer, n)) return;
			}
			if (b != INVALID_SOCKET && FD_ISSET(b, &ready))
			{
				int n = recv(b, buffer, sizeof(buffer), 0);
				if (n <= 0 || !SendAll(a, buffer, n)) return;
			}
		}
	}

	Kind m_kind;
	SOCKET m_listener = INVALID_SOCKET;
	WORD m_port = 0;
	volatile bool m_stop = false;
	volatile LONG m_accepted = 0;
	std::thread m_thread;
	std::mutex m_lock;
	std::string m_target;
};

static ProxyInfo Hop(const TCHAR* type, WORD port, const TCHAR* user = TEXT(""), const TCHAR* pass = TEXT(""))
{
	ProxyInfo hop;
	ZeroMemory(&hop, sizeof(hop));
	hop.strProxyType = type;
	hop.strProxyHost = TEXT("127.0.0.1");
	hop.nProxyPort = port;
	hop.strProxyUser = user;
	hop.strProxyPass = pass;
	hop.reserved = PROXY_TRANSPORT_PLAIN;
	return hop;
}

class Settings : public IProxySettings
{
public:
	ProxyChain chain;
	BOOL GetProxySettings(LPProxySettingsInfo settings) override
	{
		ZeroMemory(settings, sizeof(*settings));
		settings->bHookTCP = TRUE;
		settings->nDNSOption = PSI_DNSOPT_REMOTE;
		return TRUE;
	}
	LONG chainQueries = 0;
	BOOL GetProxyInfo(const LPPRCClient, LPProxyInfo result) override
	{
		*result = chain[0];
		return TRUE;
	}
	INT GetProxyChain(const LPPRCClient, LPProxyInfo hops, INT capacity) override
	{
		++chainQueries;
		if (chain.size() < 2)
			return 0;
		if (hops && capacity >= (INT)chain.size())
			std::copy(chain.begin(), chain.end(), hops);
		return (INT)chain.size();
	}
};

class Log : public IProxyLog
{
public:
	LONG failed = 0, proxyFailures = 0;
	std::wstring description;
	void LogText(LPCWSTR) override {}
	void LogNewProxyTask(const LPPRCClient) override {}
	BOOL ShouldInjectNewProcess(LPHookNewProcessInfo) override { return TRUE; }
	void OnHookWsock(LPHookWSockResult) override {}
	void OnHookLogtext(LPHookLogtext) override {}
	void OnChildInjectionResult(LPHookNewProcessInfo, BOOL) override {}
	void OnConnectionEvent(ConnectionEvent, const LPPRCClient, LPCWSTR) override {}
	void OnConnectionFailure(const LPPRCClient, LPCWSTR, ConnectionStage, DWORD) override { ++failed; }
	void OnProxyFailure(const LPPRCClient, LPCWSTR, LPCWSTR, BOOL, DWORD, LPCWSTR detail) override
	{
		++proxyFailures;
		description = detail ? detail : L"";
	}
};

static void PipeWrite(HANDLE pipe, const void* data, DWORD size)
{
	DWORD transferred;
	Check(WriteFile(pipe, data, size, &transferred, NULL) && transferred == size, "pipe write");
}

static void PipeRead(HANDLE pipe, void* data, DWORD size)
{
	DWORD transferred;
	Check(ReadFile(pipe, data, size, &transferred, NULL) && transferred == size, "pipe read");
}

// Sends one connection through the PRC with the given chain; returns whether
// a byte round-trips through the echo target.
static bool Through(Settings& settings, Log& log, WORD targetPort, bool byName)
{
	IGlobalProxy* proxy = GetGlobalProxyInstance();
	Check(proxy != NULL, "global proxy");
	proxy->GetSettingsInstance()->AddInstance(&settings);
	proxy->GetLogInstance()->AddInstance(&log);
	Check(proxy->EnableProxy() != FALSE, "enable proxy");

	SOCKET client = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in source = {};
	source.sin_family = AF_INET;
	source.sin_addr.s_addr = inet_addr("127.0.0.1");
	Check(bind(client, (sockaddr*)&source, sizeof(source)) == 0, "client bind");
	int len = sizeof(source);
	Check(getsockname(client, (sockaddr*)&source, &len) == 0, "client address");

	char name[MAX_PATH];
	Check(proxy->GetPRCInstance()->GetPRCPipeName(name, sizeof(name)) != FALSE, "pipe name");
	HANDLE pipe = CreateFileA(name, GENERIC_READ | FILE_WRITE_DATA,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	Check(pipe != INVALID_HANDLE_VALUE, "pipe open");
	PRCPipeDataHead header = {};
	header.action = PRCPD_GETSTARTUPINFO;
	PipeWrite(pipe, &header, sizeof(header));
	PipeRead(pipe, &header, sizeof(header));
	Check(header.flag == 1 && header.dataSize == sizeof(PRCINFO), "startup header");
	PRCINFO startup;
	PipeRead(pipe, &startup, sizeof(startup));
	PRCClient registration;
	registration.zero();
	registration.dwPid = GetCurrentProcessId();
	registration.dwTid = GetCurrentThreadId();
	registration.sType = SOCK_STREAM;
	registration.s = client;
	registration.socketGeneration = 1;
	FILETIME created, exited, kernel, user;
	Check(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user) != FALSE, "process identity");
	registration.processCreateTime = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
	registration.srcAddr = source;
	registration.dstAddr.SetIP(byName ? "127.255.0.1" : "127.0.0.1");
	registration.dstAddr.SetPort(targetPort);
	if (byName) strcpy_s(registration.szDomainName, "localhost");
	header.action = PRCPD_REGISTERCLIENT;
	header.flag = 0;
	header.dataSize = sizeof(registration);
	PipeWrite(pipe, &header, sizeof(header));
	PipeWrite(pipe, &registration, sizeof(registration));
	PipeRead(pipe, &header, sizeof(header));
	Check(header.flag == 1 && header.dataSize == 0, "register");
	CloseHandle(pipe);

	startup.tcpaddr.SetIP("127.0.0.1");
	Check(connect(client, &startup.tcpaddr, startup.tcpaddr.Size()) == 0, "connect PRC");
	DWORD receiveTimeout = 5000;
	setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&receiveTimeout, sizeof(receiveTimeout));
	const char payload[] = "chain-ok";
	char reply[sizeof(payload)] = {};
	const bool echo = SendAll(client, payload, sizeof(payload)) &&
		RecvAll(client, reply, sizeof(reply)) && memcmp(payload, reply, sizeof(payload)) == 0;
	closesocket(client);
	Sleep(300);
	Check(proxy->DisableProxy() != FALSE, "disable proxy");
	settings.Detach();
	log.Detach();
	ReleaseGlobalProxyInstance();
	return echo;
}

class TesterResult : public IProxyTesterCallback
{
public:
	volatile LONG done = 0;
	int code = -1;
	void OnProxyTesterCallback(IProxyTester*, int error, WPARAM, LPARAM) override
	{
		if (HIWORD(error) == LAYERCALLBACK_LAYERSPECIFIC)
		{
			code = LOWORD(error);
			done = 1;
		}
	}
};

// Runs the tester through the chain; returns the failed hop (-1 = none).
static int TestChain(const ProxyChain& chain, WORD targetPort, int& code)
{
	IGlobalProxy* proxy = GetGlobalProxyInstance();
	Check(proxy != NULL, "tester global proxy");
	IProxyTester* tester = proxy->CreateTester();
	Check(tester != NULL, "create tester");
	PRCClient client;
	client.zero();
	client.sType = SOCK_STREAM;
	strcpy_s(client.szDomainName, "localhost");
	client.dstAddr.SetPort(targetPort);
	TesterResult result;
	Check(tester->StartChain(&result, &client, &chain[0], (INT)chain.size()) != FALSE, "start chain test");
	const DWORD started = GetTickCount();
	while (!result.done && GetTickCount() - started < 20000)
	{
		MSG msg;
		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		Sleep(5);
	}
	Check(result.done != 0, "chain test completes");
	code = result.code;
	const int hop = tester->GetFailedHop();
	tester->Stop();
	tester->Release();
	ReleaseGlobalProxyInstance();
	return hop;
}

static std::string Narrow(const std::wstring& text)
{
	std::string narrow; // log details are ASCII
	for (wchar_t ch : text) narrow += static_cast<char>(ch);
	return narrow;
}

static bool Report(bool passed, const char* name, const std::string& detail = std::string())
{
	printf("%s: %s%s%s\n", passed ? "PASS" : "FAIL", name, detail.empty() ? "" : " - ", detail.c_str());
	return passed;
}

int main()
{
	setvbuf(stdout, NULL, _IONBF, 0);
	WSADATA wsa;
	Check(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "Winsock");
	bool passed = true;
	Server echo(Server::ECHO);
	const WORD target = echo.Start();
	const std::string targetIp = "127.0.0.1:" + std::to_string(target);
	const std::string targetName = "localhost:" + std::to_string(target);

	{
		Server a(Server::SOCKS5), b(Server::SOCKS5);
		a.Start(); b.Start();
		Settings settings; Log log;
		settings.chain.push_back(Hop(TEXT("SOCKS5"), a.Port()));
		settings.chain.push_back(Hop(TEXT("SOCKS5"), b.Port()));
		const bool ok = Through(settings, log, target, false);
		passed &= Report(ok && a.Target() == "127.0.0.1:" + std::to_string(b.Port()) &&
			b.Target() == targetIp && log.proxyFailures == 0,
			"SOCKS5 -> SOCKS5, IP target", "hop1 saw " + a.Target() + ", hop2 saw " + b.Target());
	}
	{
		Server a(Server::HTTP), b(Server::SOCKS5);
		a.Start(); b.Start();
		Settings settings; Log log;
		settings.chain.push_back(Hop(TEXT("HTTP"), a.Port()));
		settings.chain.push_back(Hop(TEXT("SOCKS5"), b.Port()));
		const bool ok = Through(settings, log, target, true);
		passed &= Report(ok && a.Target() == "127.0.0.1:" + std::to_string(b.Port()) &&
			b.Target() == targetName,
			"HTTP CONNECT -> SOCKS5, hostname target", "hop1 saw " + a.Target() + ", hop2 saw " + b.Target());
	}
	{
		Server a(Server::SOCKS5), b(Server::HTTP), c(Server::SOCKS5);
		a.Start(); b.Start(); c.Start();
		Settings settings; Log log;
		settings.chain.push_back(Hop(TEXT("SOCKS5"), a.Port()));
		settings.chain.push_back(Hop(TEXT("HTTP"), b.Port()));
		settings.chain.push_back(Hop(TEXT("SOCKS5"), c.Port()));
		const bool ok = Through(settings, log, target, true);
		passed &= Report(ok && b.Target() == "127.0.0.1:" + std::to_string(c.Port()) &&
			c.Target() == targetName, "SOCKS5 -> HTTP -> SOCKS5, three hops");
	}
	{
		Server a(Server::SOCKS5), b(Server::SOCKS5);
		b.user = "alice"; b.pass = "secret";
		a.Start(); b.Start();
		Settings settings; Log log;
		settings.chain.push_back(Hop(TEXT("SOCKS5"), a.Port()));
		settings.chain.push_back(Hop(TEXT("SOCKS5"), b.Port(), TEXT("alice"), TEXT("secret")));
		passed &= Report(Through(settings, log, target, false) && b.Target() == targetIp,
			"per-hop credentials on hop 2");
	}
	{
		Server a(Server::SOCKS5), b(Server::SOCKS5);
		b.reject = true;
		a.Start(); b.Start();
		Settings settings; Log log;
		settings.chain.push_back(Hop(TEXT("SOCKS5"), a.Port()));
		settings.chain.push_back(Hop(TEXT("SOCKS5"), b.Port()));
		const bool ok = Through(settings, log, target, false);
		const bool named = log.description.find(L"hop 2 of 2") != std::wstring::npos;
		passed &= Report(!ok && log.proxyFailures == 1 && named,
			"hop 2 rejects: one failure, logged as hop 2", Narrow(log.description));
	}
	{
		Server a(Server::SOCKS5), b(Server::SOCKS5);
		a.Start(); b.Start();
		ProxyChain chain(2);
		chain[0] = Hop(TEXT("SOCKS5"), a.Port());
		chain[1] = Hop(TEXT("SOCKS5"), b.Port());
		int code = -1;
		const int hop = TestChain(chain, target, code);
		passed &= Report(code == 0 && hop == -1, "tester: two hops succeed",
			"code " + std::to_string(code) + ", hop " + std::to_string(hop));
	}
	{
		Server a(Server::SOCKS5), b(Server::SOCKS5);
		b.reject = true;
		a.Start(); b.Start();
		ProxyChain chain(2);
		chain[0] = Hop(TEXT("SOCKS5"), a.Port());
		chain[1] = Hop(TEXT("SOCKS5"), b.Port());
		int code = -1;
		const int hop = TestChain(chain, target, code);
		passed &= Report(code != 0 && hop == 1, "tester: hop 2 rejection names hop 2",
			"code " + std::to_string(code) + ", hop " + std::to_string(hop));
	}
	{
		Server b(Server::SOCKS5);
		b.user = "alice"; b.pass = "secret";
		Server a(Server::SOCKS5);
		a.Start(); b.Start();
		ProxyChain chain(2);
		chain[0] = Hop(TEXT("SOCKS5"), a.Port());
		chain[1] = Hop(TEXT("SOCKS5"), b.Port(), TEXT("alice"), TEXT("wrong"));
		int code = -1;
		const int hop = TestChain(chain, target, code);
		passed &= Report(code == PROXYERROR_AUTHFAILED && hop == 1, "tester: bad hop 2 password names hop 2",
			"code " + std::to_string(code) + ", hop " + std::to_string(hop));
	}
	{
		// Nothing listens on the first hop's port.
		SOCKET reserve = socket(AF_INET, SOCK_STREAM, 0);
		sockaddr_in local = {};
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = inet_addr("127.0.0.1");
		Check(bind(reserve, (sockaddr*)&local, sizeof(local)) == 0, "reserve port");
		int len = sizeof(local);
		getsockname(reserve, (sockaddr*)&local, &len);
		const WORD closedPort = ntohs(local.sin_port);
		closesocket(reserve);
		Server b(Server::SOCKS5);
		b.Start();
		ProxyChain chain(2);
		chain[0] = Hop(TEXT("SOCKS5"), closedPort);
		chain[1] = Hop(TEXT("SOCKS5"), b.Port());
		int code = -1;
		const int hop = TestChain(chain, target, code);
		passed &= Report(code != 0 && hop == 0, "tester: unreachable hop 1 names hop 1",
			"code " + std::to_string(code) + ", hop " + std::to_string(hop));
	}

	{
		// A single upstream: one chain query, then the old one-layer path.
		Server a(Server::SOCKS5);
		a.Start();
		Settings settings; Log log;
		settings.chain.push_back(Hop(TEXT("SOCKS5"), a.Port()));
		const bool ok = Through(settings, log, target, false);
		passed &= Report(ok && a.Target() == targetIp && settings.chainQueries == 1 && log.proxyFailures == 0,
			"single upstream still uses one layer", "hop saw " + a.Target() +
			", chain queries " + std::to_string(settings.chainQueries));
	}
	{
		// No hop limit: eight hops, alternating SOCKS5 and HTTP.
		const int count = 8;
		std::vector<std::unique_ptr<Server>> hops;
		Settings settings; Log log;
		for (int i = 0; i < count; ++i)
		{
			hops.emplace_back(new Server(i % 2 ? Server::HTTP : Server::SOCKS5));
			hops.back()->Start();
			settings.chain.push_back(Hop(i % 2 ? TEXT("HTTP") : TEXT("SOCKS5"), hops.back()->Port()));
		}
		const bool ok = Through(settings, log, target, true);
		bool linked = true;
		for (int i = 0; i + 1 < count; ++i)
			linked &= hops[i]->Target() == "127.0.0.1:" + std::to_string(hops[i + 1]->Port());
		passed &= Report(ok && linked && hops.back()->Target() == targetName && log.proxyFailures == 0,
			"eight hops, each tunnels to the next", "last hop saw " + hops.back()->Target());
	}
	{
		// The tester with six hops, the fifth rejecting.
		const int count = 6;
		std::vector<std::unique_ptr<Server>> hops;
		ProxyChain chain;
		for (int i = 0; i < count; ++i)
		{
			hops.emplace_back(new Server(Server::SOCKS5));
			hops.back()->reject = i == 4;
			hops.back()->Start();
			chain.push_back(Hop(TEXT("SOCKS5"), hops.back()->Port()));
		}
		int code = -1;
		const int hop = TestChain(chain, target, code);
		passed &= Report(code != 0 && hop == 4, "tester: six hops, hop 5 rejection names hop 5",
			"code " + std::to_string(code) + ", hop " + std::to_string(hop));
	}

	echo.Stop();
	WSACleanup();
	puts(passed ? "Proxy chain transport tests passed" : "Proxy chain transport tests FAILED");
	return passed ? 0 : 1;
}
