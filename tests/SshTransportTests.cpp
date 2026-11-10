// Real SSH loopback integration against ssh_test_servers.py: multiplexing,
// mixed routes, host trust, flow control, keepalive and demand reconnection.
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
	LONG chainQueries = 0;
	bool redirectPrivateDns = false;
	BOOL GetProxySettings(LPProxySettingsInfo settings) override
	{
		ZeroMemory(settings, sizeof(*settings));
		settings->bHookTCP = TRUE;
		settings->nDNSOption = PSI_DNSOPT_REMOTE;
		if (redirectPrivateDns)
		{
			settings->bRedirectPrivateDNS = TRUE;
			settings->redirectDNSAddr.SetIP("8.8.8.8");
			settings->redirectDNSAddr.SetPort(53);
		}
		return TRUE;
	}
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
        printf("PROXY FAILURE: %ls\n", description.c_str());
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

static SOCKET Open(IGlobalProxy* proxy, WORD targetPort, const char* targetHost = NULL)
{
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
	registration.dstAddr.SetIP("127.0.0.1");
	registration.dstAddr.SetPort(targetPort);
	if (targetHost) strcpy_s(registration.szDomainName, targetHost);

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
	DWORD receiveTimeout = 10000;
	setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&receiveTimeout, sizeof(receiveTimeout));
	return client;
}

static bool Echo(SOCKET socket, int size = 32)
{
    std::string sent(size, 'x'), received(size, 0);
    for (int i = 0; i < size; ++i) sent[i] = static_cast<char>(i * 37);
    bool written = false;
    std::thread writer([&]() { written = SendAll(socket, sent.data(), size); });
    const bool read = RecvAll(socket, &received[0], size);
    writer.join();
    return written && read && received == sent;
}
static int controlPort;
static std::string Control(const char* command = "stats")
{
    SOCKET s = ConnectTo("127.0.0.1", std::to_string(controlPort));
    Check(s != INVALID_SOCKET, "control connect");
    std::string request = std::string(command) + '\n', response;
    Check(SendAll(s, request.data(), (int)request.size()), "control send");
    char c;
    while (recv(s, &c, 1, 0) == 1 && c != '\n') response += c;
    closesocket(s);
    return response;
}
static int Stat(const char* key)
{
    std::string stats = Control(), name = std::string("\"") + key + "\":";
    size_t start = stats.find(name);
    Check(start != std::string::npos, "stat exists");
    return atoi(stats.c_str() + start + name.size());
}
static void Pass(bool result, const char* name) { Check(result, name); printf("PASS %s\n", name); }
static void PumpMessages() {
    MSG msg;
    while (PeekMessage(&msg,NULL,0,0,PM_REMOVE)) { TranslateMessage(&msg); DispatchMessage(&msg); }
}
static bool WaitSessions(int expected) {
    DWORD start = GetTickCount();
    do {
        PumpMessages();
        if (Stat("active_sessions") == expected) return true;
        Sleep(10);
    } while (GetTickCount()-start < 5000);
    return false;
}
static void WaitStat(const char* key, int minimum) {
    DWORD start = GetTickCount();
    while (Stat(key) < minimum && GetTickCount()-start < 10000) Sleep(20);
    Check(Stat(key) >= minimum, key);
}

struct TestResult : IProxyTesterCallback {
    bool done = false; int code = -1, hop = -1; std::string detail;
    std::vector<ProxyTestHopProgress> progress;
    void OnProxyTesterCallback(IProxyTester* tester, int error, WPARAM node, LPARAM data) override {
        if (HIWORD(error) == LAYERCALLBACK_TESTPROGRESS) {
            if (progress.size() <= node) progress.resize(node + 1);
            const int stage = LOWORD(error);
            if (stage > PTS_WAITING && stage <= PTS_PASSED) {
                for (size_t i = 0; i < node; ++i) Check(progress[i].stage == PTS_PASSED, "nested SSH progress follows tunnel order");
                if (stage == PTS_PASSED) Check(progress[node].Active(), "SSH hop started before passing");
            }
            Check(progress[node].Apply(stage, (DWORD)data), "SSH progress has no duplicates or late updates");
            return;
        }
        if (HIWORD(error) != LAYERCALLBACK_LAYERSPECIFIC) return;
        code = LOWORD(error); hop = tester->GetFailedHop();
        if (data) detail = reinterpret_cast<const char*>(data);
        tester->Release(); // Same synchronous release as the Profiles page.
        done = true;
    }
};
static TestResult Test(IGlobalProxy* proxy, ProxyChain route, WORD port) {
    PRCClient client; client.zero(); client.sType = SOCK_STREAM;
    client.dstAddr.SetIP("127.0.0.1"); client.dstAddr.SetPort(port);
    TestResult result;
    IProxyTester* tester = proxy->CreateTester();
    Check(route.size() == 1 ? tester->Start(&result,&client,&route[0]) != FALSE :
        tester->StartChain(&result,&client,route.data(),(int)route.size()) != FALSE,"tester start");
    DWORD start = GetTickCount();
    while (!result.done && GetTickCount()-start < 15000) {
        MSG msg;
        while (PeekMessage(&msg,NULL,0,0,PM_REMOVE)) { TranslateMessage(&msg); DispatchMessage(&msg); }
        Sleep(5);
    }
    Check(result.done,"tester completed"); return result;
}

int main(int argc, char** argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    Check(argc >= 8, "fixture arguments");
    WSADATA wsa; Check(!WSAStartup(MAKEWORD(2,2), &wsa), "Winsock");
    const WORD a = atoi(argv[1]), b = atoi(argv[2]), socks = atoi(argv[3]), http = atoi(argv[4]), target = atoi(argv[5]);
    controlPort = atoi(argv[6]);
    auto ssh = [&](WORD port) {
        ProxyInfo hop = Hop(L"SSH", port, L"test-user", L"test-password");
        strcpy_s(hop.strTransportPsk.szbuf, argv[7]); return hop;
    };
    Settings settings; Log log;
    settings.chain = { ssh(a) };
    IGlobalProxy* proxy = GetGlobalProxyInstance(); Check(proxy != NULL, "global proxy");
    proxy->GetSettingsInstance()->AddInstance(&settings); proxy->GetLogInstance()->AddInstance(&log);
    Check(proxy->EnableProxy() != FALSE, "enable proxy");
    ProxyInfo unknown = ssh(a); unknown.strTransportPsk = L"";
    TestResult tested = Test(proxy,{unknown},target);
    Pass(tested.code == PROXYERROR_SSH_HOSTKEY_UNKNOWN && tested.detail == argv[7], "tester returns untrusted fingerprint before authentication");
    Pass(WaitSessions(0), "untrusted test leaves no SSH session");
    unknown = ssh(b); unknown.strTransportPsk = L"SHA256:wrong";
    tested = Test(proxy,{ssh(a),unknown},target);
    Pass(tested.code == PROXYERROR_SSH_HOSTKEY_CHANGED && tested.hop == 1, "tester identifies SSH failed hop in chain");
    Pass(WaitSessions(0), "failed nested test releases every SSH hop");
    tested = Test(proxy,{ssh(a)},target);
    Pass(tested.code == 0, "tester succeeds after fingerprint confirmation");
    Pass(WaitSessions(0), "successful test leaves no SSH session");
    int testAuth = Stat("auth_a");
    tested = Test(proxy,{ssh(a),ssh(b)},target);
    Pass(tested.code == 0 && Stat("auth_a") == testAuth+1 && WaitSessions(0),
        "next test authenticates anew and releases its entire SSH chain");
    Pass(tested.progress.size() == 2 && tested.progress[0].stage == PTS_PASSED &&
        tested.progress[1].stage == PTS_PASSED, "nested SSH exposes progress for each node");
    tested = Test(proxy,{Hop(L"SOCKS5",socks),ssh(a),Hop(L"HTTP",http),ssh(b)},target);
    Pass(tested.code == 0 && tested.progress.size() == 4 && WaitSessions(0), "mixed SOCKS5 / SSH / HTTP / SSH progress");

    // Cancel while a nested test's final OPEN awaits confirmation.
    Control("hold-opens");
    PRCClient testClient; testClient.zero(); testClient.sType = SOCK_STREAM;
    testClient.dstAddr.SetIP("127.0.0.1"); testClient.dstAddr.SetPort(target);
    strcpy_s(testClient.szDomainName, "hold-open.test");
    ProxyChain testRoute = {ssh(a),ssh(b)};
    TestResult cancelled;
    IProxyTester* pendingTest = proxy->CreateTester();
    Check(pendingTest->StartChain(&cancelled,&testClient,testRoute.data(),(int)testRoute.size()) != FALSE,"pending tester start");
    DWORD cancelStart = GetTickCount();
    while (!Stat("open_held") && GetTickCount()-cancelStart < 10000) { PumpMessages(); Sleep(10); }
    Check(Stat("open_held") == 1 && !cancelled.done,"test OPEN is pending");
    Pass(cancelled.progress.size() == 2 && cancelled.progress[0].stage == PTS_PASSED &&
        cancelled.progress[1].stage == PTS_OPENING, "SSH waits for final OPEN before marking success");
    pendingTest->Release();
    Pass(cancelled.progress[0].stage == PTS_PASSED && cancelled.progress[1].stage == PTS_CANCELLED,
        "SSH cancellation preserves completed node and cancels pending node");
    Pass(WaitSessions(0), "cancelling pending nested test releases every SSH hop");
    Control("release-opens");
    while (Stat("open_held")) Sleep(10);
    int auth = Stat("auth_a");
    SOCKET first = Open(proxy, target);
    Pass(Echo(first), "single SSH TCP echo");
    tested = Test(proxy,{ssh(a)},target);
    Pass(tested.code == 0 && WaitSessions(1) && Echo(first),
        "test cleanup preserves an active business session");
    ++auth; // The isolated test used its own authentication.
    Control("hold-opens");
    SOCKET pendingOpen = Open(proxy, target, "hold-open.test");
    WaitStat("open_held", 1);
    const int concurrentAuth = Stat("auth_a"), priorFast = Stat("fast_while_held");
    SOCKET fastOpen = Open(proxy, target);
    DWORD fastTimeout = 3000;
    setsockopt(fastOpen,SOL_SOCKET,SO_RCVTIMEO,(char*)&fastTimeout,sizeof(fastTimeout));
    Pass(Echo(fastOpen) && Stat("open_held") == 1 &&
        Stat("fast_while_held") > priorFast && Stat("auth_a") == concurrentAuth,
        "B confirms and transfers while A remains unconfirmed on the SAME session");
    Pass(Echo(first), "existing channel transfers while another OPEN is pending");
    Control("release-opens");
    Pass(Echo(pendingOpen), "delayed A completes after B without reply mixup");
    closesocket(pendingOpen); closesocket(fastOpen);

    Control("hold-opens");
    pendingOpen = Open(proxy, target, "hold-fail.test");
    WaitStat("open_held", 1);
    fastOpen = Open(proxy, target);
    Pass(Echo(fastOpen), "pending rejection does not serialize another OPEN");
    Control("release-opens");
    char rejectedByte;
    Pass(recv(pendingOpen,&rejectedByte,1,0) <= 0 && Echo(fastOpen),
        "late OPEN_FAILURE only fails its own connection");
    closesocket(pendingOpen); closesocket(fastOpen);

    Control("hold-opens");
    pendingOpen = Open(proxy, target, "hold-open.test");
    WaitStat("open_held", 1);
    int lateClose = Stat("late_close");
    closesocket(pendingOpen); Sleep(200);
    fastOpen = Open(proxy, target);
    Pass(Echo(fastOpen) && Stat("auth_a") == concurrentAuth,
        "cancelled pending OPEN does not block another channel or reauthenticate");
    Control("release-opens");
    WaitStat("late_close", lateClose+1);
    Pass(Echo(first), "late confirmation of cancelled OPEN is closed on server");
    closesocket(fastOpen);

    Control("hold-opens");
    std::vector<SOCKET> burst;
    for (int i=0;i<40;++i) burst.push_back(Open(proxy,target,"hold-open.test"));
    WaitStat("open_held",32); Sleep(200);
    Pass(Stat("open_held") == 32 && Echo(first), "32 in-flight OPEN limit bounds pending state without blocking active traffic");
    Control("release-opens");
    bool burstOk = true;
    for (SOCKET s : burst) { burstOk = Echo(s) && burstOk; closesocket(s); }
    Pass(burstOk && Stat("auth_a") == concurrentAuth, "queued OPENs resume and all 40 channels use one authentication");
    std::vector<SOCKET> clients;
    for (int i=0;i<6;++i) clients.push_back(Open(proxy,target));
    for (SOCKET s : clients) Pass(Echo(s), "multiplexed channel");
    Pass(Stat("auth_a") == auth+1, "concurrent channels authenticate once");
    for (SOCKET s : clients) closesocket(s);
    SOCKET second = Open(proxy,target);
    Pass(Echo(second) && Stat("auth_a") == auth+1, "sequential channel reuses session");
    Pass(Echo(first, 2*1024*1024), "large full duplex stream with backpressure");
    SOCKET slow = Open(proxy,target);
    bool slowOk = false;
    std::thread slowWriter([&]() {
        std::string payload(4*1024*1024, 's');
        slowOk = SendAll(slow,payload.data(),(int)payload.size());
    });
    Sleep(500);
    Pass(Echo(first), "slow consumer does not block another channel");
    std::string slowData(4*1024*1024,0);
    bool slowRead = RecvAll(slow,&slowData[0],(int)slowData.size());
    slowWriter.join();
    Pass(slowOk && slowRead && slowData == std::string(slowData.size(),'s'), "slow channel resumes without data loss");
    closesocket(slow);
    SOCKET rejected = Open(proxy,1); char byte;
    Pass(recv(rejected,&byte,1,0) <= 0 && Echo(first), "channel refusal preserves other channels");
    closesocket(rejected);
    shutdown(second, SD_SEND);
    Pass(recv(second,&byte,1,0) == 0 && Echo(first), "half close preserves other channels");
    closesocket(second);
    int authBeforeRoutes = Stat("auth_a"), bBeforeRoutes = Stat("auth_b");
    for (ProxyChain route : std::vector<ProxyChain>{
        {ssh(a),Hop(L"SOCKS5",socks)}, {Hop(L"SOCKS5",socks),ssh(a)},
        {Hop(L"SOCKS5",socks),ssh(a),Hop(L"HTTP",http)},
        {ssh(a),ssh(b)}, {ssh(a),Hop(L"HTTP",http),ssh(b)}}) {
        settings.chain = route;
        SOCKET s = Open(proxy,target);
        Pass(Echo(s), "SSH at arbitrary position in mixed chain"); closesocket(s);
    }
    Pass(Stat("auth_a") == authBeforeRoutes+1 && Stat("auth_b") == bBeforeRoutes+2,
        "pool isolates different route prefixes and reuses identical prefixes");
    settings.chain = {ssh(a)};
    SOCKET named = Open(proxy,target,"localhost");
    Pass(Echo(named), "destination hostname resolved by SSH server"); closesocket(named);
    auth = Stat("auth_a");
    for (int kind=0;kind<3;++kind) {
        settings.chain = {ssh(a)};
        if (kind == 0) settings.chain[0].strProxyPass = L"wrong";
        else if (kind == 1) settings.chain[0].strTransportPsk = L"";
        else settings.chain[0].strTransportPsk = L"SHA256:wrong";
        SOCKET s = Open(proxy,target);
        Pass(recv(s,&byte,1,0) <= 0, "reject invalid credentials or untrusted host key"); closesocket(s);
    }
    Pass(Stat("auth_a") == auth+1, "host key checked before password authentication");
    settings.chain = {ssh(a)};
    int keepalive = Stat("keepalive");
    Sleep(17000);
    Pass(Stat("keepalive") > keepalive && Echo(first), "15 second keepalive retains usable session");
    Control("drop");
    Pass(recv(first,&byte,1,0) <= 0, "server disconnect fails existing connection"); closesocket(first);
    Sleep(500);
    auth = Stat("auth_a"); first = Open(proxy,target);
    Pass(Echo(first) && Stat("auth_a") == auth+1, "new connection recovers after disconnect");
    if (argc > 8) {
        Control("hold-opens");
        SOCKET timedOpen = Open(proxy,target,"hold-open.test");
        WaitStat("open_held",1);
        DWORD openTimeout = 70000;
        setsockopt(timedOpen,SOL_SOCKET,SO_RCVTIMEO,(char*)&openTimeout,sizeof(openTimeout));
        auth = Stat("auth_a"); lateClose = Stat("late_close");
        DWORD openStarted = GetTickCount();
        Pass(recv(timedOpen,&byte,1,0) <= 0 && GetTickCount()-openStarted < 67000 && Echo(first),
            "one OPEN timeout preserves healthy session and established channel");
        closesocket(timedOpen);
        Control("release-opens"); WaitStat("late_close",lateClose+1);
        SOCKET afterTimeout = Open(proxy,target);
        Pass(Echo(afterTimeout) && Stat("auth_a") == auth, "late timeout confirmation closed and next OPEN reuses session");
        closesocket(afterTimeout);
        Control("silence");
        DWORD timeout = 70000; setsockopt(first,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
        DWORD start = GetTickCount();
        Pass(recv(first,&byte,1,0) <= 0 && GetTickCount()-start < 67000, "silent session expires within liveness timeout");
        closesocket(first); Control("respond");
        auth = Stat("auth_a"); first = Open(proxy,target);
        Pass(Echo(first) && Stat("auth_a") == auth+1, "new connection recovers after unresponsive session");
        closesocket(first); first = INVALID_SOCKET;
        auth = Stat("auth_a");
        Sleep(64000);
        first = Open(proxy,target);
        Pass(Echo(first) && Stat("auth_a") == auth, "idle business session survives old 60 second limit and reuses authentication");
    }
    closesocket(first);
    Check(proxy->DisableProxy() != FALSE,"disable proxy");
    Pass(WaitSessions(0), "stopping proxy closes retained SSH sessions immediately");
    settings.Detach(); log.Detach(); ReleaseGlobalProxyInstance();
    WSACleanup(); printf("All SSH transport tests passed.\n"); return 0;
}
