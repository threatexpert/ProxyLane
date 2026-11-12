// Reuse the existing real-PRC fixture helpers. No injection, profiles or CA edits.
#define main ExistingProxyChainMain
#include "ProxyChainTransportTests.cpp"
#undef main
#include "IsolateProxyTestProcess.h"
#pragma comment(lib, "advapi32.lib")

// Restrict only this disposable fixture process. Retain an authorized handle
// to restore its DACL; log lookups that reopen it must get access denied.
class DenyProcessQueries {
    HANDLE process;
    std::vector<BYTE> original;
public:
    DenyProcessQueries() : process(OpenProcess(READ_CONTROL | WRITE_DAC, FALSE, GetCurrentProcessId())) {
        Check(process != NULL, "open fixture security handle");
        DWORD bytes = 0;
        GetKernelObjectSecurity(process, DACL_SECURITY_INFORMATION, NULL, 0, &bytes);
        Check(bytes != 0, "read fixture DACL size");
        original.resize(bytes);
        Check(GetKernelObjectSecurity(process, DACL_SECURITY_INFORMATION,
            reinterpret_cast<PSECURITY_DESCRIPTOR>(original.data()), bytes, &bytes) != FALSE, "save fixture DACL");
        ACL empty; SECURITY_DESCRIPTOR descriptor;
        Check(InitializeAcl(&empty, sizeof(empty), ACL_REVISION) &&
            InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) &&
            SetSecurityDescriptorDacl(&descriptor, TRUE, &empty, FALSE) &&
            SetKernelObjectSecurity(process, DACL_SECURITY_INFORMATION, &descriptor), "restrict fixture process");
        HANDLE denied = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
        DWORD error = GetLastError();
        if (denied) CloseHandle(denied);
        Check(!denied && error == ERROR_ACCESS_DENIED, "fixture reproduces denied process-name lookup");
    }
    ~DenyProcessQueries() {
        SetKernelObjectSecurity(process, DACL_SECURITY_INFORMATION,
            reinterpret_cast<PSECURITY_DESCRIPTOR>(original.data()));
        CloseHandle(process);
    }
};

static SOCKET OpenDohClient(IGlobalProxy* proxy, const char* domain, bool udp, _SockAddr& endpoint) {
    SOCKET client = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    sockaddr_in source = {}; source.sin_family = AF_INET; source.sin_addr.s_addr = inet_addr("127.0.0.1");
    Check(bind(client, (sockaddr*)&source, sizeof(source)) == 0, "bind DoH client");
    int size = sizeof(source); getsockname(client, (sockaddr*)&source, &size);
    char name[MAX_PATH]; proxy->GetPRCInstance()->GetPRCPipeName(name, sizeof(name));
    HANDLE pipe = CreateFileA(name, GENERIC_READ | FILE_WRITE_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    Check(pipe != INVALID_HANDLE_VALUE, "DoH pipe");
    PRCPipeDataHead header = {}; header.action = PRCPD_GETSTARTUPINFO;
    PipeWrite(pipe, &header, sizeof(header)); PipeRead(pipe, &header, sizeof(header));
    PRCINFO startup; PipeRead(pipe, &startup, sizeof(startup));
    PRCClient c = {}; c.dwPid = GetCurrentProcessId(); c.dwTid = GetCurrentThreadId();
    c.sType = udp ? SOCK_DGRAM : SOCK_STREAM; c.s = client; c.socketGeneration = client;
    FILETIME created, exited, kernel, user; GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user);
    c.processCreateTime = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
    // Use a registered name distinct from this fixture's real executable.
    // Logs must use the PRC identity, not re-open the process to obtain host.exe.
    HookProcessIdentityInfo identity = {};
    identity.dwProcessId = c.dwPid; identity.processCreateTime = c.processCreateTime;
    wcscpy_s(identity.szAppPath, L"C:\\ProxyLaneTests\\RegisteredDoh.exe");
    header.action = PRCPD_REGISTER_PROCESS_IDENTITY; header.dataSize = sizeof(identity);
    PipeWrite(pipe, &header, sizeof(header)); PipeWrite(pipe, &identity, sizeof(identity));
    c.srcAddr = source; c.dstAddr.SetIP("127.255.0.1"); c.dstAddr.SetPort(18888);
    strcpy_s(c.szDomainName, domain);
    header.action = PRCPD_REGISTERCLIENT; header.flag = 0; header.dataSize = sizeof(c);
    PipeWrite(pipe, &header, sizeof(header)); PipeWrite(pipe, &c, sizeof(c)); PipeRead(pipe, &header, sizeof(header));
    Check(header.flag == 1, "register DoH client");
    if (udp) { Check(header.dataSize == sizeof(c), "UDP registration size"); PipeRead(pipe, &c, sizeof(c)); endpoint = c.udpAddr; }
    else endpoint = startup.tcpaddr;
    CloseHandle(pipe); endpoint.SetIP("127.0.0.1");
    DWORD timeout = 65000; setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    Check(connect(client, &endpoint, endpoint.Size()) == 0, "connect DoH route");
    return client;
}
class DohLog : public Log {
    void LogText(LPCWSTR text) override { fwprintf(stderr, L"%s", text); }
};
int main(int argc, char** argv) {
    Check(argc >= 5, "arguments: socks-port http-port url bootstrap [failure]");
    IsolateTestProcess();
    DenyProcessQueries restrictedIdentity;
    WSADATA ws; WSAStartup(MAKEWORD(2,2), &ws);
    Settings settings; DohLog log;
    settings.chain.push_back(Hop(TEXT("SOCKS5"), (WORD)atoi(argv[1])));
    if (atoi(argv[2])) settings.chain.push_back(Hop(TEXT("HTTP"), (WORD)atoi(argv[2])));
    auto& first = settings.chain.front(); first.dohEnabled = 1;
    strcpy_s(first.dohUrl.szbuf, argv[3]); strcpy_s(first.dohBootstrap.szbuf, argv[4]);
    IGlobalProxy* proxy = GetGlobalProxyInstance();
    proxy->GetSettingsInstance()->AddInstance(&settings); proxy->GetLogInstance()->AddInstance(&log);
    Check(proxy->EnableProxy() != FALSE, "enable DoH host");
    bool failure = false, skipUdp = false;
    for (int i = 5; i < argc; ++i) {
        if (strcmp(argv[i], "failure") == 0) failure = true;
        if (strcmp(argv[i], "skip-udp") == 0) skipUdp = true;
    }
    int passed = 0;
    for (int batch = 0; batch < (failure ? 1 : 2); ++batch) {
        std::vector<SOCKET> clients;
        for (int i = 0; i < (batch ? 3 : 8); ++i) {
            _SockAddr endpoint; clients.push_back(OpenDohClient(proxy, "example.org", false, endpoint));
        }
        // Cancel one waiter while the others still need the shared answer.
        if (!batch) {
            linger reset = {1, 0};
            setsockopt(clients.back(), SOL_SOCKET, SO_LINGER, (char*)&reset, sizeof(reset));
            closesocket(clients.back()); clients.pop_back();
        }
        for (SOCKET client : clients) send(client, "doh-route", 9, 0);
        for (SOCKET client : clients) {
            char output[9]; const bool ok = RecvAll(client, output, 9) && memcmp(output, "doh-route", 9) == 0;
            Check(ok != failure, "DoH result / explicit failure"); if (ok) ++passed;
            closesocket(client);
        }
    }
    if (!failure && !skipUdp && settings.chain.size() == 1) {
        _SockAddr endpoint; SOCKET udp = OpenDohClient(proxy, "example.org", true, endpoint);
        DWORD timeout = 10000; setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        send(udp, "doh-udp", 7, 0); char output[16];
        Check(recv(udp, output, sizeof(output), 0) == 7 && memcmp(output, "doh-udp", 7) == 0, "UDP uses resolved IP");
        closesocket(udp);
    }
    for (int attempt=0;attempt<(failure ? 1 : 2);++attempt) {
        TesterResult result;
        IProxyTester* tester = proxy->CreateTester();
        Check(tester != NULL,"create DoH tester");
        PRCClient client = {}; client.sType = SOCK_STREAM;
        client.dstAddr.SetIP("127.255.0.1"); client.dstAddr.SetPort(18888);
        strcpy_s(client.szDomainName,"example.org");
        BOOL started = settings.chain.size()==1 ? tester->Start(&result,&client,&first) :
            tester->StartChain(&result,&client,settings.chain.data(),(int)settings.chain.size());
        Check(started != FALSE,"start DoH tester");
        DWORD since = GetTickCount();
        while (!result.done && GetTickCount()-since<30000) {
            MSG message;
            while (PeekMessage(&message,NULL,0,0,PM_REMOVE)) {
                // Every connectivity test must use fresh network I/O, without polling.
                if (message.message != WM_TIMER) DispatchMessage(&message);
            }
            MsgWaitForMultipleObjects(0,NULL,FALSE,100,QS_ALLINPUT);
        }
        Check(result.done && (failure ? result.code==PROXYERROR_DOH_FAILED : result.code==0),
            "DoH tester completes without dispatching WM_TIMER");
        if (!failure) {
            Check(result.ordered && result.progress.size() == settings.chain.size(), "DoH chain progress ordered");
            for (const auto& hop : result.progress) Check(hop.stage == PTS_PASSED, "DoH hop passed");
        }
        tester->Release();
    }
    Check(proxy->DisableProxy() != FALSE, "stop DoH host");
    settings.Detach(); log.Detach(); ReleaseGlobalProxyInstance(); WSACleanup();
    printf("DOH_PASS %d\n", passed); return 0;
}
