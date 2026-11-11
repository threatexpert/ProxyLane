// Probe-only harness: no injection, no profile/CA edits, no business sockets.
#define main ExistingProxyChainMain
#include "ProxyChainTransportTests.cpp"
#undef main
#include "IsolateProxyTestProcess.h"

class ProbeResult : public TesterResult {
public:
    int phases = 0, callbacks = 0, attempts = 0;
    std::string detail;
    void OnProxyTesterCallback(IProxyTester* tester, int error, WPARAM param, LPARAM value) override {
        ++callbacks;
        if (HIWORD(error) == LAYERCALLBACK_DOHTEST && LOWORD(error) == DTS_CONNECTING) ++attempts;
        if (HIWORD(error) == LAYERCALLBACK_DOHTEST && LOWORD(error) == DTS_QUERYING) ++phases;
        if (HIWORD(error) == LAYERCALLBACK_LAYERSPECIFIC && value) detail = (const char*)value;
        TesterResult::OnProxyTesterCallback(tester, error, param, value);
    }
};
static void Messages() {
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) DispatchMessage(&msg);
    MsgWaitForMultipleObjects(0, NULL, FALSE, 20, QS_ALLINPUT);
}
int main(int argc, char** argv) {
    Check(argc >= 7, "socks-port ssh-port fingerprint url bootstrap pass|timeout|cancel|error [error text]");
    IsolateTestProcess();
    WSADATA ws; WSAStartup(MAKEWORD(2,2), &ws);
    ProxyChain chain;
    chain.push_back(Hop(TEXT("SOCKS5"), (WORD)atoi(argv[1])));
    if (atoi(argv[2])) {
        auto ssh = Hop(TEXT("SSH"), (WORD)atoi(argv[2]));
        ssh.strProxyUser = TEXT("test-user"); ssh.strProxyPass = TEXT("test-password");
        strcpy_s(ssh.strTransportPsk.szbuf, strcmp(argv[3], "unknown") ? argv[3] : "");
        chain.push_back(ssh);
    }
    if (argc > 8) chain.push_back(Hop(TEXT("SOCKS5"), (WORD)atoi(argv[8])));
    chain[0].dohEnabled = 1;
    strcpy_s(chain[0].dohUrl.szbuf, argv[4]); strcpy_s(chain[0].dohBootstrap.szbuf, argv[5]);
    IGlobalProxy* proxy = GetGlobalProxyInstance();
    const bool pass = strcmp(argv[6], "pass") == 0;
    const bool cancel = strcmp(argv[6], "cancel") == 0;
    for (int run=0; run<(pass ? 2 : 1); ++run) {
        ProbeResult result;
        IProxyTester* tester = proxy->CreateTester();
        PRCClient client = {}; client.sType = SOCK_STREAM; client.dstAddr.SetPort(80);
        strcpy_s(client.szDomainName, "example.org");
        const DWORD began = GetTickCount();
        Check((chain.size()>1 ? tester->StartChain(&result, &client, chain.data(), (int)chain.size()) :
            tester->Start(&result, &client, &chain[0])) != FALSE, "start probe");
        while (!result.done && GetTickCount()-began < (cancel ? 500u : 20000u)) Messages();
        const DWORD elapsed = GetTickCount()-began;
        if (cancel) {
            tester->Release();
            const int callbacks = result.callbacks;
            const DWORD stopped = GetTickCount();
            while (GetTickCount()-stopped < 1000) Messages();
            Check(result.callbacks == callbacks && !result.done, "no callbacks after release");
            puts("CANCEL_PASS"); continue;
        }
        printf("PROBE_RESULT %d hop=%d elapsed=%lu done=%ld attempts=%d detail=%s\n", result.code, tester->GetFailedHop(), elapsed, result.done, result.attempts, result.detail.c_str());
        Check(result.done && (pass ? result.code == 0 : result.code != 0), "probe outcome");
        if (pass) {
            Check(result.phases == 1 && result.ordered && result.progress.size() == chain.size(), "live ordered progress");
            for (const auto& hop : result.progress) Check(hop.stage == PTS_PASSED, "hop passed");
        } else {
            Check(!result.detail.empty(), "failure has specific detail");
            if (argc > 7) Check(result.detail.find(argv[7]) != std::string::npos, "expected failure detail");
            if (!strcmp(argv[6], "timeout")) Check(elapsed >= 11000 && elapsed < 15000, "12-second deadline");
        }
        tester->Release();
    }
    ReleaseGlobalProxyInstance(); WSACleanup();
    return 0;
}
