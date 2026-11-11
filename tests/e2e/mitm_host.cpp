// Test-only PRC host. Injects one child; never modifies application profiles.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include "../../src/ProxyLaneHook/ProxyModule.h"

class Settings : public IProxySettings {
public:
    int port;
    const wchar_t* type;
    BOOL GetProxySettings(LPProxySettingsInfo s) {
        ZeroMemory(s, sizeof(*s)); s->bHookTCP = TRUE; return TRUE;
    }
    BOOL GetProxyInfo(const LPPRCClient, LPProxyInfo p) {
        ZeroMemory(p, sizeof(*p)); p->strProxyType = type;
        p->strProxyHost = L"127.0.0.1"; p->nProxyPort = port; return TRUE;
    }
};
class Log : public IProxyLog {
public:
    void LogText(LPCWSTR text) { fwprintf(stderr, L"%s", text); }
    void LogNewProxyTask(const LPPRCClient c) { fprintf(stderr, "CONNECTION pid=%lu generation=%I64u\n", c->dwPid, c->socketGeneration); }
    BOOL ShouldInjectNewProcess(LPHookNewProcessInfo) { return FALSE; }
    void OnHookWsock(LPHookWSockResult r) { fprintf(stderr, "HOOK pid=%lu error=%lu\n", r->dwProcessId, r->err); }
    void OnHookLogtext(LPHookLogtext r) { fwprintf(stderr, L"HOOKLOG %s\n", r->str); }
    void OnChildInjectionResult(LPHookNewProcessInfo, BOOL) {}
    void OnConnectionEvent(ConnectionEvent event, const LPPRCClient c, LPCWSTR) { fprintf(stderr, "ROUTE pid=%lu event=%d\n", c->dwPid, event); }
    void OnConnectionFailure(const LPPRCClient c, LPCWSTR, ConnectionStage stage, DWORD error) { fprintf(stderr, "FAIL pid=%lu stage=%d error=%lu\n", c->dwPid, stage, error); }
};
static std::string ProtocolQuery(IProxyTlsControl* tls, const std::string& request) {
    std::vector<char> buffer(4096);
    for (int attempt = 0; attempt != 4; ++attempt) {
        int result = tls->QueryProtocol(request.c_str(), buffer.data(), buffer.size());
        if (result < 0) { fprintf(stderr, "PROTOCOL_QUERY_ERROR %s\n", buffer.data()); return ""; }
        if (result <= (int)buffer.size()) { printf("PROTOCOL_JSON %s\n", buffer.data()); return buffer.data(); }
        if (result > 8 * 1024 * 1024) ExitProcess(30);
        buffer.resize(result);
    }
    ExitProcess(31); return "";
}
static void DumpProtocol(IProxyTlsControl* tls) {
    char sentinel = '!';
    if (tls->QueryProtocol("{\"type\":\"stats\"}", &sentinel, 1) <= 1 || sentinel != '!') ExitProcess(32);
    std::string stats = ProtocolQuery(tls, "{\"type\":\"stats\"}");
    ProtocolQuery(tls, "{\"type\":\"poll\",\"limit\":64}");
    const std::string key = "\"run_id\":\"";
    size_t start = stats.find(key);
    if (start == std::string::npos) return;
    start += key.size();
    std::string run = stats.substr(start, stats.find('"', start) - start);
    for (int id = 1; id <= 8; ++id) {
        std::string base = "\"run_id\":\"" + run + "\",\"cache_id\":" + std::to_string(id);
        ProtocolQuery(tls, "{\"type\":\"cache_status\"," + base + "}");
        if (id <= 4) {
            ProtocolQuery(tls, "{\"type\":\"cache_read\",\"direction\":\"server\",\"offset\":0,\"length\":65536," + base + "}");
            ProtocolQuery(tls, "{\"type\":\"cache_decode\",\"direction\":\"server\"," + base + "}");
        }
    }
}
static bool WaitTestGate(const wchar_t* path) {
    if (!path[0]) return true;
    fprintf(stderr, "CRL_TEST_WAITING\n"); fflush(stderr);
    DWORD start = GetTickCount();
    while (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        if (GetTickCount() - start > 90000) return false;
        Sleep(20);
    }
    return true;
}
static bool AttachChild(const PROCESS_INFORMATION& child, const char* pipe) {
#ifdef _WIN64
    BOOL wow64=FALSE;
    if (IsWow64Process(child.hProcess,&wow64) && wow64) {
        // Match the GUI's cross-bitness path: a 32-bit helper injects Hook32,
        // while the proxy service and optional TLS modules remain in this host.
        wchar_t windows[MAX_PATH]={},host[MAX_PATH]={},command[2048]={};
        GetWindowsDirectoryW(windows,MAX_PATH);GetModuleFileNameW(NULL,host,MAX_PATH);
        wchar_t* slash=wcsrchr(host,L'\\');if(!slash)return false;*slash=0;
        _snwprintf_s(command,_countof(command),_TRUNCATE,
            L"\"%s\\SysWOW64\\rundll32.exe\" \"%s\\ProxyLaneHook32.dll\",AttachTo --pid=%lu --tid=%lu --pipe=%hs",
            windows,host,child.dwProcessId,child.dwThreadId,pipe);
        STARTUPINFOW startup={sizeof(startup)};PROCESS_INFORMATION helper={};
        if(!CreateProcessW(NULL,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startup,&helper))return false;
        DWORD code=0;
        if(WaitForSingleObject(helper.hProcess,15000)==WAIT_OBJECT_0)GetExitCodeProcess(helper.hProcess,&code);
        else TerminateProcess(helper.hProcess,1);
        CloseHandle(helper.hThread);CloseHandle(helper.hProcess);return code==0xFF01;
    }
#endif
    return AttachToI(child.dwProcessId,child.dwThreadId,pipe)==0xFF01;
}
int wmain(int argc, wchar_t** argv) {
    IGlobalProxy* proxy = GetGlobalProxyInstance();
    IProxyTlsControl* tls = proxy->GetTlsControl();
    IProxyMonitor* monitor = proxy->GetMonitorInstance();
    if (argc == 2 && wcscmp(argv[1], L"monitor-queue") == 0) {
        gp_UnhookWinsock();
        if (!proxy->EnableProxy()) return 25;
        auto data = proxy->GetPRCInstance()->GetPDHInstance();
        PRCClient client = {}; client.dwPid = 42; client.socketGeneration = 7;
        auto record = [&](DWORD value) {
            ProxyPacketInfo packet = {};
            packet.lpC = &client; packet.pData = (const char*)&value; packet.datalen = sizeof(value);
            data->OnEachPacket(&packet);
        };
        monitor->SetEnabled(TRUE);
        for (DWORD i = 0; i < 10000; ++i) record(i);
        if (monitor->TakeDroppedCount() != 10000 - 512) return 20;
        ProxyMonitorEvent event; DWORD expected = 10000 - 512;
        while (monitor->Poll(&event)) {
            DWORD value = 0; memcpy(&value, event.data, sizeof(value));
            if (value != expected++ || event.client.dwPid != 42 || event.kind != 3) return 21;
        }
        if (expected != 10000 || monitor->TakeDroppedCount()) return 22;
        record(expected);
        monitor->Clear(); if (monitor->Poll(&event)) return 23;
        monitor->SetEnabled(FALSE);
        record(expected);
        if (monitor->Poll(&event)) return 24;
        proxy->DisableProxy();
        ReleaseGlobalProxyInstance();
        // Services survive destruction/recreation of the reference-counted owner.
        proxy = GetGlobalProxyInstance();
        if (proxy->GetMonitorInstance() != monitor || proxy->GetTlsControl() != tls) return 26;
        if (!proxy->EnableProxy()) return 27;
        data = proxy->GetPRCInstance()->GetPDHInstance();
        monitor->SetEnabled(TRUE); record(123);
        if (!monitor->Poll(&event) || event.kind != 3) return 28;
        monitor->SetEnabled(FALSE); proxy->DisableProxy(); ReleaseGlobalProxyInstance();
        puts("Monitor interfaces, core capture, overflow, clear, pause and restart passed"); return 0;
    }
    if (argc == 2 && wcsncmp(argv[1], L"ca-", 3) == 0) {
        char details[4096] = {};
        int flags = tls->ManageCA(static_cast<IProxyTlsControl::CaAction>(_wtoi(argv[1] + 3)), details, sizeof(details));
        printf("FLAGS=%d\n%s\n", flags, details); ReleaseGlobalProxyInstance(); return flags < 0 ? 1 : 0;
    }
    if (argc != 4) { fputs("mitm_host port proxy-type \"child command line\"\n", stderr); return 2; }
    // This test host may inherit a developer's running ProxyLane hook. No sockets
    // or worker threads exist here yet; remove ONLY this host's inherited hooks.
    gp_UnhookWinsock();
    char error[4096] = {};
    if (tls->IsEnabled()) return 9; // Test GUI API without the legacy env switch.
    if (!tls->SetEnabled(TRUE, error, sizeof(error))) { fprintf(stderr, "%s\n", error); return 10; }
    if (!tls->IsEnabled()) return 11;
    char skipTest[8] = {};
    if (GetEnvironmentVariableA("PROXYLANE_TEST_SKIP_UPSTREAM", skipTest, sizeof(skipTest))) {
        if (tls->QueryProtocol("{\"type\":\"mitm_options\",\"skip_upstream_verify\":true}", error, sizeof(error)) < 0) return 37;
    }
    char crlTest[8] = {};
    if (GetEnvironmentVariableA("PROXYLANE_TEST_CRL", crlTest, sizeof(crlTest))) {
        char details[4096] = {};
        if (tls->ManageCA(IProxyTlsControl::QueryCA, details, sizeof(details)) < 0) return 34;
        fprintf(stderr, "CRL_TEST_CA\n%s\n", details); fflush(stderr);
    }
    char protocolMode[8] = {}, monitorOff[8] = {};
    bool protocolTest = GetEnvironmentVariableA("PROXYLANE_TEST_PROTOCOL", protocolMode, sizeof(protocolMode)) != 0;
    bool noMonitor = GetEnvironmentVariableA("PROXYLANE_TEST_NO_MONITOR", monitorOff, sizeof(monitorOff)) != 0;
    if (!noMonitor && tls->QueryProtocol("{\"type\":\"monitor_start\"}", error, sizeof(error)) < 0) return 38;
    char previewOff[8] = {};
    bool noPreview = GetEnvironmentVariableA("PROXYLANE_TEST_NO_PREVIEW", previewOff, sizeof(previewOff)) != 0;
    monitor->SetEnabled(!noMonitor && !noPreview);
    char disabled[8] = {};
    bool disableBeforeConnect = GetEnvironmentVariableA("PROXYLANE_MITM_TEST_DISABLED", disabled, sizeof(disabled)) != 0;
    if (disableBeforeConnect) tls->SetEnabled(FALSE, NULL, 0);
    WSADATA data; if (WSAStartup(MAKEWORD(2,2), &data)) return 3;
    Settings settings; settings.port = _wtoi(argv[1]); settings.type = argv[2];
    Log log;
    proxy->GetSettingsInstance()->AddInstance(&settings);
    proxy->GetLogInstance()->AddInstance(&log);
    if (!proxy->EnableProxy()) return 4;
    char pipe[MAX_PATH] = {0};
    if (!proxy->GetPRCInstance()->GetPRCPipeName(pipe, sizeof(pipe))) return 5;
    wchar_t repeatGate[MAX_PATH] = {}, holdGate[MAX_PATH] = {};
    GetEnvironmentVariableW(L"PROXYLANE_TEST_REPEAT_GATE", repeatGate, _countof(repeatGate));
    GetEnvironmentVariableW(L"PROXYLANE_TEST_HOLD_GATE", holdGate, _countof(holdGate));
    wchar_t stopGate[MAX_PATH] = {};
    GetEnvironmentVariableW(L"PROXYLANE_TEST_MONITOR_STOP", stopGate, _countof(stopGate));
    if(stopGate[0]) monitor->SetEnabled(FALSE);
    int stopStage=0;std::string stoppedStats;
    auto exists=[&](const wchar_t* suffix) { return GetFileAttributesW((std::wstring(stopGate)+suffix).c_str())!=INVALID_FILE_ATTRIBUTES; };
    auto signal=[&](const wchar_t* suffix) { FILE* f=nullptr;_wfopen_s(&f,(std::wstring(stopGate)+suffix).c_str(),L"wb");if(!f) ExitProcess(60);fclose(f); };
    auto stopStep=[&]() {
        if(!stopGate[0]) return;
        if(stopStage==0 && exists(L".stop")) {
            if(tls->QueryProtocol("{\"type\":\"monitor_stop\"}",error,sizeof(error))<0) ExitProcess(61);
            stoppedStats=ProtocolQuery(tls,"{\"type\":\"stats\"}");
            signal(L".stopped");stopStage=1;
        } else if(stopStage==1 && exists(L".resume")) {
            if(stoppedStats!=ProtocolQuery(tls,"{\"type\":\"stats\"}")) ExitProcess(62);
            if(tls->QueryProtocol("{\"type\":\"monitor_start\",\"decrypt\":true}",error,sizeof(error))<0) ExitProcess(63);
            signal(L".resumed");stopStage=2;
        } else if(stopStage==2 && exists(L".check")) {
            if(stoppedStats!=ProtocolQuery(tls,"{\"type\":\"stats\"}")) ExitProcess(64);
            signal(L".new");stopStage=3;
        }
    };
    DWORD code = 8;
    for (int attempt = 0; attempt < (repeatGate[0] ? 2 : 1); ++attempt) {
    STARTUPINFOW startup = {sizeof(startup)};
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION child = {0};
    std::wstring command(argv[3]);
    if (!CreateProcessW(NULL, &command[0], NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &child)) return 6;
    bool injected = proxy->GetPRCInstance()->AuthorizeProcessPipeAccess(child.hProcess) && AttachChild(child, pipe);
    if (!injected) { TerminateProcess(child.hProcess, 7); return 7; }
    fprintf(stderr, "CHILD pid=%lu\n", child.dwProcessId);
    ResumeThread(child.hThread);
    DWORD started = GetTickCount(); bool toggled = false;
    auto drain = [&]() {
        ProxyMonitorEvent e;
        while (monitor->Poll(&e)) {
            if (e.client.dwPid != child.dwProcessId || !e.client.processCreateTime) ExitProcess(12);
            if (e.kind == 5) {
                fprintf(stderr, "CONNECTION_EVENT pid=%lu bytes=%lu\n", e.client.dwPid, e.length);
                continue;
            }
            if (e.kind >= 3) {
                fprintf(stderr, "RAW_EVENT pid=%lu kind=%lu bytes=%lu\n", e.client.dwPid, e.kind, e.length);
                continue;
            }
            if (disableBeforeConnect) ExitProcess(14);
            if (!e.connection) ExitProcess(12);
            std::string bytes((const char*)e.data, e.length);
            if (e.kind == 0) fprintf(stderr, "TLS_ERROR %s\n", bytes.c_str());
            fprintf(stderr, "GUI_EVENT pid=%lu birth=%I64u connection=%I64u kind=%lu bytes=%lu get=%d response=%d\n",
                e.client.dwPid, e.client.processCreateTime, e.connection, e.kind, e.length,
                bytes.find("GET /probe") != std::string::npos, bytes.find("HTTP/1.1 200") != std::string::npos);
            // Switching off must not interrupt an already established TLS stream.
            if (!protocolTest && !toggled && e.kind == 1) { tls->SetEnabled(FALSE, NULL, 0); toggled = true; }
        }
    };
    while (WaitForSingleObject(child.hProcess, 10) != WAIT_OBJECT_0) {
        drain();stopStep();
        if (GetTickCount() - started > 45000) { TerminateProcess(child.hProcess, 8); break; }
    }
    // Allow the PRC to finish both TLS shutdown directions before tearing it down.
    DWORD closing = GetTickCount();
    for (;;) {
        drain();
        DWORD count = 0;
        proxy->GetPRCInstance()->GetPTMInstance(0)->GetTaskCount(&count);
        if (!count || GetTickCount() - closing >= 2000) break;
        Sleep(10);
    }
    drain();
    GetExitCodeProcess(child.hProcess, &code);
    CloseHandle(child.hThread); CloseHandle(child.hProcess);
    if (code) break;
    if (attempt == 0 && !WaitTestGate(repeatGate)) { code = 35; break; }
    }
    if (holdGate[0]) {
        tls->SetEnabled(FALSE, NULL, 0);
        if (!WaitTestGate(holdGate)) code = 36;
    }
    if(stopGate[0] && stopStage!=3) return 65;
    if (protocolTest) DumpProtocol(tls);
    proxy->DisableProxy();
    if (protocolTest && ProtocolQuery(tls, "{\"type\":\"stats\"}") != "{\"type\":\"inactive\"}") return 33;
    settings.Detach(); log.Detach(); ReleaseGlobalProxyInstance(); WSACleanup();
    if (monitor->TakeDroppedCount()) return 13;
    monitor->SetEnabled(FALSE);
    return (int)code;
}
