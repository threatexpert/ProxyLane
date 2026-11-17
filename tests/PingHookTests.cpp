// Real injected-DLL hooks in a test-owned host. All successful probes stay on
// loopback; disabled-policy probes also use local addresses only.
#define main ExistingProxyChainMain
#include "ProxyChainTransportTests.cpp"
#undef main
#include "IsolateProxyTestProcess.h"
#include "../src/ProxyLaneHook/DetourHooks.h"
#include <iphlpapi.h>
#include <icmpapi.h>
#include <winternl.h>

typedef DWORD (WINAPI* EchoEx)(HANDLE, HANDLE, FARPROC, PVOID, IPAddr, IPAddr,
    LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
static EchoEx echoEx;
static HMODULE icmpModule;
static decltype(&GetProcAddress) originalGetProcAddress = GetProcAddress;
static LONG missingExportQueries;
static FARPROC WINAPI WithoutEchoEx(HMODULE module, LPCSTR name) {
    if (module == icmpModule && (ULONG_PTR)name > 0xffff && !strcmp(name, "IcmpSendEcho2Ex")) {
        InterlockedIncrement(&missingExportQueries);
        SetLastError(ERROR_PROC_NOT_FOUND); return NULL;
    }
    return originalGetProcAddress(module, name);
}

class PingSettings : public Settings {
public:
    bool block = false;
    BOOL GetProxySettings(LPProxySettingsInfo value) override {
        ZeroMemory(value, sizeof(*value));
        value->bBlockPing = block;
        value->bHookCreateProcess = TRUE;
        // Independent of TCP/UDP proxying and the other block policies.
        value->bBlockUDP = TRUE; value->bBlockIPv6 = TRUE;
        value->nDNSOption = PSI_DNSOPT_LOCAL;
        return TRUE;
    }
};

struct Completion { LONG calls = 0; DWORD thread = GetCurrentThreadId(); };
static VOID NTAPI Complete(PVOID context, PIO_STATUS_BLOCK, ULONG) {
    Completion* state = (Completion*)context;
    Check(GetCurrentThreadId() == state->thread, "APC runs on requesting thread");
    ++state->calls;
}

static void Probe(int api, int async, bool block, bool fake = false, bool explicitSource = false) {
    const bool ipv6 = api == 3;
    HANDLE handle = ipv6 ? Icmp6CreateFile() : IcmpCreateFile();
    Check(handle != INVALID_HANDLE_VALUE, "create ICMP handle");
    HANDLE event = async == 1 ? CreateEvent(NULL, TRUE, FALSE, NULL) : NULL;
    Check(async != 1 || event != NULL, "create completion event");
    Completion completion;
    char payload[] = "PL Ping regression payload";
    alignas(16) BYTE reply[2048] = {};
    IP_OPTION_INFORMATION options = {}; options.Ttl = 64;
    sockaddr_in6 source = {}, destination = {};
    source.sin6_family = destination.sin6_family = AF_INET6;
    const BYTE remote6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7};
    if (block) memcpy(&destination.sin6_addr, remote6, 16);
    else destination.sin6_addr.u.Byte[15] = 1;
    if (fake) { destination.sin6_addr.u.Byte[0] = 0xfd; destination.sin6_addr.u.Byte[1] = 0xff; }
    if (explicitSource) {
        memcpy(&source.sin6_addr, remote6, 16);
        source.sin6_scope_id = 999;
        destination.sin6_scope_id = 999;
    }
    const sockaddr_in6 originalSource = source, originalDestination = destination;
    const IPAddr target = inet_addr(block ? (fake ? "127.255.0.7" : "198.51.100.7") : "127.0.0.1");
    FARPROC callback = async == 2 ? reinterpret_cast<FARPROC>(Complete) : NULL;
    DWORD count;
    if (api == 0) count = IcmpSendEcho(handle, target, payload, sizeof(payload), &options, reply, sizeof(reply), 1000);
    else if (api == 1) count = IcmpSendEcho2(handle, event, callback, &completion,
        target, payload, sizeof(payload), &options, reply, sizeof(reply), 1000);
    else if (api == 2) count = echoEx(handle, event, callback, &completion,
        explicitSource ? inet_addr("192.0.2.99") : 0, target, payload, sizeof(payload), &options, reply, sizeof(reply), 1000);
    else count = Icmp6SendEcho2(handle, event, callback, &completion, &source, &destination,
        payload, sizeof(payload), &options, reply, sizeof(reply), 1000);
    if (async) {
        Check(count == 0 && GetLastError() == ERROR_IO_PENDING, "system asynchronous pending result");
        if (event) Check(WaitForSingleObject(event, 3000) == WAIT_OBJECT_0, "event completes");
        else {
            DWORD start = GetTickCount();
            while (!completion.calls && GetTickCount() - start < 3000) SleepEx(50, TRUE);
            Check(completion.calls == 1, "exactly one APC with original context");
        }
        count = ipv6 ? Icmp6ParseReplies(reply, sizeof(reply)) : IcmpParseReplies(reply, sizeof(reply));
    }
    Check(count > 0, "ICMP reply received");
    if (ipv6) {
        auto result = reinterpret_cast<PICMPV6_ECHO_REPLY>(reply);
        const BYTE loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        Check(result->Status == IP_SUCCESS && !memcmp(result->Address.sin6_addr, loopback, 16), "IPv6 real loopback reply");
        Check(!memcmp(&source, &originalSource, sizeof(source)) && !memcmp(&destination, &originalDestination, sizeof(destination)), "caller addresses unchanged");
    } else {
        auto result = reinterpret_cast<PICMP_ECHO_REPLY>(reply);
        Check(result->Status == IP_SUCCESS && result->Address == inet_addr("127.0.0.1"), "IPv4 real loopback reply");
        Check(result->DataSize == sizeof(payload) && !memcmp(result->Data, payload, sizeof(payload)), "payload echoed unchanged");
    }
    Check(options.Ttl == 64 && options.OptionsSize == 0, "caller options unchanged");
    IcmpCloseHandle(handle); if (event) CloseHandle(event);
}

static void CheckErrors() {
    BYTE reply[1024] = {}; char payload[] = "test";
    Check(IcmpSendEcho(INVALID_HANDLE_VALUE, inet_addr("198.51.100.7"), payload, sizeof(payload), NULL, reply, sizeof(reply), 100) == 0, "invalid handle not fabricated as success");
    HANDLE h = IcmpCreateFile();
    Check(h != INVALID_HANDLE_VALUE, "error test handle");
    Check(IcmpSendEcho(h, inet_addr("198.51.100.7"), payload, sizeof(payload), NULL, reply, 0, 100) == 0, "short reply buffer not fabricated as success");
    BYTE route[] = {131, 7, 4, 192, 0, 2, 1};
    IP_OPTION_INFORMATION options = {}; options.Ttl = 64; options.OptionsSize = sizeof(route); options.OptionsData = route;
    Check(IcmpSendEcho(h, inet_addr("198.51.100.7"), payload, sizeof(payload), &options, reply, sizeof(reply), 100) == 0 && GetLastError() == ERROR_NOT_SUPPORTED, "source route cannot escape loopback policy");
    IcmpCloseHandle(h);
}

static void CheckPingProcess() {
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    HANDLE reader = NULL, writer = NULL;
    Check(CreatePipe(&reader, &writer, &security, 0) != FALSE, "ping output pipe");
    Check(SetHandleInformation(reader, HANDLE_FLAG_INHERIT, 0) != FALSE, "private pipe reader");
    WCHAR system[MAX_PATH]; Check(GetSystemDirectoryW(system, MAX_PATH) != 0, "system directory");
    WCHAR command[2*MAX_PATH]; swprintf_s(command, L"\"%s\\ping.exe\" -4 -n 1 -w 1000 198.51.100.7", system);
    STARTUPINFOW startup = {}; startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = startup.hStdError = writer; startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION child = {};
    Check(CreateProcessW(NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startup, &child) != FALSE, "launch owned ping through existing child injection");
    CloseHandle(writer);
    DWORD waited = WaitForSingleObject(child.hProcess, 10000);
    if (waited != WAIT_OBJECT_0) TerminateProcess(child.hProcess, 2);
    Check(waited == WAIT_OBJECT_0, "ping finishes");
    DWORD code; Check(GetExitCodeProcess(child.hProcess, &code) != FALSE && code == 0, "ping succeeds on local reply");
    char output[8192] = {}; DWORD count = 0;
    Check(ReadFile(reader, output, sizeof(output)-1, &count, NULL) != FALSE && count > 0, "read ping output");
    Check(strstr(output, "127.0.0.1") != NULL, "actual ping.exe reports loopback responder");
    CloseHandle(reader); CloseHandle(child.hThread); CloseHandle(child.hProcess);
    puts("PASS owned ping.exe child injected and replied from 127.0.0.1");
}

int main() {
    IsolateTestProcess(); WSADATA ws; Check(WSAStartup(MAKEWORD(2,2), &ws) == 0, "WSAStartup");
    icmpModule = LoadLibraryA("iphlpapi.dll"); Check(icmpModule != NULL, "load ICMP API");
    echoEx = reinterpret_cast<EchoEx>(GetProcAddress(icmpModule, "IcmpSendEcho2Ex"));
    Check(echoEx != NULL, "modern regression host provides Echo2Ex");
    PVOID entries[] = {(PVOID)IcmpSendEcho, (PVOID)IcmpSendEcho2, (PVOID)echoEx, (PVOID)Icmp6SendEcho2};
    BYTE original[4][16]; for (int i=0;i<4;++i) memcpy(original[i], entries[i], 16);
    PingSettings settings; Log log; settings.chain.push_back(Hop(TEXT("NOPROXY"), 0));
    auto proxy = GetGlobalProxyInstance();
    proxy->GetSettingsInstance()->AddInstance(&settings); proxy->GetLogInstance()->AddInstance(&log);
    Check(proxy->EnableProxy() != FALSE, "own host start");
    char pipe[MAX_PATH]; proxy->GetPRCInstance()->GetPRCPipeName(pipe, sizeof(pipe));
    for (int cycle=0;cycle<4;++cycle) {
        settings.block = cycle == 1 || cycle == 2;
        const bool missing = cycle == 2;
        DetourHookBinding lookup = {(PVOID*)&originalGetProcAddress, (PVOID)WithoutEchoEx};
        if (missing) Check(InstallDetourHooks(&lookup, 1) == NO_ERROR, "simulate XP missing Echo2Ex export");
        Check(gp_HookWinsock(pipe) != FALSE, "hook install including missing optional export");
        for (int api=0;api<4;++api) {
            const bool hooked = settings.block && !(missing && api == 2);
            Check((memcmp(original[api], entries[api], 16) != 0) == hooked, "only enabled and available ICMP exports patched");
            if (missing && api == 2) continue;
            for (int async=0;async<(api ? 3 : 1);++async) Probe(api, async, settings.block);
            if (settings.block) Probe(api, 0, true, true, api >= 2);
        }
        if (settings.block) {
            CheckErrors();
            if (!missing) CheckPingProcess();
            std::vector<std::thread> workers;
            for (int n=0;n<4;++n) workers.emplace_back([] { for (int i=0;i<8;++i) Probe(i%2 ? 3 : 1, 2, true); });
            for (auto& worker : workers) worker.join();
        }
        Check(gp_UnhookWinsock() != FALSE, "detach after requests complete");
        for (int api=0;api<4;++api) Check(!memcmp(original[api], entries[api], 16), "ICMP entries restored on detach");
        if (missing) {
            Check(missingExportQueries > 0, "missing export path exercised");
            Check(RemoveDetourHooks(&lookup, 1) == NO_ERROR, "remove test resolver hook");
        }
        printf("PASS Ping cycle %d enabled=%d missing-Echo2Ex=%d\n", cycle, settings.block, missing);
    }
    Check(proxy->DisableProxy() != FALSE, "host stop");
    settings.Detach(); log.Detach(); ReleaseGlobalProxyInstance(); FreeLibrary(icmpModule); WSACleanup();
    puts("PING_HOOK_PASS sync/event/APC/concurrency/errors/FakeIP/optional-export/off-on-off");
}
