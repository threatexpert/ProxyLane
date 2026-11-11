// Actual Winsock hooks and local SOCKS5 echo: API returns, packet counts and
// policy precedence. No external destination is contacted by the fixture.
#define PL_DNS_RELAY_HELPERS_ONLY
#include "DnsDohRelayHost.cpp"
#undef PL_DNS_RELAY_HELPERS_ONLY

class SendSettings : public Settings {
public:
    std::string mode;
    BOOL GetProxySettings(LPProxySettingsInfo p) override {
        ZeroMemory(p, sizeof(*p));
        p->bHookUDP = mode != "doh-local";
        p->nDNSOption = mode.find("doh") == 0 ? PSI_DNSOPT_DOH : PSI_DNSOPT_REMOTE;
        p->bBlockUDP = mode == "blocked" || mode == "doh-blocked";
        p->bBlockIPv6 = mode == "ipv6-blocked";
        p->bDisableMDNS = mode == "mdns-blocked";
        return TRUE;
    }
};

static void CheckFakeDns() {
    const char* name = "udp-send-hook.invalid";
    auto host = gethostbyname(name);
    Check(host && host->h_addrtype == AF_INET && host->h_length == 4, "fake hostent");
    DWORD ip = 0; memcpy(&ip, host->h_addr_list[0], sizeof(ip));
    Check((ntohl(ip) >> 16) == 0x7fff, "gethostbyname still returns FakeIP");
    HWND window = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
    Check(window != NULL, "DNS completion window");
    char buffer[MAXGETHOSTSTRUCT] = {};
    const UINT message = WM_APP + 51;
    HANDLE request = WSAAsyncGetHostByName(window, message, name, buffer, sizeof(buffer));
    Check(request != NULL, "async fake DNS handle");
    MSG result = {};
    Check(PeekMessage(&result, window, message, message, PM_REMOVE) &&
        result.wParam == (WPARAM)request && WSAGETASYNCERROR(result.lParam) == 0, "async fake DNS notification");
    auto answer = reinterpret_cast<hostent*>(buffer);
    Check(answer->h_addrtype == AF_INET && answer->h_length == 4 &&
        !memcmp(answer->h_addr_list[0], &ip, sizeof(ip)), "async and sync FakeIP agree");
    DestroyWindow(window);
}

static int SendError(int variant, const _SockAddr& target) {
    SOCKET s = Socket(true);
    char byte = 'x';
    WSASetLastError(0);
    int result = sendto(s, &byte, variant == 0 ? -1 : 1,
        variant == 1 ? MSG_OOB : 0, &target, variant == 2 ? 1 : target.Size());
    int error = WSAGetLastError();
    closesocket(s);
    Check(result == SOCKET_ERROR, "native sendto rejects invalid arguments");
    return error;
}

static void CheckEcho(const _SockAddr& target) {
    for (int api = 0; api < 10; ++api) {
        SOCKET s = Socket(true);
        DWORD timeout = 3000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        const bool connected = api >= 3 && api <= 7;
        if (connected) Check(connect(s, &target, target.Size()) == 0, "UDP connect");
        GUID id = WSAID_WSASENDMSG; LPFN_WSASENDMSG sendMessage = NULL; DWORD returned = 0;
        Check(WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &sendMessage,
            sizeof(sendMessage), &returned, NULL, NULL) == 0, "sendmsg lookup");
        for (int seq = 0; seq < 11; ++seq) {
            char data[32]; sprintf_s(data, "packet-%d-%d", api, seq);
            DWORD length = seq == 10 ? 0 : (DWORD)strlen(data); // Empty datagrams must also arrive once.
            WSABUF buffers[] = {{length / 2, data}, {length - length / 2, data + length / 2}};
            DWORD sent = 0;
            const sockaddr* destination = connected ? NULL : &target;
            const int destinationLength = connected ? 0 : target.Size();
            WSAMSG message = {}; message.name = (sockaddr*)destination; message.namelen = destinationLength;
            message.lpBuffers = buffers; message.dwBufferCount = 2;
            WSAOVERLAPPED overlapped = {};
            if (api >= 8) { overlapped.hEvent = WSACreateEvent(); Check(overlapped.hEvent != WSA_INVALID_EVENT, "send event"); }
            int result = SOCKET_ERROR;
            if (api == 0 || api == 5) {
                result = sendto(s, data, length, 0, destination, destinationLength);
                Check(result == (int)length, "sendto returns bytes");
            }
            if (api == 1 || api == 6 || api == 8)
                result = WSASendTo(s, buffers, 2, &sent, 0, destination, destinationLength, api >= 8 ? &overlapped : NULL, NULL);
            if (api == 2 || api == 7 || api == 9)
                result = sendMessage(s, &message, 0, &sent, api >= 8 ? &overlapped : NULL, NULL);
            if (api == 3) { result = send(s, data, length, 0); Check(result == (int)length, "send returns bytes"); }
            if (api == 4) result = WSASend(s, buffers, 2, &sent, 0, NULL, NULL);
            if (api >= 8) {
                Check(result == 0 || (result == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING), "overlapped send");
                Check(WSAWaitForMultipleEvents(1, &overlapped.hEvent, TRUE, 3000, FALSE) == WSA_WAIT_EVENT_0, "send completion event");
                DWORD flags = 0;
                Check(WSAGetOverlappedResult(s, &overlapped, &sent, FALSE, &flags) != FALSE && sent == length, "completed byte count");
                WSACloseEvent(overlapped.hEvent);
            } else if (api != 0 && api != 3 && api != 5)
                Check(result == 0 && sent == length, "WSA send status and byte count");
            char reply[128]; int received = recv(s, reply, sizeof(reply), 0);
            Check(received == (int)length && !memcmp(reply, data, length), "exact echo ID and length");
        }
        // Also exercise nonblocking sends on a cached, writable route.
        u_long nonblocking = 1; Check(ioctlsocket(s, FIONBIO, &nonblocking) == 0, "nonblocking mode");
        Check(sendto(s, "n", 1, 0, connected ? NULL : &target, connected ? 0 : target.Size()) == 1, "nonblocking sendto");
        nonblocking = 0; ioctlsocket(s, FIONBIO, &nonblocking);
        char byte; Check(recv(s, &byte, 1, 0) == 1 && byte == 'n', "nonblocking packet received");
        timeout = 200; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        char extra[128];
        Check(recv(s, extra, sizeof(extra), 0) == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT, "no duplicate echo");
        closesocket(s);
        printf("PASS API %d: scatter/gather, empty packet, cached route, no duplicates\n", api);
    }
}

int main(int argc, char** argv) {
    Check(argc == 3, "arguments: socks-port mode");
    IsolateTestProcess(); WSADATA ws; WSAStartup(MAKEWORD(2, 2), &ws);
    _SockAddr target = {}; target.SetIP("192.0.2.10"); target.SetPort(9999);
    _SockAddr local = {}; local.SetIP("127.0.0.1"); local.SetPort(9999);
    int nativeErrors[3]; for (int i = 0; i < 3; ++i) nativeErrors[i] = SendError(i, local);
    SendSettings settings; settings.mode = argv[2]; Log log;
    settings.chain.push_back(Hop(TEXT("SOCKS5"), (WORD)atoi(argv[1])));
    if (settings.mode.find("doh") == 0) {
        settings.chain[0].dohEnabled = 1;
        strcpy_s(settings.chain[0].dohUrl.szbuf, "https://dns.google/dns-query");
        strcpy_s(settings.chain[0].dohBootstrap.szbuf, "8.8.8.8");
        target.SetIP("192.168.99.1"); target.SetPort(53);
    }
    auto proxy = GetGlobalProxyInstance();
    proxy->GetSettingsInstance()->AddInstance(&settings); proxy->GetLogInstance()->AddInstance(&log);
    Check(proxy->EnableProxy() != FALSE, "host start");
    char pipe[MAX_PATH]; proxy->GetPRCInstance()->GetPRCPipeName(pipe, sizeof(pipe));
    Check(gp_HookWinsock(pipe) != FALSE, "own hook installation");
    if (settings.mode == "normal") {
        CheckFakeDns();
        for (int i = 0; i < 3; ++i) Check(SendError(i, target) == nativeErrors[i], "sendto retains native argument errors");
        CheckEcho(target);
    } else if (settings.mode == "doh-local") {
        queryName = "1.99.168.192.in-addr.arpa";
        for (int api = 0; api < 2; ++api) {
            SOCKET s = Socket(true); auto q = Question(0x4400 + api, 12);
            WSABUF buffer = {(ULONG)q.size(), q.data()}; DWORD sent = 0;
            Check(api == 0 ? sendto(s, q.data(), (int)q.size(), 0, &target, target.Size()) == q.size() :
                WSASendTo(s, &buffer, 1, &sent, 0, &target, target.Size(), NULL, NULL) == 0 && sent == q.size(), "DoH DNS send");
            char reply[512]; _SockAddr source = {}; int size = sizeof(source);
            int n = recvfrom(s, reply, sizeof(reply), 0, &source, &size);
            Check(n >= 12 && (reply[3] & 15) == 5, "DoH local private PTR refusal");
            Check(source.IsLoopback() && !(source == target), "actual UDP relay source is preserved");
            closesocket(s);
        }
    } else {
        int expected = WSAEACCES;
        if (settings.mode == "ipv6-blocked") { target.SetIP("2001:db8::10"); expected = WSAEAFNOSUPPORT; }
        if (settings.mode == "mdns-blocked") { target.SetIP("224.0.0.251"); target.SetPort(5353); expected = WSAEHOSTUNREACH; }
        SOCKET s = socket(target.sa_family, SOCK_DGRAM, 0);
        char byte = 'x'; WSABUF buffer = {1, &byte}; DWORD sent = 0;
        Check(sendto(s, &byte, 1, 0, &target, target.Size()) == SOCKET_ERROR && WSAGetLastError() == expected, "sendto policy");
        Check(WSASendTo(s, &buffer, 1, &sent, 0, &target, target.Size(), NULL, NULL) == SOCKET_ERROR && WSAGetLastError() == expected, "WSASendTo policy");
        Check(sendto(s, &byte, -1, 0, &target, target.Size()) == SOCKET_ERROR && WSAGetLastError() == expected, "policy still precedes negative length");
        closesocket(s);
    }
    Check(gp_UnhookWinsock() != FALSE, "unhook");
    Check(proxy->DisableProxy() != FALSE, "host stop");
    settings.Detach(); log.Detach(); ReleaseGlobalProxyInstance(); WSACleanup();
    printf("UDP_SEND_HOOK_PASS %s\n", argv[2]);
}
