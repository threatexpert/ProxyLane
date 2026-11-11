// Exercise the production socket/layer code with observable bypass entry points.
#include "stdafx.h"
#include "asynsocket/AsyncSocketExLayer.h"
#include <stdio.h>

static int connects, resolves;
static _SockAddr lastDestination;
static void Check(bool ok, const char* message)
{
    if (!ok) { printf("FAIL %s (WSA %d)\n", message, WSAGetLastError()); exit(1); }
}

int WSAAPI Bypass_connect(SOCKET, const sockaddr* address, int length)
{
    ++connects;
    Check(lastDestination.Set(address, length) != FALSE, "capture destination");
    WSASetLastError(WSAEWOULDBLOCK);
    return SOCKET_ERROR;
}
HANDLE WSAAPI Bypass_WSAAsyncGetHostByName(HWND window, unsigned int message,
    const char* name, char* buffer, int length)
{
    ++resolves;
    return WSAAsyncGetHostByName(window, message, name, buffer, length);
}
hostent* WSAAPI Bypass_gethostbyname(const char* name) { return gethostbyname(name); }
int WSAAPI Bypass_sendto(SOCKET s, const char* b, int n, int f, const sockaddr* a, int l)
{ return sendto(s, b, n, f, a, l); }
int WSAAPI Bypass_WSASendTo(SOCKET s, LPWSABUF b, DWORD n, LPDWORD sent, DWORD f,
    const sockaddr* a, int l, LPWSAOVERLAPPED o, LPWSAOVERLAPPED_COMPLETION_ROUTINE c)
{ return WSASendTo(s, b, n, sent, f, a, l, o, c); }

class Layer : public CAsyncSocketExLayer { public: Layer() {} ~Layer() {} };

static void Pump()
{
    MSG message;
    while (PeekMessage(&message, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&message);
        DispatchMessage(&message);
    }
}

static void AddressIsReadOnly(const char* ip)
{
    Layer layer;
    CAsyncSocketEx socket;
    Check(socket.AddLayer(&layer) != FALSE, "add layer");
    _SockAddr expected = {};
    Check(expected.SetIP(ip) != FALSE, "parse IP");
    expected.SetPort(443);
    if (expected.IsIPv4())
        memset(reinterpret_cast<sockaddr_in*>(&expected)->sin_zero, 0xa5, 8);
    else {
        reinterpret_cast<sockaddr_in6*>(&expected)->sin6_flowinfo = 0x12345678;
        reinterpret_cast<sockaddr_in6*>(&expected)->sin6_scope_id = 7;
    }
    Check(socket.Create(0, SOCK_STREAM, FD_CONNECT, NULL, FALSE, expected.sa_family) != FALSE,
        "create socket");
    void* page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Check(page != NULL, "allocate address");
    memcpy(page, &expected, sizeof(expected));
    DWORD oldProtection;
    Check(VirtualProtect(page, 4096, PAGE_READONLY, &oldProtection) != FALSE, "readonly address");
    connects = 0;
    socket.Connect(static_cast<const SOCKADDR*>(page), expected.Size());
    Check(connects == 1 && memcmp(&lastDestination, &expected, sizeof(expected)) == 0,
        "address, port, padding, flow and scope unchanged");
    Check(memcmp(page, &expected, sizeof(expected)) == 0, "caller address unchanged");
    socket.Close();
    VirtualFree(page, 0, MEM_RELEASE);
    printf("PASS readonly %s\n", ip);
}

static void NameTransport(bool asynchronous, bool bypass)
{
    SOCKET listener = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in local = {};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Check(bind(listener, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0 &&
        listen(listener, 1) == 0, "local listener");
    int size = sizeof(local);
    Check(getsockname(listener, reinterpret_cast<sockaddr*>(&local), &size) == 0, "listener port");
    Layer layer;
    CAsyncSocketEx socket;
    Check(socket.AddLayer(&layer) != FALSE && socket.Create() != FALSE, "name socket");
    layer.BypassHook(bypass);
    connects = resolves = 0;
    socket.Connect(asynchronous ? "localhost" : "127.0.0.1", ntohs(local.sin_port));
    // The in-flight request must retain its selected transport even if the
    // layer policy changes before the DNS completion message is dispatched.
    layer.BypassHook(!bypass);
    bool ready = false;
    DWORD started = GetTickCount();
    while (GetTickCount() - started < 3000) {
        Pump();
        fd_set readable;
        FD_ZERO(&readable); FD_SET(listener, &readable);
        timeval timeout = {};
        ready = select(0, &readable, NULL, NULL, &timeout) > 0;
        if (bypass ? connects > 0 : ready) break;
        Sleep(1);
    }
    if (bypass) {
        Check(connects == 1 && resolves == (asynchronous ? 1 : 0) && !ready,
            "bypass retained for resolution and connection");
        Check(lastDestination.GetdwIP() == htonl(INADDR_LOOPBACK) &&
            lastDestination.GetPort() == ntohs(local.sin_port), "resolved endpoint");
    } else {
        Check(connects == 0 && resolves == 0 && ready, "ordinary Winsock retained");
        SOCKET accepted = accept(listener, NULL, NULL);
        Check(accepted != INVALID_SOCKET, "ordinary connection accepted");
        closesocket(accepted);
    }
    socket.Close();
    closesocket(listener);
    Pump();
    printf("PASS %s bypass=%d\n", asynchronous ? "async hostname" : "numeric hostname", bypass);
}

int main()
{
    WSADATA data;
    Check(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Winsock");
    AddressIsReadOnly("192.0.2.10");
    AddressIsReadOnly("240e:ff:e020:99b:0:ff:b099:cff1");
    AddressIsReadOnly("2001:db8:1234:5678:9abc:def0:1234:5678");
    for (int bypass = 0; bypass <= 1; ++bypass) {
        NameTransport(false, bypass != 0);
        NameTransport(true, bypass != 0);
    }
    WSACleanup();
    return 0;
}
