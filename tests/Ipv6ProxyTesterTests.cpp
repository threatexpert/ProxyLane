#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "../src/ProxyLaneHook/ProxyModule.h"

static void Check(bool value, const char* message)
{
    if (!value) { printf("FAIL %s (WSA %d)\n", message, WSAGetLastError()); exit(1); }
}

class Callback : public IProxyTesterCallback
{
public:
    int result = -1;
    void OnProxyTesterCallback(IProxyTester*, int code, WPARAM, LPARAM) override
    {
        if (HIWORD(code) == LAYERCALLBACK_LAYERSPECIFIC) result = LOWORD(code);
    }
};

static void Run(IGlobalProxy* proxy, bool ipv6, bool refused, bool hostname)
{
    SOCKET listener = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    _SockAddr address = {};
    address.SetIP(ipv6 ? "::1" : "127.0.0.1");
    Check(bind(listener, &address, address.Size()) == 0, "bind listener");
    if (!refused) Check(listen(listener, 1) == 0, "listen");
    int length = sizeof(address);
    Check(getsockname(listener, &address, &length) == 0, "listener address");
    PRCClient client = {};
    client.sType = SOCK_STREAM;
    client.dstAddr = address;
    if (hostname) {
        strcpy_s(client.szDomainName, "localhost");
        client.dstAddr.SetIP("fd00::1"); // Identity token must not select the family.
    }
    ProxyInfo settings = {};
    settings.strProxyType = TEXT("NOPROXY");
    Callback callback;
    IProxyTester* tester = proxy->CreateTester();
    Check(tester != NULL, "create tester");
    if (!tester->Start(&callback, &client, &settings))
        callback.result = WSAGetLastError();
    DWORD started = GetTickCount();
    while (callback.result == -1 && GetTickCount() - started < 5000) {
        MSG message;
        while (PeekMessage(&message, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessage(&message);
        }
        Sleep(1);
    }
    Check(callback.result == (refused ? WSAECONNREFUSED : 0), "tester connection result");
    if (!refused) {
        fd_set readable;
        FD_ZERO(&readable); FD_SET(listener, &readable);
        timeval timeout = { 1, 0 };
        Check(select(0, &readable, NULL, NULL, &timeout) == 1, "real connection reached listener");
        SOCKET accepted = accept(listener, NULL, NULL);
        Check(accepted != INVALID_SOCKET, "accept real connection");
        closesocket(accepted);
    }
    tester->Release();
    closesocket(listener);
    printf("PASS NOPROXY %s hostname=%d refused=%d result=%d\n",
        ipv6 ? "IPv6" : "IPv4", hostname, refused, callback.result);
}

int main()
{
    WSADATA data;
    Check(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Winsock");
    IGlobalProxy* proxy = GetGlobalProxyInstance();
    Check(proxy != NULL, "global proxy");
    Run(proxy, false, false, false);
    Run(proxy, true, false, false);
    Run(proxy, true, true, false);
    Run(proxy, false, false, true);
    ReleaseGlobalProxyInstance();
    WSACleanup();
    return 0;
}
