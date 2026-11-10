// Real Winsock interception + PRC + DoH transport. The test owns its hook and host.
#define main ExistingProxyChainMain
#include "ProxyChainTransportTests.cpp"
#undef main
#include <mswsock.h>
#include <tlhelp32.h>

#include "IsolateProxyTestProcess.h"

class RelaySettings : public Settings {
public:
    bool block = false;
    BOOL GetProxySettings(LPProxySettingsInfo settings) override {
        ZeroMemory(settings, sizeof(*settings));
        settings->nDNSOption = PSI_DNSOPT_DOH;
        // Exercise DNS interception independently of ordinary TCP/UDP proxying.
        settings->bHookTCP = FALSE; settings->bHookUDP = FALSE;
        settings->bBlockUDP = block;
        return TRUE;
    }
};
class RelayLog : public Log {
public:
    LONG udpRegistrations = 0, dnsQueries = 0;
    void LogText(LPCWSTR text) override {
        if (wcsstr(text, L"intercepted; waiting for DNS datagram")) InterlockedIncrement(&udpRegistrations);
        if (wcsstr(text, L"query received; resolving via proxy")) InterlockedIncrement(&dnsQueries);
        fwprintf(stderr, L"%s", text);
    }
};
static std::string queryName = "example.org";
static std::vector<char> Question(unsigned id, unsigned type = 1) {
    std::vector<char> q = {char(id>>8),char(id),1,0,0,1,0,0,0,0,0,0};
    for (size_t pos=0;pos<queryName.size();) {
        size_t end=queryName.find('.',pos); if(end==std::string::npos)end=queryName.size();
        Check(end>pos && end-pos<=63,"valid fixture DNS label");
        q.push_back(char(end-pos)); q.insert(q.end(),queryName.begin()+pos,queryName.begin()+end); pos=end+1;
    }
    q.insert(q.end(),{0,0,char(type),0,1});
    return q;
}
static SOCKET Socket(bool udp) {
    SOCKET s = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    Check(s != INVALID_SOCKET, "socket");
    DWORD timeout = 65000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    return s;
}
static _SockAddr Target(bool privateIp) {
    _SockAddr t = {}; t.SetIP(privateIp ? "192.168.99.1" : "192.0.2.53"); t.SetPort(53); return t;
}
static void CheckReply(const char* data, int size, unsigned id, bool failure, bool requireAnswer = true) {
    Check(size >= 12 && (unsigned char)data[0] == (id >> 8) && (unsigned char)data[1] == (id & 255), "DNS response ID");
    Check((data[2] & 0x80) != 0, "DNS response flag");
    Check((data[3] & 15) == (failure ? 2 : 0), "DNS response code");
    if (!failure && requireAnswer) Check((unsigned char)data[6] || (unsigned char)data[7], "DNS answer records");
}
static void TcpQuery(SOCKET s, unsigned id) {
    auto q = Question(id); char prefix[] = {char(q.size()>>8),char(q.size())};
    // Deliberately split the TCP length field and packet.
    Check(send(s, prefix, 1, 0) == 1, "TCP first length byte");
    Check(send(s, prefix+1, 1, 0) == 1, "TCP second length byte");
    Check(send(s, q.data(), (int)q.size(), 0) == q.size(), "TCP DNS body");
}
static void TcpReply(SOCKET s, unsigned id, bool failure) {
    unsigned char prefix[2]; Check(RecvAll(s, prefix, 2), "TCP DNS response prefix");
    std::vector<char> body((prefix[0]<<8)|prefix[1]);
    Check(RecvAll(s, body.data(), (int)body.size()), "TCP DNS response body");
    CheckReply(body.data(), (int)body.size(), id, failure);
}
static void PtrQuery(bool udp, bool privateIp, bool failure) {
    const unsigned id = 0x7800 + (udp ? 1 : 0) + (privateIp ? 2 : 0);
    std::vector<char> q = {char(id>>8),char(id),1,0,0,1,0,0,0,0,0,0};
    std::string name = privateIp ? "182.88.16.172.in-addr.arpa" : "8.8.8.8.in-addr.arpa";
    for (size_t pos=0;pos<name.size();) {
        size_t end=name.find('.',pos); if(end==std::string::npos)end=name.size();
        q.push_back((char)(end-pos)); q.insert(q.end(),name.begin()+pos,name.begin()+end); pos=end+1;
    }
    q.insert(q.end(),{0,0,12,0,1});
    SOCKET s=Socket(udp); auto target=Target(true);
    Check(connect(s,&target,target.Size())==0,"PTR connection");
    std::vector<char> packet=q;
    if(!udp) { packet.insert(packet.begin(),{char(q.size()>>8),char(q.size())}); }
    Check(send(s,packet.data(),(int)packet.size(),0)==packet.size(),"PTR query send");
    std::vector<char> reply(65536); int count;
    if(udp) count=recv(s,reply.data(),(int)reply.size(),0);
    else {
        unsigned char prefix[2]; Check(RecvAll(s,prefix,2),"PTR TCP response prefix");
        count=(prefix[0]<<8)|prefix[1]; Check(RecvAll(s,reply.data(),count),"PTR TCP response body");
    }
    Check(count>=12 && (unsigned char)reply[0]==(id>>8) && (unsigned char)reply[1]==(id&255),"PTR reply ID");
    Check((reply[2]&0x80)!=0 && (reply[3]&15)==(privateIp?5:failure?2:0),"private PTR REFUSED; public PTR follows DoH");
    if(privateIp) {
        Check(count==q.size() && std::equal(q.begin()+12,q.end(),reply.begin()+12),"local REFUSED preserves question");
        for(int i=6;i<12;++i)Check(reply[i]==0,"local REFUSED contains no records");
    }
    closesocket(s);
}

static void UdpQuery(int api, bool privateIp, bool blocked, bool failure, unsigned type = 1) {
    printf("UDP API %d blocked=%d\n", api, blocked); fflush(stdout);
    SOCKET s = Socket(true); auto target = Target(privateIp); auto q = Question(0x3400+api, type);
    WSABUF buffer = {(ULONG)q.size(),q.data()}; DWORD sent = 0; int result = SOCKET_ERROR;
    if (api < 2) {
        result = api == 0 ? connect(s, &target, target.Size()) : WSAConnect(s, &target, target.Size(), NULL,NULL,NULL,NULL);
        if (!blocked) {
            Check(result == 0, "UDP connect redirected");
            _SockAddr peer = {}; int size = sizeof(peer);
            Check(getpeername(s, &peer, &size) == 0 && peer.IsLoopback() && !(peer == target), "UDP DNS getpeername exposes actual local relay");
            result = send(s, q.data(), (int)q.size(), 0);
        }
    } else if (api == 2) result = sendto(s, q.data(), (int)q.size(), 0, &target, target.Size());
    else if (api == 3) result = WSASendTo(s, &buffer, 1, &sent, 0, &target, target.Size(), NULL, NULL);
    else {
        GUID id = WSAID_WSASENDMSG; LPFN_WSASENDMSG fn = NULL; DWORD returned = 0;
        Check(WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &fn, sizeof(fn), &returned, NULL, NULL) == 0, "WSASendMsg lookup");
        WSAMSG message = {}; message.name = &target; message.namelen = target.Size(); message.lpBuffers = &buffer; message.dwBufferCount = 1;
        result = fn(s, &message, 0, &sent, NULL, NULL);
    }
    if (blocked) Check(result == SOCKET_ERROR && WSAGetLastError() == WSAEACCES, "UDP block has priority over DNS");
    else {
        Check(result != SOCKET_ERROR, "UDP DNS send accepted without proxy-UDP setting");
        char reply[65536]; int count;
        if (api < 2) count = recv(s, reply, sizeof(reply), 0);
        else {
            SOCKADDR_STORAGE source = {}; int sourceSize = sizeof(source);
            if (api == 2) count = recvfrom(s, reply, sizeof(reply), 0, (SOCKADDR*)&source, &sourceSize);
            else {
                WSABUF output = {sizeof(reply), reply}; DWORD flags = 0, bytes = 0;
                OVERLAPPED ov = {}; ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
                HANDLE port = api == 3 ? CreateIoCompletionPort((HANDLE)s, NULL, 7, 1) : NULL;
                int r;
                if (api == 3) r = WSARecvFrom(s, &output, 1, &bytes, &flags, (SOCKADDR*)&source, &sourceSize, &ov, NULL);
                else {
                    GUID id = WSAID_WSARECVMSG; LPFN_WSARECVMSG receive = NULL; DWORD returned = 0;
                    Check(WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &receive, sizeof(receive), &returned, NULL, NULL) == 0, "WSARecvMsg lookup");
                    WSAMSG message = {}; message.name = (SOCKADDR*)&source; message.namelen = sourceSize;
                    message.lpBuffers = &output; message.dwBufferCount = 1;
                    r = receive(s, &message, &bytes, &ov, NULL);
                    Check(r == 0 || WSAGetLastError() == WSA_IO_PENDING, "WSARecvMsg pending");
                    Check(WSAGetOverlappedResult(s, &ov, &bytes, TRUE, &flags) != FALSE, "WSARecvMsg completion");
                    sourceSize = message.namelen;
                }
                if (api == 3) {
                    Check(r == 0 || WSAGetLastError() == WSA_IO_PENDING, "WSARecvFrom pending");
                    ULONG_PTR key = 0; LPOVERLAPPED completed = NULL;
                    Check(GetQueuedCompletionStatus(port, &bytes, &key, &completed, 65000) && completed == &ov && key == 7, "DNS IOCP completion");
                }
                count = (int)bytes;
                if (port) CloseHandle(port); CloseHandle(ov.hEvent);
            }
            Check(count >= 12, "UDP DNS reply must arrive (no skipped response checks)");
            _SockAddr actual = {}; actual.Set((SOCKADDR*)&source, sourceSize);
            Check(actual.IsLoopback() && !(actual == target), "DNS reply exposes actual local relay source without rewriting");
        }
        // Arbitrary live domains need not publish AAAA records. NOERROR with
        // no answers is valid; retain the positive-answer check for default data.
        CheckReply(reply, count, 0x3400+api, failure, type != 28 || queryName == "example.org");
    }
    closesocket(s);
}
#ifndef PL_DNS_RELAY_HELPERS_ONLY
int main(int argc, char** argv) {
    Check(argc >= 5, "arguments: socks-port http-port url bootstrap [failure]");
    IsolateTestProcess();
    WSADATA ws; WSAStartup(MAKEWORD(2,2), &ws);
    RelaySettings settings; RelayLog log;
    settings.chain.push_back(Hop(atoi(argv[1]) ? TEXT("SOCKS5") : TEXT("HTTP"), (WORD)atoi(argv[atoi(argv[1]) ? 1 : 2])));
    if (atoi(argv[1]) && atoi(argv[2])) settings.chain.push_back(Hop(TEXT("HTTP"), (WORD)atoi(argv[2])));
    auto& first = settings.chain.front(); first.dohEnabled = 1;
    strcpy_s(first.dohUrl.szbuf, argv[3]); strcpy_s(first.dohBootstrap.szbuf, argv[4]);
    bool failure = false;
    for (int i=5;i<argc;++i) {
        if (strcmp(argv[i],"failure")==0) failure=true;
        else if (strncmp(argv[i],"name=",5)==0) queryName=argv[i]+5;
        else Check(false,"unknown DNS fixture argument");
    }
    IGlobalProxy* proxy = GetGlobalProxyInstance();
    proxy->GetSettingsInstance()->AddInstance(&settings); proxy->GetLogInstance()->AddInstance(&log);
    Check(proxy->EnableProxy() != FALSE, "enable DNS DoH host");
    char pipe[MAX_PATH]; proxy->GetPRCInstance()->GetPRCPipeName(pipe, sizeof(pipe));
    Check(gp_HookWinsock(pipe) != FALSE, "install test-owned hook");
    // Must work even for the deliberately broken DoH endpoint, without
    // adding any upstream request. Public PTR still uses the selected DoH.
    PtrQuery(true, true, failure); PtrQuery(false, true, failure);
    PtrQuery(false, false, failure);
    std::vector<SOCKET> clients;
    for (unsigned i=0;i<6;++i) {
        SOCKET s = Socket(false); auto target = Target(i%2 != 0);
        Check(connect(s, &target, target.Size()) == 0, "TCP DNS connect");
        TcpQuery(s, 0x1200+i); clients.push_back(s);
    }
    for (unsigned i=0;i<clients.size();++i) { TcpReply(clients[i], 0x1200+i, failure); closesocket(clients[i]); }
    if (!failure) {
        // A single burst exceeds the 32-request processing limit. Cached replies
        // and the buffered tail must drain through notifications, including EOF.
        SOCKET burst = Socket(false); auto target = Target(true);
        Check(connect(burst, &target, target.Size()) == 0, "TCP burst connect");
        std::vector<char> packets;
        for (unsigned i=0;i<80;++i) {
            auto q = Question(0x5000+i);
            packets.push_back(char(q.size()>>8)); packets.push_back(char(q.size()));
            packets.insert(packets.end(),q.begin(),q.end());
        }
        Check(send(burst,packets.data(),(int)packets.size(),0)==packets.size(),"TCP DNS burst send");
        Check(shutdown(burst,SD_SEND)==0,"TCP DNS burst EOF");
        for (unsigned i=0;i<80;++i) TcpReply(burst,0x5000+i,false);
        closesocket(burst);
    }
    // A fresh UDP-only AAAA query must complete without an upstream UDP socket.
    UdpQuery(2, true, false, failure, 28);
    // Cached requests share across TCP and UDP, original resolver IPs and IDs.
    for (int api=0;api<5;++api) UdpQuery(api, api%2 != 0, false, failure);
    Check(gp_UnhookWinsock() != FALSE, "unhook before settings change");
    settings.block = true;
    Check(gp_HookWinsock(pipe) != FALSE, "install UDP-blocked snapshot");
    for (int api=0;api<5;++api) UdpQuery(api, api%2 != 0, true, failure);
    SOCKET tcp = Socket(false); auto target = Target(true);
    Check(connect(tcp, &target, target.Size()) == 0, "TCP DNS works when UDP blocked");
    TcpQuery(tcp, 0x4567); TcpQuery(tcp, 0x4568);
    Check(shutdown(tcp, SD_SEND) == 0, "TCP DNS half-close");
    TcpReply(tcp, 0x4567, failure); TcpReply(tcp, 0x4568, failure); closesocket(tcp);
    tcp = Socket(false); Check(connect(tcp, &target, target.Size()) == 0, "malformed-query TCP connect");
    char malformed[14] = {0,12,0x12,0x34,1,0}; // DNS header with no question.
    Check(send(tcp, malformed, sizeof(malformed), 0) == sizeof(malformed), "malformed DNS send");
    unsigned char errorReply[14]; Check(RecvAll(tcp, errorReply, sizeof(errorReply)), "malformed DNS response");
    Check(errorReply[0] == 0 && errorReply[1] == 12 && errorReply[2] == 0x12 && errorReply[3] == 0x34 && (errorReply[5] & 15) == 1, "malformed DNS FORMERR without upstream query");
    closesocket(tcp);
    Check(log.udpRegistrations >= 5, "UDP DNS interception is logged before a reply is available");
    Check(log.dnsQueries >= 6, "DNS query receipt is logged before completion");
    Check(gp_UnhookWinsock() != FALSE, "unhook test");
    Check(proxy->DisableProxy() != FALSE, "stop test host");
    settings.Detach(); log.Detach(); ReleaseGlobalProxyInstance(); WSACleanup();
    puts("DNS_RELAY_PASS"); return 0;
}

#endif
