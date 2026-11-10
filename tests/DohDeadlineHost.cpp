// Real DNS/TCP and UDP requests share a stalled DoH exchange. No external DNS.
#define PL_DNS_RELAY_HELPERS_ONLY
#include "DnsDohRelayHost.cpp"
#undef PL_DNS_RELAY_HELPERS_ONLY

int main(int argc, char** argv) {
    Check(argc == 4, "arguments: stalled-socks-port bootstrap-list expected-ms");
    IsolateTestProcess();
    WSADATA ws; WSAStartup(MAKEWORD(2,2), &ws);
    RelaySettings settings; RelayLog log;
    settings.chain.push_back(Hop(TEXT("SOCKS5"), (WORD)atoi(argv[1])));
    auto& first = settings.chain.front(); first.dohEnabled = 1;
    strcpy_s(first.dohUrl.szbuf,"https://dns.google/dns-query");
    strcpy_s(first.dohBootstrap.szbuf,argv[2]);
    IGlobalProxy* proxy = GetGlobalProxyInstance();
    proxy->GetSettingsInstance()->AddInstance(&settings); proxy->GetLogInstance()->AddInstance(&log);
    Check(proxy->EnableProxy() != FALSE,"enable deadline host");
    char pipe[MAX_PATH]; proxy->GetPRCInstance()->GetPRCPipeName(pipe,sizeof(pipe));
    Check(gp_HookWinsock(pipe) != FALSE,"install test-owned DNS hook");
    SOCKET tcp=Socket(false), udp=Socket(true); auto target=Target(true);
    Check(connect(tcp,&target,target.Size())==0,"TCP DNS connection");
    const DWORD started=GetTickCount();
    TcpQuery(tcp,0x1100); // Keep the TCP send side open, as interactive nslookup does.
    auto q=Question(0x2200);
    Check(sendto(udp,q.data(),(int)q.size(),0,&target,target.Size())==q.size(),"UDP DNS query");
    TcpReply(tcp,0x1100,true);
    char reply[65536]; int received=recv(udp,reply,sizeof(reply),0);
    CheckReply(reply,received,0x2200,true);
    const DWORD elapsed=GetTickCount()-started;
    const DWORD expected=(DWORD)atoi(argv[3]);
    Check(elapsed>=expected-1000 && elapsed<=expected+5000,"deadline yields SERVFAIL on both transports");
    closesocket(tcp); closesocket(udp);
    Check(gp_UnhookWinsock()!=FALSE,"unhook deadline host");
    Check(proxy->DisableProxy()!=FALSE,"stop deadline host");
    settings.Detach(); log.Detach(); ReleaseGlobalProxyInstance(); WSACleanup();
    printf("DEADLINE_PASS %lu ms\n",elapsed);
    return 0;
}
