// Test-only host: the child uses the shipping Hook UDP/DNS route. No GUI/profile edits.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include "../../src/ProxyLaneHook/ProxyModule.h"

class Settings : public IProxySettings {
public:
    int port;
    const wchar_t* type;
    BOOL GetProxySettings(LPProxySettingsInfo s) {
        ZeroMemory(s,sizeof(*s)); s->bHookUDP=TRUE; s->bHookLanIP=TRUE;
        s->nDNSOption=PSI_DNSOPT_REMOTE; return TRUE;
    }
    BOOL GetProxyInfo(const LPPRCClient, LPProxyInfo p) {
        ZeroMemory(p,sizeof(*p)); p->strProxyType=type;
        p->strProxyHost=L"127.0.0.1"; p->nProxyPort=port; return TRUE;
    }
};
class Log : public IProxyLog {
public:
    void LogText(LPCWSTR text) { fwprintf(stderr,L"%s",text); }
    void LogNewProxyTask(const LPPRCClient c) { fprintf(stderr,"ROUTE pid=%lu generation=%I64u birth=%I64u\n",c->dwPid,c->socketGeneration,c->processCreateTime); }
    BOOL ShouldInjectNewProcess(LPHookNewProcessInfo) { return FALSE; }
    void OnHookWsock(LPHookWSockResult r) { fprintf(stderr,"HOOK pid=%lu error=%lu\n",r->dwProcessId,r->err); }
    void OnHookLogtext(LPHookLogtext r) { fwprintf(stderr,L"%s\n",r->str); }
    void OnChildInjectionResult(LPHookNewProcessInfo,BOOL) {}
    void OnConnectionEvent(ConnectionEvent e,const LPPRCClient c,LPCWSTR) { fprintf(stderr,"EVENT pid=%lu kind=%d\n",c->dwPid,e); }
    void OnConnectionFailure(const LPPRCClient c,LPCWSTR,ConnectionStage s,DWORD e) { fprintf(stderr,"FAIL pid=%lu stage=%d error=%lu\n",c->dwPid,s,e); }
};
int wmain(int argc,wchar_t** argv) {
    if(argc!=4) return 2; // proxy type, port, complete child command line
    gp_UnhookWinsock();
    WSADATA wsa; if(WSAStartup(MAKEWORD(2,2),&wsa)) return 3;
    auto proxy=GetGlobalProxyInstance(); Settings settings; Log log;
    settings.type=argv[1]; settings.port=_wtoi(argv[2]);
    proxy->GetSettingsInstance()->AddInstance(&settings);
    proxy->GetLogInstance()->AddInstance(&log);
    if(!proxy->EnableProxy()) return 4;
    char pipe[MAX_PATH]={}; if(!proxy->GetPRCInstance()->GetPRCPipeName(pipe,sizeof(pipe))) return 5;
    STARTUPINFOW si={sizeof(si)}; PROCESS_INFORMATION pi={};
    si.dwFlags=STARTF_USESTDHANDLES; si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE); si.hStdError=GetStdHandle(STD_ERROR_HANDLE);
    std::wstring cmd=argv[3];
    if(!CreateProcessW(NULL,&cmd[0],NULL,NULL,TRUE,CREATE_SUSPENDED|CREATE_NO_WINDOW,NULL,NULL,&si,&pi)) return 6;
    HANDLE job=CreateJobObjectW(NULL,NULL); JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={};
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if(!job || !SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)) || !AssignProcessToJobObject(job,pi.hProcess)) {
        TerminateProcess(pi.hProcess,7); return 7;
    }
    if(!proxy->GetPRCInstance()->AuthorizeProcessPipeAccess(pi.hProcess) || AttachToI(pi.dwProcessId,pi.dwThreadId,pipe)!=0xFF01) {
        TerminateProcess(pi.hProcess,8); return 8;
    }
    fprintf(stderr,"CHILD pid=%lu\n",pi.dwProcessId); ResumeThread(pi.hThread);
    if(WaitForSingleObject(pi.hProcess,180000)!=WAIT_OBJECT_0) TerminateProcess(pi.hProcess,9);
    WaitForSingleObject(pi.hProcess,5000);
    DWORD code=9; GetExitCodeProcess(pi.hProcess,&code);
    ULONGLONG tx=0,rx=0; proxy->GetPRCInstance()->GetTrafficTotals(tx,rx);
    fprintf(stderr,"ROUTE_TOTALS sent=%I64u received=%I64u\n",tx,rx);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(job);
    proxy->DisableProxy(); settings.Detach(); log.Detach(); ReleaseGlobalProxyInstance(); WSACleanup();
    return code;
}
