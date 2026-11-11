// Test-only host: the child uses the shipping Hook UDP/DNS route. No GUI/profile edits.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include "../../src/ProxyLaneHook/ProxyModule.h"

class Settings : public IProxySettings {
public:
    bool blockUdp=false;
    bool hookTcp=false;
    bool hookChildren=false;
    int port;
    const wchar_t* type;
    BOOL GetProxySettings(LPProxySettingsInfo s) {
        ZeroMemory(s,sizeof(*s)); s->bHookUDP=TRUE; s->bHookTCP=hookTcp; s->bHookLanIP=TRUE; s->bBlockUDP=blockUdp; s->bHookCreateProcess=hookChildren;
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
    void OnHookLogtext(LPHookLogtext r) { fwprintf(stderr,L"TICK=%llu PID=%lu %s\n",GetTickCount64(),r->dwProcessId,r->str); fflush(stderr); }
    void OnChildInjectionResult(LPHookNewProcessInfo,BOOL) {}
    void OnConnectionEvent(ConnectionEvent e,const LPPRCClient c,LPCWSTR) { fprintf(stderr,"EVENT pid=%lu kind=%d\n",c->dwPid,e); }
    void OnConnectionFailure(const LPPRCClient c,LPCWSTR,ConnectionStage s,DWORD e) { fprintf(stderr,"FAIL pid=%lu stage=%d error=%lu\n",c->dwPid,s,e); }
};

#include "../../third_party/nlohmann/json.hpp"
#include <atlbase.h>
#include <atlconv.h>
using namespace ATL;
#include "../../src/ProxyLaneHook/ProcessCreationRecording.h"
#include "../../src/ProxyLaneHook/ProcessCreationSnapshot.h"
#include <iostream>
int wmain(int argc,wchar_t** argv) {
    gp_UnhookWinsock(); WSADATA wsa;WSAStartup(MAKEWORD(2,2),&wsa);
    auto proxy=GetGlobalProxyInstance(); Settings settings; Log log;
    settings.type=argc>1?argv[1]:L"NOPROXY";settings.port=argc>2?_wtoi(argv[2]):0;
    proxy->GetSettingsInstance()->AddInstance(&settings);proxy->GetLogInstance()->AddInstance(&log);
    if(!proxy->EnableProxy())return 4;
    char pipe[MAX_PATH]={};proxy->GetPRCInstance()->GetPRCPipeName(pipe,sizeof(pipe));
    using Json=nlohmann::json; std::string line;
    while(std::getline(std::cin,line)) {
        Json reply;
        try {auto q=Json::parse(line);auto type=q.value("type",std::string());
            if(type=="quit")break;
            if(type=="test_traffic") {
                ULONGLONG upload=0,download=0;proxy->GetPRCInstance()->GetTrafficTotals(upload,download);
                reply={{"upload",upload},{"download",download}};
            } else if(type=="test_pipe") {reply={{"pipe",pipe}};
            } else if(type=="test_recorded_launch") {
                HookNewProcessInfo child={};GetSystemDirectoryW(child.szAppPath,MAX_PATH);wcscat_s(child.szAppPath,L"\\cmd.exe");
                WCHAR command[]=L"cmd.exe /D /C exit 0";STARTUPINFOW si={sizeof(si)};PROCESS_INFORMATION pi={};
                if(!CreateProcessW(child.szAppPath,command,NULL,NULL,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW,NULL,NULL,&si,&pi))throw std::runtime_error("create launcher child");
                child.dwProcessId=pi.dwProcessId;child.dwThreadId=pi.dwThreadId;FILETIME c={},e={},k={},u={};
                GetProcessTimes(pi.hProcess,&c,&e,&k,&u);child.processCreateTime=(ULONGLONG(c.dwHighDateTime)<<32)|c.dwLowDateTime;
                RecordProcessCreation(proxy->GetTlsControl(),MakeProcessCreationNotice(child),"launcher");
                ResumeThread(pi.hThread);WaitForSingleObject(pi.hProcess,30000);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
                reply={{"child_pid",child.dwProcessId},{"child_start",child.processCreateTime}};
            } else if(type=="test_udp_policy") { settings.blockUdp=q.value("blocked",false);reply={{"ok",true}};
            } else if(type=="test_child_policy") { settings.hookChildren=q.value("enabled",false);reply={{"ok",true}};
            } else if(type=="test_tcp_policy") { settings.hookTcp=q.value("enabled",false);reply={{"ok",true}};
            } else if(type=="attach") {
                DWORD pid=q.at("pid");HANDLE h=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
                bool allowed=h&&proxy->GetPRCInstance()->AuthorizeProcessPipeAccess(h);
                DWORD result=allowed?AttachToI(pid,0,pipe):GetLastError();if(h)CloseHandle(h);
                reply={{"result",result}};
            } else if(type=="register") {
                DWORD pid=q.at("pid");HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
                HookProcessIdentityInfo identity={};identity.dwProcessId=pid;DWORD n=MAX_PATH;FILETIME c,e,k,u;
                if(h&&QueryFullProcessImageNameW(h,0,identity.szAppPath,&n)&&GetProcessTimes(h,&c,&e,&k,&u)) {
                    identity.processCreateTime=((ULONGLONG)c.dwHighDateTime<<32)|c.dwLowDateTime;
                    reply={{"result",proxy->GetProcessRegistry()->Register(&identity)}};
                } else throw std::runtime_error("cannot identify process");if(h)CloseHandle(h);
            } else {
                std::vector<char> out(4*1024*1024);int n=proxy->GetTlsControl()->QueryProtocol(line.c_str(),out.data(),out.size());
                if(n<0)throw std::runtime_error(out.data());if(n>out.size())throw std::runtime_error("reply too big");
                reply=Json::parse(out.data());
            }
        }catch(const std::exception& e){reply={{"error",e.what()}};}
        std::cout<<reply.dump()<<std::endl;
    }
    char out[1024];proxy->GetTlsControl()->QueryProtocol("{\"type\":\"monitor_stop\"}",out,sizeof(out));
    proxy->DisableProxy();settings.Detach();log.Detach();ReleaseGlobalProxyInstance();WSACleanup();return 0;
}
