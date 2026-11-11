#include "stdafx.h"
#include "QuicBridge.h"
#include "UdpProxyTask.h"
#include "ProxyTaskMgr.h"
#include "BrowserQuicPolicy.h"
#include "PRCUdpPeer.h"
#include "InetCompat.h"
#include "ProxyLog.h"
#include "../../third_party/nlohmann/json.hpp"
#include <atomic>
#include <mutex>
static std::atomic<unsigned long long> quicIds(0);
static std::atomic<unsigned> quicBridges(0);
static std::atomic<size_t> initialBytes(0);
static const size_t initialByteLimit=8*1024*1024;
static const DWORD compatibilityWaitMs=2000;
static std::atomic<unsigned> admissions(0); // <=128 retained Initial queues (8 MiB nominal)
CQuicBridge::CQuicBridge(CUdpProxyTask* task,CPRCUdpPeer* peer):m_task(task),m_peer(peer),m_window(NULL),m_handle(NULL),m_io(NULL){++quicBridges;}
CQuicBridge::~CQuicBridge() {
    --quicBridges;
    initialBytes.fetch_sub(m_bytes);
    if(m_admissionSlot)--admissions;
    // Rust closes notification queues synchronously before returning, so no callback
    // can reference the destroyed bridge/window. Tokio tasks retain only closed queues.
    if(m_handle)m_io(m_handle,3,0,NULL,0);
    if(m_probe)m_inspect(&m_probe,1,NULL,0);
    if(m_window){KillTimer(m_window,1);DestroyWindow(m_window);}
}
void __cdecl CQuicBridge::Notify(uintptr_t user) {PostMessage((HWND)user,WM_APP+83,0,0);}
LRESULT CALLBACK CQuicBridge::WindowProc(HWND window,UINT msg,WPARAM wp,LPARAM lp) {
    auto self=reinterpret_cast<CQuicBridge*>(GetWindowLongPtr(window,GWLP_USERDATA));
    if((msg==WM_APP+83 || msg==WM_TIMER) && self) {self->TryOpen();self->m_task->OnRouteWritable(self->m_peer);return 0;}
    return DefWindowProc(window,msg,wp,lp);
}
std::shared_ptr<CQuicBridge> CQuicBridge::Open(CUdpProxyTask* task,CPRCUdpPeer* peer,const PRCClient& c,const char* first,int length) {
    if(!ProxyQuicEnabled()||length<7||((unsigned char)first[0]&0xc0)!=0xc0)return {};
    DWORD compat=BrowserQuicPolicy::Lookup(task->m_pTaskmgr->m_pPRC,c.dwPid,c.processCreateTime,c.reserved);
    if(compat==BrowserQuicPolicy::Unavailable)return {};
    if(quicBridges.load()>=256 || admissions.load()>=128)return {}; // Bound pending handshake inspectors as well as live sessions.
    HMODULE module=ProxyMitmModule();if(!module)return {};
    auto open=(OpenFn)GetProcAddress(module,"plm_quic_open");auto io=(IoFn)GetProcAddress(module,"plm_quic_io");
    auto inspect=(InspectFn)GetProcAddress(module,"plm_quic_inspect");
    if(!open||!io||!inspect)return {};
    static std::once_flag registered;
    std::call_once(registered,[]{WNDCLASS wc={};wc.lpfnWndProc=WindowProc;wc.hInstance=GetModuleHandle(NULL);wc.lpszClassName=L"ProxyLane.QuicWake";RegisterClass(&wc);});
    auto bridge=std::shared_ptr<CQuicBridge>(new CQuicBridge(task,peer));bridge->m_admissionSlot=true;++admissions;
    bridge->m_owner=task->m_pTaskmgr->m_pPRC;bridge->m_compat=compat;bridge->m_io=io;bridge->m_open=open;bridge->m_inspect=inspect;
    bridge->m_pid=c.dwPid;bridge->m_birth=c.processCreateTime;bridge->m_started=GetTickCount();
    bridge->m_window=CreateWindowEx(0,L"ProxyLane.QuicWake",L"",0,0,0,0,0,HWND_MESSAGE,NULL,GetModuleHandle(NULL),NULL);
    if(!bridge->m_window)return {};
    SetWindowLongPtr(bridge->m_window,GWLP_USERDATA,(LONG_PTR)bridge.get());
    char ip[64]={};if(c.dstAddr.IsIPv6())ProxyInetNtopA(AF_INET6,c.dstAddr.GetAddr6(),ip,sizeof(ip));
    else {IN_ADDR a;a.s_addr=c.dstAddr.GetdwIP();ProxyInetNtopA(AF_INET,&a,ip,sizeof(ip));}
    bridge->m_metadata=nlohmann::json{{"connection_id",(1ull<<63)|++quicIds},{"pid",c.dwPid},{"process_create_time",c.processCreateTime},
        {"socket_generation",c.socketGeneration},{"socket",(uint64_t)c.s},{"destination",ip},{"port",c.dstAddr.GetPort()},{"transport","udp"}}.dump();
    bridge->m_host=c.szDomainName[0]?c.szDomainName:ip;
    bridge->Feed(0,first,length);
    if(bridge->m_rejected)return {};
    if(!bridge->m_handle && !SetTimer(bridge->m_window,1,50,NULL))return {};
    return bridge;
}
void CQuicBridge::TryOpen() {
    if(m_handle)return;
    if(m_rejected){if(m_admissionSlot){--admissions;m_admissionSlot=false;}KillTimer(m_window,1);return;}
    if(!ProxyQuicEnabled()||GetTickCount()-m_started>5000||m_inspected<0) m_rejected=true;
    else if(m_compat==BrowserQuicPolicy::Pending) {
        DWORD latest=BrowserQuicPolicy::Lookup(m_owner,m_pid,m_birth,m_compat);
        if(GetTickCount()-m_started>=compatibilityWaitMs || latest==BrowserQuicPolicy::Unavailable) {
            m_rejected=true;
            PrintText(L"QUIC compatibility wait ended (PID %lu): passthrough, elapsed %lu ms.\r\n",m_pid,GetTickCount()-m_started);
        } else if(latest==BrowserQuicPolicy::Ready) m_compat=latest;
        // Missing reports remain bounded by this connection's original deadline.
    }
    if(!m_rejected && m_compat!=BrowserQuicPolicy::Pending && m_inspected==1) {
        char error[2048]={};auto& first=m_initial.front();
        int result=m_open(m_host.c_str(),m_metadata.c_str(),(const uint8_t*)first.data(),first.size(),m_probe,Notify,(uintptr_t)m_window,&m_handle,error,sizeof(error));
        if(result==1) {
            for(size_t i=1;i<m_initial.size();++i) m_io(m_handle,0,0,(uint8_t*)m_initial[i].data(),m_initial[i].size());
            m_initial.clear();initialBytes.fetch_sub(m_bytes);m_bytes=0;
        } else {
            m_rejected=true;
            PrintText(L"QUIC MITM unavailable (PID %lu): %hs\r\n",m_pid,result<0?error:"unsupported QUIC handshake");
        }
    }
    if(m_handle||m_rejected){if(m_admissionSlot){--admissions;m_admissionSlot=false;}KillTimer(m_window,1);if(m_probe)m_inspect(&m_probe,1,NULL,0);}
}
bool CQuicBridge::Feed(unsigned side,const char* b,int n) {
    if(m_handle){m_io(m_handle,0,side,(uint8_t*)b,n);return true;}
    if(side!=0||n<0)return false;
    // Overflow ends admission, never starts MITM. If the process-wide byte
    // budget is exhausted, let the caller forward this datagram normally.
    if(m_bytes+(size_t)n>65536||m_initial.size()>=64)m_rejected=true;
    size_t used=initialBytes.load();
    for(;;) {
        if(m_bytes+(size_t)n>512*1024 || (size_t)n>initialByteLimit-used) {
            m_rejected=true;TryOpen();return false;
        }
        if(initialBytes.compare_exchange_weak(used,used+n))break;
    }
    try {m_initial.emplace_back(b,b+n);}catch(...) {
        initialBytes.fetch_sub(n);m_rejected=true;TryOpen();return false;
    }
    m_bytes+=n;
    if(!m_rejected)m_inspected=m_inspect(&m_probe,0,(const uint8_t*)b,n);
    TryOpen();return true;
}
int CQuicBridge::Peek(unsigned side,char* b,int n) {
    if(m_handle){int count=m_io(m_handle,1,side,(uint8_t*)b,n);return count;}
    if(!m_rejected||side!=1||m_initial.empty()||m_initial.front().size()>(size_t)n)return 0;
    memcpy(b,m_initial.front().data(),m_initial.front().size());return (int)m_initial.front().size();
}
void CQuicBridge::Consume(unsigned side) {
    if(m_handle){m_io(m_handle,2,side,NULL,0);return;}
    if(side==1&&!m_initial.empty()){m_bytes-=m_initial.front().size();initialBytes.fetch_sub(m_initial.front().size());m_initial.pop_front();}
}
bool CQuicBridge::Drained() {
    if(!m_handle)return m_rejected && m_initial.empty();
    if(m_io(m_handle,4,0,NULL,0)!=1)return false;
    char packet[65536];
    return m_io(m_handle,1,0,(uint8_t*)packet,sizeof(packet))==0 &&
           m_io(m_handle,1,1,(uint8_t*)packet,sizeof(packet))==0;
}
