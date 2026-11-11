#pragma once
#include "structinfo.h"
#include <memory>
#include <deque>
#include <vector>
#include <string>
class CUdpProxyTask;
class CPRCUdpPeer;
// All methods except Notify are called on the owning PRC event thread.
class CQuicBridge {
public:
    static std::shared_ptr<CQuicBridge> Open(CUdpProxyTask*,CPRCUdpPeer*,const PRCClient&,const char*,int);
    ~CQuicBridge();
    bool Feed(unsigned side,const char*,int);
    int Peek(unsigned side,char*,int);
    void Consume(unsigned side);
    bool Passthrough() const { return m_rejected; }
    bool Drained();
    bool WasMitm() const { return m_handle != NULL; }
private:
    typedef void (__cdecl *NotifyFn)(uintptr_t);
    typedef int (__cdecl *OpenFn)(const char*,const char*,const uint8_t*,size_t,void*,NotifyFn,uintptr_t,void**,char*,size_t);
    typedef int (__cdecl *IoFn)(void*,uint32_t,uint32_t,uint8_t*,size_t);
    typedef int (__cdecl *InspectFn)(void**,uint32_t,const uint8_t*,size_t);
    void TryOpen();
    CQuicBridge(CUdpProxyTask*,CPRCUdpPeer*);
    static void __cdecl Notify(uintptr_t);
    static LRESULT CALLBACK WindowProc(HWND,UINT,WPARAM,LPARAM);
    CUdpProxyTask* m_task;CPRCUdpPeer* m_peer;
    HWND m_window;void* m_handle;IoFn m_io;
    OpenFn m_open; InspectFn m_inspect; void* m_probe = nullptr;
    std::deque<std::vector<char>> m_initial;
    std::string m_host,m_metadata;
    const void* m_owner=nullptr;DWORD m_compat=0;bool m_admissionSlot=false;
    DWORD m_pid=0,m_started=0;ULONGLONG m_birth=0;
    size_t m_bytes=0;int m_inspected=0;bool m_rejected=false;
};
HMODULE ProxyMitmModule();
bool ProxyQuicEnabled();
