#pragma once
#include "../ProxyLaneMitm/ProxyLaneMitm.h"
#include "structinfo.h"
#include <atomic>

class CTcpProxyTask;
class CPRCTcpPeer;

class CMitmBridge
{
public:
    explicit CMitmBridge(CTcpProxyTask* task);
    ~CMitmBridge();
    static bool Enabled();
    bool Initialize();
    void OnRead(CPRCTcpPeer* peer, int error);
    void OnWritable();
    void Connected(int error);
    void TransportClosed(unsigned side, int error);
private:
    static void __cdecl Observe(uintptr_t user, uint32_t kind, const uint8_t* data, size_t length);
    ULONGLONG m_connection;
    bool Pump();
    void Fail(int error = 0);
    static LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wp, LPARAM lp);
    HWND m_window = NULL;
    bool m_pollHandshake = false;
    CTcpProxyTask* m_task;
    void* m_session;
    PLM_IO_FN m_io;
    PLM_ERROR_FN m_error;
    PLM_FREE_FN m_free;
    bool m_failed;
    bool m_paused[2] = {false, false};
};

// Optional observation of the existing TCP forwarding path. Never owns sockets.
class CProtocolTap {
public:
    explicit CProtocolTap(CTcpProxyTask* task);
    CProtocolTap(const PRCClient& client, bool udp);
    ~CProtocolTap();
    void Data(unsigned side, const void* bytes, size_t length);
    void Eof(unsigned side);
    void CloseReason(const char* reason);
    void TransportClosed(unsigned side, int error);
    void Connected(int error);
    static bool Enabled();
    bool IsActive() const { return m_active.load(); }
private:
    std::atomic<bool> m_active{false};
    void* m_handle;
    PLM_STREAM_IO_FN m_io;
    bool m_udp;
};
