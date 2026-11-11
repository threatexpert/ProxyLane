#include "stdafx.h"
#include "AsyncSshSocketLayer.h"

CAsyncSshSocketLayer::CAsyncSshSocketLayer(const ProxyChain& route,
    SshSessionUse use, SshSession* dependent)
    : m_route(route), m_use(use), m_dependent(dependent) {}
CAsyncSshSocketLayer::~CAsyncSshSocketLayer() { Close(); }
BOOL CAsyncSshSocketLayer::Connect(LPCSTR host, UINT port)
{
    if (m_channel || !host || !*host || !port || port > 65535) { WSASetLastError(WSAEINVAL); return FALSE; }
    SetLayerState(connecting);
    m_channel = SshSessionManager::Open(m_route, host, port, this, m_use, m_dependent);
    if (!m_channel) { WSASetLastError(WSAENOBUFS); return FALSE; }
    WSASetLastError(WSAEWOULDBLOCK);
    return FALSE;
}
BOOL CAsyncSshSocketLayer::Connect(const SOCKADDR* address, int length)
{
    _SockAddr target;
    if (!address || !target.Set(address, length)) { WSASetLastError(WSAEINVAL); return FALSE; }
    char host[INET6_ADDRSTRLEN];
    const void* ip = target.IsIPv6() ? static_cast<const void*>(target.GetAddr6()) : static_cast<const void*>(target.GetAddr());
    if (!ProxyInetNtopA(target.sa_family, ip, host, sizeof(host))) return FALSE;
    return Connect(host, target.GetPort());
}
void CAsyncSshSocketLayer::Close()
{
    if (m_channel) m_channel->Detach();
    m_channel.reset();
    m_ready = false;
    CloseNext();
}
int CAsyncSshSocketLayer::GetProxyOpID() const { return m_ready || m_failed ? 0 : 1; }
BOOL CAsyncSshSocketLayer::HasPendingRead() const { return m_channel && m_channel->PendingRead(); }
int CAsyncSshSocketLayer::FailedHop() const { return m_channel ? m_channel->FailedHop() : -1; }
int CAsyncSshSocketLayer::Send(const void* data, int length, int flags)
{
    if (flags) { WSASetLastError(WSAEOPNOTSUPP); return SOCKET_ERROR; }
    if (!m_channel) { WSASetLastError(WSAENOTCONN); return SOCKET_ERROR; }
    return m_channel->Send(data, length);
}
int CAsyncSshSocketLayer::Receive(void* data, int length, int flags)
{
    if (!m_channel) { WSASetLastError(WSAENOTCONN); return SOCKET_ERROR; }
    return m_channel->Receive(data, length, flags);
}
BOOL CAsyncSshSocketLayer::ShutDown(int how)
{
    if (m_channel && how != SD_RECEIVE) m_channel->Shutdown();
    return TRUE;
}
void CAsyncSshSocketLayer::Ready()
{
    m_ready = true;
    SetLayerState(connected);
    TriggerEvent(FD_CONNECT, 0, TRUE);
}
void CAsyncSshSocketLayer::Readable() { if (m_ready) TriggerEvent(FD_READ, 0, TRUE); }
void CAsyncSshSocketLayer::Writable() { if (m_ready) TriggerEvent(FD_WRITE, 0, TRUE); }
void CAsyncSshSocketLayer::Failed(int code, int socketError, const CStringA& detail)
{
    if (m_failed) return;
    m_failed = true;
    TriggerEvent(m_ready ? FD_CLOSE : FD_CONNECT, socketError, TRUE);
    // The synchronous callback can release the tester and delete this layer.
    // Do not touch this object afterwards; detail remains owned by the caller.
    DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, code, socketError, (LPARAM)(LPCSTR)detail);
}
