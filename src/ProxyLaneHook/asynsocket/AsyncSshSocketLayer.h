#pragma once
#include "AsyncProxySocketLayer.h"
#include "../SshSessionManager.h"

// A channel adapter. The shared session owns the lower route through the SSH
// server; the remaining (upper) chain belongs to this business socket.
class CAsyncSshSocketLayer : public CAsyncProxySocketLayer
{
public:
    explicit CAsyncSshSocketLayer(const ProxyChain& route);
    ~CAsyncSshSocketLayer();
    BOOL Connect(LPCSTR host, UINT port) override;
    BOOL Connect(const SOCKADDR* address, int length) override;
    void Close() override;
    int GetProxyOpID() const override;
    BOOL HasPendingRead() const override;
    int FailedHop() const override;
    void Ready();
    void Readable();
    void Writable();
    void Failed(int code, int socketError, const CStringA& detail);
protected:
    int Send(const void* data, int length, int flags) override;
    int Receive(void* data, int length, int flags) override;
    BOOL ShutDown(int how) override;
private:
    ProxyChain m_route;
    std::shared_ptr<SshChannel> m_channel;
    bool m_ready = false;
    bool m_failed = false;
};
