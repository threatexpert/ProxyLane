#pragma once
#include "ProxyModule.h"
#include "SshSessionLifetime.h"
#include <memory>

class CAsyncSshSocketLayer;
class SshSession;

// One logical TCP stream. Session ownership is independent of the business
// socket; a closed layer detaches its observer before queued events can run.
class SshChannel
{
public:
    ~SshChannel();
    int Send(const void* data, int length);
    int Receive(void* data, int length, int flags);
    void Shutdown();
    void Detach();
    bool PendingRead() const;
    int FailedHop() const;
private:
    friend class SshSession;
    friend class SshSessionManager;
    struct State;
    SshChannel();
    std::unique_ptr<State> m;
};

// All business sockets in a PRC use its network thread. Testers use their own
// event thread and pool: no session or libssh2 handle crosses thread boundaries.
class SshSessionManager
{
public:
    static std::shared_ptr<SshChannel> Open(const ProxyChain& route,
        const CStringA& target, int port, CAsyncSshSocketLayer* observer,
        SshSessionUse use, SshSession* dependent = NULL);
    static void ShutdownCurrentThread();
};
