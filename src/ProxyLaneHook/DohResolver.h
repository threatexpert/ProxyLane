#pragma once
#include "ProxyChainLayers.h"
#include "TimerQueue.h"
#include "DohWakeup.h"
#include <memory>
#include <string>
#include <list>
#include <functional>
class CProtocolTap;
class CProxyReceptionCentre;

// Per application request, never stored on a shared query.
struct DohQueryLogInfo {
    CString processName;
    DWORD started = 0;
    bool cacheHit = false, shared = false;
};

// Owner-thread-bound shared queries. Completion posts generation-checked
// messages to live waiters. Dropping the last owner cancels I/O.
class CDohQuery : public CAsyncSocketEx, public CWndTimer {
public:
    using TestProgress = std::function<void(int, int, WPARAM, LPARAM)>;
    static std::shared_ptr<CDohQuery> Resolve(const PRCClient&, const ProxyInfo&, const ProxyChain* = NULL, bool test = false, DohQueryLogInfo* = NULL, TestProgress = {}, CProxyReceptionCentre* = NULL);
    void CancelTestProgress() { m_testProgress = {}; }
    int FailureCode() const { return m_failureCode; }
    int FailedHop() const { return m_failedHop; }
    const CStringA& FailureDetail() const { return m_failureDetail; }
    void LogAddressResult(const PRCClient&, const DohQueryLogInfo&) const;
    static std::shared_ptr<CDohQuery> Exchange(const PRCClient&, const ProxyInfo&, const ProxyChain*, const std::vector<unsigned char>&, bool* cacheHit = NULL, bool* shared = NULL);
    static void ClearCache();
    ~CDohQuery();
    bool Done() const { return m_done; }
    bool Succeeded() const { return m_done && m_error.IsEmpty() && (m_probeSucceeded || !m_addresses.empty() || !m_wireAnswer.empty()); }
    const CStringA& Error() const { return m_error; }
    const std::vector<_SockAddr>& Addresses() const { return m_addresses; }
    const std::vector<unsigned char>& WireAnswer() const { return m_wireAnswer; }
    DWORD AnswerAge() const { return (GetTickCount() - m_answerStored) / 1000; }
    DWORD CacheLifetime() const { return m_ttl; }
    bool NotifyWhenReady(const std::shared_ptr<CDohWakeup>&);
    void OnConnect(int error) override;
    void OnReceive(int error) override;
    void OnSend(int error) override;
    void OnClose(int error) override;
    void OnTimer(UINT_PTR) override;
    void OnMessage(UINT, WPARAM, LPARAM, BOOL&) override;
    int OnLayerCallback(const CAsyncSocketExLayer*, int type, int code, WPARAM, LPARAM) override;
    void RemoveAllLayers() override;
private:
    CDohQuery();
    static std::shared_ptr<CDohQuery> Start(const PRCClient&, const ProxyInfo&, const ProxyChain*, bool, const std::vector<unsigned char>&, bool* cacheHit = NULL, bool* shared = NULL, TestProgress = {});
    bool Begin();
    void Pump();
    void Fail(const char* text);
    void Complete();
    void ResetTransport();
    void NotifyWaiters();
    bool ScheduleWork();
    std::shared_ptr<CDohWakeup> m_wakeup;
    std::vector<std::weak_ptr<CDohWakeup>> m_waiters;
    ProxyInfo m_proxy;
    ProxyChain m_route;
    CProxyChainLayers m_layers;
    std::vector<_SockAddr> m_bootstrap, m_addresses;
    size_t m_endpoint = 0;
    CStringA m_name, m_error;
    bool m_ipv6 = false, m_connected = false, m_done = false, m_pumping = false, m_retry = false;
    bool m_test = false;
    bool m_probeSucceeded = false;
    TestProgress m_testProgress;
    int m_failureCode = PROXYERROR_DOH_FAILED, m_failedHop = -1;
    int m_testHop = 0, m_testStage = PTS_CONNECTING;
    CStringA m_failureDetail;
    DWORD m_started = 0, m_attemptStarted = 0, m_ttl = 0;
    std::string m_key;
    std::string m_summaryText;
    std::vector<unsigned char> m_wireQuery, m_wireAnswer;
    DWORD m_answerStored = 0;
    void* m_tls = NULL;
    typedef int (__cdecl *CreateFn)(const char*, const char*, void**, char*, size_t);
    typedef int (__cdecl *IoFn)(void*, uint32_t, uint8_t*, size_t);
    typedef void (__cdecl *FreeFn)(void*);
    CreateFn m_create = NULL;
    IoFn m_io = NULL;
    FreeFn m_free = NULL;
    unsigned char m_output[16384];
    int m_outputSize = 0, m_outputSent = 0;
};

// One application transaction; the shared exchange excludes its DNS ID.
class CDnsDohRequest {
public:
    bool Begin(const PRCClient&, const ProxyInfo&, const ProxyChain*, const char*, int, CProxyReceptionCentre* = NULL);
    bool NotifyWhenReady(const std::shared_ptr<CDohWakeup>&);
    bool TryBuildReply(bool udp, std::vector<unsigned char>& response);
private:
    void LogResult(CStringA summary, bool local = false);
    std::vector<unsigned char> m_query;
    std::vector<unsigned char> m_rejected;
    std::shared_ptr<CDohQuery> m_exchange;
    CStringA m_name, m_type;
    CString m_processName;
    DWORD m_pid = 0;
    DWORD m_started = 0;
    bool m_cacheHit = false, m_shared = false, m_resultLogged = false;
};

// Application-facing DNS/TCP session, owned by the existing TCP task.
class CDnsDohTcp : public CAsyncSocketEx, public CWndTimer {
public:
    CDnsDohTcp(const PRCClient&, const ProxyInfo&, const ProxyChain*, CProxyReceptionCentre*);
    ~CDnsDohTcp();
    bool StartDeadline() { return SetTimer(1, 1000) != FALSE; }
    void Pump();
    void OnReceive(int error) override;
    void OnSend(int error) override;
    void OnClose(int error) override;
    void OnTimer(UINT_PTR) override;
    void OnMessage(UINT, WPARAM, LPARAM, BOOL&) override;
private:
    std::shared_ptr<CDohWakeup> m_wakeup;
    PRCClient m_client;
    ProxyInfo m_proxy;
    ProxyChain m_chain;
    std::vector<unsigned char> m_input, m_output;
    std::list<CDnsDohRequest> m_pending;
    size_t m_sent = 0;
    DWORD m_activity = GetTickCount();
    bool m_eof = false, m_pumping = false, m_noticeFailed = false;
    std::unique_ptr<CProtocolTap> m_capture;
    CProxyReceptionCentre* m_host;
};
