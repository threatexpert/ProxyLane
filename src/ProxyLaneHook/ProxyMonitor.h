#pragma once
#include "ProxyModule.h"
#include <atomic>
#include <deque>
#include <mutex>

// Internal producer API. Only IProxyMonitor is exposed through IGlobalProxy.
class CProxyMonitor : public IProxyMonitor
{
public:
    static CProxyMonitor& Instance();
    void SetEnabled(BOOL enabled) override;
    BOOL Poll(ProxyMonitorEvent* event) override;
    DWORD TakeDroppedCount() override;
    void Clear() override;
    void Record(ULONGLONG connection, const PRCClient& client, DWORD kind,
        const BYTE* data, size_t length);
    void RecordPacket(LPProxyPacketInfo packet, DWORD kind, const char* status = nullptr);
private:
    CProxyMonitor() : m_enabled(false), m_dropped(0) {}
    std::atomic<bool> m_enabled;
    std::mutex m_lock;
    std::deque<ProxyMonitorEvent> m_events;
    DWORD m_dropped;
};
