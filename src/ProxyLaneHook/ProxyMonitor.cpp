#include "stdafx.h"
#include "ProxyMonitor.h"
#include <algorithm>

CProxyMonitor& CProxyMonitor::Instance()
{
    static CProxyMonitor instance;
    return instance;
}
void CProxyMonitor::SetEnabled(BOOL enabled)
{
    std::lock_guard<std::mutex> guard(m_lock);
    m_enabled.store(enabled != FALSE);
    if (!enabled) { m_events.clear(); m_dropped = 0; }
}
BOOL CProxyMonitor::Poll(ProxyMonitorEvent* event)
{
    if (!event) return FALSE;
    std::lock_guard<std::mutex> guard(m_lock);
    if (m_events.empty()) return FALSE;
    *event = m_events.front(); m_events.pop_front(); return TRUE;
}
DWORD CProxyMonitor::TakeDroppedCount()
{
    std::lock_guard<std::mutex> guard(m_lock);
    DWORD result = m_dropped; m_dropped = 0; return result;
}
void CProxyMonitor::Clear()
{
    std::lock_guard<std::mutex> guard(m_lock);
    m_events.clear(); m_dropped = 0;
}
void CProxyMonitor::Record(ULONGLONG connection, const PRCClient& client,
    DWORD kind, const BYTE* data, size_t length)
{
    if (!m_enabled.load() || !data) return;
    // Never propagate allocation failures into forwarding or Rust callbacks.
    try {
        std::lock_guard<std::mutex> guard(m_lock);
        if (!m_enabled.load()) return;
        while (length) {
            ProxyMonitorEvent event = {};
            event.connection = connection; event.client = client; event.kind = kind;
            event.length = static_cast<DWORD>((std::min)(length, sizeof(event.data)));
            memcpy(event.data, data, event.length);
            if (m_events.size() >= 512) { m_events.pop_front(); ++m_dropped; }
            m_events.push_back(event);
            data += event.length; length -= event.length;
        }
    } catch (...) { /* Monitoring must never break forwarding. */ }
}
void CProxyMonitor::RecordPacket(LPProxyPacketInfo packet, DWORD kind, const char* status)
{
    if (!m_enabled.load() || !packet || !packet->lpC) return;
    const BYTE* data = status ? (const BYTE*)status : (const BYTE*)packet->pData;
    size_t length = status ? strlen(status) : (packet->datalen > 0 ? packet->datalen : 0);
    Record(0, *packet->lpC, kind, data, length);
}
