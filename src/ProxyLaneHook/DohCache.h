#pragma once
#include "structinfo.h"
#include "TimerQueue.h"
#include <string>
#include <utility>
#include <vector>

// Owned and accessed only by the query's event thread. No query objects or
// completion callbacks belong here: the timer only releases expired values.
class CDohCache : public CWndTimer {
public:
    CDohCache() = default;
    struct Entry {
        std::vector<_SockAddr> addresses;
        std::vector<unsigned char> wire;
        DWORD stored, lifetime;
        std::string summaryText;
    };

    ~CDohCache() { Clear(); }

    const Entry* Find(const std::string& key) {
        Prune(); // TTL validity must not depend on timer delivery.
        auto it = m_entries.find(key);
        return it == m_entries.end() ? NULL : &it->second;
    }

    bool Store(const std::string& key, Entry entry) {
        Prune();
        if (!entry.lifetime) return false;
        if (!m_timerArmed) {
            // If Windows cannot create the cleanup timer, skip caching this
            // answer; the caller still receives the successful DNS result.
            if (!SetTimer(1, 30000)) return false;
            m_timerArmed = true;
        }
        if (m_entries.size() >= 512 && m_entries.find(key) == m_entries.end())
            m_entries.erase(m_entries.begin());
        m_entries[key] = std::move(entry);
        return true;
    }

    void Clear() {
        m_entries.clear();
        StopTimer();
    }

    size_t Size() const { return m_entries.size(); }

    void OnTimer(UINT_PTR id) override {
        if (id == 1 && m_timerArmed) Prune();
    }

private:
    void StopTimer() {
        if (m_timerArmed) { KillTimer(1); m_timerArmed = false; }
    }

    void Prune() {
        const DWORD now = GetTickCount();
        for (auto it = m_entries.begin(); it != m_entries.end();) {
            if (now - it->second.stored >= it->second.lifetime)
                it = m_entries.erase(it);
            else ++it;
        }
        if (m_entries.empty()) StopTimer();
    }

    std::map<std::string, Entry> m_entries;
    bool m_timerArmed = false;
    CDohCache(const CDohCache&) = delete;
    CDohCache& operator=(const CDohCache&) = delete;
};
