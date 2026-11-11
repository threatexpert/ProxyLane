#pragma once
#include <windows.h>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>

// Owner-thread-only notification token. The query holds weak references; the
// message contains a generation, never an application/task pointer. Reuses the
// owner's existing CWndTimer window without starting a timer.
class CDohWakeup {
public:
    enum { Message = WM_APP + 0x32d };
    explicit CDohWakeup(HWND window, std::function<void()> failed = {})
        : m_window(window), m_failedCallback(std::move(failed)) {
        static std::atomic<uint64_t> sequence{0};
        m_generation = ++sequence;
    }
    ~CDohWakeup() { Cancel(); }
    CDohWakeup(const CDohWakeup&) = delete;
    CDohWakeup& operator=(const CDohWakeup&) = delete;
    bool Notify() {
        if (!m_active || m_pending) return true;
        if (m_failed) return false;
        m_pending = true;
        if (m_window && PostMessage(m_window, Message, (DWORD)m_generation,
            (LPARAM)(DWORD)(m_generation >> 32))) return true;
        m_pending = false; m_failed = true;
        // Failure callbacks must only mark the owner for deferred teardown;
        // never release a query/socket from inside its network callback.
        if (m_failedCallback) m_failedCallback();
        return false;
    }
    bool Accept(UINT message, WPARAM low, LPARAM high) {
        if (!m_active || message != Message ||
            m_generation != (uint64_t((DWORD)high) << 32 | (DWORD)low)) return false;
        m_pending = false;
        return true;
    }
    void Cancel() { m_active = false; m_pending = false; m_failedCallback = {}; }
private:
    HWND m_window;
    uint64_t m_generation;
    bool m_active = true, m_pending = false, m_failed = false;
    std::function<void()> m_failedCallback;
};
