#pragma once
#include <stdint.h>

enum class SshSessionUse { Business, Test };

// Keepalive traffic does not count as business use. Unsigned subtraction
// preserves the deadline across GetTickCount's wraparound.
class SshSessionLifetime
{
public:
    explicit SshSessionLifetime(SshSessionUse use) : m_use(use) {}
    void Observe(bool needed, uint32_t now) {
        if (needed) m_idle = false;
        else if (!m_idle) { m_idle = true; m_idleSince = now; }
    }
    bool Expired(uint32_t now) const {
        return m_idle && (m_use == SshSessionUse::Test ||
            static_cast<uint32_t>(now - m_idleSince) >= 30u * 60u * 1000u);
    }
private:
    SshSessionUse m_use;
    bool m_idle = false;
    uint32_t m_idleSince = 0;
};
