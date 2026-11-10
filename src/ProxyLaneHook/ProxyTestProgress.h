#pragma once
#include <stdint.h>

// Progress callbacks use the existing callback ABI: HIWORD = this type,
// LOWORD = stage, wParam = zero-based hop, lParam = source GetTickCount().
// Progress is opt-in on transport layers; ordinary business sockets emit none.
#define LAYERCALLBACK_TESTPROGRESS 2
enum ProxyTestStage
{
    PTS_WAITING, PTS_CONNECTING, PTS_TLS, PTS_NEGOTIATING, PTS_SSH,
    PTS_HOSTKEY, PTS_AUTH, PTS_OPENING, PTS_PASSED, PTS_FAILED,
    PTS_TIMED_OUT, PTS_CANCELLED, PTS_SKIPPED, PTS_COUNT
};

// Monotonic, source-event timing. Waiting for earlier hops is excluded. The
// request to open the next tunnel belongs to the proxy receiving that request.
// Unsigned subtraction handles the 32-bit tick counter wrapping.
struct ProxyTestHopProgress
{
    int stage = PTS_WAITING, lastActiveStage = PTS_WAITING;
    bool started = false;
    uint32_t began = 0, changed = 0, elapsed = 0;
    uint32_t stages[PTS_COUNT] = {};
    bool Active() const { return stage > PTS_WAITING && stage < PTS_PASSED; }
    bool Terminal() const { return stage >= PTS_PASSED; }
    uint32_t Elapsed(uint32_t now) const { return Active() ? now - began : elapsed; }
    bool Apply(int next, uint32_t tick)
    {
        if (next <= PTS_WAITING || next >= PTS_COUNT || Terminal() || stage == next) return false;
        if (Active())
        {
            stages[stage] += tick - changed;
            elapsed = tick - began;
            lastActiveStage = stage;
        }
        if (!started && next != PTS_SKIPPED && next != PTS_CANCELLED)
        { started = true; began = tick; }
        stage = next; changed = tick;
        return true;
    }
};
