#pragma once
#include "../ProxyLaneHook/ProxyTestProgress.h"
#include <vector>

// UI projection only: transport events and their source-hop timings stay intact.
namespace ChainProgressPresentation {
struct Card {
    int stage = PTS_WAITING, lastStage = PTS_WAITING;
    int linkSource = -1, errorSource = -1;
    bool started = false, connectedOnly = false;
    uint32_t elapsed = 0, stages[PTS_COUNT] = {};
};
inline bool Failed(int stage) { return stage == PTS_FAILED || stage == PTS_TIMED_OUT; }
inline bool Opening(const ProxyTestHopProgress& p, bool linkFailed) {
    return p.stage == PTS_OPENING || (p.lastActiveStage == PTS_OPENING &&
        (!Failed(p.stage) || linkFailed));
}
inline std::vector<Card> Project(const std::vector<ProxyTestHopProgress>& raw,
    const std::vector<bool>& negotiated, const std::vector<bool>& linkFailed, uint32_t now) {
    std::vector<Card> cards(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        const auto& p = raw[i]; auto& c = cards[i];
        c.stage = p.stage; c.lastStage = p.lastActiveStage; c.started = p.started;
        c.elapsed = p.started ? p.Elapsed(now) : 0;
        c.errorSource = Failed(p.stage) ? (int)i : -1;
        for (int stage = PTS_CONNECTING; stage < PTS_PASSED; ++stage)
            c.stages[stage] = p.stages[stage] + (p.Active() && p.stage == stage ? now - p.changed : 0);
        if (Opening(p, linkFailed[i])) {
            const uint32_t opening = c.stages[PTS_OPENING];
            c.elapsed -= opening; c.stages[PTS_OPENING] = 0; c.errorSource = -1;
            if (negotiated[i]) c.stage = PTS_PASSED;
            else if (p.Active()) c.stage = PTS_AUTH; // HTTP CONNECT has not confirmed authentication yet.
            else { c.stage = PTS_WAITING; c.connectedOnly = true; }
        } else if (Failed(p.stage) && p.lastActiveStage == PTS_OPENING) {
            // HTTP 407 belongs to this proxy, including the time awaiting its reply.
            c.lastStage = PTS_AUTH;
            c.stages[PTS_AUTH] += c.stages[PTS_OPENING]; c.stages[PTS_OPENING] = 0;
        }
    }
    for (size_t i = 0; i + 1 < raw.size(); ++i) {
        const auto& p = raw[i];
        if (!Opening(p, linkFailed[i])) continue;
        auto& destination = cards[i + 1];
        const uint32_t opening = p.stages[PTS_OPENING] + (p.stage == PTS_OPENING ? now - p.changed : 0);
        destination.elapsed += opening; destination.stages[PTS_CONNECTING] += opening; destination.started = true;
        if (p.stage == PTS_OPENING || Failed(p.stage) || p.stage == PTS_CANCELLED) {
            destination.stage = p.stage == PTS_OPENING ? PTS_CONNECTING : p.stage;
            destination.lastStage = PTS_CONNECTING; destination.linkSource = (int)i;
            destination.errorSource = Failed(p.stage) ? (int)i : -1;
        } else if (destination.stage == PTS_WAITING) destination.stage = PTS_CONNECTING;
    }
    return cards;
}
}
