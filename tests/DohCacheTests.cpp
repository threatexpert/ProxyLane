#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include "../src/ProxyLaneHook/DohCache.h"

static void Check(bool ok, const char* message) {
    if (!ok) { fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}

static CDohCache::Entry Answer(DWORD lifetime) {
    CDohCache::Entry entry = {};
    entry.stored = GetTickCount(); entry.lifetime = lifetime;
    entry.wire.assign(4096, 42);
    entry.summaryText = "NOERROR";
    return entry;
}

class ObservedCache : public CDohCache {
public:
    unsigned ticks = 0;
    void OnTimer(UINT_PTR id) override { ++ticks; CDohCache::OnTimer(id); }
};

int main() {
    ObservedCache cache;
    Check(GetWindowThreadProcessId(cache.GetHwnd(), NULL) == GetCurrentThreadId(),
        "cleanup window belongs to cache owner thread");
    Check(cache.Store("short", Answer(100)), "successful insertion reports cache admission");
    cache.Store("long", Answer(120000));
    const DWORD started = GetTickCount();
    // No Find, Store or new query while idle: only the real Windows timer
    // may remove the short-lived entry. Keep the production 30-second period.
    while (!cache.ticks && GetTickCount() - started < 35000) {
        MsgWaitForMultipleObjects(0, NULL, FALSE, 1000, QS_ALLINPUT);
        MSG message;
        while (PeekMessage(&message, NULL, 0, 0, PM_REMOVE)) DispatchMessage(&message);
    }
    Check(cache.ticks == 1, "idle cache receives low-frequency timer");
    Check(GetTickCount() - started >= 29000, "cleanup is not a high-frequency timer");
    Check(cache.Size() == 1, "timer deletes expired values without new queries");
    const auto* kept = cache.Find("long");
    Check(kept && kept->wire.size() == 4096 && kept->summaryText == "NOERROR",
        "live answer is retained unchanged");

    cache.Clear();
    // A WM_TIMER already in the queue before cancellation must be harmless.
    SendMessage(cache.GetHwnd(), WM_TIMER, 1, 0);
    Check(cache.Size() == 0, "clear cancels maintenance safely");
    Check(!cache.Store("zero", Answer(0)), "zero TTL reports no cache admission");
    Check(cache.Size() == 0, "zero TTL is not cached");
    cache.Store("again", Answer(100));
    Sleep(150);
    Check(!cache.Find("again") && cache.Size() == 0,
        "lookup rejects expired answers before maintenance runs");
    cache.Store("again", Answer(100));
    Sleep(150);
    SendMessage(cache.GetHwnd(), WM_TIMER, 1, 0);
    Check(cache.Size() == 0, "maintenance restarts after empty cache");

    for (int i = 0; i < 600; ++i) cache.Store(std::to_string(i), Answer(120000));
    Check(cache.Size() == 512, "existing entry limit remains bounded");
    cache.Clear();
    // Simulate unavailable timer window: answers should remain usable by
    // the resolver, but must not enter a cache with no idle cleanup.
    Check(cache.DestroyWnd() != FALSE, "destroy cleanup window for failure test");
    Check(!cache.Store("no-timer", Answer(120000)), "timer failure reports no cache admission");
    Check(cache.Size() == 0, "timer creation failure skips caching");
    puts("PASS: idle DoH cache expiry, TTL validity, restart, capacity, timer failure");
}
