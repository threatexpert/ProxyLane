#include "UdpBlockLogLimiter.h"
#include <atomic>
#include <iostream>
#include <thread>
#include <vector>

int UdpBlockLogLimiterTestsMain()
{
	_SockAddr first = {}, second = {};
	first.SetIP("192.0.2.1"); first.SetPort(443);
	second = first; second.SetPort(53);
	CUdpBlockLogLimiter limiter;
	if (!limiter.Allow(first, 100) || limiter.Allow(first, 101) ||
		!limiter.Allow(second, 101) || limiter.Allow(first, 5099) ||
		!limiter.Allow(first, 5100)) return 1;
	CUdpBlockLogLimiter budget;
	for (int i = 0; i < 1000; ++i)
	{
		second.SetPort(static_cast<WORD>(i + 1));
		if (budget.Allow(second, 100) != (i < CUdpBlockLogLimiter::MaxPerInterval)) return 1;
	}
	if (!budget.Allow(second, 5100)) return 1;
	CUdpBlockLogLimiter wrap;
	if (!wrap.Allow(first, MAXDWORD - 100) || wrap.Allow(first, 100) ||
		!wrap.Allow(first, 4900)) return 1;
	_SockAddr unknown = {};
	if (!wrap.Allow(unknown, 4900) || wrap.Allow(unknown, 4901)) return 1;
	CUdpBlockLogLimiter concurrent;
	std::atomic<int> logged(0);
	std::vector<std::thread> workers;
	for (int i = 0; i < 8; ++i)
		workers.emplace_back([&]() {
			for (int n = 0; n < 1000; ++n) if (concurrent.Allow(first)) ++logged;
		});
	for (auto& worker : workers) worker.join();
	if (logged != 1) return 1;
	// Repeated windows of new endpoints must reclaim expired entries.
	CUdpBlockLogLimiter expiry;
	for (DWORD window = 1; window <= 1000; ++window)
	{
		first.SetPort(static_cast<WORD>(window));
		if (!expiry.Allow(first, 1000 + window * 5000)) return 1;
	}
	std::cout << "UDP block log cooldown, flood budget, wraparound and concurrency passed" << std::endl;
	return 0;
}
