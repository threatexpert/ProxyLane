#pragma once
#include "structinfo.h"

// Per injected process. Fixed storage bounds memory, and both the destination
// cooldown and process-wide budget apply before any pipe I/O.
class CUdpBlockLogLimiter
{
public:
	enum { IntervalMs = 5000, MaxPerInterval = 10, Capacity = 64 };
	CUdpBlockLogLimiter() : m_windowStart(0), m_windowCount(0)
	{
		ZeroMemory(m_entries, sizeof(m_entries));
		InitializeCriticalSection(&m_lock);
	}
	~CUdpBlockLogLimiter() { DeleteCriticalSection(&m_lock); }
	bool Allow(const _SockAddr& destination)
	{
		EnterCriticalSection(&m_lock);
		// Read the clock after acquiring the lock so competing callers cannot
		// submit timestamps out of order and appear to wrap the DWORD clock.
		const bool allowed = AllowLocked(destination, GetTickCount());
		LeaveCriticalSection(&m_lock);
		return allowed;
	}
	// Explicit timestamps keep cooldown/wraparound tests deterministic.
	bool Allow(const _SockAddr& destination, DWORD now)
	{
		EnterCriticalSection(&m_lock);
		const bool allowed = AllowLocked(destination, now);
		LeaveCriticalSection(&m_lock);
		return allowed;
	}
private:
	struct Entry { bool used; _SockAddr destination; DWORD lastLogged; };
	bool AllowLocked(const _SockAddr& destination, DWORD now)
	{
		if (now - m_windowStart >= IntervalMs) { m_windowStart = now; m_windowCount = 0; }
		if (m_windowCount >= MaxPerInterval) return false;
		int slot = -1;
		for (int i = 0; i < Capacity; ++i)
		{
			Entry& entry = m_entries[i];
			const bool same = entry.used && ((entry.destination == destination) ||
				(entry.destination.sa_family == AF_UNSPEC && destination.sa_family == AF_UNSPEC));
			if (same)
			{
				if (now - entry.lastLogged < IntervalMs) return false;
				slot = i;
				break;
			}
			if (slot < 0 && (!entry.used || now - entry.lastLogged >= IntervalMs)) slot = i;
		}
		if (slot < 0) return false; // Never evict a live cooldown to admit a new destination.
		m_entries[slot].used = true;
		m_entries[slot].destination = destination;
		m_entries[slot].lastLogged = now;
		++m_windowCount;
		return true;
	}
	CUdpBlockLogLimiter(const CUdpBlockLogLimiter&);
	CUdpBlockLogLimiter& operator=(const CUdpBlockLogLimiter&);
	CRITICAL_SECTION m_lock;
	Entry m_entries[Capacity];
	DWORD m_windowStart;
	unsigned int m_windowCount;
};
