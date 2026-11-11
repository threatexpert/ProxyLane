#pragma once
#include "ProcessIdentity.h"
#include <map>
#include <wchar.h>

class CProcessRegistry : public IProxyProcessRegistry
{
public:
	CProcessRegistry() { InitializeCriticalSection(&m_lock); }
	~CProcessRegistry() { DeleteCriticalSection(&m_lock); }

	BOOL Register(const HookProcessIdentityInfo* identity) override
	{
		if (!identity || !identity->dwProcessId || !identity->processCreateTime ||
			!identity->szAppPath[0]) return FALSE;
		ScopedLock lock(m_lock);
		HookProcessIdentityInfo& entry = m_processes[identity->dwProcessId];
		if (entry.processCreateTime > identity->processCreateTime) return FALSE;
		if (entry.processCreateTime != identity->processCreateTime)
		{
			ZeroMemory(&entry, sizeof(entry));
			entry.dwProcessId = identity->dwProcessId;
			entry.processCreateTime = identity->processCreateTime;
		}
		// A late path report must not erase a final Hook result.
		wcsncpy_s(entry.szAppPath, MAX_PATH, identity->szAppPath, MAX_PATH - 1);
		entry.szAppPath[MAX_PATH - 1] = L'\0';
		return TRUE;
	}

	BOOL Update(DWORD pid, ULONGLONG creationTime, DWORD error) override
	{
		if (!pid || !creationTime) return FALSE;
		ScopedLock lock(m_lock);
		HookProcessIdentityInfo& entry = m_processes[pid];
		if (entry.processCreateTime > creationTime) return FALSE;
		if (entry.processCreateTime != creationTime)
		{
			ZeroMemory(&entry, sizeof(entry));
			entry.dwProcessId = pid;
			entry.processCreateTime = creationTime;
		}
		// A failed retry does not remove an already installed remote Hook.
		if (entry.hookState != PROCESS_HOOK_STATE_SUCCEEDED)
		{
			entry.hookState = error ? PROCESS_HOOK_STATE_FAILED : PROCESS_HOOK_STATE_SUCCEEDED;
			entry.hookError = error;
		}
		return TRUE;
	}

	BOOL Get(DWORD pid, ULONGLONG creationTime, HookProcessIdentityInfo* identity) override
	{
		if (!pid || !identity) return FALSE;
		ScopedLock lock(m_lock);
		Records::const_iterator it = m_processes.find(pid);
		if (it == m_processes.end() ||
			(creationTime && it->second.processCreateTime != creationTime)) return FALSE;
		*identity = it->second;
		return TRUE;
	}

	void PruneExited() override
	{
		Records snapshot;
		{
			ScopedLock lock(m_lock);
			snapshot = m_processes;
		}
		if (snapshot.empty()) return;
		ProxyProcessIdentity::Snapshot processes;
		if (!ProxyProcessIdentity::QuerySnapshot(processes)) return;
		for (Records::const_iterator it = snapshot.begin(); it != snapshot.end(); ++it)
		{
			if (!processes.HasExited(it->second)) continue;
			ScopedLock lock(m_lock);
			Records::iterator current = m_processes.find(it->first);
			// A concurrent registration of a reused PID must survive this scan.
			if (current != m_processes.end() &&
				current->second.processCreateTime == it->second.processCreateTime)
				m_processes.erase(current);
		}
	}

	DWORD SnapshotHooked(HookProcessIdentityInfo* identities, DWORD capacity) override
	{
		ScopedLock lock(m_lock);
		DWORD count = 0;
		for (Records::const_iterator it = m_processes.begin(); it != m_processes.end(); ++it)
			if (it->second.hookState == PROCESS_HOOK_STATE_SUCCEEDED) ++count;
		if (!identities || capacity < count) return count;
		DWORD index = 0;
		for (Records::const_iterator it = m_processes.begin(); it != m_processes.end(); ++it)
			if (it->second.hookState == PROCESS_HOOK_STATE_SUCCEEDED)
				identities[index++] = it->second;
		return count;
	}

private:
	typedef std::map<DWORD, HookProcessIdentityInfo> Records;
	class ScopedLock
	{
	public:
		explicit ScopedLock(CRITICAL_SECTION& lock) : m_lock(lock) { EnterCriticalSection(&m_lock); }
		~ScopedLock() { LeaveCriticalSection(&m_lock); }
	private:
		CRITICAL_SECTION& m_lock;
	};
	CProcessRegistry(const CProcessRegistry&);
	CProcessRegistry& operator=(const CProcessRegistry&);
	CRITICAL_SECTION m_lock;
	Records m_processes;
};
