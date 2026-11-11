#pragma once
#include <windows.h>
#include <map>
#include <vector>
#include <string>

#pragma pack(push, 1)
typedef struct _HookProcessIdentityInfo
{
	DWORD dwProcessId;
	ULONGLONG processCreateTime;
	WCHAR szAppPath[MAX_PATH];
	DWORD hookState;
	DWORD hookError;
} HookProcessIdentityInfo, *LPHookProcessIdentityInfo;
#pragma pack(pop)

#define PROCESS_HOOK_STATE_PENDING 0
#define PROCESS_HOOK_STATE_SUCCEEDED 1
#define PROCESS_HOOK_STATE_FAILED 2

namespace ProxyProcessIdentity
{
	// Fixed prefix of SystemProcessInformation, also used by the process list
	// and child guard. Resolve the native API dynamically for older Windows.
	// Never use this snapshot alone to authorize a kill.
	struct SystemProcessPrefix
	{
		ULONG nextEntryOffset;
		BYTE reserved[28];
		LARGE_INTEGER createTime;
		BYTE times[16];
		USHORT imageLength, imageMaximumLength;
		PWSTR imageBuffer;
		LONG basePriority;
		HANDLE processId;
		HANDLE parentProcessId;
		ULONG handleCount;
		ULONG sessionId;
	};
	static_assert(FIELD_OFFSET(SystemProcessPrefix, createTime) == 32, "Creation time offset");
#ifdef _WIN64
	static_assert(FIELD_OFFSET(SystemProcessPrefix, processId) == 80, "64-bit PID offset");
	static_assert(FIELD_OFFSET(SystemProcessPrefix, parentProcessId) == 88, "64-bit parent PID offset");
	static_assert(FIELD_OFFSET(SystemProcessPrefix, sessionId) == 100, "64-bit session offset");
#else
	static_assert(FIELD_OFFSET(SystemProcessPrefix, processId) == 68, "32-bit PID offset");
	static_assert(FIELD_OFFSET(SystemProcessPrefix, parentProcessId) == 72, "32-bit parent PID offset");
	static_assert(FIELD_OFFSET(SystemProcessPrefix, sessionId) == 80, "32-bit session offset");
#endif

	struct Process
	{
		DWORD pid, parentPid;
		ULONGLONG creationTime;
		std::wstring name;
		DWORD sessionId;
	};

	struct Snapshot
	{
		BOOL complete = FALSE;
		// Preserve system enumeration order for the process list; the map is
		// an index for batch lifetime checks against this same snapshot.
		std::vector<Process> processes;
		std::map<DWORD, ULONGLONG> creationTimes;

		BOOL HasExited(const HookProcessIdentityInfo& identity) const
		{
			if (!complete || !identity.dwProcessId || !identity.processCreateTime) return FALSE;
			const auto found = creationTimes.find(identity.dwProcessId);
			return found == creationTimes.end() ||
				(found->second && found->second != identity.processCreateTime);
		}
	};

	inline BOOL ReadSnapshot(const BYTE* buffer, size_t length, Snapshot& snapshot)
	{
		snapshot.complete = FALSE;
		snapshot.processes.clear();
		snapshot.creationTimes.clear();
		if (!buffer) return FALSE;
		std::map<DWORD, ULONGLONG> times;
		std::vector<Process> processes;
		size_t offset = 0;
		for (;;)
		{
			if (length - offset < sizeof(SystemProcessPrefix)) return FALSE;
			SystemProcessPrefix entry;
			CopyMemory(&entry, buffer + offset, sizeof(entry));
			const ULONG_PTR pid = reinterpret_cast<ULONG_PTR>(entry.processId);
			const ULONG_PTR parentPid = reinterpret_cast<ULONG_PTR>(entry.parentProcessId);
			if (pid > MAXDWORD || parentPid > MAXDWORD) return FALSE;
			// A present PID with an unavailable time remains unknown, not gone.
			const ULONGLONG time = entry.createTime.QuadPart > 0 ? entry.createTime.QuadPart : 0;
			if (!times.insert(std::make_pair(static_cast<DWORD>(pid), time)).second) return FALSE;
			Process process = { static_cast<DWORD>(pid), static_cast<DWORD>(parentPid), time, L"", entry.sessionId };
			if (entry.imageLength % sizeof(WCHAR) || entry.imageLength > entry.imageMaximumLength)
				return FALSE;
			if (entry.imageLength)
			{
				// UNICODE_STRING is length-delimited and points into the returned
				// buffer. Copy it before that buffer is released; do not use wcslen.
				const ULONG_PTR name = reinterpret_cast<ULONG_PTR>(entry.imageBuffer);
				const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(buffer);
				if (name < base || name - base > length || entry.imageLength > length - (name - base))
					return FALSE;
				process.name.resize(entry.imageLength / sizeof(WCHAR));
				CopyMemory(&process.name[0], entry.imageBuffer, entry.imageLength);
			}
			processes.push_back(process);
			if (!entry.nextEntryOffset) break;
			if (entry.nextEntryOffset < sizeof(entry) || entry.nextEntryOffset > length - offset)
				return FALSE;
			offset += entry.nextEntryOffset;
		}
		snapshot.creationTimes.swap(times);
		snapshot.processes.swap(processes);
		snapshot.complete = TRUE;
		return TRUE;
	}

	// One complete system snapshot per scan; no per-process handles or fallback
	// enumeration. Failure leaves the snapshot unknown, never an empty success.
	inline BOOL QuerySnapshot(Snapshot& snapshot)
	{
		snapshot.complete = FALSE;
		snapshot.processes.clear();
		snapshot.creationTimes.clear();
		typedef LONG (WINAPI *QuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		QuerySystemInformation query = ntdll ? reinterpret_cast<QuerySystemInformation>(
			GetProcAddress(ntdll, "NtQuerySystemInformation")) : NULL;
		if (!query) return FALSE;
		const ULONG maxSize = 64 * 1024 * 1024;
		ULONG size = 64 * 1024;
		std::vector<BYTE> buffer;
		for (int attempt = 0; attempt < 8 && size <= maxSize; ++attempt)
		{
			buffer.resize(size);
			ULONG returned = 0;
			const LONG status = query(5 /* SystemProcessInformation */, &buffer[0], size, &returned);
			if (status != static_cast<LONG>(0xC0000004L) /* STATUS_INFO_LENGTH_MISMATCH */)
				return status >= 0 && returned <= size && ReadSnapshot(&buffer[0], returned, snapshot);
			if (returned > maxSize - 64 * 1024) return FALSE;
			size = returned > size ? returned + 64 * 1024 : size * 2;
		}
		return FALSE;
	}

	inline BOOL HasExited(const HookProcessIdentityInfo& identity)
	{
		Snapshot snapshot;
		return QuerySnapshot(snapshot) && snapshot.HasExited(identity);
	}
}

// Borrowed from the Hook module loaded by the GUI. Survives service recreation.
// All methods are thread-safe; no STL objects cross the DLL boundary.
class IProxyProcessRegistry
{
public:
	virtual BOOL Register(const HookProcessIdentityInfo* identity) = 0;
	virtual BOOL Update(DWORD pid, ULONGLONG creationTime, DWORD error) = 0;
	// creationTime == 0 queries the latest registered lifetime for path lookup.
	virtual BOOL Get(DWORD pid, ULONGLONG creationTime, HookProcessIdentityInfo* identity) = 0;
	virtual void PruneExited() = 0;
	// Copy a consistent snapshot of successful hooks into caller-owned memory.
	// Returns the required entry count; if capacity is too small, writes nothing.
	// Appended to preserve existing virtual method slots across the DLL boundary.
	virtual DWORD SnapshotHooked(HookProcessIdentityInfo* identities, DWORD capacity) = 0;
protected:
	virtual ~IProxyProcessRegistry() {}
};
