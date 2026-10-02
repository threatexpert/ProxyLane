#pragma once
#include <windows.h>

namespace ProcessActions
{
	inline ULONGLONG CreationTime(HANDLE process)
	{
		FILETIME created, exited, kernel, user;
		if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
		ULARGE_INTEGER value;
		value.LowPart = created.dwLowDateTime;
		value.HighPart = created.dwHighDateTime;
		return value.QuadPart;
	}

	inline HANDLE OpenForTermination(DWORD pid, ULONGLONG expectedCreationTime)
	{
		if (pid <= 4 || pid == GetCurrentProcessId())
		{ SetLastError(ERROR_ACCESS_DENIED); return NULL; }
		if (!expectedCreationTime)
		{ SetLastError(ERROR_INVALID_DATA); return NULL; }
		HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE |
			PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!process) process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE |
			0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, FALSE, pid);
		if (!process) return NULL;
		DWORD error = ERROR_SUCCESS;
		if (CreationTime(process) != expectedCreationTime) error = ERROR_INVALID_DATA;
		else if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) error = ERROR_NOT_FOUND;
		else
		{
			// Prevent an accidental system crash. No Windows 8-only import.
			typedef BOOL (WINAPI *IsCritical)(HANDLE, PBOOL);
			IsCritical isCritical = reinterpret_cast<IsCritical>(GetProcAddress(
				GetModuleHandleW(L"kernel32.dll"), "IsProcessCritical"));
			BOOL critical = FALSE;
			if (isCritical)
			{
				if (!isCritical(process, &critical)) error = GetLastError();
			}
			else
			{
				typedef LONG (WINAPI *QueryProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
				QueryProcess query = reinterpret_cast<QueryProcess>(GetProcAddress(
					GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
				ULONG breakOnTermination = 0;
				if (!query || query(process, 29, &breakOnTermination,
					sizeof(breakOnTermination), NULL) < 0) error = ERROR_ACCESS_DENIED;
				critical = breakOnTermination != 0;
			}
			if (critical) error = ERROR_ACCESS_DENIED;
		}
		if (error != ERROR_SUCCESS)
		{
			CloseHandle(process);
			SetLastError(error);
			return NULL;
		}
		return process; // Hold through confirmation: PID reuse cannot change it.
	}
}
