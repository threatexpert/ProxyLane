#pragma once
#include <windows.h>
#include <vector>
#include "../ProxyLaneHook/ProcessIdentity.h"

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
		if (!process)
		{
			const DWORD error = GetLastError();
			HookProcessIdentityInfo identity = { 0 };
			identity.dwProcessId = pid;
			identity.processCreateTime = expectedCreationTime;
			// Opening with terminate rights can fail for an already exited
			// object. Recheck its lifetime in the system snapshot before reporting a failure.
			SetLastError(ProxyProcessIdentity::HasExited(identity) ? ERROR_NOT_FOUND : error);
			return NULL;
		}
		DWORD error = ERROR_SUCCESS;
		SetLastError(ERROR_SUCCESS);
		const ULONGLONG actualCreationTime = CreationTime(process);
		if (!actualCreationTime) error = GetLastError() ? GetLastError() : ERROR_INVALID_DATA;
		// The captured lifetime is gone. Never terminate the new owner of its PID.
		else if (actualCreationTime != expectedCreationTime) error = ERROR_NOT_FOUND;
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

	struct TerminationTarget
	{
		DWORD pid;
		ULONGLONG creationTime;
	};

	// Only the explicitly supplied process lifetimes are affected. Issue all
	// requests first, then share one bounded wait budget across the entire batch.
	inline std::vector<DWORD> TerminateExactProcesses(
		const std::vector<TerminationTarget>& targets, DWORD waitMs = 3000, HANDLE cancel = NULL)
	{
		const DWORD started = GetTickCount();
		const auto interrupted = [&]() -> DWORD {
			if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) return ERROR_CANCELLED;
			return GetTickCount() - started >= waitMs ? ERROR_TIMEOUT : ERROR_SUCCESS;
		};
		std::vector<DWORD> errors(targets.size(), ERROR_SUCCESS);
		std::vector<HANDLE> handles(targets.size(), NULL);
		struct Cleanup
		{
			std::vector<HANDLE>& handles;
			~Cleanup() { for (size_t i = 0; i < handles.size(); ++i)
				if (handles[i]) CloseHandle(handles[i]); }
		} cleanup = { handles };
		for (size_t i = 0; i < targets.size(); ++i)
		{
			if ((errors[i] = interrupted()) != ERROR_SUCCESS) continue;
			handles[i] = OpenForTermination(targets[i].pid, targets[i].creationTime);
			if (!handles[i])
			{
				const DWORD error = GetLastError();
				// The user may have closed an application while confirming.
				if (error != ERROR_NOT_FOUND && error != ERROR_INVALID_PARAMETER)
					errors[i] = error;
				continue;
			}
		}
		// Capture every identity before terminating any process: one process can
		// cause another listed process to exit as part of its own shutdown.
		for (size_t i = 0; i < handles.size(); ++i)
		{
			if (!handles[i]) continue;
			if ((errors[i] = interrupted()) != ERROR_SUCCESS) continue;
			// A previous round may have requested exit while outstanding I/O or
			// a debugger still delays the process becoming signalled. Keep waiting
			// instead of treating a repeated TerminateProcess access denial as failure.
			DWORD exitCode = STILL_ACTIVE;
			const bool exiting = GetExitCodeProcess(handles[i], &exitCode) && exitCode != STILL_ACTIVE;
			if (!exiting && WaitForSingleObject(handles[i], 0) != WAIT_OBJECT_0 &&
				!TerminateProcess(handles[i], 1))
			{
				const DWORD error = GetLastError();
				if (WaitForSingleObject(handles[i], 0) != WAIT_OBJECT_0)
					errors[i] = error;
			}
		}
		for (size_t i = 0; i < handles.size(); ++i)
		{
			if (!handles[i]) continue;
			const DWORD elapsed = GetTickCount() - started;
			const DWORD remaining = elapsed < waitMs ? waitMs - elapsed : 0;
			HANDLE waits[] = {handles[i], cancel};
			const DWORD waited = WaitForMultipleObjects(cancel ? 2 : 1, waits, FALSE, remaining);
			if (waited == WAIT_OBJECT_0)
				errors[i] = ERROR_SUCCESS;
			else if (!errors[i])
				errors[i] = waited == WAIT_TIMEOUT ? ERROR_TIMEOUT :
					(waited == WAIT_OBJECT_0 + 1 ? ERROR_CANCELLED : GetLastError());
		}
		return errors;
	}
}
