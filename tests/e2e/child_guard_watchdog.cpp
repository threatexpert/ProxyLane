#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#ifndef _countof
#define _countof(array) (sizeof(array) / sizeof((array)[0]))
#endif

#include "../../src/ProxyLaneHook/ProxyModule.h"

static ULONGLONG ProcessCreateTime(HANDLE process)
{
	FILETIME created, exited, kernel, user;
	if (!GetProcessTimes(process, &created, &exited, &kernel, &user))
		return 0;
	return (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) |
		created.dwLowDateTime;
}

static void Quote(WCHAR *output, size_t outputCount, LPCWSTR value)
{
	_snwprintf(output, outputCount - 1, L"\"%s\"", value);
	output[outputCount - 1] = L'\0';
}

static int RunChild(LPCWSTR resumedEventName)
{
	HANDLE resumed = OpenEventW(EVENT_MODIFY_STATE, FALSE, resumedEventName);
	if (!resumed)
		return 20;
	SetEvent(resumed);
	CloseHandle(resumed);
	return 0;
}

struct GuardChildPids
{
	DWORD orphaned;
	DWORD excluded;
};

static BOOL StartSuspendedChild(LPCWSTR resumedEventName, DWORD *processId)
{
	if (!processId)
		return FALSE;
	WCHAR modulePath[MAX_PATH] = L"";
	GetModuleFileNameW(NULL, modulePath, _countof(modulePath));
	WCHAR quotedModule[MAX_PATH * 2] = L"";
	WCHAR quotedEvent[256] = L"";
	Quote(quotedModule, _countof(quotedModule), modulePath);
	Quote(quotedEvent, _countof(quotedEvent), resumedEventName);
	WCHAR commandLine[1024] = L"";
	_snwprintf(commandLine, _countof(commandLine) - 1,
		L"%s --child %s", quotedModule, quotedEvent);
	commandLine[_countof(commandLine) - 1] = L'\0';

	STARTUPINFOW startup = { sizeof(startup) };
	PROCESS_INFORMATION process = { 0 };
	if (!CreateProcessW(NULL, commandLine, NULL, NULL, FALSE,
		CREATE_SUSPENDED, NULL, NULL, &startup, &process))
	{
		return FALSE;
	}
	*processId = process.dwProcessId;
	CloseHandle(process.hThread);
	CloseHandle(process.hProcess);
	return TRUE;
}

static int RunParent(
	LPCWSTR mappingName,
	LPCWSTR readyEventName,
	LPCWSTR resumedEventName,
	LPCWSTR excludedEventName)
{
	HANDLE mapping = OpenFileMappingW(FILE_MAP_WRITE, FALSE, mappingName);
	HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, readyEventName);
	if (!mapping || !ready)
		return 21;
	GuardChildPids *childPids = static_cast<GuardChildPids *>(MapViewOfFile(
		mapping, FILE_MAP_WRITE, 0, 0, sizeof(GuardChildPids)));
	if (!childPids)
		return 22;
	if (!StartSuspendedChild(resumedEventName, &childPids->orphaned) ||
		!StartSuspendedChild(excludedEventName, &childPids->excluded))
	{
		return 23;
	}
	FlushViewOfFile(childPids, sizeof(*childPids));
	SetEvent(ready);
	UnmapViewOfFile(childPids);
	CloseHandle(mapping);
	CloseHandle(ready);
	// Deliberately exit without ResumeThread: the host PRC must recognize and
	// terminate this marked, old, single-threaded orphan after two observations.
	return 0;
}

static BOOL NotifyReleasedChild(IGlobalProxy *proxy, DWORD processId)
{
	if (!proxy || !processId)
		return FALSE;
	IProxyReceptionCentre *receptionCentre = proxy->GetPRCInstance();
	char pipeName[MAX_PATH] = "";
	if (!receptionCentre ||
		!receptionCentre->GetPRCPipeName(pipeName, _countof(pipeName)))
	{
		return FALSE;
	}
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (!process)
		return FALSE;
	HookNewProcessInfo child = { 0 };
	child.dwProcessId = processId;
	child.processCreateTime = ProcessCreateTime(process);
	CloseHandle(process);
	if (!child.processCreateTime)
		return FALSE;

	HANDLE pipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (pipe == INVALID_HANDLE_VALUE)
		return FALSE;
	PRCPipeDataHead header = { 0 };
	header.action = PRCPD_CHILD_RELEASED;
	header.dataSize = sizeof(child);
	DWORD written = 0;
	const BOOL result = WriteFile(pipe, &header, sizeof(header), &written,
		NULL) && written == sizeof(header) &&
		WriteFile(pipe, &child, sizeof(child), &written, NULL) &&
		written == sizeof(child);
	CloseHandle(pipe);
	return result;
}

static void CleanupChild(DWORD processId)
{
	if (!processId)
		return;
	HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE,
		processId);
	if (process)
	{
		if (WaitForSingleObject(process, 0) == WAIT_TIMEOUT)
			TerminateProcess(process, 99);
		CloseHandle(process);
	}
}

static DWORD WaitWithMessagePump(HANDLE object, DWORD timeout)
{
	const DWORD started = GetTickCount();
	for (;;)
	{
		const DWORD elapsed = GetTickCount() - started;
		if (elapsed >= timeout)
			return WAIT_TIMEOUT;
		const DWORD result = MsgWaitForMultipleObjects(1, &object, FALSE,
			timeout - elapsed, QS_ALLINPUT);
		if (result == WAIT_OBJECT_0 || result == WAIT_TIMEOUT ||
			result == WAIT_FAILED)
		{
			return result;
		}
		MSG message;
		while (PeekMessage(&message, NULL, 0, 0, PM_REMOVE))
		{
			TranslateMessage(&message);
			DispatchMessage(&message);
		}
	}
}

static int RunHost()
{
	WCHAR suffix[64] = L"";
	_snwprintf(suffix, _countof(suffix) - 1, L"%lu_%lu",
		GetCurrentProcessId(), GetTickCount());
	WCHAR mappingName[128] = L"Local\\ProxyLaneGuardMap_";
	WCHAR readyEventName[128] = L"Local\\ProxyLaneGuardReady_";
	WCHAR resumedEventName[128] = L"Local\\ProxyLaneGuardResumed_";
	WCHAR excludedEventName[128] = L"Local\\ProxyLaneGuardExcluded_";
	wcsncat(mappingName, suffix,
		_countof(mappingName) - wcslen(mappingName) - 1);
	wcsncat(readyEventName, suffix,
		_countof(readyEventName) - wcslen(readyEventName) - 1);
	wcsncat(resumedEventName, suffix,
		_countof(resumedEventName) - wcslen(resumedEventName) - 1);
	wcsncat(excludedEventName, suffix,
		_countof(excludedEventName) - wcslen(excludedEventName) - 1);

	HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
		PAGE_READWRITE, 0, sizeof(GuardChildPids), mappingName);
	HANDLE ready = CreateEventW(NULL, TRUE, FALSE, readyEventName);
	HANDLE resumed = CreateEventW(NULL, TRUE, FALSE, resumedEventName);
	HANDLE excluded = CreateEventW(NULL, TRUE, FALSE, excludedEventName);
	if (!mapping || !ready || !resumed || !excluded)
		return 10;
	GuardChildPids *childPids = static_cast<GuardChildPids *>(MapViewOfFile(
		mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(GuardChildPids)));
	if (!childPids)
		return 11;
	ZeroMemory(childPids, sizeof(*childPids));

	WCHAR markerName[64] = L"PLCGWATCHDOGTEST";
	const ULONGLONG generationTime = ProcessCreateTime(GetCurrentProcess());
	if (!SetProxyLaneChildGuardInfo(markerName, generationTime) ||
		!SetEnvironmentVariableW(markerName, L"1"))
	{
		return 12;
	}

	IGlobalProxy *proxy = GetGlobalProxyInstance();
	if (!proxy || !proxy->EnableProxy())
		return 13;

	WCHAR modulePath[MAX_PATH] = L"";
	GetModuleFileNameW(NULL, modulePath, _countof(modulePath));
	WCHAR quotedModule[MAX_PATH * 2] = L"";
	WCHAR quotedMapping[256] = L"";
	WCHAR quotedReady[256] = L"";
	WCHAR quotedResumed[256] = L"";
	WCHAR quotedExcluded[256] = L"";
	Quote(quotedModule, _countof(quotedModule), modulePath);
	Quote(quotedMapping, _countof(quotedMapping), mappingName);
	Quote(quotedReady, _countof(quotedReady), readyEventName);
	Quote(quotedResumed, _countof(quotedResumed), resumedEventName);
	Quote(quotedExcluded, _countof(quotedExcluded), excludedEventName);
	WCHAR commandLine[1536] = L"";
	_snwprintf(commandLine, _countof(commandLine) - 1,
		L"%s --parent %s %s %s %s", quotedModule, quotedMapping,
		quotedReady, quotedResumed, quotedExcluded);
	commandLine[_countof(commandLine) - 1] = L'\0';

	STARTUPINFOW startup = { sizeof(startup) };
	PROCESS_INFORMATION parent = { 0 };
	int result = 14;
	if (CreateProcessW(NULL, commandLine, NULL, NULL, FALSE, 0,
		NULL, NULL, &startup, &parent))
	{
		CloseHandle(parent.hThread);
		if (WaitWithMessagePump(ready, 10000) == WAIT_OBJECT_0)
		{
			WaitForSingleObject(parent.hProcess, 10000);
			HANDLE orphanedProcess = OpenProcess(SYNCHRONIZE, FALSE,
				childPids->orphaned);
			if (!orphanedProcess)
				result = 17;
			else if (!NotifyReleasedChild(proxy, childPids->excluded))
				result = 16;
			else
			{
				// 60-second minimum age plus two 30-second checks.  Allow scheduling
				// margin without making the production watchdog more aggressive.
				result = WaitWithMessagePump(orphanedProcess, 125000) == WAIT_OBJECT_0 &&
					WaitForSingleObject(resumed, 0) == WAIT_TIMEOUT &&
					WaitForSingleObject(excluded, 0) == WAIT_TIMEOUT ? 0 : 15;
			}
			if (orphanedProcess)
				CloseHandle(orphanedProcess);
		}
		CloseHandle(parent.hProcess);
	}

	CleanupChild(childPids->orphaned);
	CleanupChild(childPids->excluded);
	proxy->DisableProxy();
	ReleaseGlobalProxyInstance();
	SetEnvironmentVariableW(markerName, NULL);
	UnmapViewOfFile(childPids);
	CloseHandle(mapping);
	CloseHandle(ready);
	CloseHandle(resumed);
	CloseHandle(excluded);
	if (!result)
		wprintf(L"Child guard watchdog test passed.\n");
	return result;
}

int wmain(int argc, wchar_t **argv)
{
	if (argc == 3 && _wcsicmp(argv[1], L"--child") == 0)
		return RunChild(argv[2]);
	if (argc == 6 && _wcsicmp(argv[1], L"--parent") == 0)
		return RunParent(argv[2], argv[3], argv[4], argv[5]);
	return RunHost();
}
