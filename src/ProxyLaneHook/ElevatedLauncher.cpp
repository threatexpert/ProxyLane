#include "stdafx.h"
#include "ElevatedLauncher.h"
#include "ElevatedLaunchProtocol.h"
#include "ProxyModule.h"

#include <strsafe.h>

extern HMODULE g_hDllModule;

namespace
{
	BOOL IsCurrentProcessElevated()
	{
		OSVERSIONINFO versionInfo = { 0 };
		versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
		if (GetVersionEx(&versionInfo) && versionInfo.dwMajorVersion < 6)
			return TRUE;

		HANDLE token = NULL;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
			return FALSE;

		TOKEN_ELEVATION elevation = { 0 };
		DWORD returnedSize = 0;
		const BOOL result = GetTokenInformation(
			token,
			TokenElevation,
			&elevation,
			sizeof(elevation),
			&returnedSize);
		CloseHandle(token);
		return result && elevation.TokenIsElevated;
	}

	BOOL IsWow64ProcessDynamic(HANDLE process)
	{
		typedef BOOL(WINAPI* IsWow64ProcessFunction)(HANDLE, PBOOL);
		IsWow64ProcessFunction function = reinterpret_cast<IsWow64ProcessFunction>(
			GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process"));
		BOOL wow64 = FALSE;
		return function && function(process, &wow64) && wow64;
	}

	BOOL Is64BitProcess(HANDLE process)
	{
#ifdef _WIN64
		return !IsWow64ProcessDynamic(process);
#else
		if (!IsWow64ProcessDynamic(GetCurrentProcess()))
			return FALSE;
		return !IsWow64ProcessDynamic(process);
#endif
	}

	BOOL IsCurrentModule64Bit()
	{
#ifdef _WIN64
		return TRUE;
#else
		return FALSE;
#endif
	}

	BOOL GetModuleDirectory(WCHAR* directory, size_t directoryCount)
	{
		if (!directory || directoryCount == 0)
			return FALSE;
		if (!GetModuleFileNameW(g_hDllModule, directory, static_cast<DWORD>(directoryCount)))
			return FALSE;
		directory[directoryCount - 1] = L'\0';
		WCHAR* slash = wcsrchr(directory, L'\\');
		if (!slash)
			return FALSE;
		*slash = L'\0';
		return TRUE;
	}

	BOOL BuildCompanionPaths(
		BOOL targetIs64Bit,
		WCHAR* hookPath,
		size_t hookPathCount,
		WCHAR* rundllPath,
		size_t rundllPathCount)
	{
		WCHAR moduleDirectory[MAX_PATH] = { 0 };
		WCHAR windowsDirectory[MAX_PATH] = { 0 };
		if (!GetModuleDirectory(moduleDirectory, _countof(moduleDirectory)) ||
			!GetWindowsDirectoryW(windowsDirectory, _countof(windowsDirectory)))
		{
			return FALSE;
		}

		if (FAILED(StringCchPrintfW(
			hookPath,
			hookPathCount,
			L"%s\\ProxyLaneHook%s.dll",
			moduleDirectory,
			targetIs64Bit ? L"64" : L"32")))
		{
			return FALSE;
		}

		const WCHAR* systemFolder = L"System32";
#ifdef _WIN64
		if (!targetIs64Bit)
			systemFolder = L"SysWOW64";
#else
		if (IsWow64ProcessDynamic(GetCurrentProcess()) && !targetIs64Bit)
			systemFolder = L"SysWOW64";
#endif
		if (FAILED(StringCchPrintfW(
			rundllPath,
			rundllPathCount,
			L"%s\\%s\\rundll32.exe",
			windowsDirectory,
			systemFolder)))
		{
			return FALSE;
		}

		const DWORD hookAttributes = GetFileAttributesW(hookPath);
		return hookAttributes != INVALID_FILE_ATTRIBUTES &&
			!(hookAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
			wcschr(hookPath, L',') == NULL;
	}

	BOOL SetWow64Redirection(BOOL disable, PVOID* oldValue)
	{
		typedef BOOL(WINAPI* DisableFunction)(PVOID*);
		typedef BOOL(WINAPI* RevertFunction)(PVOID);
		HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
		if (disable)
		{
			DisableFunction function = reinterpret_cast<DisableFunction>(
				GetProcAddress(kernel, "Wow64DisableWow64FsRedirection"));
			return function ? function(oldValue) : FALSE;
		}

		RevertFunction function = reinterpret_cast<RevertFunction>(
			GetProcAddress(kernel, "Wow64RevertWow64FsRedirection"));
		return function ? function(*oldValue) : FALSE;
	}

}

BOOL ProxyLaneInjectSuspendedProcess(
	HANDLE targetProcess,
	HANDLE targetThread,
	DWORD processId,
	DWORD threadId,
	LPCSTR pipeName,
	ProxyLaneCreateProcessWFunction createProcessFunction)
{
	if (!targetProcess || !targetThread || !pipeName || !pipeName[0])
		return FALSE;

	const BOOL targetIs64Bit = Is64BitProcess(targetProcess);
	if (targetIs64Bit == IsCurrentModule64Bit())
		return AttachToHandles(targetProcess, targetThread, pipeName) == 0xFF01;

	WCHAR hookPath[MAX_PATH] = { 0 };
	WCHAR rundllPath[MAX_PATH] = { 0 };
	if (!BuildCompanionPaths(
		targetIs64Bit,
		hookPath,
		_countof(hookPath),
		rundllPath,
		_countof(rundllPath)))
	{
		return FALSE;
	}

	WCHAR pipeNameWide[PROXYLANE_ELEVATED_PIPE_CCH] = { 0 };
	if (!MultiByteToWideChar(
		CP_ACP,
		0,
		pipeName,
		-1,
		pipeNameWide,
		_countof(pipeNameWide)))
	{
		return FALSE;
	}

	WCHAR helperCommand[1024] = { 0 };
	if (FAILED(StringCchPrintfW(
		helperCommand,
		_countof(helperCommand),
		L"\"%s\" \"%s\",AttachTo --pid=%lu --tid=%lu --pipe=%s",
		rundllPath,
		hookPath,
		processId,
		threadId,
		pipeNameWide)))
	{
		return FALSE;
	}

	STARTUPINFOW startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	PROCESS_INFORMATION processInfo = { 0 };
	PVOID oldRedirection = NULL;
	BOOL redirectionDisabled = FALSE;
#ifndef _WIN64
	if (targetIs64Bit && IsWow64ProcessDynamic(GetCurrentProcess()))
		redirectionDisabled = SetWow64Redirection(TRUE, &oldRedirection);
#endif
	if (!createProcessFunction)
		createProcessFunction = CreateProcessW;
	const BOOL created = createProcessFunction(
		NULL,
		helperCommand,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&startupInfo,
		&processInfo);
	if (redirectionDisabled)
		SetWow64Redirection(FALSE, &oldRedirection);
	if (!created)
		return FALSE;

	WaitForSingleObject(processInfo.hProcess, INFINITE);
	DWORD exitCode = 0;
	const BOOL gotExitCode = GetExitCodeProcess(processInfo.hProcess, &exitCode);
	CloseHandle(processInfo.hThread);
	CloseHandle(processInfo.hProcess);
	return gotExitCode && exitCode == 0xFF01;
}

void CALLBACK ElevatedLaunch(HWND, HINSTANCE, LPSTR commandLine, int)
{
	const char requestPrefix[] = "--request=";
	while (commandLine && (*commandLine == ' ' || *commandLine == '\t'))
		++commandLine;
	if (!commandLine || strncmp(commandLine, requestPrefix, sizeof(requestPrefix) - 1) != 0)
		ExitProcess(PROXYLANE_ELEVATED_INVALID_REQUEST);

	ProxyLaneElevatedLaunchRequest request;
	ZeroMemory(&request, sizeof(request));
	if (!ProxyLaneDecodeElevatedRequest(
		commandLine + sizeof(requestPrefix) - 1,
		&request) ||
		!ProxyLaneValidateElevatedRequest(request))
	{
		ExitProcess(PROXYLANE_ELEVATED_INVALID_REQUEST);
	}

	if (!IsCurrentProcessElevated())
		ExitProcess(PROXYLANE_ELEVATED_NOT_ELEVATED);

	const DWORD attributes = GetFileAttributesW(request.targetPath);
	if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
		ExitProcess(PROXYLANE_ELEVATED_INVALID_TARGET);

	WCHAR mutableCommandLine[PROXYLANE_ELEVATED_COMMAND_CCH] = { 0 };
	if (FAILED(StringCchCopyW(
		mutableCommandLine,
		_countof(mutableCommandLine),
		request.commandLine)))
	{
		ExitProcess(PROXYLANE_ELEVATED_INVALID_REQUEST);
	}

	STARTUPINFOW startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	PROCESS_INFORMATION processInfo = { 0 };
	if (!CreateProcessW(
		request.targetPath,
		mutableCommandLine,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		request.workingDirectory[0] ? request.workingDirectory : NULL,
		&startupInfo,
		&processInfo))
	{
		ExitProcess(PROXYLANE_ELEVATED_CREATE_FAILED);
	}

	if (!ProxyLaneInjectSuspendedProcess(
		processInfo.hProcess,
		processInfo.hThread,
		processInfo.dwProcessId,
		processInfo.dwThreadId,
		request.pipeName,
		CreateProcessW))
	{
		TerminateProcess(processInfo.hProcess, PROXYLANE_ELEVATED_INJECTION_FAILED);
		CloseHandle(processInfo.hThread);
		CloseHandle(processInfo.hProcess);
		ExitProcess(PROXYLANE_ELEVATED_INJECTION_FAILED);
	}

	if (ResumeThread(processInfo.hThread) == static_cast<DWORD>(-1))
	{
		TerminateProcess(processInfo.hProcess, PROXYLANE_ELEVATED_RESUME_FAILED);
		CloseHandle(processInfo.hThread);
		CloseHandle(processInfo.hProcess);
		ExitProcess(PROXYLANE_ELEVATED_RESUME_FAILED);
	}

	CloseHandle(processInfo.hThread);
	CloseHandle(processInfo.hProcess);
	ExitProcess(PROXYLANE_ELEVATED_SUCCESS);
}
