#include "stdafx.h"
#include "ElevatedLauncher.h"
#include "ElevatedLaunchProtocol.h"
#include "ProxyModule.h"

#include <strsafe.h>
#include <vector>

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

	BOOL Utf8FieldToWide(
		const BYTE* source,
		DWORD sourceLength,
		size_t maximumCharacterCount,
		std::vector<WCHAR>& destination)
	{
		destination.clear();
		if (!sourceLength)
		{
			destination.push_back(L'\0');
			return TRUE;
		}

		const int requiredLength = MultiByteToWideChar(
			CP_UTF8,
			MB_ERR_INVALID_CHARS,
			reinterpret_cast<LPCSTR>(source),
			static_cast<int>(sourceLength),
			NULL,
			0);
		if (requiredLength <= 0 ||
			static_cast<size_t>(requiredLength) >= maximumCharacterCount)
		{
			return FALSE;
		}

		destination.resize(static_cast<size_t>(requiredLength) + 1, L'\0');
		if (MultiByteToWideChar(
			CP_UTF8,
			MB_ERR_INVALID_CHARS,
			reinterpret_cast<LPCSTR>(source),
			static_cast<int>(sourceLength),
			&destination[0],
			requiredLength) != requiredLength)
		{
			return FALSE;
		}

		for (int index = 0; index < requiredLength; ++index)
		{
			if (destination[index] == L'\0')
				return FALSE;
		}
		return TRUE;
	}

	BOOL ValidateDecodedElevatedRequest(
		const std::vector<WCHAR>& targetPath,
		const std::vector<WCHAR>& commandLine,
		const std::vector<WCHAR>& workingDirectory,
		const std::vector<CHAR>& pipeName)
	{
		if (targetPath.size() <= 1 || commandLine.size() <= 1 || pipeName.size() <= 1)
			return FALSE;

		const size_t targetLength = targetPath.size() - 1;
		const BOOL targetDriveAbsolute =
			targetLength >= 3 && targetPath[1] == L':' &&
			(targetPath[2] == L'\\' || targetPath[2] == L'/');
		const BOOL targetUncAbsolute =
			targetLength >= 2 && targetPath[0] == L'\\' && targetPath[1] == L'\\';
		if (!targetDriveAbsolute && !targetUncAbsolute)
			return FALSE;

		if (workingDirectory.size() > 1)
		{
			const size_t directoryLength = workingDirectory.size() - 1;
			const BOOL directoryDriveAbsolute =
				directoryLength >= 3 && workingDirectory[1] == L':' &&
				(workingDirectory[2] == L'\\' || workingDirectory[2] == L'/');
			const BOOL directoryUncAbsolute =
				directoryLength >= 2 && workingDirectory[0] == L'\\' &&
				workingDirectory[1] == L'\\';
			if (!directoryDriveAbsolute && !directoryUncAbsolute)
				return FALSE;
		}

		static const char pipePrefix[] = "\\\\.\\pipe\\PRCPipeName";
		return pipeName.size() - 1 >= sizeof(pipePrefix) - 1 &&
			memcmp(&pipeName[0], pipePrefix, sizeof(pipePrefix) - 1) == 0;
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

	const char* encodedRequest = commandLine + sizeof(requestPrefix) - 1;
	const size_t encodedLength = strlen(encodedRequest);
	const size_t decodedCapacity = ProxyLaneBase64UrlDecodedLength(encodedLength);
	if (decodedCapacity == static_cast<size_t>(-1) ||
		decodedCapacity < sizeof(ProxyLaneElevatedLaunchWireHeader) ||
		decodedCapacity > PROXYLANE_ELEVATED_MAX_WIRE_BYTES)
	{
		ExitProcess(PROXYLANE_ELEVATED_INVALID_REQUEST);
	}

	std::vector<BYTE> decodedRequest(decodedCapacity);
	size_t decodedLength = 0;
	ProxyLaneElevatedLaunchRequestView request = { 0 };
	if (!ProxyLaneBase64UrlDecode(
		encodedRequest,
		encodedLength,
		&decodedRequest[0],
		decodedRequest.size(),
		&decodedLength) ||
		!ProxyLaneParseElevatedRequest(&decodedRequest[0], decodedLength, &request))
	{
		ExitProcess(PROXYLANE_ELEVATED_INVALID_REQUEST);
	}

	std::vector<WCHAR> targetPath;
	std::vector<WCHAR> targetCommandLine;
	std::vector<WCHAR> workingDirectory;
	std::vector<CHAR> pipeName;
	if (!Utf8FieldToWide(
		request.targetPath,
		request.targetPathBytes,
		PROXYLANE_ELEVATED_TARGET_CCH,
		targetPath) ||
		!Utf8FieldToWide(
			request.commandLine,
			request.commandLineBytes,
			PROXYLANE_ELEVATED_COMMAND_CCH,
			targetCommandLine) ||
		!Utf8FieldToWide(
			request.workingDirectory,
			request.workingDirectoryBytes,
			PROXYLANE_ELEVATED_DIRECTORY_CCH,
			workingDirectory) ||
		!request.pipeNameBytes ||
		request.pipeNameBytes >= PROXYLANE_ELEVATED_PIPE_CCH)
	{
		ExitProcess(PROXYLANE_ELEVATED_INVALID_REQUEST);
	}

	pipeName.resize(static_cast<size_t>(request.pipeNameBytes) + 1, '\0');
	memcpy(&pipeName[0], request.pipeName, request.pipeNameBytes);
	for (DWORD index = 0; index < request.pipeNameBytes; ++index)
	{
		if (pipeName[index] == '\0')
			ExitProcess(PROXYLANE_ELEVATED_INVALID_REQUEST);
	}
	if (!ValidateDecodedElevatedRequest(
		targetPath,
		targetCommandLine,
		workingDirectory,
		pipeName))
	{
		ExitProcess(PROXYLANE_ELEVATED_INVALID_REQUEST);
	}

	if (!IsCurrentProcessElevated())
		ExitProcess(PROXYLANE_ELEVATED_NOT_ELEVATED);

	const DWORD attributes = GetFileAttributesW(&targetPath[0]);
	if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
		ExitProcess(PROXYLANE_ELEVATED_INVALID_TARGET);

	STARTUPINFOW startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	PROCESS_INFORMATION processInfo = { 0 };
	if (!CreateProcessW(
		&targetPath[0],
		&targetCommandLine[0],
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		workingDirectory[0] ? &workingDirectory[0] : NULL,
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
		&pipeName[0],
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
