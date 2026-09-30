#pragma once

#include <windows.h>

typedef BOOL(WINAPI* ProxyLaneCreateProcessWFunction)(
	LPCWSTR applicationName,
	LPWSTR commandLine,
	LPSECURITY_ATTRIBUTES processAttributes,
	LPSECURITY_ATTRIBUTES threadAttributes,
	BOOL inheritHandles,
	DWORD creationFlags,
	LPVOID environment,
	LPCWSTR currentDirectory,
	LPSTARTUPINFOW startupInfo,
	LPPROCESS_INFORMATION processInformation);

// Inject the matching Hook module using handles returned by process creation,
// including when the target belongs to a different user. On Vista+ the
// cross-bitness helper inherits only these two handles through an allowlist.
// A hooked parent supplies its original CreateProcess trampoline so an internal cross-bitness
// rundll32 launch does not recursively enter the child-process proxy path.
BOOL ProxyLaneInjectSuspendedProcess(
	HANDLE targetProcess,
	HANDLE targetThread,
	DWORD processId,
	DWORD threadId,
	LPCSTR pipeName,
	ProxyLaneCreateProcessWFunction createProcessFunction);

// Elevated rundll32 entry point hosted by the existing Hook DLL.
void CALLBACK ElevatedLaunch(HWND hwnd, HINSTANCE instance, LPSTR commandLine, int showCommand);
