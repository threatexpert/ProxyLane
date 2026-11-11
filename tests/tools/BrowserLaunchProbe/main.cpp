#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static DWORD watchedPid;
static UINT shellMessage;
static LRESULT CALLBACK ProbeWindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	if (message == WM_APP + 20) return SetForegroundWindow(window);
	if (message == WM_APP + 21) return AllowSetForegroundWindow(static_cast<DWORD>(wparam));
	if (message == WM_APP + 22) return LockSetForegroundWindow(static_cast<UINT>(wparam));
	if (message == WM_APP + 23) { watchedPid = static_cast<DWORD>(wparam); return 0; }
	if (message == WM_APP + 24)
	{
		DWORD pid = 0;
		GetWindowThreadProcessId(reinterpret_cast<HWND>(wparam), &pid);
		return pid == watchedPid && SetForegroundWindow(reinterpret_cast<HWND>(wparam));
	}
	if (message == shellMessage && wparam == HSHELL_FLASH && watchedPid)
	{
		DWORD pid = 0;
		GetWindowThreadProcessId(reinterpret_cast<HWND>(lparam), &pid);
		if (pid == watchedPid)
		{
			FILE* output = NULL;
			if (!_wfopen_s(&output, L"attention.log", L"a"))
			{
				fprintf(output, "flash %lu\n", pid);
				fclose(output);
			}
		}
		return 0;
	}
	if (message == WM_TIMER || message == WM_CLOSE)
	{
		LockSetForegroundWindow(LSFW_UNLOCK);
		DestroyWindow(window);
		return 0;
	}
	if (message == WM_DESTROY) { PostQuitMessage(0); return 0; }
	return DefWindowProcW(window, message, wparam, lparam);
}

static void HoldWindow()
{
	WNDCLASSW type = {};
	type.lpfnWndProc = ProbeWindowProc;
	type.hInstance = GetModuleHandleW(NULL);
	type.lpszClassName = L"ProxyLaneBrowserProbe";
	type.hCursor = LoadCursor(NULL, IDC_ARROW);
	type.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	RegisterClassW(&type);
	HWND window = CreateWindowW(type.lpszClassName, L"ProxyLane test browser", WS_OVERLAPPEDWINDOW,
		100, 100, 450, 200, NULL, NULL, type.hInstance, NULL);
	shellMessage = RegisterWindowMessageW(L"SHELLHOOK");
	RegisterShellHookWindow(window);
	ShowWindow(window, SW_SHOW);
	SetTimer(window, 1, 180000, NULL);
	MSG message;
	while (GetMessageW(&message, NULL, 0, 0) > 0)
	{
		TranslateMessage(&message);
		DispatchMessageW(&message);
	}
}

// Test-only executable, copied as msedge.exe/chrome.exe into disposable folders.
// Never launches or contacts a real browser or makes network requests.
int wmain(int argc, wchar_t** argv)
{
	if (argc > 1 && !wcscmp(argv[1], L"--hold"))
	{
		if (argc > 2 && !wcscmp(argv[2], L"--tree"))
		{
			WCHAR executable[MAX_PATH];
			GetModuleFileNameW(NULL, executable, MAX_PATH);
			const WCHAR* roles[] = {
				L"--type=utility --utility-sub-type=network.mojom.NetworkService", L"--type=renderer"
			};
			for (const WCHAR* role : roles)
			{
				WCHAR command[1024];
				swprintf_s(command, L"\"%s\" --hold %s", executable, role);
				STARTUPINFOW startup = {sizeof(startup)};
				PROCESS_INFORMATION process = {};
				if (!CreateProcessW(executable, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) return 1;
				CloseHandle(process.hThread);
				CloseHandle(process.hProcess);
			}
		}
		bool window = false;
		for (int i = 2; i < argc; ++i) if (!wcscmp(argv[i], L"--window")) window = true;
		if (window) HoldWindow();
		else Sleep(180000);
		return 0;
	}
	FILE* output = NULL;
	if (!_wfopen_s(&output, L"launched.pid", L"w"))
	{
		fprintf(output, "%lu", GetCurrentProcessId());
		fclose(output);
	}
	Sleep(GetFileAttributesW(L"stay.flag") != INVALID_FILE_ATTRIBUTES ? 8000 :
		GetFileAttributesW(L"late.flag") != INVALID_FILE_ATTRIBUTES ? 3000 : 200);
	return 0;
}
