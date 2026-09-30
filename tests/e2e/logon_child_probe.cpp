// Credentials are supplied only through a transient environment variable.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")

static bool Hooked()
{
	return GetModuleHandleW(L"ProxyLaneHook32.dll") || GetModuleHandleW(L"ProxyLaneHook64.dll");
}

static DWORD WaitChild(PROCESS_INFORMATION& pi)
{
	DWORD code = 99;
	if (WaitForSingleObject(pi.hProcess, 30000) != WAIT_OBJECT_0)
		TerminateProcess(pi.hProcess, 99);
	else
		GetExitCodeProcess(pi.hProcess, &code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return code;
}

static int Child(int argc, wchar_t** argv)
{
	if (argc != 7) return 10;
	WCHAR user[256] = L"";
	DWORD length = 256;
	GetUserNameW(user, &length);
	bool good = Hooked() && _wcsicmp(user, argv[2]) == 0;
	WCHAR value[256] = L"";
	GetEnvironmentVariableW(L"PL_LOGON_PROBE", value, 256);
	if (wcscmp(argv[6], L"null") == 0)
	{
		// NULL must use the other user's profile, never inherit our sentinel.
		good = good && value[0] == 0;
		GetEnvironmentVariableW(L"USERNAME", value, 256);
		good = good && _wcsicmp(value, argv[2]) == 0;
	}
	else good = good && wcscmp(value, L"explicit") == 0;
	WSADATA data;
	int startupError = WSAStartup(MAKEWORD(2, 2), &data);
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	DWORD timeout = 10000;
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	sockaddr_in address = {};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr("203.0.113.10");
	address.sin_port = htons((u_short)_wtoi(argv[4]));
	int connected = connect(s, (sockaddr*)&address, sizeof(address));
	int connectError = connected ? WSAGetLastError() : 0;
	char reply[4] = {};
	bool network = connected == 0 && send(s, "PING", 4, 0) == 4 && recv(s, reply, 4, MSG_WAITALL) == 4 && memcmp(reply, "PONG", 4) == 0;
	closesocket(s);
	WSACleanup();
	FILE* report = _wfopen(argv[3], L"w");
	if (!report) return 11;
	fwprintf(report, L"user=%s hooked=%d network=%d environment=%d startup_error=%d connect_error=%d\n", user, Hooked(), network, good, startupError, connectError);
	fclose(report);
	if (!good || !network) return 12;
	if (wcscmp(argv[5], L"child") == 0)
	{
		WCHAR self[MAX_PATH];
		GetModuleFileNameW(NULL, self, MAX_PATH);
		std::wstring command = L"\"" + std::wstring(self) + L"\" --child \"" + argv[2] + L"\" \"" + argv[3] + L".grandchild\" " + argv[4] + L" grandchild " + argv[6];
		STARTUPINFOW si = {sizeof(si)};
		PROCESS_INFORMATION pi = {};
		if (!CreateProcessW(NULL, &command[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return 13;
		return WaitChild(pi);
	}
	return 0;
}

int wmain(int argc, wchar_t** argv)
{
	if (argc == 2 && wcscmp(argv[1], L"--hold") == 0) { Sleep(15000); return 0; }
	if (argc > 1 && wcscmp(argv[1], L"--child") == 0) return Child(argc, argv);
	if (argc != 8) return 20;
	// --parent user domain child-exe report target-port mode
	WCHAR password[256] = L"";
	if (!GetEnvironmentVariableW(L"PROXYLANE_TEST_PASSWORD", password, 256)) return 21;
	SetEnvironmentVariableW(L"PROXYLANE_TEST_PASSWORD", NULL);
	SetEnvironmentVariableW(L"PL_LOGON_PROBE", L"caller-only");
	std::wstring command = L"\"" + std::wstring(argv[4]) + L"\" --child \"" + argv[2] + L"\" \"" + argv[5] + L".child\" " + argv[6] + L" child " + argv[7];

	STARTUPINFOW si = {sizeof(si)};
	PROCESS_INFORMATION pi = {};
	DWORD flags = CREATE_NO_WINDOW;
	LPVOID environment = NULL;
	WCHAR windows[MAX_PATH] = L"";
	GetWindowsDirectoryW(windows, MAX_PATH);
	std::wstring entries = L"PL_LOGON_PROBE=explicit";
	entries.push_back(0);
	entries += L"SystemRoot=" + std::wstring(windows);
	entries.push_back(0);
	entries.push_back(0);
	LPVOID wideEnvironment = &entries[0];
	int bytes = WideCharToMultiByte(CP_ACP, 0, entries.data(), (int)entries.size(), NULL, 0, NULL, NULL);
	std::vector<char> ansi(bytes);
	WideCharToMultiByte(CP_ACP, 0, entries.data(), (int)entries.size(), &ansi[0], bytes, NULL, NULL);
	LPVOID ansiEnvironment = &ansi[0];
	if (wcscmp(argv[7], L"unicode") == 0) { environment = wideEnvironment; flags |= CREATE_UNICODE_ENVIRONMENT; }
	if (wcscmp(argv[7], L"ansi") == 0) environment = ansiEnvironment;
	if (wcscmp(argv[7], L"suspended") == 0) { environment = wideEnvironment; flags |= CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED; }
	const bool invalidFlags = wcscmp(argv[7], L"invalid-flags") == 0;
	const bool missingFile = wcscmp(argv[7], L"missing-file") == 0;
	std::wstring missing = std::wstring(windows) + L"\\ProxyLane-does-not-exist.exe";
	bool created = CreateProcessWithLogonW(argv[2], argv[3], password, LOGON_WITH_PROFILE,
		missingFile ? missing.c_str() : argv[4], &command[0], invalidFlags ? 0xffffffff : flags,
		environment, NULL, &si, &pi) != FALSE;
	DWORD error = GetLastError(), code = 98, resume = 0;
	SecureZeroMemory(password, sizeof(password));
	if (created)
	{
		if (flags & CREATE_SUSPENDED)
		{
			Sleep(150);
			// No child report may exist until the caller releases its suspension.
			std::wstring childReport = std::wstring(argv[5]) + L".child";
			if (GetFileAttributesW(childReport.c_str()) != INVALID_FILE_ATTRIBUTES) return 22;
			resume = ResumeThread(pi.hThread);
		}
		code = WaitChild(pi);
	}
	FILE* report = _wfopen(argv[5], L"w");
	if (!report) return 23;
	fwprintf(report, L"parent_hooked=%d created=%d error=%lu child_exit=%lu resume=%lu\n", Hooked(), created, error, code, resume);
	fclose(report);
	return created && code == 0 && (!(flags & CREATE_SUSPENDED) || resume == 1) ? 0 : 24;
}
