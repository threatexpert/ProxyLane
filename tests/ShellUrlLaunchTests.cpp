#include "stdafx.h"
#include "ShellUrlLaunch.h"
#include "AutomationOptions.h"
#include <iostream>
#include <stdexcept>

CWinApp application;
static void Check(bool result, const char* message) { if (!result) throw std::runtime_error(message); }

int wmain()
{
	if (!AfxWinInit(GetModuleHandle(NULL), NULL, GetCommandLine(), 0)) return 2;
	CoInitialize(NULL);
	try
	{
		const CString exe = L"C:\\Program Files\\Browser\\chrome.exe";
		const CString url = L"https://example.invalid/login?a=1&b=%PL_URL_TEST%&c=%22x%22&d=%25#fragment";
		SetEnvironmentVariableW(L"PL_URL_TEST", L"must not appear in URL");
		SetEnvironmentVariableW(L"PL_URL_PROFILE", L"profile with spaces");
		CString arguments;
		Check(ShellUrlLaunch::BuildCommand(url, exe, L"\"" + exe + L"\" --single-argument %1", arguments) == S_OK &&
			arguments == L"--single-argument " + url, "Chromium raw URL tail");
		Check(ShellUrlLaunch::BuildCommand(url, exe, L"\"" + exe + L"\" --single-argument=%1", arguments) == S_OK &&
			arguments == L"--single-argument=" + url, "legacy Chromium raw URL tail");
		Check(ShellUrlLaunch::BuildCommand(url, exe, L"\"" + exe + L"\" --profile \"%PL_URL_PROFILE%\" \"%1\"", arguments) == S_OK,
			"ordinary command template");
		int count = 0;
		LPWSTR* argv = CommandLineToArgvW(L"browser.exe " + arguments, &count);
		Check(argv && count == 4 && !wcscmp(argv[1], L"--profile") && !wcscmp(argv[2], L"profile with spaces") &&
			url == argv[3], "URL remains one literal argument, environment expanded only in template");
		LocalFree(argv);
		Check(ShellUrlLaunch::BuildCommand(L"HTTP://example.invalid/a b", exe, L"\"" + exe + L"\" %L", arguments) == S_OK &&
			arguments == L"\"HTTP://example.invalid/a b\"", "case insensitive scheme and quoted URL argument");
		const LPCWSTR invalid[] = {L" --single-argument %1 --other", L" %1 %1", L" --url=%1", L" %2", L" --new-window", L" %1 %UNKNOWN_VARIABLE%"};
		for (const auto pattern : invalid)
			Check(FAILED(ShellUrlLaunch::BuildCommand(url, exe, L"\"" + exe + L"\"" + pattern, arguments)) && arguments.IsEmpty(), "unsupported template rejected atomically");
		Check(FAILED(ShellUrlLaunch::BuildCommand(L"https://example.invalid/\" --evil", exe, L"\"" + exe + L"\" %1", arguments)), "raw quote rejected");
		Check(FAILED(ShellUrlLaunch::BuildCommand(L"https://", exe, L"\"" + exe + L"\" %1", arguments)), "empty authority rejected");
		Check(FAILED(ShellUrlLaunch::BuildCommand(url, exe, L"other.exe %1", arguments)), "executable mismatch rejected");
		CString image;
		Check(ShellUrlLaunch::Resolve(L"C:\\test.exe", image, arguments) == S_FALSE, "non-URL is not resolved");
		for (const LPCWSTR protocol : {L"http://example.invalid/", L"https://example.invalid/"})
		{
			const HRESULT hr = ShellUrlLaunch::Resolve(protocol, image, arguments);
			std::wcout << L"Default association (read only): " << protocol << L" hr=0x" << std::hex << hr
				<< L" image=" << static_cast<LPCWSTR>(image) << L" args=" << static_cast<LPCWSTR>(arguments) << L"\n";
		}
		std::cout << "PASS: URL templates, quoting, literal URL data, environment and fail-closed parsing\n";
	}
	catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << "\n"; CoUninitialize(); return 1; }
	CoUninitialize();
	return 0;
}
