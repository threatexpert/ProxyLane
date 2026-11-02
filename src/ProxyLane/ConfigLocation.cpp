#include "stdafx.h"
#include "ConfigLocation.h"
#include "ConfigLocationPolicy.h"
#include <shlobj.h>
#include <string>
#include <vector>

namespace
{
	const size_t kBackupsToKeep = 3;
	CString g_settingsPath;

	// Matches examples/ProxyLane.ini: what a fresh release used to ship with.
	const wchar_t kDefaultSettings[] =
		L"\xFEFF[options]\r\n"
		L"testhost=www.baidu.com:80\r\n"
		L"IPv6TestAddress=2001:4860:4860::8888\r\n"
		L"lastselected=Test\r\n"
		L"DisableLLMNR=1\r\n"
		L"DisableMDNS=1\r\n"
		L"DecryptHTTPS=1\r\n"
		L"DecryptQUIC=1\r\n"
		L"\r\n"
		L"[proxy_Test]\r\n"
		L"HookChildProcess=1\r\nHookTCP=1\r\nHookUDP=0\r\nBlockUDP=1\r\nBlockIPv6=0\r\n"
		L"dnsOpt=1\r\nChildFilter=\r\nChildFilterMode=1\r\nTargetFilter=\r\nTargetFilterMode=1\r\n"
		L"Type=SOCKS5\r\nHost=127.0.0.1\r\nPort=1080\r\nUser=\r\nPass=\r\nTransport=PLAIN\r\nPSK=\r\n"
		L"\r\n"
		L"[proxy_Direct]\r\n"
		L"HookChildProcess=1\r\nHookTCP=1\r\nHookUDP=1\r\nBlockUDP=0\r\nBlockIPv6=0\r\n"
		L"dnsOpt=1\r\nRedirectPrivateDNS=0\r\nRedirectDNS=\r\nChildFilter=\r\nChildFilterMode=1\r\n"
		L"TargetFilter=\r\nTargetFilterMode=1\r\n"
		L"Type=NOPROXY\r\nHost=\r\nPort=0\r\nUser=\r\nPass=\r\nTransport=PLAIN\r\nPSK=\r\n";

	bool FileExists(const std::wstring& path)
	{
		const DWORD attributes = GetFileAttributesW(path.c_str());
		return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
	}

	std::wstring ExecutablePath()
	{
		wchar_t path[MAX_PATH] = { 0 };
		GetModuleFileNameW(NULL, path, _countof(path));
		return path;
	}

	std::wstring RoamingDirectory()
	{
		wchar_t path[MAX_PATH] = { 0 };
		return SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, path)) ? path : L"";
	}

	bool ReadWholeFile(const std::wstring& path, std::vector<BYTE>& contents)
	{
		HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, 0, NULL);
		if (file == INVALID_HANDLE_VALUE)
			return false;
		const DWORD size = GetFileSize(file, NULL);
		contents.resize(size);
		DWORD read = 0;
		const bool ok = size != INVALID_FILE_SIZE
			&& (!size || ReadFile(file, &contents[0], size, &read, NULL)) && read == size;
		CloseHandle(file);
		return ok;
	}

	void WriteDefaults(const std::wstring& path)
	{
		// CREATE_NEW leaves a file written by a concurrent instance alone. The BOM
		// makes the profile APIs store names and paths as UTF-16.
		HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE)
			return;
		DWORD written = 0;
		WriteFile(file, kDefaultSettings, sizeof(kDefaultSettings) - sizeof(wchar_t), &written, NULL);
		CloseHandle(file);
	}

	std::vector<std::wstring> ListBackups(const std::wstring& directory)
	{
		std::vector<std::wstring> names;
		WIN32_FIND_DATAW found;
		HANDLE search = FindFirstFileW((directory + L"\\ProxyLane-*.ini").c_str(), &found);
		if (search == INVALID_HANDLE_VALUE)
			return names;
		do { names.push_back(found.cFileName); } while (FindNextFileW(search, &found));
		FindClose(search);
		return names;
	}

	void BackupIfChanged(const std::wstring& path)
	{
		std::vector<BYTE> current;
		if (!ReadWholeFile(path, current) || current.empty())
			return;

		const std::wstring directory = ConfigLocationPolicy::DirectoryOf(path) + L"\\backups";
		CreateDirectoryW(directory.c_str(), NULL);
		std::vector<std::wstring> names = ListBackups(directory);
		if (!names.empty())
		{
			std::vector<BYTE> newest;
			if (ReadWholeFile(directory + L"\\" + *std::max_element(names.begin(), names.end()), newest)
				&& newest == current)
				return;
		}

		SYSTEMTIME now;
		GetLocalTime(&now);
		wchar_t name[64];
		swprintf_s(name, L"ProxyLane-%04u%02u%02u-%02u%02u%02u.ini",
			now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond);
		if (!CopyFileW(path.c_str(), (directory + L"\\" + name).c_str(), TRUE))
			return;
		names.push_back(name);
		const std::vector<std::wstring> stale = ConfigLocationPolicy::BackupsToPrune(names, kBackupsToKeep);
		for (size_t i = 0; i < stale.size(); ++i)
			DeleteFileW((directory + L"\\" + stale[i]).c_str());
	}
}

CString ConfigLocation::SettingsPath()
{
	if (g_settingsPath.IsEmpty())
	{
		const std::wstring executable = ExecutablePath();
		const std::wstring directory = ConfigLocationPolicy::DirectoryOf(executable);
		g_settingsPath = ConfigLocationPolicy::Resolve(executable, RoamingDirectory(),
			FileExists(directory + L"\\portable.flag"),
			FileExists(ConfigLocationPolicy::BesideExecutable(executable))).c_str();
	}
	return g_settingsPath;
}

void ConfigLocation::PrepareStorage()
{
	std::wstring path = (LPCWSTR)SettingsPath();
	const std::wstring directory = ConfigLocationPolicy::DirectoryOf(path);
	if (!CreateDirectoryW(directory.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
	{
		// The user profile is unusable; settings beside the program still work.
		path = ConfigLocationPolicy::BesideExecutable(ExecutablePath());
		g_settingsPath = path.c_str();
	}
	if (FileExists(path))
		BackupIfChanged(path);
	else
		WriteDefaults(path);
}
