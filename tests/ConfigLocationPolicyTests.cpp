#include "ConfigLocationPolicy.h"
#include <iostream>

using namespace ConfigLocationPolicy;

namespace
{
	int g_failures = 0;

	void Check(bool condition, const char* name)
	{
		if (condition)
			return;
		std::cerr << "ConfigLocationPolicy failed: " << name << std::endl;
		++g_failures;
	}
}

int ConfigLocationPolicyTestsMain()
{
	const std::wstring exe = L"D:\\Tools\\ProxyLane\\ProxyLane64.exe";
	const std::wstring beside = L"D:\\Tools\\ProxyLane\\ProxyLane.ini";
	const std::wstring appData = L"C:\\Users\\demo\\AppData\\Roaming";
	const std::wstring roaming = appData + L"\\ProxyLane\\ProxyLane.ini";

	Check(BesideExecutable(exe) == beside, "x64 shares the Win32 ini");
	Check(BesideExecutable(L"D:\\a.b\\ProxyLane.exe") == L"D:\\a.b\\ProxyLane.ini", "dot in directory");
	Check(DirectoryOf(beside) == L"D:\\Tools\\ProxyLane", "directory of path");

	Check(Resolve(exe, appData, false, false) == roaming, "fresh install uses the user profile");
	Check(Resolve(exe, appData, false, true) == beside, "existing ini stays in place");
	Check(Resolve(exe, appData, true, false) == beside, "portable flag stays beside the program");
	Check(Resolve(exe, L"", false, false) == beside, "no user profile falls back");

	std::vector<std::wstring> names;
	names.push_back(L"ProxyLane-20261102-090000.ini");
	names.push_back(L"ProxyLane-20261001-090000.ini");
	names.push_back(L"ProxyLane-20261103-090000.ini");
	Check(BackupsToPrune(names, 3).empty(), "nothing to prune at the limit");
	names.push_back(L"ProxyLane-20260901-090000.ini");
	const std::vector<std::wstring> stale = BackupsToPrune(names, 3);
	Check(stale.size() == 1 && stale[0] == L"ProxyLane-20260901-090000.ini", "oldest backup is pruned");

	return g_failures ? 1 : 0;
}
