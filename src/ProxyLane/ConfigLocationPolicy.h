#pragma once

#include <algorithm>
#include <string>
#include <vector>

// Path rules for the settings file, free of MFC so unit tests can cover them.
namespace ConfigLocationPolicy
{
	// ProxyLane.exe and ProxyLane64.exe share one ProxyLane.ini.
	inline std::wstring BesideExecutable(const std::wstring& executable)
	{
		const size_t slash = executable.find_last_of(L"\\/");
		const size_t dot = executable.find_last_of(L'.');
		std::wstring stem = dot != std::wstring::npos && (slash == std::wstring::npos || dot > slash)
			? executable.substr(0, dot) : executable;
		if (stem.size() >= 2 && stem.compare(stem.size() - 2, 2, L"64") == 0)
			stem.resize(stem.size() - 2);
		return stem + L".ini";
	}

	inline std::wstring DirectoryOf(const std::wstring& path)
	{
		const size_t slash = path.find_last_of(L"\\/");
		return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
	}

	// An existing INI beside the executable keeps working in place, so current
	// installs and portable copies are never moved behind the user's back.
	inline std::wstring Resolve(const std::wstring& executable, const std::wstring& appData,
		bool portableFlagExists, bool besideExists)
	{
		if (portableFlagExists || besideExists || appData.empty())
			return BesideExecutable(executable);
		return appData + L"\\ProxyLane\\ProxyLane.ini";
	}

	// Backup names sort by timestamp; returns the oldest ones beyond keep.
	inline std::vector<std::wstring> BackupsToPrune(std::vector<std::wstring> names, size_t keep)
	{
		std::sort(names.begin(), names.end());
		if (names.size() <= keep)
			return std::vector<std::wstring>();
		names.resize(names.size() - keep);
		return names;
	}
}
