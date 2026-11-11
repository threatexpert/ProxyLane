#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <utility>

// Path enrichment only. The caller must recheck the snapshot's creation time
// after querying by PID, because this API does not bind a process lifetime.
namespace ProcessImagePath
{
	struct UnicodeString
	{
		USHORT length, maximumLength;
		PWSTR buffer;
	};
	struct ProcessIdInformation
	{
		HANDLE processId;
		UnicodeString imageName;
	};
#ifdef _WIN64
	static_assert(sizeof(ProcessIdInformation) == 24, "64-bit native path query layout");
#else
	static_assert(sizeof(ProcessIdInformation) == 12, "32-bit native path query layout");
#endif

	inline bool Query(DWORD pid, std::wstring& path)
	{
		path.clear();
		if (!pid) return false;
		typedef LONG (WINAPI *QuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		QuerySystemInformation query = ntdll ? reinterpret_cast<QuerySystemInformation>(
			GetProcAddress(ntdll, "NtQuerySystemInformation")) : NULL;
		if (!query) return false;
		std::vector<WCHAR> buffer(128);
		for (int attempt = 0; attempt < 4; ++attempt)
		{
			ProcessIdInformation info = {};
			info.processId = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
			info.imageName.maximumLength = static_cast<USHORT>(buffer.size() * sizeof(WCHAR));
			info.imageName.buffer = &buffer[0];
			const LONG status = query(88 /* SystemProcessIdInformation */, &info, sizeof(info), NULL);
			if (status == static_cast<LONG>(0xC0000004L) /* STATUS_INFO_LENGTH_MISMATCH */)
			{
				// Unlike SystemProcessInformation, the required size is in the string.
				const size_t needed = info.imageName.maximumLength;
				if (needed <= buffer.size() * sizeof(WCHAR) || needed % sizeof(WCHAR)) return false;
				buffer.resize(needed / sizeof(WCHAR));
				continue;
			}
			if (status < 0 || info.imageName.buffer != &buffer[0] || !info.imageName.length ||
				info.imageName.length % sizeof(WCHAR) ||
				info.imageName.length > buffer.size() * sizeof(WCHAR)) return false;
			path.assign(&buffer[0], info.imageName.length / sizeof(WCHAR));
			return path.find(L'\0') == std::wstring::npos;
		}
		return false;
	}

	inline bool Prefix(const std::wstring& path, const std::wstring& prefix)
	{
		return !prefix.empty() && path.size() >= prefix.size() &&
			_wcsnicmp(path.c_str(), prefix.c_str(), prefix.size()) == 0;
	}

	inline bool ComponentPrefix(const std::wstring& path, const std::wstring& prefix)
	{
		return Prefix(path, prefix) && (path.size() == prefix.size() || path[prefix.size()] == L'\\');
	}

	struct Resolver
	{
		std::wstring windowsDirectory;
		std::vector<std::pair<std::wstring, std::wstring> > drives;

		// Refresh once per process-list scan so new drive mappings are reflected.
		void Refresh()
		{
			drives.clear();
			WCHAR windows[MAX_PATH] = {};
			const UINT length = GetWindowsDirectoryW(windows, MAX_PATH);
			windowsDirectory = length && length < MAX_PATH ? windows : L"";
			for (WCHAR letter = L'A'; letter <= L'Z'; ++letter)
			{
				WCHAR drive[] = { letter, L':', L'\0' };
				std::vector<WCHAR> target(512);
				for (;;)
				{
					if (QueryDosDeviceW(drive, &target[0], static_cast<DWORD>(target.size())))
					{
						// The first string is the current mapping; following strings are old mappings.
						drives.push_back(std::make_pair(std::wstring(&target[0]), std::wstring(drive)));
						break;
					}
					if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || target.size() >= 32768) break;
					target.resize(target.size() * 2);
				}
			}
		}

		std::wstring Convert(const std::wstring& path) const
		{
			if (Prefix(path, L"\\??\\UNC\\")) return L"\\\\" + path.substr(8);
			if (Prefix(path, L"\\??\\"))
			{
				const std::wstring rest = path.substr(4);
				// Preserve volume-GUID paths as valid Win32 extended paths.
				return Prefix(rest, L"Volume{") ? L"\\\\?\\" + rest : rest;
			}
			if (!windowsDirectory.empty())
			{
				if (ComponentPrefix(path, L"\\SystemRoot")) return windowsDirectory + path.substr(11);
				if (Prefix(path, L"system32\\")) return windowsDirectory + L"\\" + path;
			}
			size_t best = 0;
			std::wstring drive;
			for (size_t i = 0; i < drives.size(); ++i)
			{
				if (drives[i].first.size() > best && ComponentPrefix(path, drives[i].first))
				{
					best = drives[i].first.size();
					drive = drives[i].second;
				}
			}
			if (best) return drive + path.substr(best);
			// Common network redirector forms. Leave unknown device paths intact.
			const WCHAR* providers[] = { L"\\Device\\Mup\\", L"\\Device\\LanmanRedirector\\" };
			for (size_t i = 0; i < _countof(providers); ++i)
			{
				if (!Prefix(path, providers[i])) continue;
				std::wstring rest = path.substr(wcslen(providers[i]));
				if (!rest.empty() && rest[0] == L';')
				{
					const size_t slash = rest.find(L'\\');
					if (slash == std::wstring::npos) return path;
					rest.erase(0, slash + 1);
				}
				if (!rest.empty()) return L"\\\\" + rest;
			}
			return path;
		}
	};
}
