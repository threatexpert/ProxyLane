#pragma once
#include <windows.h>
#include <string>
#include <vector>

// Role metadata only. Liveness, session and parent identity still come from the
// system snapshot. Never retain or log a process's command line.
namespace ProcessCommandLine
{
	typedef LONG (WINAPI *QueryInformation)(HANDLE, ULONG, PVOID, ULONG, PULONG);
	struct Handle
	{
		HANDLE value;
		explicit Handle(HANDLE handle) : value(handle) {}
		~Handle() { if (value) CloseHandle(value); }
	private:
		Handle(const Handle&);
		Handle& operator=(const Handle&);
	};
	inline bool SameLifetime(HANDLE handle, ULONGLONG expected)
	{
		FILETIME created, exited, kernel, user;
		return expected && GetProcessTimes(handle, &created, &exited, &kernel, &user) &&
			((static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime) == expected;
	}
	inline bool NativeQuery(HANDLE handle, QueryInformation query, std::wstring& result)
	{
		struct String { USHORT length, maximum; PWSTR buffer; };
		std::vector<BYTE> bytes(1024);
		for (int attempt = 0; attempt < 3; ++attempt)
		{
			ULONG needed = 0;
			LONG status = query(handle, 60 /* ProcessCommandLineInformation: Windows 8.1+ */,
				bytes.data(), static_cast<ULONG>(bytes.size()), &needed);
			if (status < 0)
			{
				if (needed <= bytes.size() || needed > 128 * 1024) return false;
				bytes.resize(needed);
				continue;
			}
			if (needed < sizeof(String) || needed > bytes.size()) return false;
			String value;
			CopyMemory(&value, bytes.data(), sizeof(value));
			const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(bytes.data());
			const ULONG_PTR pointer = reinterpret_cast<ULONG_PTR>(value.buffer);
			if (!value.length || value.length % sizeof(WCHAR) || value.length > value.maximum ||
				pointer < base || pointer - base > needed || value.length > needed - (pointer - base)) return false;
			result.assign(value.buffer, value.length / sizeof(WCHAR));
			return result.find(L'\0') == std::wstring::npos;
		}
		return false;
	}

	// Read only the two documented-in-symbols PEB fields needed on older Windows.
	// Fixed-width layouts also cover 64-bit GUI -> 32-bit browser and the reverse.
	template<class Read>
	bool ReadPeb(ULONGLONG peb, bool wide, Read read, std::wstring& result)
	{
		ULONGLONG parameters = 0;
		if (!peb || !read(peb + (wide ? 0x20 : 0x10), &parameters, wide ? 8 : 4) || !parameters) return false;
		struct String32 { USHORT length, maximum; ULONG buffer; };
		struct String64 { USHORT length, maximum; ULONG padding; ULONGLONG buffer; };
		USHORT length, maximum;
		ULONGLONG pointer;
		if (wide)
		{
			String64 value = {};
			if (!read(parameters + 0x70, &value, sizeof(value))) return false;
			length = value.length; maximum = value.maximum; pointer = value.buffer;
		}
		else
		{
			String32 value = {};
			if (!read(parameters + 0x40, &value, sizeof(value))) return false;
			length = value.length; maximum = value.maximum; pointer = value.buffer;
		}
		if (!pointer || !length || length % sizeof(WCHAR) || length > maximum) return false;
		std::wstring text(length / sizeof(WCHAR), L'\0');
		if (!read(pointer, &text[0], length) || text.find(L'\0') != std::wstring::npos) return false;
		result.swap(text);
		return true;
	}

	inline bool LegacyQuery(HANDLE handle, QueryInformation query, HMODULE ntdll, std::wstring& result)
	{
		typedef BOOL (WINAPI *IsWow64)(HANDLE, PBOOL);
		IsWow64 isWow64 = reinterpret_cast<IsWow64>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process"));
		BOOL targetWow = FALSE;
		if (isWow64 && !isWow64(handle, &targetWow)) return false;
		ULONGLONG peb = 0;
#ifdef _WIN64
		const bool wide = !targetWow;
		if (targetWow)
		{
			ULONG_PTR value = 0;
			if (query(handle, 26 /* ProcessWow64Information */, &value, sizeof(value), NULL) < 0) return false;
			peb = value;
		}
		else
#else
		BOOL selfWow = FALSE;
		if (isWow64 && !isWow64(GetCurrentProcess(), &selfWow)) return false;
		if (selfWow && !targetWow)
		{
			typedef LONG (WINAPI *Read64)(HANDLE, ULONGLONG, PVOID, ULONGLONG, ULONGLONG*);
			QueryInformation query64 = reinterpret_cast<QueryInformation>(GetProcAddress(ntdll, "NtWow64QueryInformationProcess64"));
			Read64 read64 = reinterpret_cast<Read64>(GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64"));
			ULONGLONG basic[6] = {};
			if (!query64 || !read64 || query64(handle, 0, basic, sizeof(basic), NULL) < 0) return false;
			return ReadPeb(basic[1], true, [=](ULONGLONG address, void* buffer, size_t size) {
				ULONGLONG read = 0;
				return read64(handle, address, buffer, size, &read) >= 0 && read == size;
			}, result);
		}
		const bool wide = false;
#endif
		{
			ULONG_PTR basic[6] = {};
			if (query(handle, 0 /* ProcessBasicInformation */, basic, sizeof(basic), NULL) < 0) return false;
			peb = basic[1];
		}
		return ReadPeb(peb, wide, [=](ULONGLONG address, void* buffer, size_t size) {
			SIZE_T read = 0;
			return address <= static_cast<ULONGLONG>(~static_cast<ULONG_PTR>(0)) &&
				ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(address)), buffer, size, &read) && read == size;
		}, result);
	}

	inline bool Query(DWORD pid, ULONGLONG time, std::wstring& result)
	{
		result.clear();
		if (!pid || !time) return false;
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		QueryInformation query = ntdll ? reinterpret_cast<QueryInformation>(GetProcAddress(ntdll, "NtQueryInformationProcess")) : NULL;
		if (!query) return false;
		{
			Handle handle(OpenProcess(0x1000 /* QUERY_LIMITED_INFORMATION */, FALSE, pid));
			if (handle.value && SameLifetime(handle.value, time) && NativeQuery(handle.value, query, result)) return true;
		}
		Handle handle(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
		return handle.value && SameLifetime(handle.value, time) && LegacyQuery(handle.value, query, ntdll, result);
	}
}
