#pragma once
#include <windows.h>
#include <shellapi.h>
#include <string>
#pragma comment(lib, "shell32.lib")

// Pointer-free wire records, identical for the XP-compatible x86 and x64 builds.
#pragma pack(push, 1)
struct AppLauncherHostInfo
{
    DWORD version;
    DWORD processId;
    ULONGLONG creationTime;
    WCHAR executable[MAX_PATH];
};
struct AppLauncherRequest
{
    WCHAR id[40];
    WCHAR aumid[256];
    DWORD hostPid;
    ULONGLONG hostCreationTime;
    DWORD parentPid;
    ULONGLONG parentCreationTime;
    ULONGLONG submittedTime;
};
struct AppLauncherResult
{
    DWORD error;
    DWORD processId;
    DWORD hookError;
};
#pragma pack(pop)

namespace AppLauncherProtocol
{
    inline ULONGLONG ProcessTime(HANDLE process)
    {
        FILETIME c, e, k, u;
        if (!GetProcessTimes(process, &c, &e, &k, &u)) return 0;
        return (static_cast<ULONGLONG>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
    }
    inline ULONGLONG Now()
    {
        FILETIME t; GetSystemTimeAsFileTime(&t);
        return (static_cast<ULONGLONG>(t.dwHighDateTime) << 32) | t.dwLowDateTime;
    }
    inline bool ValidAumid(const WCHAR* text)
    {
        if (!text || !*text || wcsnlen(text, 256) >= 256) return false;
        const WCHAR* bang = wcschr(text, L'!');
        if (!bang || bang == text || !bang[1] || wcschr(bang + 1, L'!')) return false;
        for (const WCHAR* p = text; *p; ++p)
            if (!((*p >= L'a' && *p <= L'z') || (*p >= L'A' && *p <= L'Z') ||
                (*p >= L'0' && *p <= L'9') || *p == L'.' || *p == L'_' || *p == L'-' || *p == L'!')) return false;
        return true;
    }
    inline bool ValidId(const WCHAR* text)
    {
        if (wcsnlen(text, 40) != 38 || text[0] != L'{' || text[37] != L'}') return false;
        for (int i = 1; i < 37; ++i) {
            if (i == 9 || i == 14 || i == 19 || i == 24) { if (text[i] != L'-') return false; }
            else if (!((text[i] >= L'0' && text[i] <= L'9') || (text[i] >= L'a' && text[i] <= L'f') || (text[i] >= L'A' && text[i] <= L'F'))) return false;
        }
        return true;
    }
    // Only the exact system Explorer + a single AppsFolder operand is eligible.
    inline bool ParseExplorerLaunch(LPCWSTR application, LPCWSTR command, std::wstring& aumid)
    {
        aumid.clear(); if (!command || !*command) return false;
        int count = 0; LPWSTR* argv = CommandLineToArgvW(command, &count);
        if (!argv) return false;
        bool good = false;
        if (count == 2) {
            WCHAR target[MAX_PATH] = {}, system[MAX_PATH] = {};
            LPCWSTR name = application && *application ? application : argv[0];
            DWORD length = 0;
            if (!wcschr(name, L'\\') && !wcschr(name, L'/'))
                length = SearchPathW(NULL, name, L".exe", MAX_PATH, target, NULL);
            else length = GetFullPathNameW(name, MAX_PATH, target, NULL);
            DWORD systemLength = GetWindowsDirectoryW(system, MAX_PATH);
            if (systemLength && systemLength < MAX_PATH && length && length < MAX_PATH &&
                !_wcsnicmp(target, system, systemLength)) {
                // A bare explorer.exe from a WOW64 caller can resolve to the
                // system's 32-bit Explorer instead of %windir%\explorer.exe.
                LPCWSTR relative = target + systemLength;
                const bool systemExplorer = !_wcsicmp(relative, L"\\explorer.exe") ||
                    !_wcsicmp(relative, L"\\System32\\explorer.exe") ||
                    !_wcsicmp(relative, L"\\SysWOW64\\explorer.exe");
                const DWORD attributes = systemExplorer ? GetFileAttributesW(target) : INVALID_FILE_ATTRIBUTES;
                const WCHAR prefix[] = L"shell:AppsFolder\\";
                if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    !_wcsnicmp(argv[1], prefix, _countof(prefix) - 1) &&
                    ValidAumid(argv[1] + _countof(prefix) - 1)) {
                    aumid = argv[1] + _countof(prefix) - 1; good = true;
                }
            }
        }
        LocalFree(argv); return good;
    }
}
