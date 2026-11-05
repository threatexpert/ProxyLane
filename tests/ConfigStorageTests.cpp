#include "../src/ProxyLane/stdafx.h"
#include "../src/ProxyLane/ConfigStorage.h"
#include "../src/ProxyLane/IniFile.h"
#include <thread>
#include <atomic>
#include <iostream>

static void Check(bool result, const char* label)
{
    if (!result) { std::cerr << "FAIL: " << label << " (" << GetLastError() << ")\n"; exit(1); }
    std::cout << "PASS: " << label << "\n";
}
int wmain(int argc, wchar_t** argv)
{
    AfxWinInit(GetModuleHandle(NULL), NULL, GetCommandLine(), 0);
    if (argc == 2 && wcscmp(argv[1], L"--resolve") == 0) {
        std::wcout << (LPCWSTR)ConfigStorage::Path(); return 0;
    }
    if (argc == 2 && wcscmp(argv[1], L"--initialize") == 0) {
        if (!ConfigStorage::Initialize()) return 1;
        CIniFile defaults; defaults.SetIniFileName(ConfigStorage::Path());
        return defaults.GetString(L"proxy_Test", L"Host") == L"127.0.0.1" &&
            defaults.GetInt(L"proxy_Test", L"Port") == 1080 && defaults.GetString(L"proxy_Direct", L"Type") == L"NOPROXY" ? 0 : 2;
    }
    if (argc == 3 && wcscmp(argv[1], L"--portable") == 0)
        return ConfigStorage::SetPortable(_wtoi(argv[2]) != 0) ? 0 : 1;
    wchar_t temp[MAX_PATH]; GetTempPath(_countof(temp), temp);
    CString directory; directory.Format(L"%sProxyLane-storage-test-%lu-%lu", temp, GetCurrentProcessId(), GetTickCount());
    Check(ConfigStorage::EnsureDirectory(directory), "temporary directory");
    const CString path = directory + L"\\test.ini";
    CIniFile ini; ini.SetIniFileName(path);
    Check(ini.SetString(L"proxy_Test", L"Host", L"127.0.0.1"), "create UTF-16 configuration");
    Check(ini.SetString(L"other", L"Unicode", L"\x6d4b\x8bd5"), "preserve Unicode");
    bool failed = ConfigStorage::Update(path, [](const CString& stage) {
        WritePrivateProfileString(L"proxy_Test", L"Host", L"discard", stage);
        SetLastError(ERROR_DISK_FULL); return false;
    });
    Check(!failed && GetLastError() == ERROR_DISK_FULL && ini.GetString(L"proxy_Test", L"Host") == L"127.0.0.1", "failed transaction retains old file and error");
    SetFileAttributes(path, FILE_ATTRIBUTE_READONLY);
    Check(!ini.SetString(L"proxy_Test", L"Host", L"bad") && GetLastError() == ERROR_ACCESS_DENIED, "read-only save fails");
    SetFileAttributes(path, FILE_ATTRIBUTE_NORMAL);
    Check(ini.GetString(L"proxy_Test", L"Host") == L"127.0.0.1", "read-only failure retains configuration");
    std::atomic<bool> ok(true);
    auto write = [&](int index) {
        CString key; key.Format(L"Writer%d", index);
        for (int n = 0; n < 12; ++n) if (!ini.SetInt(L"parallel", key, n)) ok = false;
    };
    std::thread first(write, 1), second(write, 2); first.join(); second.join();
    Check(ok && ini.GetInt(L"parallel", L"Writer1") == 11 && ini.GetInt(L"parallel", L"Writer2") == 11, "concurrent writers preserve independent values");
    for (int i = 0; i < 14; ++i) {
        Check(ConfigStorage::Update(path, [i](const CString& stage) {
            CString value; value.Format(L"%d", i);
            return WritePrivateProfileString(L"proxy_Test", L"Port", value, stage) != FALSE;
        }), "atomic configuration update");
    }
    Check(ini.GetString(L"other", L"Unicode") == L"\x6d4b\x8bd5", "transactions retain unrelated Unicode settings");
    WIN32_FIND_DATA data; HANDLE find = FindFirstFile(directory + L"\\*", &data); int files = 0;
    if (find != INVALID_HANDLE_VALUE) { do { if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) ++files; } while (FindNextFile(find, &data)); FindClose(find); }
    Check(files == 1 && GetFileAttributes(directory + L"\\backups") == INVALID_FILE_ATTRIBUTES,
        "saving creates no backups or leftover temporary files");
    DeleteFile(path); RemoveDirectory(directory);
    return 0;
}
