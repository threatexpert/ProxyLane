#include "stdafx.h"
#include "ConfigStorage.h"
#include <shlobj.h>
#include <algorithm>
#include <vector>

namespace
{
CString settingsPath;
CString Executable()
{
    wchar_t path[MAX_PATH] = {};
    DWORD n = GetModuleFileName(NULL, path, _countof(path));
    return n && n < _countof(path) ? CString(path) : CString();
}
bool Exists(const CString& path) { return GetFileAttributes(path) != INVALID_FILE_ATTRIBUTES; }
CString Unique()
{
    GUID id; wchar_t value[40];
    if (FAILED(CoCreateGuid(&id))) return CString();
    StringFromGUID2(id, value, _countof(value)); return value;
}
bool Read(const CString& path, std::vector<BYTE>& bytes)
{
    HANDLE file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {}; DWORD read = 0;
    bool ok = GetFileSizeEx(file, &size) != FALSE;
    if (ok && (size.QuadPart < 0 || size.QuadPart > 8 * 1024 * 1024)) { SetLastError(ERROR_FILE_TOO_LARGE); ok = false; }
    if (ok) { bytes.resize((size_t)size.QuadPart); ok = bytes.empty() || (ReadFile(file, bytes.data(), (DWORD)bytes.size(), &read, NULL) && read == bytes.size()); }
    DWORD error = GetLastError(); CloseHandle(file); SetLastError(error); return ok;
}
bool CreateUnicodeFile(const CString& path)
{
    HANDLE file = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    WORD bom = 0xfeff; DWORD written = 0;
    bool ok = WriteFile(file, &bom, sizeof(bom), &written, NULL) && written == sizeof(bom) && FlushFileBuffers(file);
    DWORD error = GetLastError(); CloseHandle(file); SetLastError(error); return ok;
}
}

ConfigStorage::Lock::Lock(const CString& path)
{
    wchar_t absolute[32768];
    DWORD n = GetFullPathName(path, _countof(absolute), absolute, NULL);
    if (!n || n >= _countof(absolute)) return;
    CString key(absolute); key.Replace(L'/', L'\\'); key.MakeLower();
    ULONGLONG hash = 14695981039346656037ULL;
    for (int i = 0; i < key.GetLength(); ++i) { hash ^= (WORD)key[i]; hash *= 1099511628211ULL; }
    CString name; name.Format(L"Global\\ProxyLane.RecentIni.%016I64x", hash);
    handle = CreateMutex(NULL, FALSE, name);
    if (!handle) return;
    DWORD wait = WaitForSingleObject(handle, 2000);
    owned = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
    if (!owned) SetLastError(wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_LOCK_FAILED);
}
ConfigStorage::Lock::~Lock()
{
    DWORD error = GetLastError();
    if (owned) ReleaseMutex(handle);
    if (handle) CloseHandle(handle);
    SetLastError(error);
}
CString ConfigStorage::Directory(const CString& path) { return path.Left(path.ReverseFind(L'\\')); }
CString ConfigStorage::PortablePath()
{
    CString path = Executable();
    if (path.Right(6).CompareNoCase(L"64.exe") == 0) return path.Left(path.GetLength() - 6) + L".ini";
    return path.Left(path.ReverseFind(L'.')) + L".ini";
}
CString ConfigStorage::UserPath()
{
    wchar_t path[MAX_PATH] = {};
    if (FAILED(SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, path))) return CString();
    return CString(path) + L"\\ProxyLane\\ProxyLane.ini";
}
CString ConfigStorage::Path()
{
    if (settingsPath.IsEmpty())
    {
        const CString portable = PortablePath();
        const DWORD attributes = GetFileAttributes(Directory(portable) + L"\\portable.flag");
        const bool portableMode = attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
        settingsPath = portableMode ? portable : UserPath();
    }
    return settingsPath;
}
bool ConfigStorage::SetPortable(bool enabled)
{
    const CString flag = Directory(PortablePath()) + L"\\portable.flag";
    if (!enabled) {
        if (DeleteFile(flag)) return true;
        const DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }
    // OPEN_ALWAYS preserves an existing marker; never touches either INI.
    HANDLE file = CreateFile(flag, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    CloseHandle(file); return true;
}
bool ConfigStorage::EnsureDirectory(const CString& directory)
{
    int result = SHCreateDirectoryEx(NULL, directory, NULL);
    if (result == ERROR_SUCCESS || result == ERROR_ALREADY_EXISTS || result == ERROR_FILE_EXISTS) return true;
    SetLastError(result); return false;
}
bool ConfigStorage::Update(const CString& path, const std::function<bool(const CString&)>& edit)
{
    Lock lock(path); if (!lock.Valid()) return false;
    DWORD attributes = GetFileAttributes(path);
    bool exists = attributes != INVALID_FILE_ATTRIBUTES;
    if (!exists && GetLastError() != ERROR_FILE_NOT_FOUND) return false;
    if (exists && (attributes & FILE_ATTRIBUTE_READONLY)) { SetLastError(ERROR_ACCESS_DENIED); return false; }
    CString id = Unique(); if (id.IsEmpty()) { SetLastError(ERROR_GEN_FAILURE); return false; }
    CString staged = path + L"." + id + L".tmp";
    bool ok = exists ? CopyFile(path, staged, TRUE) != FALSE : CreateUnicodeFile(staged);
    if (ok) {
        try { ok = edit(staged); }
        catch (CException* error) { error->Delete(); SetLastError(ERROR_GEN_FAILURE); ok = false; }
        catch (...) { SetLastError(ERROR_GEN_FAILURE); ok = false; }
    }
    // A cache-flush call may return zero even when successful. Check the actual
    // writes and FlushFileBuffers below, not this special profile-API return.
    if (ok) WritePrivateProfileString(NULL, NULL, NULL, staged);
    std::vector<BYTE> before, after;
    if (ok) ok = Read(staged, after) && (!exists || Read(path, before));
    if (ok && exists && before == after) { DeleteFile(staged); return true; }
    if (ok)
    {
        HANDLE file = CreateFile(staged, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (file == INVALID_HANDLE_VALUE) ok = false;
        else { ok = FlushFileBuffers(file) != FALSE; DWORD error = GetLastError(); CloseHandle(file); SetLastError(error); }
    }
    if (ok) ok = exists ? ReplaceFile(path, staged, NULL, 0, NULL, NULL) != FALSE : MoveFileEx(staged, path, MOVEFILE_WRITE_THROUGH) != FALSE;
    DWORD error = GetLastError(); DeleteFile(staged);
    if (ok) WritePrivateProfileString(NULL, NULL, NULL, path);
    SetLastError(ok ? ERROR_SUCCESS : error ? error : ERROR_WRITE_FAULT); return ok;
}
BOOL ConfigStorage::WriteValue(LPCTSTR section, LPCTSTR key, LPCTSTR value, const CString& path)
{
    return Update(path, [&](const CString& staged) { return WritePrivateProfileString(section, key, value, staged) != FALSE; });
}
CString ConfigStorage::ErrorText(DWORD error)
{
    wchar_t* buffer = NULL;
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error, 0, (LPWSTR)&buffer, 0, NULL);
    CString text = buffer ? buffer : L""; if (buffer) LocalFree(buffer); text.Trim();
    if (text.IsEmpty()) text.Format(L"Windows error %lu", error);
    return text;
}
static bool g_createdDefaults = false;
bool ConfigStorage::CreatedDefaults() { return g_createdDefaults; }
bool ConfigStorage::Initialize()
{
    const CString path = Path();
    if (path.IsEmpty()) { SetLastError(ERROR_PATH_NOT_FOUND); return false; }
    if (!EnsureDirectory(Directory(path))) return false;
    Lock lock(path); if (!lock.Valid()) return false;
    if (Exists(path)) return true;
    // The release ZIP contains no active INI, so upgrades cannot overwrite it.
    return g_createdDefaults = Update(path, [](const CString& staged) {
        static const wchar_t defaults[] =
            L"[options]\r\nlastselected=Test\r\nDecryptHTTPS=1\r\nDecryptQUIC=1\r\n"
            L"[proxy_Test]\r\nType=SOCKS5\r\nHost=127.0.0.1\r\nPort=1080\r\nHookChildProcess=1\r\nHookTCP=1\r\nHookUDP=0\r\nBlockUDP=1\r\nTargetFilterMode=1\r\n"
            L"[proxy_Direct]\r\nType=NOPROXY\r\nHookChildProcess=1\r\nHookTCP=1\r\nHookUDP=1\r\nRedirectPrivateDNS=0\r\nTargetFilterMode=1\r\n";
        HANDLE file = CreateFile(staged, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (file == INVALID_HANDLE_VALUE) return false;
        SetFilePointer(file, 2, NULL, FILE_BEGIN); DWORD written = 0;
        bool ok = WriteFile(file, defaults, sizeof(defaults) - sizeof(wchar_t), &written, NULL) && written == sizeof(defaults) - sizeof(wchar_t) && FlushFileBuffers(file);
        DWORD error = GetLastError(); CloseHandle(file); SetLastError(error); return ok;
    });
}
