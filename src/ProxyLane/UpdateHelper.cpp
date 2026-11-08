#include "stdafx.h"
#include "UpdateHelper.h"
#include "UpdateRelease.h"
#include "AutomationOptions.h"
#include <shellapi.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <wininet.h>
#include <vector>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace
{
const wchar_t kMode[] = L"--update-helper";

struct InternetHandle
{
    HINTERNET h;
    explicit InternetHandle(HINTERNET value) : h(value) {}
    ~InternetHandle() { if (h) InternetCloseHandle(h); }
};

CString Executable()
{
    WCHAR path[MAX_PATH] = {};
    const DWORD length = GetModuleFileName(NULL, path, _countof(path));
    return length && length < _countof(path) ? CString(path) : CString();
}

DWORD Download(const CString& url, const CString& output, unsigned long long limit, bool direct)
{
    // Inside an injected helper the hook is the proxy; a system proxy on top of
    // it would route the request through two proxies.
    InternetHandle session(InternetOpen(L"ProxyLane update",
        direct ? INTERNET_OPEN_TYPE_DIRECT : INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0));
    if (!session.h) return UpdateHelper::EXIT_NETWORK;
    DWORD timeout = 20000; // Allow the site's 15-second upstream lookup to complete.
    InternetSetOption(session.h, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(session.h, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    timeout = 60000;
    InternetSetOption(session.h, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetHandle request(InternetOpenUrl(session.h, url,
        L"Accept: application/json, application/octet-stream\r\n", (DWORD)-1,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI |
        INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_AUTH, 0));
    if (!request.h) return UpdateHelper::EXIT_NETWORK;
    DWORD status = 0, size = sizeof(status);
    if (!HttpQueryInfo(request.h, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &size, NULL) || status != 200)
        return UpdateHelper::EXIT_HTTP_STATUS;

    const CString partial = output + L".part";
    HANDLE file = CreateFile(partial, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return UpdateHelper::EXIT_WRITE_FAILED;
    DWORD result = UpdateHelper::EXIT_OK;
    unsigned long long total = 0;
    std::vector<char> buffer(64 * 1024);
    for (;;)
    {
        DWORD count = 0;
        if (!InternetReadFile(request.h, &buffer[0], static_cast<DWORD>(buffer.size()), &count)) { result = UpdateHelper::EXIT_NETWORK; break; }
        if (!count) break;
        total += count;
        if (total > limit) { result = UpdateHelper::EXIT_TOO_LARGE; break; }
        DWORD written = 0;
        if (!WriteFile(file, &buffer[0], count, &written, NULL) || written != count) { result = UpdateHelper::EXIT_WRITE_FAILED; break; }
    }
    if (result == UpdateHelper::EXIT_OK && !FlushFileBuffers(file)) result = UpdateHelper::EXIT_WRITE_FAILED;
    CloseHandle(file);
    if (result == UpdateHelper::EXIT_OK && !MoveFileEx(partial, output, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        result = UpdateHelper::EXIT_WRITE_FAILED;
    if (result != UpdateHelper::EXIT_OK) DeleteFile(partial);
    return result;
}
}

bool UpdateHelper::Run(LPCWSTR commandLine, DWORD& exitCode)
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(commandLine, &argc);
    if (!argv) return false;
    if (argc < 2 || _wcsicmp(argv[1], kMode) != 0) { LocalFree(argv); return false; }

    exitCode = EXIT_BAD_ARGUMENTS;
    const bool direct = argc > 0 && _wcsicmp(argv[argc - 1], L"--direct") == 0;
    const int count = direct ? argc - 1 : argc;
    if (count == 4 && _wcsicmp(argv[2], L"release") == 0)
    {
        exitCode = Download(UpdateRelease::ApiUrl, argv[3], UpdateRelease::MaxResponseBytes, direct);
    }
    else if (count == 5 && _wcsicmp(argv[2], L"installer") == 0)
    {
        // Re-validate here: the helper never fetches from another origin.
        const std::string path = static_cast<LPCSTR>(CStringA(argv[3]));
        if (UpdateRelease::IsAssetPath(path))
            exitCode = Download(CString(UpdateRelease::AssetOrigin) + argv[3], argv[4], UpdateRelease::MaxInstallerBytes, direct);
    }
    LocalFree(argv);
    return true;
}

CString UpdateHelper::BuildArguments(Kind kind, const CString& assetPath, const CString& output)
{
    CString arguments = CString(kMode) + (kind == RELEASE_METADATA ? L" release " : L" installer " + QuoteCommandLineArgument(assetPath) + L" ");
    arguments += QuoteCommandLineArgument(output);
    return arguments;
}

CString UpdateHelper::WorkDirectory()
{
    WCHAR temp[MAX_PATH] = {};
    const DWORD length = GetTempPath(_countof(temp), temp);
    if (!length || length >= _countof(temp)) return CString();
    CString directory(temp);
    directory.TrimRight(L'\\');
    directory += L"\\ProxyLane-Update";
    if (!CreateDirectory(directory, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return CString();
    return directory;
}

void UpdateHelper::CleanWorkDirectory(const CString& keep)
{
    const CString directory = WorkDirectory();
    if (directory.IsEmpty()) return;
    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER cutoff; cutoff.LowPart = now.dwLowDateTime; cutoff.HighPart = now.dwHighDateTime;
    cutoff.QuadPart -= 10ULL * 60 * 10000000; // 10 minutes in 100 ns units
    for (LPCWSTR pattern : { L"ProxyLane-*-Setup.exe", L"*.part", L"release-*.json" })
    {
        WIN32_FIND_DATA data = {};
        HANDLE find = FindFirstFile(directory + L"\\" + pattern, &data);
        if (find == INVALID_HANDLE_VALUE) continue;
        do
        {
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            ULARGE_INTEGER written; written.LowPart = data.ftLastWriteTime.dwLowDateTime; written.HighPart = data.ftLastWriteTime.dwHighDateTime;
            const CString path = directory + L"\\" + data.cFileName;
            if (written.QuadPart < cutoff.QuadPart && path.CompareNoCase(keep) != 0) DeleteFile(path);
        } while (FindNextFile(find, &data));
        FindClose(find);
    }
}

bool UpdateHelper::ReadSmallFile(const CString& path, std::string& bytes, size_t limit)
{
    bytes.clear();
    HANDLE file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {};
    bool ok = GetFileSizeEx(file, &size) && size.QuadPart >= 0 && static_cast<unsigned long long>(size.QuadPart) <= limit;
    if (ok && size.QuadPart)
    {
        bytes.resize(static_cast<size_t>(size.QuadPart));
        DWORD read = 0;
        ok = ReadFile(file, &bytes[0], static_cast<DWORD>(bytes.size()), &read, NULL) && read == bytes.size();
    }
    CloseHandle(file);
    if (!ok) bytes.clear();
    return ok;
}

bool UpdateHelper::Sha256File(const CString& path, std::string& hex, unsigned long long& size)
{
    hex.clear(); size = 0;
    HANDLE file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0;
    bool ok = CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash);
    std::vector<BYTE> buffer(64 * 1024);
    while (ok)
    {
        DWORD read = 0;
        if (!ReadFile(file, &buffer[0], static_cast<DWORD>(buffer.size()), &read, NULL)) { ok = false; break; }
        if (!read) break;
        size += read;
        ok = CryptHashData(hash, &buffer[0], read, 0) != FALSE;
    }
    BYTE digest[32] = {}; DWORD length = sizeof(digest);
    if (ok) ok = CryptGetHashParam(hash, HP_HASHVAL, digest, &length, 0) && length == sizeof(digest);
    if (hash) CryptDestroyHash(hash);
    if (provider) CryptReleaseContext(provider, 0);
    CloseHandle(file);
    if (!ok) return false;
    static const char digits[] = "0123456789abcdef";
    for (DWORD i = 0; i < length; ++i) { hex += digits[digest[i] >> 4]; hex += digits[digest[i] & 15]; }
    return true;
}

bool UpdateHelper::IsInstalledCopy()
{
    CString directory = Executable();
    directory = directory.Left(directory.ReverseFind(L'\\'));
    return !directory.IsEmpty() && PathFileExists(directory + L"\\unins000.exe") && PathFileExists(directory + L"\\unins000.dat");
}

CString UpdateHelper::InstallerParameters()
{
    // /SILENT keeps a progress window; the setup reuses the previous directory
    // and tasks, waits for ProxyLane to exit and starts it again when done.
    return L"/SILENT /SUPPRESSMSGBOXES /NORESTART /SP- /AUTOUPDATE";
}
