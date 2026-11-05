#include "stdafx.h"
#include "ConfigImport.h"
#include "ConfigStorage.h"
#include "Localization.h"
#include "AutomationOptions.h"
#include "ProxyProfileStore.h"
#include <set>

namespace
{
struct Handle
{
    HANDLE value;
    explicit Handle(HANDLE h) : value(h) { if (h == INVALID_HANDLE_VALUE) throw GetLastError(); }
    ~Handle() { CloseHandle(value); }
};
bool Exists(const CString& path)
{
    DWORD attributes = GetFileAttributes(path);
    if (attributes != INVALID_FILE_ATTRIBUTES) return true;
    DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return false;
    throw error;
}
std::vector<BYTE> Read(const CString& path)
{
    // Deny concurrent writes/deletes while taking this fixed snapshot.
    Handle file(CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL));
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file.value, &size)) throw GetLastError();
    if (size.QuadPart > 8 * 1024 * 1024) throw DWORD(ERROR_FILE_TOO_LARGE);
    std::vector<BYTE> bytes(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    if (!bytes.empty() && (!ReadFile(file.value, bytes.data(), (DWORD)bytes.size(), &read, NULL) || read != bytes.size()))
        throw DWORD(ERROR_READ_FAULT);
    return bytes;
}
void WriteNew(const CString& path, const std::vector<BYTE>& bytes)
{
    Handle file(CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL));
    DWORD written = 0;
    if ((!bytes.empty() && (!WriteFile(file.value, bytes.data(), (DWORD)bytes.size(), &written, NULL) || written != bytes.size())) ||
        !FlushFileBuffers(file.value)) throw DWORD(ERROR_WRITE_FAULT);
}
bool SameFile(const CString& a, const CString& b)
{
    Handle first(CreateFile(a, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL));
    Handle second(CreateFile(b, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL));
    BY_HANDLE_FILE_INFORMATION x = {}, y = {};
    if (!GetFileInformationByHandle(first.value, &x) || !GetFileInformationByHandle(second.value, &y)) throw GetLastError();
    return x.dwVolumeSerialNumber == y.dwVolumeSerialNumber && x.nFileIndexHigh == y.nFileIndexHigh && x.nFileIndexLow == y.nFileIndexLow;
}
CString Decode(std::vector<BYTE>& bytes)
{
    if (bytes.empty()) throw Localization::Get(L"import.invalid");
    CString text;
    if (bytes.size() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe)
    {
        if (bytes.size() % 2) throw Localization::Get(L"import.invalid");
        text.SetString(reinterpret_cast<const wchar_t*>(bytes.data() + 2), (int)(bytes.size() / 2 - 1));
    }
    else
    {
        if (bytes.size() >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff) throw Localization::Get(L"import.encoding");
        const bool bom = bytes.size() >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf;
        const char* data = reinterpret_cast<const char*>(bytes.data()) + (bom ? 3 : 0);
        const int size = (int)bytes.size() - (bom ? 3 : 0);
        UINT codepage = CP_UTF8;
        int count = MultiByteToWideChar(codepage, MB_ERR_INVALID_CHARS, data, size, NULL, 0);
        if (!count && !bom) { codepage = CP_ACP; count = MultiByteToWideChar(codepage, 0, data, size, NULL, 0); }
        if (!count) throw Localization::Get(L"import.encoding");
        MultiByteToWideChar(codepage, codepage == CP_UTF8 ? MB_ERR_INVALID_CHARS : 0, data, size, text.GetBuffer(count), count);
        text.ReleaseBuffer(count);
        bool nonAscii = false;
        for (int i = 0; i < text.GetLength(); ++i) nonAscii |= text[i] > 127;
        // Windows profile APIs do not consistently read UTF-8 on older Windows.
        // Preserve all text, comments and unknown fields, converting encoding only.
        if (codepage == CP_UTF8 && (bom || nonAscii))
        {
            bytes.resize(2 + text.GetLength() * sizeof(wchar_t));
            bytes[0] = 0xff; bytes[1] = 0xfe;
            memcpy(bytes.data() + 2, (LPCWSTR)text, bytes.size() - 2);
        }
    }
    for (int i = 0; i < text.GetLength(); ++i)
        if (text[i] == 0 || (text[i] < 32 && text[i] != L'\r' && text[i] != L'\n' && text[i] != L'\t'))
            throw Localization::Get(L"import.invalid");
    return text;
}
UINT Validate(const CString& text, const CString& path)
{
    std::set<CString, CIniFile::KeyLess> sections;
    bool inSection = false, recognized = false;
    int position = 0;
    while (position >= 0 && position < text.GetLength())
    {
        CString line = text.Tokenize(L"\r\n", position); line.Trim();
        if (line.IsEmpty() || line[0] == L';' || line[0] == L'#') continue;
        if (line[0] == L'[')
        {
            if (line.Right(1) != L"]") throw Localization::Get(L"import.invalid");
            CString section = line.Mid(1, line.GetLength() - 2); section.Trim();
            if (section.IsEmpty() || !sections.insert(section).second) throw Localization::Get(L"import.invalid");
            recognized |= section.CompareNoCase(L"options") == 0 || section.Left(6).CompareNoCase(L"proxy_") == 0;
            inSection = true;
        }
        else if (!inSection || line.Find(L'=') <= 0) throw Localization::Get(L"import.invalid");
    }
    if (!recognized) throw Localization::Get(L"import.invalid");
    CIniFile ini; ini.SetIniFileName(path);
    CProxyProfileStore store(ini);
    CString invalid;
    UINT count = 0;
    for (const CString& section : sections)
    {
        CIniFile::Section values;
        if (!ini.ReadSection(section, values)) throw Localization::Get(L"import.invalid");
        if (section.Left(6).CompareNoCase(L"proxy_") != 0) continue;
        CfgProxyItem item; item.strName = section.Mid(6);
        CString transport = ini.GetString(section, L"Transport");
        CString port = ini.GetString(section, L"Port");
        port.Trim();
        const bool validPort = !port.IsEmpty() && port.GetLength() <= 5 &&
            port.SpanIncluding(L"0123456789") == port && _wtoi(port) > 0 && _wtoi(port) <= 65535;
        const bool valid = !item.strName.IsEmpty() && store.Load(item) &&
            (item.pi.GetProxyType() == PROXYTYPE_NOPROXY || validPort) &&
            (transport.IsEmpty() || transport.CompareNoCase(L"PLAIN") == 0 || transport.CompareNoCase(L"GONC_TLS_PSK") == 0);
        if (!valid) invalid += L"\r\n" + section;
        else ++count;
    }
    if (!invalid.IsEmpty()) throw Localization::Format(L"import.invalid_profiles", (LPCTSTR)invalid);
    return count;
}
void Report(const CString& text, LPCTSTR titleKey = L"import.title")
{
    ::MessageBox(NULL, text, Localization::Get(titleKey), MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
}
}

CString ConfigImport::ErrorText(DWORD error)
{
    wchar_t* buffer = NULL;
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, NULL);
    CString result = buffer ? buffer : Localization::Get(L"import.failed");
    if (buffer) LocalFree(buffer);
    result.Trim(); return result;
}
ConfigImport::Pending::~Pending()
{
    if (child.hThread) { TerminateProcess(child.hProcess, ERROR_CANCELLED); CloseHandle(child.hThread); }
    if (child.hProcess) CloseHandle(child.hProcess);
    if (ready) CloseHandle(ready);
    if (!staged.IsEmpty()) DeleteFile(staged);
}
bool ConfigImport::Pending::Prepare(const CString& path, CString& error)
{
    try
    {
        source = path; destination = Localization::SettingsPath();
        if (!ConfigStorage::EnsureDirectory(ConfigStorage::Directory(destination))) throw GetLastError();
        hadPrevious = Exists(destination);
        if (hadPrevious && SameFile(source, destination)) throw Localization::Get(L"import.same_file");
        contents = Read(source);
        CString text = Decode(contents);
        GUID guid; if (CoCreateGuid(&guid) != S_OK) throw DWORD(ERROR_GEN_FAILURE);
        wchar_t id[64]; StringFromGUID2(guid, id, _countof(id)); token = id;
        staged = destination + L".import-" + token + L".tmp";
        WriteNew(staged, contents);
        profiles = Validate(text, staged);
        if (hadPrevious)
        {
            SYSTEMTIME now; GetLocalTime(&now);
            backup.Format(L"%s.backup-%04u%02u%02u-%02u%02u%02u-%s", (LPCWSTR)destination,
                now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, (LPCWSTR)token.Mid(1, 8));
        }
        return true;
    }
    catch (DWORD code) { error = ErrorText(code); }
    catch (const CString& message) { error = message; }
    catch (...) { error = Localization::Get(L"import.failed"); }
    return false;
}
bool ConfigImport::Pending::PrepareStorageSwitch(bool portable, CString& error)
{
    switchStorage = true; usePortable = portable;
    destination = portable ? ConfigStorage::PortablePath() : ConfigStorage::UserPath();
    if (destination.IsEmpty()) { error = ErrorText(ERROR_PATH_NOT_FOUND); return false; }
    GUID guid;
    if (CoCreateGuid(&guid) != S_OK) { error = ErrorText(ERROR_GEN_FAILURE); return false; }
    wchar_t id[64]; StringFromGUID2(guid, id, _countof(id)); token = id;
    return true;
}
bool ConfigImport::Pending::Launch(bool suspended)
{
    CString command = QuoteCommandLineArgument(executable);
    if (suspended) command += L" --bootstrap-event " + QuoteCommandLineArgument(readyName);
    STARTUPINFO startup = {sizeof(startup)};
    PROCESS_INFORMATION process = {};
    const CString directory = executable.Left(executable.ReverseFind(L'\\'));
    BOOL ok = CreateProcess(executable, command.GetBuffer(), NULL, NULL, FALSE,
        suspended ? CREATE_SUSPENDED : 0, NULL, directory, &startup, &process);
    command.ReleaseBuffer();
    if (!ok) return false;
    if (suspended) child = process;
    else { CloseHandle(process.hThread); CloseHandle(process.hProcess); }
    return true;
}
bool ConfigImport::Pending::ArmRestart(CString& error)
{
    try
    {
        if (!switchStorage) {
            ConfigStorage::Lock lock(destination); if (!lock.Valid()) throw GetLastError();
            if (Exists(destination) != hadPrevious) throw DWORD(ERROR_RETRY);
            if (hadPrevious) {
                if (GetFileAttributes(destination) & FILE_ATTRIBUTE_READONLY) throw DWORD(ERROR_ACCESS_DENIED);
                previous = Read(destination);
                WriteNew(backup, previous);
                if (Read(backup) != previous) throw DWORD(ERROR_WRITE_FAULT);
            }
        }
        wchar_t path[MAX_PATH]; DWORD length = GetModuleFileName(NULL, path, _countof(path));
        if (!length || length >= _countof(path)) throw DWORD(ERROR_FILENAME_EXCED_RANGE);
        executable = path;
        readyName = L"Local\\ProxyLaneImport" + token;
        ready = CreateEvent(NULL, TRUE, FALSE, readyName);
        if (!ready) throw GetLastError();
        if (!Launch(true)) throw GetLastError();
        return true;
    }
    catch (DWORD code) { error = ErrorText(code); }
    catch (...) { error = Localization::Get(L"import.failed"); }
    return false;
}
bool ConfigImport::Pending::Restore()
{
    try
    {
        ConfigStorage::Lock lock(destination); if (!lock.Valid()) return false;
        if (!hadPrevious) return !Exists(destination) || DeleteFile(destination) != FALSE;
        if (Exists(destination) && Read(destination) == previous) return true;
        const CString restore = destination + L".restore-" + token + L".tmp";
        if (!CopyFile(backup, restore, TRUE)) return false;
        const bool restored = MoveFileEx(restore, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
        if (!restored) DeleteFile(restore);
        return restored && Read(destination) == previous;
    }
    catch (...) { return false; }
}
void ConfigImport::Pending::FinishAfterShutdown()
{
    if (switchStorage) { FinishStorageSwitch(); return; }
    // Destroying MFC's main window posts WM_QUIT. A pending quit makes a
    // Win32 MessageBox return immediately, hiding import/recovery errors.
    // InitInstance already returned FALSE; no application message loop will
    // resume, so consume that quit before reporting any shutdown-time errors.
    MSG quit;
    while (PeekMessage(&quit, NULL, WM_QUIT, WM_QUIT, PM_REMOVE)) {}
    bool changed = false, attempted = false;
    CString error;
    try
    {
        ConfigStorage::Lock lock(destination); if (!lock.Valid()) throw GetLastError();
        // All old dialogs and their workers have shut down. Never overwrite a
        // configuration changed by another writer since the confirmed backup.
        if (Exists(destination) != hadPrevious || (hadPrevious && Read(destination) != previous))
            throw DWORD(ERROR_RETRY);
        if (Read(staged) != contents) throw DWORD(ERROR_INVALID_DATA);
        attempted = true;
        const BOOL replaced = hadPrevious ? ReplaceFile(destination, staged, NULL, 0, NULL, NULL) :
            MoveFileEx(staged, destination, MOVEFILE_WRITE_THROUGH);
        if (!replaced) throw GetLastError();
        changed = true;
        WritePrivateProfileString(NULL, NULL, NULL, destination);
        if (Read(destination) != contents) throw DWORD(ERROR_WRITE_FAULT);
    }
    catch (DWORD code) { error = ErrorText(code); }
    catch (...) { error = Localization::Get(L"import.failed"); }
    if (!error.IsEmpty())
    {
        const bool restored = !attempted || Restore();
        if (!restored)
        {
            Report(Localization::Format(L"import.restore_failed", (LPCTSTR)backup, (LPCTSTR)error));
            return;
        }
        changed = false;
        Report(Localization::Format(L"import.kept_original", (LPCTSTR)error));
    }
    if (ResumeThread(child.hThread) != DWORD(-1))
    {
        CloseHandle(child.hThread); child.hThread = NULL;
        HANDLE handles[] = {ready, child.hProcess};
        if (WaitForMultipleObjects(2, handles, FALSE, 30000) == WAIT_OBJECT_0) return;
    }
    // This is only the new, explicitly prepared replacement GUI, never a user application.
    if (WaitForSingleObject(child.hProcess, 0) != WAIT_OBJECT_0)
    {
        TerminateProcess(child.hProcess, ERROR_PROCESS_ABORTED);
        if (WaitForSingleObject(child.hProcess, 5000) != WAIT_OBJECT_0)
        {
            Report(Localization::Format(L"import.restore_failed", (LPCTSTR)backup, (LPCTSTR)Localization::Get(L"import.restart_failed")));
            return;
        }
    }
    if (changed && !Restore())
    {
        Report(Localization::Format(L"import.restore_failed", (LPCTSTR)backup, (LPCTSTR)Localization::Get(L"import.restart_failed")));
        return;
    }
    Report(Localization::Get(L"import.restart_restored"));
    if (!Launch(false)) Report(Localization::Format(L"import.kept_original", (LPCTSTR)ErrorText(GetLastError())));
}

void ConfigImport::Pending::FinishStorageSwitch()
{
    // Clear the main window's WM_QUIT so shutdown-time error dialogs can appear.
    MSG quit;
    while (PeekMessage(&quit, NULL, WM_QUIT, WM_QUIT, PM_REMOVE)) {}
    CString error;
    try
    {
        // No INI reads, copies, moves or overwrites during a location switch.
        if (!ConfigStorage::SetPortable(usePortable)) throw GetLastError();
    }
    catch (DWORD code) { error = ErrorText(code); }
    catch (...) { error = Localization::Get(L"import.failed"); }
    if (!error.IsEmpty())
        Report(Localization::Format(L"settings.switch_failed", (LPCTSTR)error), L"settings.data");
    if (ResumeThread(child.hThread) != DWORD(-1))
    {
        CloseHandle(child.hThread); child.hThread = NULL;
        HANDLE handles[] = {ready, child.hProcess};
        if (WaitForMultipleObjects(2, handles, FALSE, 30000) == WAIT_OBJECT_0) return;
    }
    // Only stop the replacement GUI created by this operation, never user apps.
    if (WaitForSingleObject(child.hProcess, 0) != WAIT_OBJECT_0)
    {
        TerminateProcess(child.hProcess, ERROR_PROCESS_ABORTED);
        WaitForSingleObject(child.hProcess, 5000);
    }
    Report(Localization::Get(L"settings.restart_manual"), L"settings.data");
}
