#include "stdafx.h"
#include "LaunchShortcut.h"
#include "ConfigStorage.h"
#include "Localization.h"
#include <atlbase.h>
#include <afxdlgs.h>
#include <shlobj.h>
#include <shlwapi.h>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "shlwapi.lib")

namespace
{
bool IsLink(const CString& path) { return CString(PathFindExtension(path)).CompareNoCase(L".lnk") == 0; }

HRESULT LastErrorResult() { DWORD error = GetLastError(); return HRESULT_FROM_WIN32(error ? error : ERROR_WRITE_FAULT); }

// Store a real ICO, not a temporary HICON handle or a reference to the exported link.
HRESULT CacheIcon(HICON icon, CString& path)
{
    if (!icon) return E_FAIL;
    ICONINFO info = {};
    if (!GetIconInfo(icon, &info)) return LastErrorResult();
    BITMAP bitmap = {};
    const bool valid = info.hbmColor && GetObject(info.hbmColor, sizeof(bitmap), &bitmap);
    if (!valid || bitmap.bmWidth <= 0 || bitmap.bmWidth > 256 || bitmap.bmHeight <= 0 || bitmap.bmHeight > 256)
    {
        if (info.hbmColor) DeleteObject(info.hbmColor);
        if (info.hbmMask) DeleteObject(info.hbmMask);
        return E_FAIL;
    }
    const DWORD width = bitmap.bmWidth, height = bitmap.bmHeight;
    const DWORD maskStride = ((width + 31) / 32) * 4;
    std::vector<BYTE> pixels(width * height * 4), mask(maskStride * height);
    BITMAPINFO color = {};
    color.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    color.bmiHeader.biWidth = width; color.bmiHeader.biHeight = height;
    color.bmiHeader.biPlanes = 1; color.bmiHeader.biBitCount = 32;
    struct MaskInfo { BITMAPINFOHEADER header; RGBQUAD colors[2]; } mono = {};
    mono.header = color.bmiHeader; mono.header.biBitCount = 1;
    mono.colors[1].rgbBlue = mono.colors[1].rgbGreen = mono.colors[1].rgbRed = 255;
    HDC dc = GetDC(NULL);
    const bool copied = dc && GetDIBits(dc, info.hbmColor, 0, height, &pixels[0], &color, DIB_RGB_COLORS) == static_cast<int>(height) &&
        GetDIBits(dc, info.hbmMask, 0, height, &mask[0], reinterpret_cast<BITMAPINFO*>(&mono), DIB_RGB_COLORS) == static_cast<int>(height);
    if (dc) ReleaseDC(NULL, dc);
    DeleteObject(info.hbmColor); DeleteObject(info.hbmMask);
    if (!copied) return E_FAIL;
#pragma pack(push, 1)
    struct IconHeader { WORD reserved, type, count; } header = { 0, 1, 1 };
    struct IconEntry { BYTE width, height, colors, reserved; WORD planes, bits; DWORD size, offset; } entry =
        { static_cast<BYTE>(width), static_cast<BYTE>(height), 0, 0, 1, 32,
          static_cast<DWORD>(sizeof(BITMAPINFOHEADER) + pixels.size() + mask.size()), sizeof(IconHeader) + sizeof(IconEntry) };
#pragma pack(pop)
    color.bmiHeader.biHeight *= 2;
    color.bmiHeader.biSizeImage = static_cast<DWORD>(pixels.size() + mask.size());
    std::vector<BYTE> bytes(entry.offset + entry.size);
    BYTE* cursor = &bytes[0];
    memcpy(cursor, &header, sizeof(header)); cursor += sizeof(header);
    memcpy(cursor, &entry, sizeof(entry)); cursor += sizeof(entry);
    memcpy(cursor, &color.bmiHeader, sizeof(color.bmiHeader)); cursor += sizeof(color.bmiHeader);
    memcpy(cursor, &pixels[0], pixels.size()); cursor += pixels.size();
    memcpy(cursor, &mask[0], mask.size());
    const CString directory = ConfigStorage::Directory(ConfigStorage::Path()) + L"\\ShortcutIcons";
    if (!ConfigStorage::EnsureDirectory(directory)) return LastErrorResult();
    GUID guid; WCHAR id[40];
    if (FAILED(CoCreateGuid(&guid))) return E_FAIL;
    StringFromGUID2(guid, id, _countof(id));
    path = directory + L"\\" + id + L".ico";
    HANDLE file = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return LastErrorResult();
    DWORD written = 0;
    const BOOL saved = WriteFile(file, &bytes[0], static_cast<DWORD>(bytes.size()), &written, NULL) && written == bytes.size();
    const HRESULT result = saved ? S_OK : LastErrorResult();
    CloseHandle(file);
    if (FAILED(result)) { DeleteFile(path); path.Empty(); }
    return result;
}
}

CString LaunchShortcut::ExecutablePath()
{
    WCHAR path[32768] = {};
    DWORD length = GetModuleFileName(NULL, path, _countof(path));
    return length && length < _countof(path) ? CString(path) : CString();
}

BOOL LaunchShortcut::IsProxyLaneExecutable(const CString& path)
{
    if (path.IsEmpty()) return FALSE;
    if (path.CompareNoCase(ExecutablePath()) == 0) return TRUE;
    // Check identity too: a renamed ProxyLane must not become a launch target.
    DWORD ignored = 0, size = GetFileVersionInfoSize(path, &ignored);
    if (!size || size > 1024 * 1024) return FALSE;
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfo(path, 0, size, &data[0])) return FALSE;
    struct Translation { WORD language, codepage; } *translations = NULL;
    UINT bytes = 0;
    if (!VerQueryValue(&data[0], L"\\VarFileInfo\\Translation", reinterpret_cast<void**>(&translations), &bytes)) return FALSE;
    for (UINT i = 0; i < bytes / sizeof(Translation); ++i)
    {
        CString key; key.Format(L"\\StringFileInfo\\%04x%04x\\ProductName", translations[i].language, translations[i].codepage);
        LPWSTR value = NULL; UINT count = 0;
        if (VerQueryValue(&data[0], key, reinterpret_cast<void**>(&value), &count) && value && count &&
            CString(value).CompareNoCase(L"ProxyLane") == 0) return TRUE;
    }
    return FALSE;
}

LaunchShortcut::DecodeResult LaunchShortcut::Decode(const InstalledApplications::Application& source,
    InstalledApplications::Application& target, AutomationOptions& options)
{
    InstalledApplications::Application resolved = source;
    if (IsLink(source.path) && !InstalledApplications::ResolveShortcut(source.path, resolved)) return Invalid;
    if (resolved.IsPackaged() || !IsProxyLaneExecutable(resolved.path)) return NotManaged;
    CString error;
    if (!ParseAutomationOptions(QuoteCommandLineArgument(resolved.path) + L" " + resolved.arguments, options, error) ||
        !options.enabled || options.showHelp || !options.bootstrapEventName.IsEmpty()) return Invalid;
    target = InstalledApplications::Application();
    if (options.packaged) target.aumid = options.targetPath;
    else target.path = options.targetPath;
    target.arguments = options.initialArguments;
    target.workingDirectory = options.workingDirectory;
    if (IsLink(target.path))
    {
        // Legacy --run links may point at an ordinary application shortcut. Nested
        // ProxyLane links are rejected instead of recursively interpreting commands.
        if (!InstalledApplications::ResolveShortcut(target.path, target) || IsLink(target.path)) return Invalid;
        if (!options.initialArguments.IsEmpty())
        {
            if (!target.arguments.IsEmpty()) target.arguments += L" ";
            target.arguments += options.initialArguments;
        }
    }
    if (!target.IsPackaged() && IsProxyLaneExecutable(target.path)) return Invalid;
    for (size_t i = 0; i < options.targetArguments.size(); ++i)
    {
        if (!target.arguments.IsEmpty()) target.arguments += L" ";
        target.arguments += QuoteCommandLineArgument(options.targetArguments[i]);
    }
    target.sources.clear(); target.icon = NULL;
    target.name = target.IsPackaged() ? target.aumid : CString(PathFindFileName(target.path));
    if (!options.applicationName.IsEmpty()) target.name = options.applicationName;
    options.targetPath = target.IsPackaged() ? target.aumid : target.path;
    options.packaged = target.IsPackaged();
    options.initialArguments = target.arguments; options.workingDirectory = target.workingDirectory;
    options.targetArguments.clear();
    return Decoded;
}

HRESULT LaunchShortcut::Create(const CString& destination, const CString& profile, const RecentApplications::Entry& entry)
{
    InstalledApplications::Application app;
    if (profile.IsEmpty() || !RecentApplications::Resolve(entry, app)) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    AutomationOptions decoded;
    InstalledApplications::Application original;
    DecodeResult state = Decode(app, original, decoded);
    if (state == Invalid) return E_INVALIDARG;
    if (state == Decoded) app = original;
    AutomationOptions options;
    options.enabled = options.shortcut = TRUE; options.profileName = profile;
    options.applicationName = entry.app.name;
    options.targetPath = app.IsPackaged() ? app.aumid : app.path;
    options.initialArguments = app.arguments; options.workingDirectory = app.workingDirectory;
    options.packaged = app.IsPackaged(); options.elevated = entry.elevated || decoded.elevated;
    if (options.packaged) options.elevated = FALSE;
    const CString executable = ExecutablePath(), arguments = BuildAutomationCommandLine(options, NULL);
    if (executable.IsEmpty() || arguments.GetLength() + executable.GetLength() + 4 >= 32767) return E_INVALIDARG;

    CString iconPath, cachedIcon; int iconIndex = 0;
    if (!entry.shortcut.IsEmpty())
    {
        CComPtr<IShellLinkW> source;
        if (SUCCEEDED(source.CoCreateInstance(CLSID_ShellLink)))
        {
            CComQIPtr<IPersistFile> file(source); WCHAR path[32768] = {};
            if (file && SUCCEEDED(file->Load(entry.shortcut, STGM_READ)) &&
                SUCCEEDED(source->GetIconLocation(path, _countof(path), &iconIndex)) && path[0])
            {
                WCHAR expanded[32768] = {};
                const DWORD count = ExpandEnvironmentStrings(path, expanded, _countof(expanded));
                if (count && count <= _countof(expanded)) iconPath = expanded;
                if (!iconPath.IsEmpty() && PathIsRelative(iconPath)) iconPath = ConfigStorage::Directory(entry.shortcut) + L"\\" + iconPath;
                if (GetFileAttributes(iconPath) == INVALID_FILE_ATTRIBUTES) iconPath.Empty();
            }
        }
    }
    if (iconPath.IsEmpty() && !app.IsPackaged() && CString(PathFindExtension(app.path)).CompareNoCase(L".exe") == 0)
    { iconPath = app.path; iconIndex = 0; }
    if (iconPath.IsEmpty())
    {
        RecentApplications::Entry iconEntry = entry; iconEntry.app = app; iconEntry.available = TRUE;
        HICON icon = RecentApplications::LoadIcon(iconEntry);
        HRESULT result = CacheIcon(icon, cachedIcon);
        if (icon) DestroyIcon(icon);
        if (FAILED(result)) return result;
        iconPath = cachedIcon; iconIndex = 0;
    }

    CComPtr<IShellLinkW> link;
    HRESULT result = link.CoCreateInstance(CLSID_ShellLink);
    if (SUCCEEDED(result)) result = link->SetPath(executable);
    if (SUCCEEDED(result)) result = link->SetArguments(arguments);
    if (SUCCEEDED(result)) result = link->SetWorkingDirectory(ConfigStorage::Directory(executable));
    if (SUCCEEDED(result)) result = link->SetDescription(entry.app.name + L" (" + profile + L") - ProxyLane");
    if (SUCCEEDED(result)) result = link->SetIconLocation(iconPath, iconIndex);
    CComQIPtr<IPersistFile> file(link);
    // Write alongside the destination, then replace atomically. A failed export
    // must leave an existing shortcut untouched.
    WCHAR temporary[MAX_PATH] = {};
    if (SUCCEEDED(result) && !GetTempFileName(ConfigStorage::Directory(destination), L"PLS", 0, temporary)) result = LastErrorResult();
    if (SUCCEEDED(result)) result = file ? file->Save(temporary, TRUE) : E_NOINTERFACE;
    if (SUCCEEDED(result))
    {
        CComPtr<IShellLinkW> verify; result = verify.CoCreateInstance(CLSID_ShellLink);
        CComQIPtr<IPersistFile> persisted(verify); WCHAR actual[32768] = {};
        if (SUCCEEDED(result)) result = persisted ? persisted->Load(temporary, STGM_READ) : E_NOINTERFACE;
        if (SUCCEEDED(result)) result = verify->GetArguments(actual, _countof(actual));
        if (SUCCEEDED(result) && arguments != actual) result = HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
    }
    if (SUCCEEDED(result) && !MoveFileEx(temporary, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) result = LastErrorResult();
    if (temporary[0]) DeleteFile(temporary);
    if (FAILED(result) && !cachedIcon.IsEmpty()) DeleteFile(cachedIcon);
    if (SUCCEEDED(result)) SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW, static_cast<LPCWSTR>(destination), NULL);
    return result;
}

BOOL LaunchShortcut::Start(const AutomationOptions& options)
{
    const CString executable = ExecutablePath(), arguments = BuildAutomationCommandLine(options, NULL);
    SHELLEXECUTEINFO info = { sizeof(info) };
    info.lpFile = executable; info.lpParameters = arguments; info.nShow = SW_HIDE;
    return ShellExecuteEx(&info);
}

BOOL LaunchShortcut::PromptCreate(CWnd* owner, const CString& profile, const RecentApplications::Entry& entry,
    const std::function<BOOL()>& stillCurrent)
{
    CString name = entry.app.name + L" (" + profile + (entry.elevated ? L", " + Localization::Get(L"recent.elevated") : CString()) + L")";
    for (int i = 0; i < name.GetLength(); ++i)
        if (name[i] < 32 || CString(L"\\/:*?\"<>|").Find(name[i]) >= 0) name.SetAt(i, L'_');
    name = name.Left(160); name.TrimRight(L" ."); name += L".lnk";
    WCHAR desktop[MAX_PATH] = {};
    SHGetFolderPath(NULL, CSIDL_DESKTOPDIRECTORY, NULL, SHGFP_TYPE_CURRENT, desktop);
    const CString filter = Localization::Get(L"shortcut.filter"), title = Localization::Get(L"shortcut.create");
    CFileDialog dialog(FALSE, L"lnk", name, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR | OFN_NODEREFERENCELINKS, filter, owner);
    dialog.m_ofn.lpstrInitialDir = desktop; dialog.m_ofn.lpstrTitle = title;
    if (dialog.DoModal() != IDOK || !stillCurrent()) return FALSE;
    const CString destination = dialog.GetPathName();
    if (destination.Right(4).CompareNoCase(L".lnk") != 0)
    {
        owner->MessageBox(Localization::Get(L"shortcut.extension"), title, MB_OK | MB_ICONWARNING); return FALSE;
    }
    const HRESULT result = Create(destination, profile, entry);
    if (FAILED(result))
    {
        const CString error = ConfigStorage::ErrorText(HRESULT_FACILITY(result) == FACILITY_WIN32 ? HRESULT_CODE(result) : ERROR_INVALID_DATA);
        owner->MessageBox(Localization::Format(L"shortcut.save_failed", (LPCTSTR)error), title, MB_OK | MB_ICONWARNING);
    }
    return SUCCEEDED(result);
}

int LaunchShortcut::ChooseProfile(HWND owner, const CString& shortcutProfile, const CString& currentProfile)
{
    CString title = Localization::Get(L"shortcut.title"), heading = Localization::Get(L"shortcut.choose_profile");
    CString fromLink = Localization::Format(L"shortcut.use_link_profile", (LPCTSTR)shortcutProfile);
    CString current = Localization::Format(L"shortcut.use_current_profile", (LPCTSTR)currentProfile);
    // Resolve dynamically to retain compatibility with Windows XP.
    typedef HRESULT (WINAPI* TaskDialogFn)(const TASKDIALOGCONFIG*, int*, int*, BOOL*);
    HMODULE module = LoadLibrary(L"comctl32.dll");
    TaskDialogFn dialog = module ? reinterpret_cast<TaskDialogFn>(GetProcAddress(module, "TaskDialogIndirect")) : NULL;
    int answer = IDCANCEL;
    HRESULT result = E_NOTIMPL;
    if (dialog)
    {
        TASKDIALOG_BUTTON buttons[] = { { IDYES, fromLink }, { IDNO, current } };
        TASKDIALOGCONFIG config = { sizeof(config) };
        config.hwndParent = owner; config.pszWindowTitle = title; config.pszMainInstruction = heading;
        config.dwFlags = TDF_USE_COMMAND_LINKS | TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
        config.dwCommonButtons = TDCBF_CANCEL_BUTTON; config.cButtons = _countof(buttons); config.pButtons = buttons;
        config.nDefaultButton = IDCANCEL;
        result = dialog(&config, &answer, NULL, NULL);
    }
    if (module) FreeLibrary(module);
    if (FAILED(result))
        answer = ::MessageBox(owner, Localization::Format(L"shortcut.profile_conflict", (LPCTSTR)shortcutProfile, (LPCTSTR)currentProfile),
            title, MB_YESNOCANCEL | MB_ICONQUESTION | MB_DEFBUTTON3);
    return answer;
}

void LaunchShortcut::ReportFailure(const AutomationOptions& options, int exitCode)
{
    if (!options.shortcut || !exitCode) return;
    LPCTSTR key = exitCode == AUTOMATION_EXIT_PROFILE_INVALID ? L"shortcut.profile_missing" :
        exitCode == AUTOMATION_EXIT_TARGET_INVALID ? L"shortcut.target_invalid" : L"shortcut.launch_failed";
    CString message = Localization::Format(key, static_cast<LPCTSTR>(options.profileName), static_cast<LPCTSTR>(options.targetPath));
    ::MessageBox(NULL, message, Localization::Get(L"shortcut.title"), MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
}
