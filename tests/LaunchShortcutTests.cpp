#include "stdafx.h"
#include "LaunchShortcut.h"
#include "ConfigStorage.h"
// Exercise the actual wire codec, including its backwards-compatible v1 format.
#include "../src/ProxyLane/ProfileCommandBroker.cpp"
#include <atlbase.h>
#include <shlobj.h>
#include <iostream>
#include <stdexcept>

CWinApp application;
static void Check(bool ok, const char* what) { if (!ok) throw std::runtime_error(what); }
static void WriteLink(const CString& path, const CString& target, const CString& arguments,
    const CString& directory = CString(), const CString& icon = CString(), int index = 0)
{
    CComPtr<IShellLinkW> link; Check(SUCCEEDED(link.CoCreateInstance(CLSID_ShellLink)), "create shell link");
    Check(SUCCEEDED(link->SetPath(target)) && SUCCEEDED(link->SetArguments(arguments)) &&
        SUCCEEDED(link->SetWorkingDirectory(directory)) && SUCCEEDED(link->SetIconLocation(icon, index)), "set link fields");
    CComQIPtr<IPersistFile> file(link); Check(file && SUCCEEDED(file->Save(path, TRUE)), "save link");
}
static CComPtr<IShellLinkW> ReadLink(const CString& path)
{
    CComPtr<IShellLinkW> link; Check(SUCCEEDED(link.CoCreateInstance(CLSID_ShellLink)), "read shell link");
    CComQIPtr<IPersistFile> file(link); Check(file && SUCCEEDED(file->Load(path, STGM_READ)), "load link"); return link;
}
static void Equal(const AutomationOptions& a, const AutomationOptions& b)
{
    Check(a.profileName == b.profileName && a.targetPath == b.targetPath &&
        a.targetArguments == b.targetArguments && a.initialArguments == b.initialArguments &&
        a.workingDirectory == b.workingDirectory && a.elevated == b.elevated && a.packaged == b.packaged &&
        a.applicationName == b.applicationName && a.shortcut == b.shortcut, "launch information round-trip");
}
static void TestArguments()
{
    AutomationOptions original; original.enabled = original.shortcut = original.elevated = TRUE;
    original.profileName = L"Test 中文 \"profile\"";
    original.applicationName = L"Example 中文 app";
    original.targetPath = L"C:\\Program Files\\Example App\\app.exe";
    original.initialArguments = L"--name \"hello world\" --literal=\\\"quote\\\" --help";
    original.workingDirectory = L"C:\\Working directory\\";
    const LPCWSTR values[] = { L"", L"--help", L"/?", L"--profile", L"中文 空格", L"backslash\\", L"space end\\", L"a\\\"b", L"\"" };
    for (size_t i = 0; i < _countof(values); ++i) original.targetArguments.push_back(values[i]);
    CString error; AutomationOptions parsed;
    AutomationOptions combined = original;
    for (size_t i = 0; i < combined.targetArguments.size(); ++i)
        combined.initialArguments += L" " + QuoteCommandLineArgument(combined.targetArguments[i]);
    combined.targetArguments.clear();
    const CString exported = BuildAutomationCommandLine(original, L"Local\\test");
    Check(exported.Find(L" --arguments ") < 0 && exported.Find(L" -- ") >= 0, "export uses raw -- tail");
    Check(ParseAutomationOptions(L"ProxyLane.exe " + exported, parsed, error), "parse exported options");
    Equal(combined, parsed); Check(parsed.shortcut && !parsed.showHelp && parsed.bootstrapEventName == L"Local\\test", "bootstrap and help boundary");
    original.packaged = TRUE; original.targetPath = L"Test.Package!App";
    combined.packaged = TRUE; combined.targetPath = original.targetPath;
    Check(ParseAutomationOptions(L"ProxyLane.exe " + BuildAutomationCommandLine(original, NULL), parsed, error), "parse packaged target"); Equal(combined, parsed);
    Check(!ParseAutomationOptions(L"ProxyLane.exe --auto --profile A --run app.exe --elevated --elevated", parsed, error), "reject duplicate flags");
    Check(!ParseAutomationOptions(L"ProxyLane.exe --auto --profile A --run app.exe --working-directory", parsed, error), "reject missing directory");
    Check(ParseAutomationOptions(L"ProxyLane.exe --auto --profile A --run app.exe -- --help", parsed, error) && !parsed.showHelp, "application help is not ProxyLane help");
    const CString raw = L"--user-data-dir=\"%APPDATA%\\browser-W\"  \"\"\t--help ";
    for (size_t i = 0; i < _countof(values); ++i)
    {
        CString name(values[i]); if (name.IsEmpty()) name = L"--";
        const CString prefix = L"\"C:\\Program Files\\ProxyLane.exe\" --auto --profile " + QuoteCommandLineArgument(name) +
            L" --run app.exe --app-name " + QuoteCommandLineArgument(name);
        Check(ParseAutomationOptions(prefix + L" -- " + raw, parsed, error) && parsed.initialArguments == raw &&
            parsed.targetArguments.empty() && parsed.applicationName == name && !parsed.showHelp, "raw tail preserves quotes, whitespace and variables");
    }
    Check(ParseAutomationOptions(L"ProxyLane.exe --auto --profile A --run app.exe --arguments " +
        QuoteCommandLineArgument(raw) + L" --shortcut", parsed, error) && parsed.initialArguments == raw && parsed.shortcut,
        "old --arguments links remain supported");
    Check(ParseAutomationOptions(L"ProxyLane.exe --auto --profile A --run app.exe --arguments old -- new \"two words\"", parsed, error) &&
        parsed.initialArguments == L"old new \"two words\"", "legacy arguments plus raw tail append once");
    Check(ParseAutomationOptions(L"ProxyLane.exe --auto --profile A --run app.exe --", parsed, error) && parsed.initialArguments.IsEmpty(), "empty tail");

    std::vector<BYTE> bytes;
    Check(SerializeCommand(original, bytes) && ParseCommand(bytes.data(), static_cast<DWORD>(bytes.size()), parsed), "v3 wire codec with notification metadata"); Equal(original, parsed);
    Check(!ParseCommand(bytes.data(), static_cast<DWORD>(bytes.size() - 1), parsed), "reject truncated wire data");
    bytes.back() = 0x80;
    Check(!ParseCommand(bytes.data(), static_cast<DWORD>(bytes.size()), parsed), "reject unknown launch flags");
    AutomationOptions unattended = original; unattended.shortcut = FALSE; unattended.applicationName.Empty();
    Check(SerializeCommand(unattended, bytes) && ParseCommand(bytes.data(), static_cast<DWORD>(bytes.size()), parsed),
        "extended CLI request without notification"); Equal(unattended, parsed);
    AutomationOptions legacy; legacy.enabled = TRUE; legacy.profileName = L"A"; legacy.targetPath = L"app.exe"; legacy.targetArguments.push_back(L"a b");
    Check(SerializeCommand(legacy, bytes) && reinterpret_cast<const CommandHeader*>(bytes.data())->version == 1 &&
        ParseCommand(bytes.data(), static_cast<DWORD>(bytes.size()), parsed), "v1 compatibility"); Equal(legacy, parsed);
    std::cout << "CLI quoting, launch metadata, notification metadata and released-protocol compatibility: PASS\n";
}

static void TestRawTailBoundary()
{
    const LPCWSTR profiles[] = { L"Test -- A", L"--", L"PL_RAW_TAIL_MARKER",
        L"Test -- PL_RAW_TAIL_MARKER A", L"a\\\"b", L"中文 路径\\", L"\"\"", L"a\tb" };
    const LPCWSTR separators[] = { L"--", L"\"--\"", L"-\"-\"", L"--\"\"" };
    const LPCWSTR tails[] = { L"-val  v=\"a\"", L"\"\"\t\"tail\\\\\" ",
        L"PL_RAW_TAIL_MARKER --profile ignored", L"\"unclosed application quote",
        L"--help --arguments \"%APPDATA%\\browser-W\"", L"" };
    CString error; AutomationOptions parsed;
    for (size_t p = 0; p < _countof(profiles); ++p)
    {
        const CString prefix = L"\"C:\\Program Files\\ProxyLane.exe\" --auto --profile " +
            QuoteCommandLineArgument(profiles[p]) + L" --run app.exe --app-name PL_RAW_TAIL_MARKER ";
        for (size_t s = 0; s < _countof(separators); ++s)
        {
            for (size_t t = 0; t < _countof(tails); ++t)
            {
                Check(ParseAutomationOptions(prefix + separators[s] + L" \t " + tails[t], parsed, error) &&
                    parsed.initialArguments == tails[t] && parsed.profileName == profiles[p] &&
                    parsed.applicationName == L"PL_RAW_TAIL_MARKER" && !parsed.showHelp && parsed.targetArguments.empty(),
                    "system-validated boundary preserves raw tail despite marker/delimiter collisions");
            }
        }
    }
    Check(ParseAutomationOptions(L"ProxyLane.exe --auto --profile A --run app.exe --arguments "
        L"\"-- PL_RAW_TAIL_MARKER\" -- -val  v=\"a\"", parsed, error) &&
        parsed.initialArguments == L"-- PL_RAW_TAIL_MARKER -val  v=\"a\"", "legacy value is not a delimiter");
    Check(ParseAutomationOptions(L"ProxyLane.exe --auto --profile A --run app.exe \"--\"", parsed, error) &&
        parsed.initialArguments.IsEmpty(), "end of command is a candidate boundary");
    Check(!ParseAutomationOptions(L"ProxyLane.exe --auto --profile A --run app.exe \"--", parsed, error) &&
        !error.IsEmpty(), "unverifiable boundary fails instead of silently dropping arguments");
    std::cout << "System-validated raw boundary, marker collisions and failure handling: PASS\n";
}

static void TestEnvironment()
{
    const LPCWSTR variable = L"PROXYLANE_TEST_SHORTCUT_ENV_7B6A";
    WCHAR previous[32768] = {}; DWORD count = GetEnvironmentVariableW(variable, previous, _countof(previous));
    Check(SetEnvironmentVariableW(variable, L"C:\\Users\\Test 中文\\Application Data") != FALSE, "set test environment");
    CString expanded;
    const BOOL ok = ExpandLaunchEnvironment(L"--user-data-dir=\"%PROXYLANE_TEST_SHORTCUT_ENV_7B6A%\\browser-W\"", expanded);
    SetEnvironmentVariableW(variable, count ? previous : NULL);
    Check(ok && expanded == L"--user-data-dir=\"C:\\Users\\Test 中文\\Application Data\\browser-W\"", "expand quoted Unicode and space paths");
    Check(ExpandLaunchEnvironment(L"%PROXYLANE_TEST_UNDEFINED_7B6A% 100% \"\"", expanded) &&
        expanded == L"%PROXYLANE_TEST_UNDEFINED_7B6A% 100% \"\"", "preserve undefined variables and literal percent");
    Check(ExpandLaunchEnvironment(CString(), expanded) && expanded.IsEmpty(), "empty arguments");
    Check(!ExpandLaunchEnvironment(CString(L'x', 32767), expanded), "reject expanded command exceeding Windows limit");
    std::cout << "Launch-time environment expansion: PASS\n";
}

static void TestLinks(const CString& directory, CString& cachedIcon)
{
    WCHAR system[MAX_PATH]; GetSystemDirectory(system, _countof(system));
    const CString appPath = CString(system) + L"\\notepad.exe", iconPath = CString(system) + L"\\shell32.dll";
    const CString source = directory + L"\\source.lnk", exported = directory + L"\\launch.lnk";
    const CString raw = L"--help \"路径 with spaces\\\"quote\" \"tail\\\\\" --user-data-dir=\"%APPDATA%\\browser-W\"";
    WriteLink(source, appPath, raw, directory, iconPath, 17);
    RecentApplications::Entry entry; entry.app.name = L"Example 中文"; entry.shortcut = source; entry.elevated = TRUE;
    Check(SUCCEEDED(LaunchShortcut::Create(exported, L"Profile 中文", entry)), "export real shortcut");
    CComPtr<IShellLinkW> link = ReadLink(exported); WCHAR value[32768] = {}; int index = 0;
    Check(SUCCEEDED(link->GetArguments(value, _countof(value))) && CString(value).Find(L" --arguments ") < 0 &&
        CString(value).Find(L" -- " + raw) >= 0, "export keeps environment variables in raw -- tail");
    Check(SUCCEEDED(link->GetIconLocation(value, _countof(value), &index)) && iconPath == value && index == 17, "preserve custom icon and resource index");
    InstalledApplications::Application input, target; input.path = exported; AutomationOptions options;
    Check(LaunchShortcut::Decode(input, target, options) == LaunchShortcut::Decoded, "decode exported shortcut");
    Check(target.path.CompareNoCase(appPath) == 0 && target.arguments == raw && target.workingDirectory == directory &&
        target.sources.empty() && options.elevated && options.profileName == L"Profile 中文" &&
        target.name == entry.app.name && options.applicationName == entry.app.name && options.shortcut, "preserve original launch and notification metadata without wrapper dependency");
    Check(DeleteFile(source) && LaunchShortcut::Decode(input, target, options) == LaunchShortcut::Decoded, "export independent of source shortcut");
    Check(SetFileAttributes(exported, FILE_ATTRIBUTE_READONLY) != FALSE, "read-only link");
    entry.shortcut.Empty(); entry.app.path = appPath;
    Check(FAILED(LaunchShortcut::Create(exported, L"Other", entry)), "report write failure");
    SetFileAttributes(exported, FILE_ATTRIBUTE_NORMAL);
    Check(LaunchShortcut::Decode(input, target, options) == LaunchShortcut::Decoded && options.profileName == L"Profile 中文", "failed export preserves old link");

    const CString own = LaunchShortcut::ExecutablePath();
    WriteLink(source, own, L"--auto --profile A --run " + QuoteCommandLineArgument(own)); input.path = source;
    Check(LaunchShortcut::Decode(input, target, options) == LaunchShortcut::Invalid, "block self launch");
    WriteLink(source, own, L"--auto --profile A --run " + QuoteCommandLineArgument(source));
    Check(LaunchShortcut::Decode(input, target, options) == LaunchShortcut::Invalid, "block self-referencing shortcut");
    WriteLink(source, own, L"--auto --profile A --run " + QuoteCommandLineArgument(exported));
    Check(LaunchShortcut::Decode(input, target, options) == LaunchShortcut::Invalid, "block nested wrapper");
    WriteLink(source, own, L"--auto --profile A");
    Check(LaunchShortcut::Decode(input, target, options) == LaunchShortcut::Invalid, "block malformed wrapper");
    WriteLink(source, appPath, L"--help");
    Check(LaunchShortcut::Decode(input, target, options) == LaunchShortcut::NotManaged, "ordinary shortcut unchanged");
    entry.app.path = own;
    Check(FAILED(LaunchShortcut::Create(exported, L"A", entry)), "cannot export ProxyLane as target");

    entry.app.path.Empty(); entry.app.aumid = L"Sample.Package!App"; entry.app.arguments = L"example arguments";
    Check(SUCCEEDED(LaunchShortcut::Create(exported, L"A", entry)), "export packaged app with cached icon");
    input.path = exported;
    Check(LaunchShortcut::Decode(input, target, options) == LaunchShortcut::Decoded && target.IsPackaged() &&
        target.aumid == entry.app.aumid && target.arguments == entry.app.arguments && !options.elevated, "packaged target round-trip");
    link = ReadLink(exported); Check(SUCCEEDED(link->GetIconLocation(value, _countof(value), &index)), "cached icon location"); cachedIcon = value;
    HICON icon = reinterpret_cast<HICON>(LoadImage(NULL, cachedIcon, IMAGE_ICON, 32, 32, LR_LOADFROMFILE));
    Check(icon != NULL, "cached ICO readable by Windows"); DestroyIcon(icon);
    std::cout << "Shell links, custom icons, persisted ICO, source independence, write failure and recursion guards: PASS\n";
}

int wmain()
{
    if (!AfxWinInit(GetModuleHandle(NULL), NULL, GetCommandLine(), 0)) return 2;
    CoInitialize(NULL); int result = 0;
    WCHAR root[MAX_PATH], temp[MAX_PATH]; GetTempPath(_countof(root), root); GetTempFileName(root, L"PLS", 0, temp);
    DeleteFile(temp); CreateDirectory(temp, NULL); CString directory(temp), icon;
    const CString flag = ConfigStorage::Directory(LaunchShortcut::ExecutablePath()) + L"\\portable.flag";
    HANDLE marker = CreateFile(flag, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    const bool createdMarker = marker != INVALID_HANDLE_VALUE; if (createdMarker) CloseHandle(marker);
    try { TestArguments(); TestRawTailBoundary(); TestEnvironment(); TestLinks(directory, icon); }
    catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << " error=" << GetLastError() << "\n"; result = 1; }
    DeleteFile(directory + L"\\source.lnk"); SetFileAttributes(directory + L"\\launch.lnk", FILE_ATTRIBUTE_NORMAL);
    DeleteFile(directory + L"\\launch.lnk"); RemoveDirectory(directory);
    if (!icon.IsEmpty()) { DeleteFile(icon); RemoveDirectory(ConfigStorage::Directory(icon)); }
    if (createdMarker) DeleteFile(flag);
    CoUninitialize(); return result;
}
