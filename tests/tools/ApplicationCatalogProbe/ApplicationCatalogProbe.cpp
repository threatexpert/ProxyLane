#include "stdafx.h"
#include "InstalledApplications.h"
#include "ApplicationCatalogCache.h"
#include <atlbase.h>
#include <shlobj.h>
#include <iostream>

CWinApp application;

static BOOL WaitForCatalog(ApplicationCatalogLoad* load)
{
	const DWORD started = GetTickCount();
	for (;;)
	{
		EnterCriticalSection(&load->lock);
		const BOOL done = load->done;
		const HRESULT result = load->result;
		LeaveCriticalSection(&load->lock);
		if (done) return SUCCEEDED(result);
		if (GetTickCount() - started > 30000) return FALSE;
		Sleep(10);
	}
}

static BOOL CheckCatalogCache()
{
	ApplicationCatalogLoad* first = AcquireApplicationCatalog(FALSE);
	first->Release(); // Simulate closing the picker before the first scan completes.
	first = AcquireApplicationCatalog(FALSE);
	BOOL passed = WaitForCatalog(first) && !first->applications.empty();
	ApplicationCatalogLoad* cached = AcquireApplicationCatalog(FALSE);
	passed = passed && cached == first;
	std::vector<InstalledApplications::Application> cloned;
	if (passed)
	{
		InstalledApplications::Clone(first->applications, cloned);
		passed = cloned.size() == first->applications.size();
		for (size_t i = 0; i < cloned.size(); ++i)
			if (first->applications[i].icon && (!cloned[i].icon || cloned[i].icon == first->applications[i].icon))
				passed = FALSE;
	}
	InstalledApplications::ReleaseIcons(cloned);
	cached->Release();
	ApplicationCatalogLoad* refreshed = AcquireApplicationCatalog(TRUE);
	passed = WaitForCatalog(refreshed) && refreshed != first && passed;
	ApplicationCatalogLoad* again = AcquireApplicationCatalog(FALSE);
	passed = passed && again == refreshed;
	again->Release();
	refreshed->Release();
	first->Release();
	// Reopening during a refresh can reuse the last successful snapshot.
	ApplicationCatalogLoad* detached = AcquireApplicationCatalog(TRUE);
	ApplicationCatalogLoad* reopened = AcquireApplicationCatalog(FALSE);
	passed = WaitForCatalog(reopened) && passed;
	passed = WaitForCatalog(detached) && passed;
	ApplicationCatalogLoad* completed = AcquireApplicationCatalog(FALSE);
	passed = passed && completed == detached;
	completed->Release();
	reopened->Release();
	detached->Release();
	std::wcout << L"catalog_cache_refresh=" << (passed ? L"PASS" : L"FAIL") << L"\n";
	return passed;
}

static BOOL GetShellData(const CString& parsingName, std::vector<InstalledApplications::Application>& applications,
	BOOL* hasFiles = NULL)
{
	LPITEMIDLIST absolute = NULL;
	HRESULT hr = SHParseDisplayName(parsingName, NULL, &absolute, 0, NULL);
	CComPtr<IShellFolder> parent;
	LPCITEMIDLIST child = NULL;
	if (SUCCEEDED(hr)) hr = SHBindToParent(absolute, IID_IShellFolder, (void**)&parent, &child);
	CComPtr<IDataObject> object;
	if (SUCCEEDED(hr)) hr = parent->GetUIObjectOf(NULL, 1, &child, IID_IDataObject, NULL, (void**)&object);
	CoTaskMemFree(absolute);
	if (FAILED(hr)) return FALSE;
	const CLIPFORMAT shellFormat = static_cast<CLIPFORMAT>(RegisterClipboardFormat(CFSTR_SHELLIDLIST));
	FORMATETC format = {CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
	if (hasFiles) *hasFiles = object->QueryGetData(&format) == S_OK;
	format.cfFormat = shellFormat;
	STGMEDIUM medium = {0};
	hr = object->GetData(&format, &medium);
	const BOOL passed = SUCCEEDED(hr) && medium.tymed == TYMED_HGLOBAL &&
		InstalledApplications::ResolveShellDrop(medium.hGlobal, applications);
	if (SUCCEEDED(hr)) ReleaseStgMedium(&medium);
	return passed;
}

static BOOL CheckShellDataObject(const CString& aumid)
{
	std::vector<InstalledApplications::Application> applications;
	BOOL hasFiles = FALSE;
	const BOOL passed = GetShellData(L"shell:AppsFolder\\" + aumid, applications, &hasFiles) &&
		applications.size() == 1 && applications[0].IsPackaged() && applications[0].aumid == aumid;
	std::wcout << L"claude_shell_hdrop=" << hasFiles << L"\n";
	std::wcout << L"claude_shell_idlist=" << (passed ? L"PASS" : L"FAIL") << L"\n";
	return passed;
}

static BOOL CheckMalformedDrop()
{
	// Reject offset/header/length/count corruption without changing caller results.
	UINT cases[][6] = {
		{0, 12, 14, 0, 0, 0}, {257, 12, 14, 0, 0, 0},
		{1, 0, 14, 0, 0, 0}, {1, 12, 0xffffffff, 0, 0, 0},
		{1, 12, 16, 0, 1, 0}, {1, 12, 16, 0, 0xffff, 0},
		{1, 12, 22, 0, 0, 0xffff0000}
	};
	BOOL passed = TRUE;
	for (size_t i = 0; i < _countof(cases); ++i)
	{
		HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, sizeof(cases[i]));
		if (!memory) return FALSE;
		void* data = GlobalLock(memory);
		if (!data) { GlobalFree(memory); return FALSE; }
		memcpy(data, cases[i], sizeof(cases[i]));
		GlobalUnlock(memory);
		std::vector<InstalledApplications::Application> applications(1);
		applications[0].name = L"sentinel";
		if (InstalledApplications::ResolveShellDrop(memory, applications) ||
			applications.size() != 1 || applications[0].name != L"sentinel") passed = FALSE;
		GlobalFree(memory);
	}
	std::wcout << L"malformed_shell_idlist=" << (passed ? L"PASS" : L"FAIL") << L"\n";
	return passed;
}

static BOOL CheckCatalogMerge()
{
	InstalledApplications::Application shell;
	shell.name = L"Developer environment";
	shell.path = L"C:\\Windows\\System32\\cmd.exe";
	shell.arguments = L"/k \"C:\\VS\\VsDevCmd.bat\"";
	shell.sources.push_back(InstalledApplications::Source(
		InstalledApplications::SOURCE_SYSTEM_APPLICATIONS, L"shell:AppsFolder\\Developer"));
	InstalledApplications::Application shortcut = shell;
	shortcut.path.MakeUpper();
	shortcut.workingDirectory = L"C:\\VS\\";
	shortcut.sources.clear();
	shortcut.sources.push_back(InstalledApplications::Source(
		InstalledApplications::SOURCE_COMMON_START_MENU, L"C:\\Start Menu\\Developer.lnk"));
	InstalledApplications::Application equivalent = shortcut;
	equivalent.workingDirectory = L"c:/vs";
	equivalent.sources[0].path.MakeUpper();
	std::vector<InstalledApplications::Application> entries;
	entries.push_back(shell);
	entries.push_back(shortcut);
	entries.push_back(equivalent);
	InstalledApplications::Deduplicate(entries);
	BOOL passed = entries.size() == 1 && entries[0].workingDirectory == shortcut.workingDirectory &&
		entries[0].arguments == shell.arguments && entries[0].sources.size() == 2;
	// Reversing source order must not erase the explicit shortcut cwd.
	entries.clear();
	entries.push_back(shortcut);
	entries.push_back(shell);
	InstalledApplications::Deduplicate(entries);
	passed = passed && entries.size() == 1 && entries[0].workingDirectory == shortcut.workingDirectory &&
		entries[0].sources.size() == 2;
	InstalledApplications::Application differentDirectory = shortcut;
	differentDirectory.workingDirectory = L"C:\\Other";
	InstalledApplications::Application differentArguments = shortcut;
	differentArguments.arguments = L"/k \"C:\\VS\\OTHER.bat\"";
	InstalledApplications::Application argumentCase = differentArguments;
	argumentCase.arguments = L"/k \"C:\\VS\\other.bat\"";
	entries.push_back(differentDirectory);
	entries.push_back(differentArguments);
	entries.push_back(argumentCase);
	InstalledApplications::Deduplicate(entries);
	passed = passed && entries.size() == 4;
	std::wcout << L"catalog_merge=" << (passed ? L"PASS" : L"FAIL") << L"\n";
	return passed;
}

static BOOL CheckLaunchDisplay()
{
	InstalledApplications::Application app;
	app.path = L"C:\\Program Files\\App\\app.exe";
	app.arguments = L"--name \"hello world\"";
	BOOL passed = InstalledApplications::LaunchTargetAndArguments(app) ==
		L"\"C:\\Program Files\\App\\app.exe\" --name \"hello world\"";
	app.aumid = L"Sample_family!App";
	passed = passed && InstalledApplications::LaunchTargetAndArguments(app) ==
		L"Sample_family!App --name \"hello world\"";
	app.arguments.Empty();
	passed = passed && InstalledApplications::LaunchTargetAndArguments(app) == app.aumid;
	app.arguments = CString(L'x', 4096);
	passed = passed && InstalledApplications::LaunchTargetAndArguments(app).GetLength() ==
		app.aumid.GetLength() + 1 + app.arguments.GetLength();
	std::wcout << L"launch_display=" << (passed ? L"PASS" : L"FAIL") << L"\n";
	return passed;
}

int wmain(int argc, wchar_t** argv)
{
	if (!AfxWinInit(GetModuleHandle(NULL), NULL, GetCommandLine(), 0)) return 1;
	const HRESULT initialized = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(initialized)) return 1;
	int failures = 0;
	std::vector<InstalledApplications::Application> applications;
	const DWORD started = GetTickCount();
	const HRESULT result = InstalledApplications::Enumerate(applications, NULL);
	std::wcout << L"catalog_result=" << std::hex << result << std::dec
		<< L" entries=" << applications.size() << L" elapsed_ms=" << (GetTickCount() - started) << L"\n";
	if (FAILED(result) || applications.empty()) ++failures;
	int desktopCount = 0, packagedCount = 0, defaultEdgeCount = 0;
	CString claudeId;
	int debugManagerCount = 0, developerCmdCount = 0, developerPowerShellCount = 0;
	for (size_t i = 0; i < applications.size(); ++i)
	{
		const InstalledApplications::Application& app = applications[i];
		if (app.sources.empty() || InstalledApplications::LaunchTargetAndArguments(app).IsEmpty()) ++failures;
		if (app.IsPackaged()) ++packagedCount; else ++desktopCount;
		if (app.name.Find(L"Developer ") == 0 || app.name == L"Debuggable Package Manager")
		{
			std::wcout << L"duplicate_candidate=" << static_cast<LPCWSTR>(app.name)
				<< L" target=" << static_cast<LPCWSTR>(app.path)
				<< L" args=" << static_cast<LPCWSTR>(app.arguments)
				<< L" cwd=" << static_cast<LPCWSTR>(app.workingDirectory)
				<< L" sources=" << app.sources.size() << L"\n";
			if (app.name == L"Debuggable Package Manager") ++debugManagerCount;
			if (app.name == L"Developer Command Prompt for VS 2019") ++developerCmdCount;
			if (app.name == L"Developer PowerShell for VS 2019") ++developerPowerShellCount;
			if (app.workingDirectory.IsEmpty()) ++failures;
		}
		if (app.name.CompareNoCase(L"Microsoft Edge") == 0)
		{
			if (app.arguments.IsEmpty()) ++defaultEdgeCount;
			std::wcout << L"edge_target=" << static_cast<LPCWSTR>(app.path)
				<< L" args=" << static_cast<LPCWSTR>(app.arguments)
				<< L" cwd=" << static_cast<LPCWSTR>(app.workingDirectory) << L"\n";
		}
		if (app.name.CompareNoCase(L"Claude") == 0)
		{
			claudeId = app.aumid;
			std::wcout << L"claude_aumid=" << static_cast<LPCWSTR>(app.aumid) << L"\n";
		}
	}
	std::wcout << L"desktop=" << desktopCount << L" packaged=" << packagedCount << L"\n";
	if (defaultEdgeCount > 1) ++failures;
	if (debugManagerCount > 1 || developerCmdCount > 1 || developerPowerShellCount > 1) ++failures;
	if (!CheckCatalogMerge()) ++failures;
	if (!CheckLaunchDisplay()) ++failures;
	if (!CheckCatalogCache()) ++failures;
	std::wcout << L"edge_dedup=" << (defaultEdgeCount <= 1 ? L"PASS" : L"FAIL") << L"\n";
	if (!claudeId.IsEmpty() && !CheckShellDataObject(claudeId)) ++failures;
	if (!CheckMalformedDrop()) ++failures;
	InstalledApplications::ReleaseIcons(applications);
	// A cancelled load must stop without enumerating Shell icons or menus.
	HANDLE cancel = CreateEvent(NULL, TRUE, TRUE, NULL);
	std::vector<InstalledApplications::Application> cancelled;
	const HRESULT cancelledResult = InstalledApplications::Enumerate(cancelled, cancel);
	if (cancelledResult != HRESULT_FROM_WIN32(ERROR_CANCELLED) || !cancelled.empty()) ++failures;
	CloseHandle(cancel);
	InstalledApplications::ReleaseIcons(cancelled);
	// Exercise actual .lnk serialization, preserving quoted arguments and cwd.
	WCHAR tempDir[MAX_PATH] = {0}, tempLink[MAX_PATH] = {0}, executable[MAX_PATH] = {0};
	GetTempPath(_countof(tempDir), tempDir);
	GetModuleFileName(NULL, executable, _countof(executable));
	if (!GetTempFileName(tempDir, L"PLC", 0, tempLink)) ++failures;
	else
	{
		const CString shortcutPath = CString(tempLink) + L".lnk";
		CComPtr<IShellLinkW> link;
		HRESULT hr = link.CoCreateInstance(CLSID_ShellLink);
		if (SUCCEEDED(hr)) hr = link->SetPath(executable);
		if (SUCCEEDED(hr)) hr = link->SetArguments(L"--value \"hello world\" --flag");
		if (SUCCEEDED(hr)) hr = link->SetWorkingDirectory(tempDir);
		CComQIPtr<IPersistFile> persist(link);
		if (SUCCEEDED(hr) && persist) hr = persist->Save(shortcutPath, TRUE);
		InstalledApplications::Application resolved;
		const BOOL passed = SUCCEEDED(hr) && InstalledApplications::ResolveShortcut(shortcutPath, resolved) &&
			!resolved.IsPackaged() && resolved.path.CompareNoCase(executable) == 0 &&
			resolved.arguments == L"--value \"hello world\" --flag" && resolved.workingDirectory == tempDir &&
			resolved.sources.size() == 1 && resolved.sources[0].kind == InstalledApplications::SOURCE_SHORTCUT &&
			resolved.sources[0].path == shortcutPath;
		std::wcout << L"desktop_shortcut=" << (passed ? L"PASS" : L"FAIL") << L"\n";
		if (!passed) ++failures;
		std::vector<InstalledApplications::Application> dropped;
		const BOOL shellPassed = GetShellData(shortcutPath, dropped) && dropped.size() == 1 &&
			dropped[0].path.CompareNoCase(executable) == 0 &&
			dropped[0].arguments == resolved.arguments && dropped[0].workingDirectory == resolved.workingDirectory;
		std::wcout << L"desktop_shell_idlist=" << (shellPassed ? L"PASS" : L"FAIL") << L"\n";
		if (!shellPassed) ++failures;
		DeleteFile(shortcutPath);
		DeleteFile(tempLink);
	}
	if (argc > 1)
	{
		InstalledApplications::Application resolved;
		const BOOL passed = InstalledApplications::ResolveShortcut(argv[1], resolved) &&
			resolved.IsPackaged() && (claudeId.IsEmpty() || resolved.aumid == claudeId);
		std::wcout << L"packaged_shortcut=" << (passed ? L"PASS" : L"FAIL")
			<< L" aumid=" << static_cast<LPCWSTR>(resolved.aumid) << L"\n";
		if (!passed) ++failures;
		std::vector<InstalledApplications::Application> dropped;
		const BOOL shellPassed = GetShellData(argv[1], dropped) && dropped.size() == 1 &&
			dropped[0].aumid == resolved.aumid;
		std::wcout << L"packaged_shortcut_shell_idlist=" << (shellPassed ? L"PASS" : L"FAIL") << L"\n";
		if (!shellPassed) ++failures;
	}
	CoUninitialize();
	std::wcout << L"probe_result=" << (failures ? L"FAIL" : L"PASS") << L"\n";
	return failures ? 1 : 0;
}
