#include "stdafx.h"
#include "InstalledApplications.h"
#include <atlbase.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <propkey.h>
#include <algorithm>
#include <map>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace
{
	BOOL Cancelled(HANDLE event)
	{
		return event && WaitForSingleObject(event, 0) == WAIT_OBJECT_0;
	}

	CString DisplayName(IShellFolder* folder, LPCITEMIDLIST item, SHGDNF flags)
	{
		STRRET name = {0};
		WCHAR buffer[32768] = {0};
		if (SUCCEEDED(folder->GetDisplayNameOf(item, flags, &name)) &&
			SUCCEEDED(StrRetToBufW(&name, item, buffer, _countof(buffer))))
			return CString(buffer);
		return CString();
	}

	CString Property(IShellFolder2* folder, LPCITEMIDLIST item, const PROPERTYKEY& key)
	{
		if (!folder)
			return CString();
		VARIANT value;
		VariantInit(&value);
		CString result;
		if (SUCCEEDED(folder->GetDetailsEx(item, &key, &value)) && value.vt == VT_BSTR)
			result = value.bstrVal;
		VariantClear(&value);
		return result;
	}

	CString PackagedId(const CString& parsingName)
	{
		CString id = parsingName.Mid(parsingName.ReverseFind(L'\\') + 1);
		const int separator = id.Find(L'!');
		if (separator <= 0 || separator == id.GetLength() - 1 ||
			id.Find(L':') >= 0 || id.Find(L'/') >= 0)
			return CString();
		return id;
	}

	BOOL IsLaunchableTarget(const CString& path)
	{
		if (path.IsEmpty() || PathIsRelative(path)) return FALSE;
		const CString extension(PathFindExtension(path));
		// Keep shortcuts and Shell items consistent with direct script drops.
		// Do not accept arbitrary documents that would require ShellExecute.
		if (extension.CompareNoCase(L".exe") != 0 &&
			extension.CompareNoCase(L".bat") != 0 &&
			extension.CompareNoCase(L".cmd") != 0) return FALSE;
		const DWORD attributes = GetFileAttributes(path);
		return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
	}

	typedef std::map<CString, std::vector<size_t> > CatalogIndex;

	CString DirectoryKey(const CString& directory)
	{
		CString key(directory);
		key.Replace(L'/', L'\\');
		while (key.GetLength() > 3 && key[key.GetLength() - 1] == L'\\')
			key.Delete(key.GetLength() - 1);
		key.MakeLower();
		return key;
	}

	void MergeSources(InstalledApplications::Application& destination,
		const InstalledApplications::Application& source)
	{
		for (size_t i = 0; i < source.sources.size(); ++i)
		{
			const InstalledApplications::Source& origin = source.sources[i];
			BOOL found = FALSE;
			for (size_t j = 0; j < destination.sources.size(); ++j)
				if (destination.sources[j].kind == origin.kind &&
					destination.sources[j].path.CompareNoCase(origin.path) == 0)
				{
					found = TRUE;
					break;
				}
			if (!found) destination.sources.push_back(origin);
		}
	}

	void Add(std::vector<InstalledApplications::Application>& entries,
		CatalogIndex& seen, InstalledApplications::Application& app)
	{
		CString key = app.IsPackaged() ? L"app:" + app.aumid : L"exe:" + app.path;
		key.Replace(L'/', L'\\');
		key.MakeLower();
		if (!app.IsPackaged())
		{
			// Arguments can be case-sensitive; do not lowercase the entire key.
			key += L"\n" + app.arguments;
		}
		std::vector<size_t>& candidates = seen[key];
		const CString directory = DirectoryKey(app.workingDirectory);
		for (size_t i = 0; i < candidates.size(); ++i)
		{
			InstalledApplications::Application& existing = entries[candidates[i]];
			if (app.IsPackaged() || directory.IsEmpty() || existing.workingDirectory.IsEmpty() ||
				directory == DirectoryKey(existing.workingDirectory))
			{
				// AppsFolder does not reliably expose the .lnk's cwd. Prefer the
				// explicit shortcut value, which may be required by its arguments.
				if (existing.workingDirectory.IsEmpty() && !app.workingDirectory.IsEmpty())
					existing.workingDirectory = app.workingDirectory;
				MergeSources(existing, app);
				if (app.icon) DestroyIcon(app.icon);
				app.icon = NULL;
				return;
			}
		}
		// Two explicitly different directories or argument sets stay distinct.
		candidates.push_back(entries.size());
		entries.push_back(app);
		app.icon = NULL;
	}

	BOOL ValidPidl(const BYTE* data, SIZE_T size, UINT offset, SIZE_T header)
	{
		if (offset < header || offset >= size) return FALSE;
		SIZE_T position = offset;
		while (position <= size && size - position >= sizeof(USHORT))
		{
			USHORT length = 0;
			memcpy(&length, data + position, sizeof(length));
			if (length == 0) return TRUE;
			if (length < sizeof(USHORT) || length > size - position) return FALSE;
			position += length;
			if (position - offset > 65536) return FALSE;
		}
		return FALSE;
	}

	BOOL ResolveShellItem(LPCITEMIDLIST absolute, InstalledApplications::Application& app)
	{
		CComPtr<IShellFolder> parent;
		LPCITEMIDLIST child = NULL;
		if (FAILED(SHBindToParent(absolute, IID_IShellFolder, (void**)&parent, &child)))
			return FALSE;
		CComQIPtr<IShellFolder2> details(parent);
		app.name = DisplayName(parent, child, SHGDN_NORMAL);
		const CString parsingName = DisplayName(parent, child, SHGDN_FORPARSING);
		app.sources.push_back(InstalledApplications::Source(InstalledApplications::SOURCE_SHELL_OBJECT, parsingName));
		app.aumid = PackagedId(Property(details, child, PKEY_AppUserModel_ID));
		if (app.aumid.IsEmpty()) app.aumid = PackagedId(parsingName);
		if (app.IsPackaged()) return TRUE;
		app.path = Property(details, child, PKEY_Link_TargetParsingPath);
		if (app.path.IsEmpty()) app.path = parsingName;
		if (CString(PathFindExtension(parsingName)).CompareNoCase(L".lnk") == 0)
		{
			InstalledApplications::Application shortcut;
			if (!InstalledApplications::ResolveShortcut(parsingName, shortcut)) return FALSE;
			shortcut.name = app.name;
			app = shortcut;
			return TRUE;
		}
		app.arguments = Property(details, child, PKEY_Link_Arguments);
		return IsLaunchableTarget(app.path);
	}

	HRESULT ReadAppsFolder(std::vector<InstalledApplications::Application>& entries,
		CatalogIndex& seen, HANDLE cancelEvent)
	{
		LPITEMIDLIST root = NULL;
		HRESULT hr = SHParseDisplayName(L"shell:AppsFolder", NULL, &root, 0, NULL);
		if (FAILED(hr))
			return hr;
		CComPtr<IShellFolder> desktop, folder;
		hr = SHGetDesktopFolder(&desktop);
		if (SUCCEEDED(hr))
			hr = desktop->BindToObject(root, NULL, IID_IShellFolder, (void**)&folder);
		CComPtr<IEnumIDList> items;
		if (SUCCEEDED(hr))
			hr = folder->EnumObjects(NULL, SHCONTF_NONFOLDERS, &items);
		CComQIPtr<IShellFolder2> details(folder);
		LPITEMIDLIST item = NULL;
		while (SUCCEEDED(hr) && items && !Cancelled(cancelEvent) &&
			items->Next(1, &item, NULL) == S_OK)
		{
			InstalledApplications::Application app;
			app.name = DisplayName(folder, item, SHGDN_NORMAL);
			app.path = Property(details, item, PKEY_Link_TargetParsingPath);
			app.arguments = Property(details, item, PKEY_Link_Arguments);
			const CString parsingName = DisplayName(folder, item, SHGDN_FORPARSING);
			app.sources.push_back(InstalledApplications::Source(
				InstalledApplications::SOURCE_SYSTEM_APPLICATIONS, parsingName));
			const CString id = Property(details, item, PKEY_AppUserModel_ID);
			app.aumid = PackagedId(id);
			if (app.aumid.IsEmpty())
				app.aumid = PackagedId(parsingName);
			if (!app.name.IsEmpty() && (app.IsPackaged() || IsLaunchableTarget(app.path)))
			{
				LPITEMIDLIST absolute = ILCombine(root, item);
				SHFILEINFO info = {0};
				if (absolute && SHGetFileInfo((LPCTSTR)absolute, 0, &info, sizeof(info),
					SHGFI_PIDL | SHGFI_ICON | SHGFI_SMALLICON))
					app.icon = info.hIcon;
				CoTaskMemFree(absolute);
				Add(entries, seen, app);
			}
			CoTaskMemFree(item);
			item = NULL;
		}
		CoTaskMemFree(root);
		return hr;
	}

	void ReadStartMenu(const CString& folder, int depth, InstalledApplications::SourceKind sourceKind,
		std::vector<InstalledApplications::Application>& entries,
		CatalogIndex& seen, HANDLE cancelEvent)
	{
		if (depth > 12 || Cancelled(cancelEvent))
			return;
		WIN32_FIND_DATA data = {0};
		HANDLE search = FindFirstFile(folder + L"\\*", &data);
		if (search == INVALID_HANDLE_VALUE)
			return;
		do
		{
			if (Cancelled(cancelEvent))
				break;
			if (data.cFileName[0] == L'.' || (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
				continue;
			const CString path = folder + L"\\" + data.cFileName;
			if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				ReadStartMenu(path, depth + 1, sourceKind, entries, seen, cancelEvent);
			else if (CString(PathFindExtension(path)).CompareNoCase(L".lnk") == 0)
			{
				InstalledApplications::Application app;
				if (InstalledApplications::ResolveShortcut(path, app))
				{
					for (size_t i = 0; i < app.sources.size(); ++i)
						app.sources[i].kind = sourceKind;
					app.name = data.cFileName;
					app.name = app.name.Left(app.name.GetLength() - 4);
					SHFILEINFO info = {0};
					if (SHGetFileInfo(path, 0, &info, sizeof(info), SHGFI_ICON | SHGFI_SMALLICON))
						app.icon = info.hIcon;
					Add(entries, seen, app);
				}
			}
		} while (FindNextFile(search, &data));
		FindClose(search);
	}
}

BOOL InstalledApplications::ResolveShellDrop(HGLOBAL memory, std::vector<Application>& applications)
{
	const SIZE_T size = memory ? GlobalSize(memory) : 0;
	if (size < sizeof(UINT) * 2 || size > 16 * 1024 * 1024) return FALSE;
	const BYTE* data = static_cast<const BYTE*>(GlobalLock(memory));
	if (!data) return FALSE;
	UINT count = 0;
	memcpy(&count, data, sizeof(count));
	BOOL valid = count > 0 && count <= 256;
	const SIZE_T header = sizeof(UINT) * (static_cast<SIZE_T>(count) + 2);
	std::vector<UINT> offsets;
	if (valid && header <= size)
	{
		offsets.resize(count + 1);
		memcpy(&offsets[0], data + sizeof(UINT), (count + 1) * sizeof(UINT));
		for (UINT i = 0; i <= count && valid; ++i)
			valid = ValidPidl(data, size, offsets[i], header);
	}
	else valid = FALSE;
	std::vector<Application> resolved;
	CatalogIndex seen;
	for (UINT i = 1; i <= count && valid; ++i)
	{
		LPITEMIDLIST absolute = ILCombine(reinterpret_cast<LPCITEMIDLIST>(data + offsets[0]),
			reinterpret_cast<LPCITEMIDLIST>(data + offsets[i]));
		Application app;
		valid = absolute && ResolveShellItem(absolute, app);
		CoTaskMemFree(absolute);
		if (valid) Add(resolved, seen, app);
	}
	GlobalUnlock(memory);
	if (valid) applications.swap(resolved);
	return valid;
}

BOOL InstalledApplications::ResolveShortcut(LPCTSTR path, Application& application)
{
	Application result;
	CComPtr<IShellLinkW> link;
	if (FAILED(link.CoCreateInstance(CLSID_ShellLink)))
		return FALSE;
	CComQIPtr<IPersistFile> persist(link);
	if (!persist || FAILED(persist->Load(path, STGM_READ)))
		return FALSE;
	// Resolve must not display dialogs or search for moved targets on the network.
	link->Resolve(NULL, SLR_NO_UI | SLR_NOSEARCH | SLR_NOTRACK);
	WCHAR buffer[32768] = {0};
	WIN32_FIND_DATAW data = {0};
	if (SUCCEEDED(link->GetPath(buffer, _countof(buffer), &data, SLGP_RAWPATH)))
	{
		WCHAR expanded[32768] = {0};
		const DWORD length = ExpandEnvironmentStringsW(buffer, expanded, _countof(expanded));
		if (length && length <= _countof(expanded))
			result.path = expanded;
	}
	if (SUCCEEDED(link->GetArguments(buffer, _countof(buffer))))
		result.arguments = buffer;
	if (SUCCEEDED(link->GetWorkingDirectory(buffer, _countof(buffer))))
	{
		WCHAR expanded[32768] = {0};
		const DWORD length = ExpandEnvironmentStringsW(buffer, expanded, _countof(expanded));
		if (length && length <= _countof(expanded))
			result.workingDirectory = expanded;
	}
	if (!IsLaunchableTarget(result.path))
	{
		LPITEMIDLIST target = NULL;
		CComPtr<IShellFolder> desktop;
		if (SUCCEEDED(link->GetIDList(&target)) && target && SUCCEEDED(SHGetDesktopFolder(&desktop)))
			result.aumid = PackagedId(DisplayName(desktop, target, SHGDN_FORPARSING));
		CoTaskMemFree(target);
		if (result.aumid.IsEmpty())
			return FALSE;
		result.path.Empty();
	}
	result.sources.push_back(Source(SOURCE_SHORTCUT, CString(path)));
	application = result;
	return TRUE;
}

HRESULT InstalledApplications::Enumerate(std::vector<Application>& applications, HANDLE cancelEvent)
{
	if (Cancelled(cancelEvent))
		return HRESULT_FROM_WIN32(ERROR_CANCELLED);
	CatalogIndex seen;
	const HRESULT shellResult = ReadAppsFolder(applications, seen, cancelEvent);
	const int locations[] = {CSIDL_PROGRAMS, CSIDL_COMMON_PROGRAMS};
	for (size_t index = 0; index < _countof(locations) && !Cancelled(cancelEvent); ++index)
	{
		WCHAR path[MAX_PATH] = {0};
		if (SUCCEEDED(SHGetFolderPath(NULL, locations[index], NULL, SHGFP_TYPE_CURRENT, path)))
			ReadStartMenu(path, 0, index == 0 ? SOURCE_USER_START_MENU : SOURCE_COMMON_START_MENU,
				applications, seen, cancelEvent);
	}
	std::stable_sort(applications.begin(), applications.end(),
		[](const Application& left, const Application& right) { return left.name.CompareNoCase(right.name) < 0; });
	if (Cancelled(cancelEvent))
		return HRESULT_FROM_WIN32(ERROR_CANCELLED);
	return !applications.empty() ? S_OK : shellResult;
}

void InstalledApplications::ReleaseIcons(std::vector<Application>& applications)
{
	for (size_t index = 0; index < applications.size(); ++index)
	{
		if (applications[index].icon)
			DestroyIcon(applications[index].icon);
		applications[index].icon = NULL;
	}
}

void InstalledApplications::Clone(const std::vector<Application>& source,
	std::vector<Application>& destination)
{
	std::vector<Application> copy(source);
	for (size_t i = 0; i < copy.size(); ++i) copy[i].icon = NULL;
	for (size_t i = 0; i < copy.size(); ++i)
		if (source[i].icon) copy[i].icon = CopyIcon(source[i].icon);
	ReleaseIcons(destination);
	destination.swap(copy);
}

void InstalledApplications::Deduplicate(std::vector<Application>& applications)
{
	CatalogIndex seen;
	std::vector<Application> unique;
	for (size_t i = 0; i < applications.size(); ++i)
		Add(unique, seen, applications[i]);
	applications.swap(unique);
}

CString InstalledApplications::LaunchTargetAndArguments(const Application& application)
{
	CString target = application.IsPackaged() ? application.aumid :
		(application.path.IsEmpty() ? CString() : L"\"" + application.path + L"\"");
	if (!application.arguments.IsEmpty())
	{
		if (!target.IsEmpty()) target += L" ";
		target += application.arguments;
	}
	return target;
}
