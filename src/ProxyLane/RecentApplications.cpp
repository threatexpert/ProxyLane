#include "stdafx.h"
#include "RecentApplications.h"
#include "Localization.h"
#include "IniFile.h"
#include "Base64.h"
#include <errno.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <algorithm>
#include <new>

namespace
{
	const size_t kMaxEntries = 128;
	// Only the recent-history operations and profile deletion participate.
	// Ordinary independent INI settings still use the Windows APIs directly.
	class HistoryLock
	{
		HANDLE mutex;
		BOOL owned;
	public:
		explicit HistoryLock(const CString& path) : mutex(NULL), owned(FALSE)
		{
			WCHAR absolute[32768];
			DWORD length = GetFullPathName(path, _countof(absolute), absolute, NULL);
			if (!length || length >= _countof(absolute)) return;
			CString key(absolute); key.Replace(L'/', L'\\'); key.MakeLower();
			ULONGLONG hash = 14695981039346656037ULL;
			for (int i = 0; i < key.GetLength(); ++i) { hash ^= static_cast<WORD>(key[i]); hash *= 1099511628211ULL; }
			CString name; name.Format(L"Global\\ProxyLane.RecentIni.%016I64x", hash);
			mutex = CreateMutex(NULL, FALSE, name);
			if (!mutex) return;
			const DWORD wait = WaitForSingleObject(mutex, 2000);
			owned = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
			if (!owned) SetLastError(wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_LOCK_FAILED);
		}
		~HistoryLock()
		{
			const DWORD error = GetLastError();
			if (owned) ReleaseMutex(mutex);
			if (mutex) CloseHandle(mutex);
			SetLastError(error);
		}
		BOOL Valid() const { return owned; }
	};

	CString NewId()
	{
		GUID guid; WCHAR text[40];
		if (FAILED(CoCreateGuid(&guid))) return CString();
		StringFromGUID2(guid, text, _countof(text));
		CString id(text); id.Remove(L'{'); id.Remove(L'}'); id.Remove(L'-'); id.MakeLower();
		return id;
	}
	BOOL ValidId(const CString& id)
	{
		if (id.GetLength() != 32) return FALSE;
		for (int i = 0; i < id.GetLength(); ++i)
			if (!((id[i] >= L'0' && id[i] <= L'9') || (id[i] >= L'a' && id[i] <= L'f'))) return FALSE;
		return TRUE;
	}
	BOOL BindProfile(CIniFile& ini, const CString& profile, CString& id, BOOL create)
	{
		id.Empty();
		if (profile.IsEmpty()) return TRUE;
		CIniFile::Section values;
		if (!ini.ReadSection(L"proxy_" + profile, values)) return FALSE;
		// Do not resurrect a profile deleted by another instance.
		if (values.empty()) return TRUE;
		id = values[L"RecentAppsId"];
		if (id.IsEmpty() && create)
		{
			id = NewId();
			if (id.IsEmpty() || !ini.SetString(L"proxy_" + profile, L"RecentAppsId", id)) return FALSE;
		}
		if (!id.IsEmpty() && !ValidId(id)) { SetLastError(ERROR_INVALID_DATA); return FALSE; }
		return TRUE;
	}
	CString Prefix(const CString& identity) { return L"recent_app_" + identity + L"_"; }

	BOOL EncodeText(const CString& text, CString& encoded)
	{
		if (text.GetLength() > 32767) { SetLastError(ERROR_BUFFER_OVERFLOW); return FALSE; }
		if (text.IsEmpty()) { encoded.Empty(); return TRUE; }
		int bytes = WideCharToMultiByte(CP_UTF8, 0, text, text.GetLength(), NULL, 0, NULL, NULL);
		if (!bytes) return FALSE;
		std::vector<BYTE> utf8(bytes);
		WideCharToMultiByte(CP_UTF8, 0, text, text.GetLength(), reinterpret_cast<LPSTR>(&utf8[0]), bytes, NULL, NULL);
		CBase64 codec;
		int length = codec.EncodeGetRequiredLength(bytes, BASE64_FLAG_NOCRLF);
		CStringA result;
		LPSTR buffer = result.GetBuffer(length + 1);
		BOOL ok = codec.Encode(&utf8[0], bytes, buffer, &length, BASE64_FLAG_NOCRLF);
		result.ReleaseBuffer(ok ? length : 0);
		if (ok) encoded = CString(result);
		return ok;
	}
	BOOL DecodeText(const CString& encoded, CString& text)
	{
		if (encoded.IsEmpty()) { text.Empty(); return TRUE; }
		if (encoded.GetLength() > 131072 || encoded.GetLength() % 4) return FALSE;
		std::vector<BYTE> decoded(encoded.GetLength());
		int bytes = static_cast<int>(decoded.size());
		CBase64 codec;
		if (!codec.DecodeW(encoded, encoded.GetLength(), &decoded[0], &bytes) || bytes <= 0) return FALSE;
		int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<LPCSTR>(&decoded[0]), bytes, NULL, 0);
		if (!chars || chars > 32767) return FALSE;
		LPWSTR buffer = text.GetBuffer(chars);
		MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<LPCSTR>(&decoded[0]), bytes, buffer, chars);
		text.ReleaseBuffer(chars);
		if (wcslen(text) != chars) return FALSE;
		CString canonical;
		// Reject invalid alphabet/padding; the legacy codec alone is permissive.
		return EncodeText(text, canonical) && canonical == encoded;
	}
	BOOL EncodeEntry(const RecentApplications::Entry& entry, CIniFile::Section& fields)
	{
		fields[L"Version"] = L"1";
		fields[L"ProfileId"] = entry.profileId;
		fields[L"Pinned"] = entry.pinned ? L"1" : L"0";
		fields[L"Elevated"] = entry.elevated ? L"1" : L"0";
		fields[L"LastUsed"].Format(L"%I64u", entry.lastUsed);
		const LPCWSTR keys[] = {L"NameUtf8Base64", L"PathUtf8Base64", L"AumidUtf8Base64", L"ArgumentsUtf8Base64", L"WorkingDirectoryUtf8Base64", L"ShortcutUtf8Base64"};
		const CString* values[] = {&entry.app.name, &entry.app.path, &entry.app.aumid, &entry.app.arguments, &entry.app.workingDirectory, &entry.shortcut};
		size_t characters = 1;
		for (size_t i = 0; i < _countof(keys); ++i)
			if (!EncodeText(*values[i], fields[keys[i]])) return FALSE;
		for (CIniFile::Section::const_iterator i = fields.begin(); i != fields.end(); ++i)
			characters += i->first.GetLength() + i->second.GetLength() + 2;
		if (characters > 32767) { SetLastError(ERROR_BUFFER_OVERFLOW); return FALSE; }
		return TRUE;
	}
	BOOL DecodeEntry(CIniFile::Section& fields, RecentApplications::Entry& entry)
	{
		const LPCWSTR required[] = {L"NameUtf8Base64", L"PathUtf8Base64", L"AumidUtf8Base64", L"ArgumentsUtf8Base64", L"WorkingDirectoryUtf8Base64", L"ShortcutUtf8Base64"};
		for (size_t i = 0; i < _countof(required); ++i) if (fields.find(required[i]) == fields.end()) return FALSE;
		if (fields[L"Version"] != L"1" || fields[L"ProfileId"] != entry.profileId ||
			(fields[L"Pinned"] != L"0" && fields[L"Pinned"] != L"1") ||
			(fields[L"Elevated"] != L"0" && fields[L"Elevated"] != L"1")) return FALSE;
		const CString timestamp = fields[L"LastUsed"];
		if (timestamp.IsEmpty() || timestamp.GetLength() > 20) return FALSE;
		for (int i = 0; i < timestamp.GetLength(); ++i) if (timestamp[i] < L'0' || timestamp[i] > L'9') return FALSE;
		errno = 0;
		entry.lastUsed = _wcstoui64(timestamp, NULL, 10);
		if (errno == ERANGE || entry.lastUsed == ~0ULL) return FALSE;
		entry.pinned = fields[L"Pinned"] == L"1";
		entry.elevated = fields[L"Elevated"] == L"1";
		return DecodeText(fields[L"NameUtf8Base64"], entry.app.name) &&
			DecodeText(fields[L"PathUtf8Base64"], entry.app.path) &&
			DecodeText(fields[L"AumidUtf8Base64"], entry.app.aumid) &&
			DecodeText(fields[L"ArgumentsUtf8Base64"], entry.app.arguments) &&
			DecodeText(fields[L"WorkingDirectoryUtf8Base64"], entry.app.workingDirectory) &&
			DecodeText(fields[L"ShortcutUtf8Base64"], entry.shortcut) &&
			(!entry.app.path.IsEmpty() || !entry.app.aumid.IsEmpty());
	}
	BOOL SameLaunch(const RecentApplications::Entry& a, const RecentApplications::Entry& b)
	{
		if (a.elevated != b.elevated) return FALSE;
		if (!a.shortcut.IsEmpty() && a.shortcut.CompareNoCase(b.shortcut) == 0) return TRUE;
		return a.app.path.CompareNoCase(b.app.path) == 0 && a.app.aumid.CompareNoCase(b.app.aumid) == 0 &&
			a.app.arguments == b.app.arguments && a.app.workingDirectory.CompareNoCase(b.app.workingDirectory) == 0;
	}
	void Sort(std::vector<RecentApplications::Entry>& entries)
	{
		std::stable_sort(entries.begin(), entries.end(), [](const RecentApplications::Entry& a, const RecentApplications::Entry& b) {
			return a.pinned != b.pinned ? a.pinned > b.pinned : a.lastUsed > b.lastUsed;
		});
	}
}

CString RecentApplications::DefaultPath()
{
	CIniFile ini; ini.SetIniFileName(L"");
	CString path = ini.GetIniFileName();
#ifdef _WIN64
	if (path.Right(6).CompareNoCase(L"64.ini") == 0) path = path.Left(path.GetLength() - 6) + L".ini";
#endif
	return path;
}

RecentApplications::Entry RecentApplications::FromApplication(const InstalledApplications::Application& app, BOOL elevated)
{
	Entry entry;
	entry.app = app;
	entry.app.icon = NULL;
	entry.elevated = elevated;
	if (CString(PathFindExtension(app.path)).CompareNoCase(L".lnk") == 0) entry.shortcut = app.path;
	for (size_t i = 0; entry.shortcut.IsEmpty() && i < app.sources.size(); ++i)
		if (CString(PathFindExtension(app.sources[i].path)).CompareNoCase(L".lnk") == 0)
			entry.shortcut = app.sources[i].path;
	return entry;
}

BOOL RecentApplications::Resolve(const Entry& entry, InstalledApplications::Application& app)
{
	if (!entry.shortcut.IsEmpty())
	{
		if (!InstalledApplications::ResolveShortcut(entry.shortcut, app)) return FALSE;
		app.name = entry.app.name;
	}
	else app = entry.app;
	app.icon = NULL;
	if (app.IsPackaged()) return TRUE;
	const DWORD attributes = GetFileAttributes(app.path);
	return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

HICON RecentApplications::LoadIcon(const Entry& entry)
{
	SHFILEINFO info = {0};
	if (entry.available && entry.app.IsPackaged())
	{
		LPITEMIDLIST item = NULL;
		if (SUCCEEDED(SHParseDisplayName(L"shell:AppsFolder\\" + entry.app.aumid, NULL, &item, 0, NULL)))
		{
			SHGetFileInfo(reinterpret_cast<LPCTSTR>(item), 0, &info, sizeof(info), SHGFI_PIDL | SHGFI_ICON | SHGFI_SMALLICON);
			CoTaskMemFree(item);
		}
	}
	else if (entry.available && !PathIsUNC(entry.app.path))
		SHGetFileInfo(entry.app.path, 0, &info, sizeof(info), SHGFI_ICON | SHGFI_SMALLICON);
	if (!info.hIcon) SHGetFileInfo(L"app.exe", FILE_ATTRIBUTE_NORMAL, &info, sizeof(info),
		SHGFI_USEFILEATTRIBUTES | SHGFI_ICON | SHGFI_SMALLICON);
	return info.hIcon;
}

CString RecentApplications::Description(const Entry& entry, const CString& profile)
{
	CString text = entry.app.name + L"\r\n" + InstalledApplications::LaunchTargetAndArguments(entry.app);
	if (!entry.available) text += L"\r\n" + Localization::Get(L"recent.unavailable_hint");
	if (!entry.shortcut.IsEmpty()) text += L"\r\n" + entry.shortcut;
	if (!entry.app.workingDirectory.IsEmpty()) text += L"\r\n" + Localization::Get(L"apps.working_directory") + L": " + entry.app.workingDirectory;
	if (entry.elevated) text += L"\r\n" + Localization::Get(L"recent.elevated");
	text += L"\r\n" + (profile.IsEmpty() ? Localization::Get(L"page3.start_proxy_first") :
		Localization::Format(L"recent.profile", static_cast<LPCTSTR>(profile)));
	return text;
}

BOOL RecentApplications::EnsureProfileId(const CString& profile, CString& id, const CString& path)
{
	HistoryLock lock(path);
	if (!lock.Valid()) return FALSE;
	CIniFile ini; ini.SetIniFileName(path);
	return BindProfile(ini, profile, id, TRUE);
}

BOOL RecentApplications::DeleteProfile(const CString& profile, const CString& path)
{
	HistoryLock lock(path);
	if (!lock.Valid()) return FALSE;
	CIniFile ini; ini.SetIniFileName(path);
	CString id;
	if (!BindProfile(ini, profile, id, FALSE)) return FALSE;
	if (!id.IsEmpty())
	{
		std::list<CString> sections;
		if (ini.GetSectionList(sections) < 0) return FALSE;
		const CString prefix = Prefix(id);
		for (std::list<CString>::const_iterator i = sections.begin(); i != sections.end(); ++i)
			if (i->Left(prefix.GetLength()).CompareNoCase(prefix) == 0 && !ini.DeleteSection(*i)) return FALSE;
	}
	return ini.DeleteSection(L"proxy_" + profile);
}

BOOL RecentApplications::Store::ReadBound(std::vector<Entry>& entries, CString& identity, BOOL create) const
{
	CIniFile ini; ini.SetIniFileName(m_path);
	if (!BindProfile(ini, m_profile, identity, create)) return FALSE;
	if (identity.IsEmpty() || (!m_profileId.IsEmpty() && m_profileId != identity))
	{
		entries.clear(); identity.Empty();
		if (create) { SetLastError(ERROR_NOT_FOUND); return FALSE; }
		return TRUE;
	}
	std::list<CString> sections;
	if (ini.GetSectionList(sections) < 0) return FALSE;
	const CString prefix = Prefix(identity);
	std::vector<Entry> loaded;
	for (std::list<CString>::const_iterator i = sections.begin(); i != sections.end(); ++i)
	{
		if (i->Left(prefix.GetLength()).CompareNoCase(prefix) != 0) continue;
		Entry entry; entry.id = i->Mid(prefix.GetLength()); entry.profileId = identity;
		CIniFile::Section fields;
		if (!ValidId(entry.id) || !ini.ReadSection(*i, fields) || !DecodeEntry(fields, entry))
		{ SetLastError(ERROR_INVALID_DATA); return FALSE; }
		loaded.push_back(entry);
		// Permit recovery of a just-written record if a previous process exited
		// after writing but before trimming the oldest entry.
		if (loaded.size() > kMaxEntries + 1) { SetLastError(ERROR_BUFFER_OVERFLOW); return FALSE; }
	}
	Sort(loaded); entries.swap(loaded);
	return TRUE;
}

BOOL RecentApplications::Store::Read(std::vector<Entry>& entries) const
{
	if (m_profile.IsEmpty()) { entries.clear(); return TRUE; }
	HistoryLock lock(m_path);
	if (!lock.Valid()) return FALSE;
	CString identity;
	return ReadBound(entries, identity, FALSE);
}

BOOL RecentApplications::Store::Write(const std::vector<Entry>& entries, const CString& identity) const
{
	CIniFile ini; ini.SetIniFileName(m_path);
	std::vector<CIniFile::Section> records(entries.size());
	// Validate all values before changing anything on disk.
	for (size_t i = 0; i < entries.size(); ++i)
		if (!EncodeEntry(entries[i], records[i])) return FALSE;
	const CString prefix = Prefix(identity);
	for (size_t i = 0; i < entries.size(); ++i)
	{
		CIniFile::Section previous;
		if (!ini.ReadSection(prefix + entries[i].id, previous)) return FALSE;
		if (previous != records[i] && !ini.WriteSection(prefix + entries[i].id, records[i])) return FALSE;
	}
	std::list<CString> sections;
	if (ini.GetSectionList(sections) < 0) return FALSE;
	for (std::list<CString>::const_iterator i = sections.begin(); i != sections.end(); ++i)
	{
		if (i->Left(prefix.GetLength()).CompareNoCase(prefix) != 0) continue;
		BOOL retain = FALSE;
		for (size_t j = 0; j < entries.size() && !retain; ++j) retain = i->CompareNoCase(prefix + entries[j].id) == 0;
		if (!retain && !ini.DeleteSection(*i)) return FALSE;
	}
	return TRUE;
}

BOOL RecentApplications::Store::Remember(Entry entry) const
{
	HistoryLock lock(m_path);
	if (!lock.Valid()) return FALSE;
	std::vector<Entry> entries; CString identity;
	// Expected identities never create an identity for a deleted/recreated profile.
	if (!ReadBound(entries, identity, m_profileId.IsEmpty())) return FALSE;
	if (identity.IsEmpty()) { SetLastError(ERROR_NOT_FOUND); return FALSE; }
	if (!entry.profileId.IsEmpty() && entry.profileId != identity)
	{ SetLastError(ERROR_INVALID_DATA); return FALSE; }
	entry.profileId = identity;
	FILETIME now; GetSystemTimeAsFileTime(&now);
	entry.lastUsed = (static_cast<ULONGLONG>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
	for (size_t i = 0; i < entries.size();)
	{
		entry.lastUsed = max(entry.lastUsed, entries[i].lastUsed + 1);
		if ((!entry.id.IsEmpty() && entry.id == entries[i].id) || SameLaunch(entry, entries[i]))
		{
			entry.id = entries[i].id; entry.pinned = entries[i].pinned;
			entries.erase(entries.begin() + i);
		}
		else ++i;
	}
	if (entry.id.IsEmpty()) entry.id = NewId();
	if (!ValidId(entry.id)) { SetLastError(ERROR_INVALID_DATA); return FALSE; }
	entries.push_back(entry); Sort(entries);
	int recent = 0;
	for (size_t i = 0; i < entries.size();)
		if (!entries[i].pinned && ++recent > 20) entries.erase(entries.begin() + i); else ++i;
	if (entries.size() > kMaxEntries) { SetLastError(ERROR_TOO_MANY_NAMES); return FALSE; }
	return Write(entries, identity);
}

BOOL RecentApplications::Store::Change(const CString& id, BOOL remove, BOOL pinned) const
{
	HistoryLock lock(m_path);
	if (!lock.Valid()) return FALSE;
	std::vector<Entry> entries; CString identity;
	if (!ReadBound(entries, identity, FALSE)) return FALSE;
	for (size_t i = 0; i < entries.size(); ++i)
		if (entries[i].id == id)
		{
			if (remove) entries.erase(entries.begin() + i); else entries[i].pinned = pinned;
			Sort(entries);
			int recent = 0;
			for (size_t j = 0; j < entries.size();)
				if (!entries[j].pinned && ++recent > 20) entries.erase(entries.begin() + j); else ++j;
			return Write(entries, identity);
		}
	SetLastError(ERROR_NOT_FOUND); return FALSE;
}
BOOL RecentApplications::Store::SetPinned(const CString& id, BOOL pinned) const { return Change(id, FALSE, pinned); }
BOOL RecentApplications::Store::Remove(const CString& id) const { return Change(id, TRUE, FALSE); }

BOOL RecentApplications::MatchesCatalog(const Entry& entry, const InstalledApplications::Application& app)
{
	// An unavailable shortcut must not hide a usable catalog launch target.
	if (!entry.available) return FALSE;
	if (entry.app.IsPackaged() != app.IsPackaged()) return FALSE;
	if (entry.app.arguments != app.arguments) return FALSE;
	if (app.IsPackaged()) return entry.app.aumid.CompareNoCase(app.aumid) == 0;
	const auto normalized = [](CString value) {
		value.Replace(L'/', L'\\');
		while (value.GetLength() > 3 && value.Right(1) == L"\\") value.Truncate(value.GetLength() - 1);
		value.MakeLower(); return value;
	};
	return normalized(entry.app.path) == normalized(app.path) &&
		(entry.app.workingDirectory.IsEmpty() || app.workingDirectory.IsEmpty() ||
		 normalized(entry.app.workingDirectory) == normalized(app.workingDirectory));
}

void RecentApplications::ReleaseIcons(std::vector<Entry>& entries)
{
	for (size_t i = 0; i < entries.size(); ++i)
		if (entries[i].app.icon) { DestroyIcon(entries[i].app.icon); entries[i].app.icon = NULL; }
}

RecentApplications::Load::Load(const CString& profileName, const CString& filePath, const CString& identity)
	: path(filePath), profile(profileName), profileId(identity), references(1), cancel(CreateEvent(NULL, TRUE, FALSE, NULL)), done(FALSE), succeeded(FALSE)
{ InitializeCriticalSection(&lock); }
RecentApplications::Load::~Load()
{
	ReleaseIcons(entries);
	if (cancel) CloseHandle(cancel);
	DeleteCriticalSection(&lock);
}
void RecentApplications::Load::AddRef() { InterlockedIncrement(&references); }
void RecentApplications::Load::Release() { if (InterlockedDecrement(&references) == 0) delete this; }

static UINT ValidateRecentApplications(LPVOID parameter)
{
	RecentApplications::Load* load = static_cast<RecentApplications::Load*>(parameter);
	const HRESULT initialized = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	BOOL success = FALSE;
	std::vector<RecentApplications::Entry> validated;
	try
	{
		std::vector<RecentApplications::Entry> saved;
		success = SUCCEEDED(initialized) && RecentApplications::Store(load->profile, load->path, load->profileId).Read(saved);
		for (size_t i = 0; success && i < saved.size() && WaitForSingleObject(load->cancel, 0) != WAIT_OBJECT_0; ++i)
		{
			InstalledApplications::Application resolved;
			saved[i].available = RecentApplications::Resolve(saved[i], resolved);
			if (saved[i].available && resolved.IsPackaged())
			{
				LPITEMIDLIST item = NULL;
				const HRESULT hr = SHParseDisplayName(L"shell:AppsFolder\\" + resolved.aumid, NULL, &item, 0, NULL);
				CoTaskMemFree(item);
				saved[i].available = SUCCEEDED(hr);
			}
			// Preserve unavailable entries so the user can still remove them.
			if (saved[i].available) saved[i].app = resolved;
			validated.push_back(saved[i]);
			validated.back().app.icon = RecentApplications::LoadIcon(validated.back());
		}
	}
	catch (CMemoryException* error) { error->Delete(); success = FALSE; }
	catch (...) { success = FALSE; }
	EnterCriticalSection(&load->lock);
	load->entries.swap(validated);
	load->succeeded = success;
	load->done = TRUE;
	LeaveCriticalSection(&load->lock);
	RecentApplications::ReleaseIcons(validated);
	if (SUCCEEDED(initialized)) CoUninitialize();
	load->Release();
	return 0;
}

RecentApplications::Load* RecentApplications::BeginLoad(const CString& profile, const CString& path, const CString& identity)
{
	Load* load = new Load(profile, path, identity);
	if (profile.IsEmpty() || identity.IsEmpty()) { load->done = TRUE; load->succeeded = TRUE; return load; }
	load->AddRef();
	if (!load->cancel || !AfxBeginThread(ValidateRecentApplications, load))
	{
		load->Release(); load->done = TRUE;
	}
	return load;
}
