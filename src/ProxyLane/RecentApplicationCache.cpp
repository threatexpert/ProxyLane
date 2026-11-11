#include "stdafx.h"
#include "RecentApplications.h"
#include "IniFile.h"
#include <map>
#include <afxmt.h>

namespace
{
	struct FileStamp
	{
		WIN32_FILE_ATTRIBUTE_DATA data;
		BOOL valid;
		explicit FileStamp(const CString& path) : data(), valid(GetFileAttributesEx(path, GetFileExInfoStandard, &data)) {}
		bool operator==(const FileStamp& other) const
		{
			return valid == other.valid && (!valid ||
				(CompareFileTime(&data.ftLastWriteTime, &other.data.ftLastWriteTime) == 0 &&
				data.nFileSizeHigh == other.data.nFileSizeHigh && data.nFileSizeLow == other.data.nFileSizeLow));
		}
	};
	CString CacheKey(const CString& path, const CString& id)
	{
		WCHAR absolute[32768];
		const DWORD length = GetFullPathName(path, _countof(absolute), absolute, NULL);
		CString key = length && length < _countof(absolute) ? CString(absolute) : path;
		key.Replace(L'/', L'\\'); key.MakeLower();
		return key + L"\n" + id;
	}
	struct CachedProfile
	{
		RecentApplications::Load* latest;
		RecentApplications::Load* ready;
		FileStamp stamp;
		ULONGLONG used;
		BOOL dirty;
		explicit CachedProfile(const CString& path) : latest(NULL), ready(NULL), stamp(path), used(0), dirty(FALSE) {}
		~CachedProfile()
		{
			if (latest) { if (latest->cancel) SetEvent(latest->cancel); latest->Release(); }
			if (ready) ready->Release();
		}
		void Remember()
		{
			if (!latest || latest == ready || dirty) return;
			EnterCriticalSection(&latest->lock);
			const BOOL success = latest->done && latest->succeeded;
			LeaveCriticalSection(&latest->lock);
			if (!success) return;
			latest->AddRef();
			if (ready) ready->Release();
			ready = latest;
		}
	};
	class RecentCache
	{
		typedef std::map<CString, CachedProfile*> Profiles;
		CCriticalSection lock;
		Profiles profiles;
		ULONGLONG clock;
	public:
		RecentCache() : clock(0) {}
		~RecentCache() { for (Profiles::iterator it = profiles.begin(); it != profiles.end(); ++it) delete it->second; }
		RecentApplications::Load* Acquire(const CString& profile, const CString& path, const CString& id, BOOL refresh)
		{
			CSingleLock guard(&lock, TRUE);
			const CString key = CacheKey(path, id);
			Profiles::iterator it = profiles.find(key);
			if (it == profiles.end())
			{
				// Bound cached profiles and icons; outstanding consumers/workers
				// retain their own references after an eviction.
				if (profiles.size() >= 4)
				{
					Profiles::iterator oldest = profiles.begin();
					for (Profiles::iterator p = profiles.begin(); p != profiles.end(); ++p)
						if (p->second->used < oldest->second->used) oldest = p;
					delete oldest->second; profiles.erase(oldest);
				}
				it = profiles.insert(std::make_pair(key, new CachedProfile(path))).first;
			}
			CachedProfile& entry = *it->second;
			entry.used = ++clock;
			const FileStamp stamp(path);
			const BOOL changed = entry.dirty || !(entry.stamp == stamp) ||
				(entry.latest && entry.latest->profile != profile);
			// Keep a completed snapshot even if unrelated INI settings changed.
			// Dirty local edits are protected by Remember() and their published rows.
			entry.Remember();
			BOOL done = TRUE;
			if (entry.latest)
			{
				EnterCriticalSection(&entry.latest->lock); done = entry.latest->done; LeaveCriticalSection(&entry.latest->lock);
			}
			if (!entry.latest || changed || (refresh && done))
			{
				RecentApplications::Load* next = RecentApplications::BeginLoad(profile, path, id);
				if (entry.latest)
				{
					if (!done && entry.latest->cancel) SetEvent(entry.latest->cancel);
					entry.latest->Release();
				}
				entry.latest = next; entry.stamp = stamp; entry.dirty = FALSE;
			}
			entry.latest->AddRef();
			return entry.latest;
		}
		RecentApplications::Load* Ready(const CString& path, const CString& id)
		{
			CSingleLock guard(&lock, TRUE);
			Profiles::iterator it = profiles.find(CacheKey(path, id));
			if (it == profiles.end()) return NULL;
			if (it->second->stamp == FileStamp(path)) it->second->Remember();
			RecentApplications::Load* ready = it->second->ready;
			if (ready) ready->AddRef();
			return ready;
		}
		BOOL Current(RecentApplications::Load* load)
		{
			if (!load) return FALSE;
			CSingleLock guard(&lock, TRUE);
			Profiles::iterator it = profiles.find(CacheKey(load->path, load->profileId));
			return it != profiles.end() && it->second->latest == load && !it->second->dirty &&
				it->second->stamp == FileStamp(load->path);
		}
		void Invalidate(const CString& path, const CString& id, BOOL forget, const std::vector<RecentApplications::Entry>* saved)
		{
			CSingleLock guard(&lock, TRUE);
			Profiles::iterator it = profiles.find(CacheKey(path, id));
			if (it == profiles.end()) return;
			if (forget) { delete it->second; profiles.erase(it); }
			else
			{
				CachedProfile& entry = *it->second;
				entry.dirty = TRUE;
				if (saved)
				{
					// Publish local edits immediately; validation/icons can refresh
					// afterwards without bringing a removed or unpinned row back.
					RecentApplications::Load* snapshot = new RecentApplications::Load(entry.latest->profile, path, id);
					RecentApplications::Clone(*saved, snapshot->entries);
					RecentApplications::SortForDisplay(snapshot->entries);
					for (size_t i = 0; entry.ready && i < snapshot->entries.size(); ++i)
						for (size_t j = 0; j < entry.ready->entries.size(); ++j)
							if (snapshot->entries[i].id == entry.ready->entries[j].id)
							{
								RecentApplications::Entry& next = snapshot->entries[i];
								const RecentApplications::Entry& previous = entry.ready->entries[j];
								if (!next.app.icon && previous.app.icon) next.app.icon = CopyIcon(previous.app.icon);
								if (next.app.path == previous.app.path && next.shortcut == previous.shortcut &&
									next.app.aumid == previous.app.aumid) next.available = previous.available;
								break;
							}
					snapshot->done = TRUE; snapshot->succeeded = TRUE;
					if (entry.ready) entry.ready->Release();
					entry.ready = snapshot;
				}
			}
		}
	} cache;
}

RecentApplications::Load* RecentApplications::AcquireLoad(const CString& profile, const CString& path, const CString& id, BOOL refresh)
{ return cache.Acquire(profile, path, id, refresh); }
RecentApplications::Load* RecentApplications::AcquireReadyLoad(const CString&, const CString& path, const CString& id)
{ return cache.Ready(path, id); }
BOOL RecentApplications::IsCurrentLoad(Load* load) { return cache.Current(load); }
void RecentApplications::InvalidateCache(const CString& path, const CString& id, BOOL forget, const std::vector<Entry>* saved)
{ cache.Invalidate(path, id, forget, saved); }

void RecentApplications::Preload(const CString& profile, const CString& path, const CString& profileId)
{
	if (profile.IsEmpty()) return;
	CString id(profileId);
	if (id.IsEmpty())
	{
		// Reading an existing identity must not create history for an unsaved,
		// renamed or deleted profile just because the selection changed.
		CIniFile ini; ini.SetIniFileName(path);
		id = ini.GetString(L"proxy_" + profile, L"RecentAppsId", L"");
	}
	if (id.IsEmpty()) return;
	Load* load = AcquireLoad(profile, path, id);
	load->Release();
}
