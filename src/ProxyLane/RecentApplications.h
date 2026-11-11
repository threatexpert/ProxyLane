#pragma once
#include "InstalledApplications.h"

#define WM_RECENT_APPLICATIONS_CHANGED (WM_APP + 311)

namespace RecentApplications
{
	struct Entry
	{
		CString id;
		CString profileId;
		InstalledApplications::Application app;
		CString shortcut;
		BOOL elevated; // Last successful launch preference, not part of target identity.
		BOOL pinned;
		BOOL available; // Transient picker validation; never persisted.
		ULONGLONG lastUsed;
		ULONGLONG displayOrder; // Stable home-screen position, independent of recency.
		Entry() : elevated(FALSE), pinned(FALSE), available(TRUE), lastUsed(0), displayOrder(0) {}
	};

	CString DefaultPath();
	BOOL EnsureProfileId(const CString& profile, CString& id, const CString& path = DefaultPath());
	BOOL DeleteProfile(const CString& profile, const CString& path = DefaultPath());
	Entry FromApplication(const InstalledApplications::Application& app, BOOL elevated);
	BOOL Resolve(const Entry& entry, InstalledApplications::Application& app);
	HICON LoadIcon(const Entry& entry); // Caller owns the returned icon.
	CString Description(const Entry& entry);
	void SortForDisplay(std::vector<Entry>& entries);
	BOOL MatchesCatalog(const Entry& entry, const InstalledApplications::Application& app);
	void ReleaseIcons(std::vector<Entry>& entries);
	void Clone(const std::vector<Entry>& source, std::vector<Entry>& destination, size_t limit = static_cast<size_t>(-1));
	// All Load snapshots (ready and validated) are in persistent display order.
	// Launching updates lastUsed for retention only, never the visual position.
	// Shared GUI-lifetime cache. Consumers release references, never cancel or
	// move entries out of a shared Load. Only supersession/eviction cancels work.
	struct Load;
	Load* AcquireLoad(const CString& profile, const CString& path, const CString& profileId, BOOL refresh = FALSE);
	Load* AcquireReadyLoad(const CString& profile, const CString& path, const CString& profileId);
	BOOL IsCurrentLoad(Load* load);
	void Preload(const CString& profile, const CString& path = DefaultPath(), const CString& profileId = CString());
	void InvalidateCache(const CString& path, const CString& profileId, BOOL forget = FALSE, const std::vector<Entry>* saved = NULL);
	// Background validation/shortcut resolution. A picker can close without
	// waiting for Shell extensions or an unavailable network path.
	struct Load
	{
		CString path;
		CString profile;
		CString profileId;
		LONG references;
		HANDLE cancel;
		CRITICAL_SECTION lock;
		BOOL done;
		BOOL succeeded;
		std::vector<Entry> entries;
		Load(const CString& profileName, const CString& filePath, const CString& identity);
		~Load();
		void AddRef();
		void Release();
	};
	Load* BeginLoad(const CString& profile, const CString& path = DefaultPath(), const CString& profileId = CString());

	class Store
	{
	public:
		explicit Store(const CString& profile, const CString& path = DefaultPath(), const CString& profileId = CString())
			: m_path(path), m_profile(profile), m_profileId(profileId) {}
		BOOL Read(std::vector<Entry>& entries) const;
		BOOL Remember(Entry entry) const;
		BOOL SetPinned(const CString& id, BOOL pinned) const;
		BOOL Move(const CString& id, int direction) const;
		BOOL MoveTo(const CString& id, const CString& targetId) const;
		BOOL Remove(const CString& id) const;
	private:
		CString m_path;
		CString m_profile;
		CString m_profileId;
		BOOL ReadBound(std::vector<Entry>& entries, CString& identity, BOOL create) const;
		BOOL Write(const std::vector<Entry>& entries, const CString& identity) const;
		BOOL Change(const CString& id, BOOL remove, BOOL pinned) const;
	};
}
