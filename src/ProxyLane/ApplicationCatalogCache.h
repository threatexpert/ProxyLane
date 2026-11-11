#pragma once
#include "InstalledApplications.h"

// Ref-counted, immutable after completion. Closing a picker does not discard
// the cached result or stop a useful background scan.
struct ApplicationCatalogLoad
{
	LONG references;
	HANDLE cancel;
	CRITICAL_SECTION lock;
	BOOL done;
	HRESULT result;
	std::vector<InstalledApplications::Application> applications;
	ApplicationCatalogLoad();
	~ApplicationCatalogLoad();
	void AddRef();
	void Release();
};

// UI-thread only. The caller must Release the returned reference.
ApplicationCatalogLoad* AcquireApplicationCatalog(BOOL forceRefresh);
void RememberApplicationCatalog(ApplicationCatalogLoad* load);

// Last successful snapshot, possibly older than the in-flight refresh.
ApplicationCatalogLoad* AcquireReadyApplicationCatalog();
void PreloadApplicationCatalog();
#define WM_PRELOAD_APPLICATIONS (WM_APP + 312)
