#include "stdafx.h"
#include "ApplicationCatalogCache.h"
#include <new>

ApplicationCatalogLoad::ApplicationCatalogLoad()
	: references(1), cancel(CreateEvent(NULL, TRUE, FALSE, NULL)),
	done(FALSE), result(E_PENDING) { InitializeCriticalSection(&lock); }
ApplicationCatalogLoad::~ApplicationCatalogLoad()
{
	InstalledApplications::ReleaseIcons(applications);
	if (cancel) CloseHandle(cancel);
	DeleteCriticalSection(&lock);
}
void ApplicationCatalogLoad::AddRef() { InterlockedIncrement(&references); }
void ApplicationCatalogLoad::Release() { if (InterlockedDecrement(&references) == 0) delete this; }

static UINT LoadApplications(LPVOID parameter)
{
	ApplicationCatalogLoad* load = static_cast<ApplicationCatalogLoad*>(parameter);
	const HRESULT initialized = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	std::vector<InstalledApplications::Application> applications;
	HRESULT result = initialized;
	if (SUCCEEDED(initialized))
	{
		try { result = InstalledApplications::Enumerate(applications, load->cancel); }
		catch (CMemoryException* error) { error->Delete(); result = E_OUTOFMEMORY; }
		catch (const std::bad_alloc&) { result = E_OUTOFMEMORY; }
		catch (...) { result = E_FAIL; }
	}
	EnterCriticalSection(&load->lock);
	load->applications.swap(applications);
	load->result = result;
	load->done = TRUE;
	LeaveCriticalSection(&load->lock);
	if (SUCCEEDED(initialized)) CoUninitialize();
	load->Release();
	return 0;
}

namespace
{
	struct ApplicationCatalogCache
	{
		ApplicationCatalogLoad* latest;
		ApplicationCatalogLoad* successful;
		ApplicationCatalogCache() : latest(NULL), successful(NULL) {}
		~ApplicationCatalogCache()
		{
			if (latest)
			{
				if (latest->cancel) SetEvent(latest->cancel);
				latest->Release();
			}
			if (successful) successful->Release();
		}
		void Remember(ApplicationCatalogLoad* load)
		{
			if (!load || load != latest || load == successful) return;
			EnterCriticalSection(&load->lock);
			const BOOL ready = load->done && SUCCEEDED(load->result);
			LeaveCriticalSection(&load->lock);
			if (!ready) return;
			load->AddRef();
			if (successful) successful->Release();
			successful = load;
		}
		ApplicationCatalogLoad* Acquire(BOOL refresh)
		{
			Remember(latest); // A picker may have closed before completion.
			BOOL done = FALSE;
			if (latest)
			{
				EnterCriticalSection(&latest->lock);
				done = latest->done;
				LeaveCriticalSection(&latest->lock);
			}
			// Reopening while an explicit refresh is still running can display
			// the last good snapshot immediately, without another loading pause.
			if (!refresh && successful)
			{
				successful->AddRef();
				return successful;
			}
			if (refresh || !latest || (done && !successful))
			{
				// Allocate before releasing the previous snapshot.
				ApplicationCatalogLoad* replacement = new ApplicationCatalogLoad;
				if (latest)
				{
					if (!done && latest->cancel) SetEvent(latest->cancel);
					latest->Release();
				}
				latest = replacement;
				latest->AddRef(); // Independent worker reference.
				if (!latest->cancel || !AfxBeginThread(LoadApplications, latest))
				{
					latest->Release();
					latest->result = E_OUTOFMEMORY;
					latest->done = TRUE;
				}
			}
			latest->AddRef();
			return latest;
		}
	} g_applicationCatalogCache;
}

ApplicationCatalogLoad* AcquireApplicationCatalog(BOOL forceRefresh)
{ return g_applicationCatalogCache.Acquire(forceRefresh); }
void RememberApplicationCatalog(ApplicationCatalogLoad* load)
{ g_applicationCatalogCache.Remember(load); }
