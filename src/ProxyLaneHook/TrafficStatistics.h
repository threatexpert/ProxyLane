#pragma once

#include <windows.h>

// Shared by the forwarding thread and UI. A lock also makes 64-bit snapshots
// safe on Win32 without requiring newer-than-XP atomic APIs.
class CTrafficStatistics
{
public:
	CTrafficStatistics() : m_upload(0), m_download(0)
	{
		InitializeCriticalSection(&m_lock);
	}
	~CTrafficStatistics() { DeleteCriticalSection(&m_lock); }

	void RecordTransfer(bool download, int bytes)
	{
		if (bytes <= 0)
			return;
		EnterCriticalSection(&m_lock);
		(download ? m_download : m_upload) += static_cast<ULONGLONG>(bytes);
		LeaveCriticalSection(&m_lock);
	}
	void GetTotals(ULONGLONG& upload, ULONGLONG& download)
	{
		EnterCriticalSection(&m_lock);
		upload = m_upload;
		download = m_download;
		LeaveCriticalSection(&m_lock);
	}
	void Reset()
	{
		EnterCriticalSection(&m_lock);
		m_upload = m_download = 0;
		LeaveCriticalSection(&m_lock);
	}

private:
	CTrafficStatistics(const CTrafficStatistics&);
	CTrafficStatistics& operator=(const CTrafficStatistics&);
	CRITICAL_SECTION m_lock;
	ULONGLONG m_upload;
	ULONGLONG m_download;
};
