#pragma once

#include <windows.h>

class CTrafficRateSampler
{
public:
	CTrafficRateSampler() { Reset(0, 0, 0); }
	void Reset(ULONGLONG upload, ULONGLONG download, DWORD tick)
	{
		m_upload = upload;
		m_download = download;
		m_tick = tick;
	}
	void Sample(ULONGLONG upload, ULONGLONG download, DWORD tick,
		double& uploadRate, double& downloadRate)
	{
		// Unsigned subtraction handles GetTickCount's wrap on XP as well.
		const DWORD elapsed = tick - m_tick;
		uploadRate = downloadRate = 0;
		if (!elapsed)
			return;
		if (upload >= m_upload && download >= m_download)
		{
			uploadRate = static_cast<double>(upload - m_upload) * 1000.0 / elapsed;
			downloadRate = static_cast<double>(download - m_download) * 1000.0 / elapsed;
		}
		Reset(upload, download, tick);
	}

private:
	ULONGLONG m_upload;
	ULONGLONG m_download;
	DWORD m_tick;
};
