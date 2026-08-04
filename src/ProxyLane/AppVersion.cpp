#include "stdafx.h"
#include "AppVersion.h"

#include <vector>
#include <winver.h>

#pragma comment(lib, "Version.lib")

namespace
{
	struct LangAndCodePage
	{
		WORD language;
		WORD codePage;
	};
}

CString AppVersion::FileVersion()
{
	TCHAR modulePath[MAX_PATH] = { 0 };
	if (!::GetModuleFileName(NULL, modulePath, _countof(modulePath)))
		return CString();
	modulePath[_countof(modulePath) - 1] = _T('\0');

	DWORD ignored = 0;
	const DWORD size = ::GetFileVersionInfoSize(modulePath, &ignored);
	if (!size)
		return CString();

	std::vector<BYTE> data(size);
	if (!::GetFileVersionInfo(modulePath, 0, size, &data[0]))
		return CString();

	LangAndCodePage* translations = NULL;
	UINT translationBytes = 0;
	if (::VerQueryValue(&data[0], _T("\\VarFileInfo\\Translation"),
		reinterpret_cast<LPVOID*>(&translations), &translationBytes)
		&& translations && translationBytes >= sizeof(LangAndCodePage))
	{
		CString query;
		query.Format(_T("\\StringFileInfo\\%04x%04x\\FileVersion"),
			translations[0].language, translations[0].codePage);

		LPTSTR versionText = NULL;
		UINT versionLength = 0;
		if (::VerQueryValue(&data[0], query,
			reinterpret_cast<LPVOID*>(&versionText), &versionLength)
			&& versionText && versionLength > 1)
		{
			CString version(versionText);
			version.Trim();
			return version;
		}
	}

	VS_FIXEDFILEINFO* fixedInfo = NULL;
	UINT fixedInfoSize = 0;
	if (::VerQueryValue(&data[0], _T("\\"),
		reinterpret_cast<LPVOID*>(&fixedInfo), &fixedInfoSize)
		&& fixedInfo && fixedInfoSize >= sizeof(VS_FIXEDFILEINFO))
	{
		CString version;
		version.Format(_T("%u.%u.%u.%u"),
			HIWORD(fixedInfo->dwFileVersionMS),
			LOWORD(fixedInfo->dwFileVersionMS),
			HIWORD(fixedInfo->dwFileVersionLS),
			LOWORD(fixedInfo->dwFileVersionLS));
		return version;
	}

	return CString();
}

CString AppVersion::DisplayTitle()
{
	CString title(_T("ProxyLane"));
	const CString version = FileVersion();
	if (!version.IsEmpty())
	{
		title += _T(" ");
		title += version;
	}

#ifdef _WIN64
	title += _T(" (x64)");
#endif

	return title;
}
