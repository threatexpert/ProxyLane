#pragma once

#include <afxwin.h>

namespace Localization
{
	BOOL Initialize();
	CString Get(LPCTSTR key);
	CString Format(LPCTSTR key, ...);
	CString CurrentLanguage();
	CString PreferredLanguage();
	BOOL SetPreferredLanguage(LPCTSTR language);
	void ApplyDialog(CWnd* dialog, UINT dialogId);
}
