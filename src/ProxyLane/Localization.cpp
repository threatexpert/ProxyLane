#include "stdafx.h"
#include "ProxyLane.h"
#include "Localization.h"
#include "resource.h"
#include <stdarg.h>

namespace
{
	CMapStringToString g_strings;
	CString g_currentLanguage;
	CString g_preferredLanguage;

	CString SettingsPath()
	{
		TCHAR path[MAX_PATH] = { 0 };
		GetModuleFileName(NULL, path, _countof(path));
		CString result(path);
		if (result.Right(6).CompareNoCase(_T("64.exe")) == 0)
			return result.Left(result.GetLength() - 6) + _T(".ini");
		int dot = result.ReverseFind(_T('.'));
		return (dot >= 0 ? result.Left(dot) : result) + _T(".ini");
	}

	void SkipWhitespace(const CString& text, int& position)
	{
		while (position < text.GetLength())
		{
			TCHAR ch = text[position];
			if (ch != _T(' ') && ch != _T('\t') && ch != _T('\r') && ch != _T('\n')
				&& ch != 0xFEFF)
				break;
			++position;
		}
	}

	BOOL ParseJsonString(const CString& text, int& position, CString& value)
	{
		SkipWhitespace(text, position);
		if (position >= text.GetLength() || text[position++] != _T('"'))
			return FALSE;
		value.Empty();
		while (position < text.GetLength())
		{
			TCHAR ch = text[position++];
			if (ch == _T('"'))
				return TRUE;
			if (ch != _T('\\'))
			{
				value += ch;
				continue;
			}
			if (position >= text.GetLength())
				return FALSE;
			ch = text[position++];
			switch (ch)
			{
			case _T('n'): value += _T('\n'); break;
			case _T('r'): value += _T('\r'); break;
			case _T('t'): value += _T('\t'); break;
			case _T('"'): value += _T('"'); break;
			case _T('\\'): value += _T('\\'); break;
			case _T('u'):
				{
					if (position + 4 > text.GetLength())
						return FALSE;
					unsigned int code = 0;
					for (int i = 0; i < 4; ++i)
					{
						TCHAR digit = text[position++];
						code <<= 4;
						if (digit >= _T('0') && digit <= _T('9')) code += digit - _T('0');
						else if (digit >= _T('a') && digit <= _T('f')) code += digit - _T('a') + 10;
						else if (digit >= _T('A') && digit <= _T('F')) code += digit - _T('A') + 10;
						else return FALSE;
					}
					value += (TCHAR)code;
				}
				break;
			default: value += ch; break;
			}
		}
		return FALSE;
	}

	BOOL ParseCatalog(const CString& text)
	{
		g_strings.RemoveAll();
		int position = 0;
		SkipWhitespace(text, position);
		if (position >= text.GetLength() || text[position++] != _T('{'))
			return FALSE;
		for (;;)
		{
			SkipWhitespace(text, position);
			if (position < text.GetLength() && text[position] == _T('}'))
				return TRUE;
			CString key;
			CString value;
			if (!ParseJsonString(text, position, key))
				return FALSE;
			SkipWhitespace(text, position);
			if (position >= text.GetLength() || text[position++] != _T(':')
				|| !ParseJsonString(text, position, value))
				return FALSE;
			g_strings.SetAt(key, value);
			SkipWhitespace(text, position);
			if (position < text.GetLength() && text[position] == _T(','))
			{
				++position;
				continue;
			}
			if (position < text.GetLength() && text[position] == _T('}'))
				return TRUE;
			return FALSE;
		}
	}

	BOOL LoadCatalog(UINT resourceId)
	{
		HINSTANCE instance = AfxGetInstanceHandle();
		HRSRC resource = FindResource(instance, MAKEINTRESOURCE(resourceId), RT_RCDATA);
		if (!resource)
			return FALSE;
		HGLOBAL loaded = LoadResource(instance, resource);
		const char* bytes = loaded ? static_cast<const char*>(LockResource(loaded)) : NULL;
		DWORD byteCount = SizeofResource(instance, resource);
		if (!bytes || !byteCount)
			return FALSE;
		int charCount = MultiByteToWideChar(CP_UTF8, 0, bytes, byteCount, NULL, 0);
		if (charCount <= 0)
			return FALSE;
		CString text;
		WCHAR* buffer = text.GetBuffer(charCount);
		MultiByteToWideChar(CP_UTF8, 0, bytes, byteCount, buffer, charCount);
		text.ReleaseBuffer(charCount);
		return ParseCatalog(text);
	}

	struct ControlTranslation
	{
		UINT id;
		LPCTSTR key;
	};

	void ApplyControls(CWnd* dialog, const ControlTranslation* translations, int count)
	{
		for (int i = 0; i < count; ++i)
		{
			CWnd* control = dialog->GetDlgItem(translations[i].id);
			if (control)
				control->SetWindowText(Localization::Get(translations[i].key));
		}
	}
}

BOOL Localization::Initialize()
{
	TCHAR preferred[32] = { 0 };
	GetPrivateProfileString(_T("options"), _T("language"), _T("auto"),
		preferred, _countof(preferred), SettingsPath());
	g_preferredLanguage = preferred;
	g_currentLanguage = g_preferredLanguage;
	if (g_currentLanguage.CompareNoCase(_T("zh-CN")) != 0
		&& g_currentLanguage.CompareNoCase(_T("en-US")) != 0)
	{
		LANGID languageId = GetUserDefaultUILanguage();
		g_currentLanguage = PRIMARYLANGID(languageId) == LANG_CHINESE
			? _T("zh-CN") : _T("en-US");
	}
	UINT selectedResource = g_currentLanguage.CompareNoCase(_T("zh-CN")) == 0
		? IDR_LANG_ZH_CN : IDR_LANG_EN_US;
	if (LoadCatalog(selectedResource))
		return TRUE;

	g_currentLanguage = _T("en-US");
	if (LoadCatalog(IDR_LANG_EN_US))
		return TRUE;
	g_currentLanguage = _T("zh-CN");
	return LoadCatalog(IDR_LANG_ZH_CN);
}

CString Localization::Get(LPCTSTR key)
{
	CString value;
	if (key && g_strings.Lookup(key, value))
		return value;
	return key ? CString(key) : CString();
}

CString Localization::Format(LPCTSTR key, ...)
{
	CString format = Get(key);
	CString result;
	va_list arguments;
	va_start(arguments, key);
	result.FormatV(format, arguments);
	va_end(arguments);
	return result;
}

CString Localization::CurrentLanguage() { return g_currentLanguage; }
CString Localization::PreferredLanguage() { return g_preferredLanguage; }

BOOL Localization::SetPreferredLanguage(LPCTSTR language)
{
	if (!language)
		return FALSE;
	g_preferredLanguage = language;
	return WritePrivateProfileString(_T("options"), _T("language"), language, SettingsPath());
}

void Localization::ApplyDialog(CWnd* dialog, UINT dialogId)
{
	if (!dialog)
		return;
	static const ControlTranslation page1[] = {
		{ IDC_STATIC_PAGE_TITLE, _T("page1.title") }, { IDC_STATIC_PAGE_SUBTITLE, _T("page1.subtitle") },
		{ IDC_STATIC_PROXY_GROUP, _T("page1.proxy_group") }, { IDC_STATIC_CONFIG_LABEL, _T("common.config") },
		{ IDC_BUTTON_SAVE_PROFILE, _T("common.save_profile") }, { IDC_BUTTON_DELETE_PROFILE, _T("common.delete") },
		{ IDC_STATIC_TYPE_LABEL, _T("common.type") }, { IDC_STATIC_HOST_LABEL, _T("common.host") },
		{ IDC_STATIC_PORT_LABEL, _T("common.port") }, { IDC_STATIC_USER_LABEL, _T("common.username") },
		{ IDC_STATIC_PASSWORD_LABEL, _T("common.password") }, { IDC_STATIC_TestProxy, _T("status.test_not_run") },
		{ IDC_STATIC_TRANSPORT_LABEL, _T("common.transport") }, { IDC_STATIC_PSK_LABEL, _T("common.psk") },
		{ IDC_TestProxy, _T("action.test_current") }, { IDOK, _T("action.start_proxy") },
		{ IDCANCEL, _T("action.stop_proxy") }, { IDC_RADIO_TAB_BASIC, _T("page1.tab_basic") },
		{ IDC_RADIO_TAB_CHILD, _T("page1.tab_child") }, { IDC_RADIO_TAB_TARGET, _T("page1.tab_target") },
		{ IDC_STATIC_GROUP_OTHER, _T("page1.network_options") }, { IDC_CHECK_HOOKTCP, _T("page1.proxy_tcp") },
		{ IDC_CHECK_HOOK_UDP, _T("page1.proxy_udp") }, { IDC_CHECK_HOOKCHILDPROCESS, _T("page1.proxy_children") },
		{ IDC_CHECK_BLOCKUDP, _T("page1.block_udp") }, { IDC_STATIC_DNS_LABEL, _T("page1.dns") },
		{ IDC_RADIO_DNSLOCAL, _T("page1.dns_local") }, { IDC_RADIO_DNSREMOTE, _T("page1.dns_remote") },
		{ IDC_CHECK_REDIRECT_PRIVATE_DNS, _T("page1.redirect_private_dns") },
		{ IDC_STATIC_CHILDFILTER_GROUP, _T("page1.child_group") }, { IDC_RADIO_CHILDFILTER_EXCLUDE, _T("page1.child_exclude") },
		{ IDC_RADIO_CHILDFILTER_INCLUDE, _T("page1.child_include") }, { IDC_STATIC_CHILDFILTER_HINT, _T("page1.child_hint") },
		{ IDC_STATIC_TARGETFILTER_GROUP, _T("page1.target_group") }, { IDC_RADIO_TARGETFILTER_BYPASS, _T("page1.target_bypass") },
		{ IDC_RADIO_TARGETFILTER_PROXY, _T("page1.target_proxy") }, { IDC_STATIC_TARGETFILTER_HINT, _T("page1.target_hint") }
	};
	static const ControlTranslation page2[] = {
		{ IDC_STATIC_PAGE_TITLE, _T("page2.title") }, { IDC_STATIC_PAGE_SUBTITLE, _T("page2.subtitle") },
		{ IDC_BTN_COPY_LOG, _T("action.copy_all") }, { IDC_BTN_CLEAR_LOG, _T("action.clear") }
	};
	static const ControlTranslation page3[] = {
		{ IDC_STATIC_PAGE_TITLE, _T("page3.title") }, { IDC_STATIC_PAGE_SUBTITLE, _T("page3.subtitle") },
		{ IDC_REFRESH, _T("action.refresh") }, { IDC_INJECTDLL, _T("action.proxy_selected") }
	};
	static const ControlTranslation page4[] = {
		{ IDC_STATIC_PAGE_TITLE, _T("page4.title") }, { IDC_STATIC_PAGE_SUBTITLE, _T("page4.subtitle") },
		{ IDC_CHECK1, _T("page4.monitor") }, { IDC_CHECK_HEX, _T("page4.hex") },
		{ IDC_BTN_CLEAR, _T("action.clear") }, { IDC_STATIC_TASKCOUNT, _T("page4.connections_zero") }
	};
	static const ControlTranslation page5[] = {
		{ IDC_STATIC_PAGE_TITLE, _T("page5.title") }, { IDC_STATIC_PAGE_SUBTITLE, _T("page5.subtitle") },
		{ IDC_STATIC_ABOUT_VERSION, _T("page5.version") }, { IDC_STATIC_ABOUT_TAGLINE, _T("page5.tagline") },
		{ IDC_STATIC_OPEN_SOURCE_GROUP, _T("page5.open_source") }, { IDC_STATIC_PROJECT_LABEL, _T("page5.project") },
		{ IDC_STATIC_LANGUAGE_LABEL, _T("page5.language") }
	};
	if (dialogId == IDD_Page1) ApplyControls(dialog, page1, _countof(page1));
	else if (dialogId == IDD_Page2) ApplyControls(dialog, page2, _countof(page2));
	else if (dialogId == IDD_Page3) ApplyControls(dialog, page3, _countof(page3));
	else if (dialogId == IDD_Page4) ApplyControls(dialog, page4, _countof(page4));
	else if (dialogId == IDD_Page5) ApplyControls(dialog, page5, _countof(page5));
}
