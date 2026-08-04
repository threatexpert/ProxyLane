#include "stdafx.h"
#include "ProxyLane.h"
#include "Page5.h"
#include "AppVersion.h"
#include "Localization.h"

IMPLEMENT_DYNAMIC(CPage5, CModernDialog)

namespace
{
	LPCTSTR kProjectUrl = _T("https://github.com/threatexpert/ProxyLane");
}

CPage5::CPage5(CWnd* parent)
	: CModernDialog(CPage5::IDD, parent)
{
}

CPage5::~CPage5()
{
}

void CPage5::DoDataExchange(CDataExchange* dataExchange)
{
	CModernDialog::DoDataExchange(dataExchange);
	DDX_Control(dataExchange, IDC_COMBO_LANGUAGE, m_languageCombo);
}

BOOL CPage5::OnInitDialog()
{
	CModernDialog::OnInitDialog();

	const CString version = AppVersion::DisplayVersion();
	CString displayVersion = version.IsEmpty() ? Localization::Get(_T("common.unknown")) : version;
	CString versionText = Localization::Format(_T("page5.version_value"),
		static_cast<LPCTSTR>(displayVersion));
	SetDlgItemText(IDC_STATIC_ABOUT_VERSION, versionText);

	m_languageCombo.AddString(Localization::Get(_T("language.auto")));
	m_languageCombo.AddString(Localization::Get(_T("language.zh-CN")));
	m_languageCombo.AddString(Localization::Get(_T("language.en-US")));
	CString preferred = Localization::PreferredLanguage();
	int selection = preferred.CompareNoCase(_T("zh-CN")) == 0 ? 1
		: preferred.CompareNoCase(_T("en-US")) == 0 ? 2 : 0;
	m_languageCombo.SetCurSel(selection);

	CWnd* projectLink = GetDlgItem(IDC_LINK_PROJECT);
	if (projectLink && m_projectTooltip.Create(this, TTS_ALWAYSTIP | TTS_NOPREFIX))
	{
		m_projectTooltip.AddTool(projectLink, kProjectUrl);
		m_projectTooltip.SetMaxTipWidth(UiTheme::ScaleForWindow(m_hWnd, 360));
		m_projectTooltip.Activate(TRUE);
	}
	return TRUE;
}

BOOL CPage5::PreTranslateMessage(MSG* message)
{
	if (m_projectTooltip.GetSafeHwnd())
		m_projectTooltip.RelayEvent(message);

	return CModernDialog::PreTranslateMessage(message);
}

BEGIN_MESSAGE_MAP(CPage5, CModernDialog)
	ON_NOTIFY(NM_CLICK, IDC_LINK_PROJECT, &CPage5::OnProjectLink)
	ON_NOTIFY(NM_RETURN, IDC_LINK_PROJECT, &CPage5::OnProjectLink)
	ON_CBN_SELCHANGE(IDC_COMBO_LANGUAGE, &CPage5::OnLanguageChanged)
END_MESSAGE_MAP()

void CPage5::OnLanguageChanged()
{
	static LPCTSTR values[] = { _T("auto"), _T("zh-CN"), _T("en-US") };
	int selection = m_languageCombo.GetCurSel();
	if (selection < 0 || selection >= _countof(values))
		return;
	Localization::SetPreferredLanguage(values[selection]);
	MessageBox(Localization::Get(_T("language.restart_message")),
		Localization::Get(_T("language.restart_title")), MB_ICONINFORMATION);
}

void CPage5::OnProjectLink(NMHDR* notifyHeader, LRESULT* result)
{
	LPCTSTR url = kProjectUrl;
	if (notifyHeader)
	{
		const NMLINK* link = reinterpret_cast<const NMLINK*>(notifyHeader);
		if (link->item.szUrl[0] != _T('\0'))
			url = link->item.szUrl;
	}

	ShellExecute(m_hWnd, _T("open"), url, NULL, NULL, SW_SHOWNORMAL);
	if (result)
		*result = 0;
}
