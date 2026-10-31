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
	, m_aboutIcon(NULL)
{
}

CPage5::~CPage5()
{
	if (m_aboutIcon) ::DestroyIcon(m_aboutIcon);
}

void CPage5::DoDataExchange(CDataExchange* dataExchange)
{
	CModernDialog::DoDataExchange(dataExchange);
	DDX_Control(dataExchange, IDC_COMBO_LANGUAGE, m_languageCombo);
	DDX_Control(dataExchange, IDC_STATIC_OPEN_SOURCE_GROUP, m_openSourceCard);
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
	// Load the icon at its display size instead of stretching the 32px one.
	m_aboutIcon = static_cast<HICON>(::LoadImage(AfxGetResourceHandle(), MAKEINTRESOURCE(IDR_MAINFRAME),
		IMAGE_ICON, UiTheme::ScaleForWindow(m_hWnd, 48), UiTheme::ScaleForWindow(m_hWnd, 48), LR_DEFAULTCOLOR));
	if (m_aboutIcon)
		static_cast<CStatic*>(GetDlgItem(IDC_ABOUT_ICON))->SetIcon(m_aboutIcon);
	if (CWnd* name = GetDlgItem(IDC_ABOUT_NAME))
		name->SetFont(&m_titleFont, FALSE);
	LayoutAboutPage();
	return TRUE;
}

BOOL CPage5::PreTranslateMessage(MSG* message)
{
	if (m_projectTooltip.GetSafeHwnd())
		m_projectTooltip.RelayEvent(message);

	return CModernDialog::PreTranslateMessage(message);
}

BEGIN_MESSAGE_MAP(CPage5, CModernDialog)
	ON_WM_SIZE()
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

BOOL CPage5::UsesSecondaryText(UINT controlId) const
{
	switch (controlId)
	{
	case IDC_STATIC_ABOUT_VERSION:
	case IDC_STATIC_ABOUT_TAGLINE:
	case IDC_STATIC_PROJECT_LABEL:
	case IDC_ABOUT_COPYRIGHT:
		return TRUE;
	}
	return CModernDialog::UsesSecondaryText(controlId);
}

void CPage5::OnSize(UINT type, int cx, int cy)
{
	CModernDialog::OnSize(type, cx, cy);
	LayoutAboutPage();
}

void CPage5::LayoutAboutPage()
{
	if (!GetSafeHwnd() || !m_languageCombo.GetSafeHwnd())
		return;
	CRect client;
	GetClientRect(&client);
	if (client.Width() <= 0)
		return;

	auto S = [this](int value) { return UiTheme::ScaleForWindow(m_hWnd, value); };
	auto place = [this](UINT id, int x, int y, int width, int height)
	{
		if (CWnd* control = GetDlgItem(id))
			control->SetWindowPos(NULL, x, y, max(0, width), max(0, height), SWP_NOZORDER | SWP_NOACTIVATE);
	};
	const int margin = S(8);
	const int pad = S(16);
	const int width = min(client.Width() - margin * 2, S(560));
	const int x0 = margin;
	int y = S(62);

	// Identity block.
	place(IDC_ABOUT_ICON, x0 + S(4), y, S(48), S(48));
	const int textX = x0 + S(68);
	place(IDC_ABOUT_NAME, textX, y, width - S(68), S(26));
	place(IDC_STATIC_ABOUT_VERSION, textX, y + S(28), width - S(68), S(18));
	place(IDC_STATIC_ABOUT_TAGLINE, textX, y + S(48), width - S(68), S(18));
	y += S(88);

	// Open source card.
	const int cardH = S(36) + S(32) + S(28) + S(10);
	place(IDC_STATIC_OPEN_SOURCE_GROUP, x0, y, width, cardH);
	int row = y + S(38);
	place(IDC_STATIC_PROJECT_LABEL, x0 + pad, row + S(2), S(80), S(20));
	place(IDC_LINK_PROJECT, x0 + pad + S(90), row, width - pad * 2 - S(90), S(24));
	row += S(32);
	place(IDC_ABOUT_COPYRIGHT, x0 + pad, row, width - pad * 2, S(20));
	y += cardH + S(20);

	// Language.
	place(IDC_STATIC_LANGUAGE_LABEL, x0 + S(2), y + S(4), S(240), S(20));
	place(IDC_COMBO_LANGUAGE, x0 + S(250), y, min(S(220), max(S(120), width - S(250))), S(240));
	m_languageCombo.SetItemHeight(-1, S(18));
	RedrawWindow(NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}
