#include "stdafx.h"
#include "ProxyLane.h"
#include "Page5.h"
#include "AppVersion.h"

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
}

BOOL CPage5::OnInitDialog()
{
	CModernDialog::OnInitDialog();

	CString versionText(_T("版本 "));
	const CString version = AppVersion::FileVersion();
	versionText += version.IsEmpty() ? _T("未知") : version;
	SetDlgItemText(IDC_STATIC_ABOUT_VERSION, versionText);

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
END_MESSAGE_MAP()

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
