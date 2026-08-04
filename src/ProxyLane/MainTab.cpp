#include "stdafx.h"
#include "ProxyLane.h"
#include "MainTab.h"
#include "ModernUI.h"
#include "Localization.h"

namespace
{
	const UINT kMainNavigationId = 0x1006;
	const UINT kTransientStatusId = 0x1007;
	const UINT_PTR kTransientStatusTimer = 0x1008;
	const UINT kSidebarStatusId = 0x1009;
	LPCTSTR kNavigationKeys[] =
	{
		_T("nav.proxy"), _T("nav.apps"), _T("nav.log"),
		_T("nav.monitor"), _T("nav.about")
	};
}

CMainTab* g_MainTab = NULL;

IMPLEMENT_DYNAMIC(CMainTab, CWnd)

CMainTab::CMainTab()
	: m_currentPage(0)
	, m_hoverPage(-1)
	, m_attentionPage(-1)
	, m_proxyRunning(FALSE)
{
	ZeroMemory(m_pages, sizeof(m_pages));
	g_MainTab = this;
}

CMainTab::~CMainTab()
{
	g_MainTab = NULL;
}

BOOL CMainTab::CreateTabCtrl(CWnd* parent)
{
	CRect rect;
	parent->GetClientRect(&rect);
	CString className = AfxRegisterWndClass(
		CS_HREDRAW | CS_VREDRAW,
		::LoadCursor(NULL, IDC_ARROW),
		(HBRUSH)::GetStockObject(NULL_BRUSH),
		NULL);

	if (!CreateEx(
		0, className, _T("ProxyLaneNavigation"),
		WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
		rect, parent, kMainNavigationId))
	{
		return FALSE;
	}

	UiTheme::CreateUiFont(m_navigationFont, m_hWnd, 10, FW_NORMAL);
	UiTheme::CreateUiFont(m_brandFont, m_hWnd, 15, FW_BOLD, _T("Tahoma"));

	if (!m_page1.Create(IDD_Page1, this)
		|| !m_page2.Create(IDD_Page2, this)
		|| !m_page3.Create(IDD_Page3, this)
		|| !m_page4.Create(IDD_Page4, this)
		|| !m_page5.Create(IDD_Page5, this))
	{
		return FALSE;
	}

	m_pages[PAGE_PROXY] = &m_page1;
	m_pages[PAGE_APPLICATIONS] = &m_page3;
	m_pages[PAGE_LOG] = &m_page2;
	m_pages[PAGE_MONITOR] = &m_page4;
	m_pages[PAGE_ABOUT] = &m_page5;

	for (int i = 0; i < PAGE_COUNT; ++i)
		m_pages[i]->ShowWindow(i == 0 ? SW_SHOW : SW_HIDE);

	CString stoppedText = Localization::Get(_T("status.proxy_stopped"));
	if (!m_sidebarStatus.Create(stoppedText,
		WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
		CRect(0, 0, 0, 0), this, kSidebarStatusId))
	{
		return FALSE;
	}
	m_sidebarStatus.SetFont(&m_navigationFont, FALSE);
	m_sidebarStatus.SetStatus(stoppedText, CStatusLabel::TONE_NEUTRAL);
	if (m_sidebarTooltip.Create(this, TTS_ALWAYSTIP | TTS_NOPREFIX))
	{
		m_sidebarTooltip.AddTool(&m_sidebarStatus, stoppedText);
		m_sidebarTooltip.SetMaxTipWidth(UiTheme::ScaleForWindow(m_hWnd, 360));
		m_sidebarTooltip.Activate(TRUE);
	}

	CWnd* statusParent = GetTopLevelParent();
	if (!statusParent || !m_transientStatus.Create(_T(""), WS_CHILD | SS_OWNERDRAW,
		CRect(0, 0, 0, 0), statusParent, kTransientStatusId))
	{
		return FALSE;
	}
	m_transientStatus.SetFont(&m_navigationFont, FALSE);

	PositionWnd();
	return TRUE;
}

BEGIN_MESSAGE_MAP(CMainTab, CWnd)
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_SIZE()
	ON_WM_LBUTTONDOWN()
	ON_WM_MOUSEMOVE()
	ON_WM_TIMER()
	ON_MESSAGE(WM_MOUSELEAVE, OnMouseLeave)
END_MESSAGE_MAP()

int CMainTab::NavigationWidth() const
{
	const int width = Localization::CurrentLanguage().CompareNoCase(_T("en-US")) == 0
		? 180 : 146;
	return UiTheme::ScaleForWindow(m_hWnd, width);
}

CRect CMainTab::NavigationItemRect(int index) const
{
	int margin = UiTheme::ScaleForWindow(m_hWnd, 10);
	int top = UiTheme::ScaleForWindow(m_hWnd, 78);
	int height = UiTheme::ScaleForWindow(m_hWnd, 40);
	int gap = UiTheme::ScaleForWindow(m_hWnd, 4);
	return CRect(
		margin,
		top + index * (height + gap),
		NavigationWidth() - margin,
		top + index * (height + gap) + height);
}

int CMainTab::HitTestNavigation(CPoint point) const
{
	for (int i = 0; i < PAGE_COUNT; ++i)
	{
		if (NavigationItemRect(i).PtInRect(point))
			return i;
	}
	return -1;
}

void CMainTab::OnPaint()
{
	CPaintDC dc(this);
	CRect client;
	GetClientRect(&client);

	dc.FillSolidRect(client, UiTheme::WindowBackground());
	CRect sidebar = client;
	sidebar.right = NavigationWidth();
	dc.FillSolidRect(sidebar, UiTheme::SidebarBackground());
	dc.FillSolidRect(sidebar.right - 1, sidebar.top, 1, sidebar.Height(), UiTheme::Border());

	dc.SetBkMode(TRANSPARENT);
	dc.SetTextColor(UiTheme::TextPrimary());
	CFont* oldFont = dc.SelectObject(&m_brandFont);
	CRect brand(UiTheme::ScaleForWindow(m_hWnd, 16), UiTheme::ScaleForWindow(m_hWnd, 10),
		NavigationWidth() - UiTheme::ScaleForWindow(m_hWnd, 14), UiTheme::ScaleForWindow(m_hWnd, 42));
	dc.DrawText(_T("ProxyLane"), brand, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

	dc.SelectObject(&m_navigationFont);
	dc.SetTextColor(UiTheme::TextSecondary());
	CRect subtitle = brand;
	subtitle.top = UiTheme::ScaleForWindow(m_hWnd, 38);
	subtitle.bottom = UiTheme::ScaleForWindow(m_hWnd, 62);
	CString subtitleText = Localization::Get(_T("nav.subtitle"));
	dc.DrawText(subtitleText, subtitle, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

	for (int i = 0; i < PAGE_COUNT; ++i)
	{
		CRect item = NavigationItemRect(i);
		BOOL selected = i == m_currentPage;
		BOOL hot = i == m_hoverPage;
		if (selected || hot)
		{
			CBrush fill(selected ? UiTheme::AccentSoft() : RGB(241, 244, 249));
			CPen pen(PS_SOLID, 1, selected ? RGB(207, 220, 251) : RGB(234, 237, 242));
			CBrush* oldBrush = dc.SelectObject(&fill);
			CPen* oldPen = dc.SelectObject(&pen);
			dc.RoundRect(item, CPoint(UiTheme::ScaleForWindow(m_hWnd, 8), UiTheme::ScaleForWindow(m_hWnd, 8)));
			dc.SelectObject(oldPen);
			dc.SelectObject(oldBrush);
		}

		if (selected)
		{
			CRect marker = item;
			marker.left += UiTheme::ScaleForWindow(m_hWnd, 3);
			marker.right = marker.left + UiTheme::ScaleForWindow(m_hWnd, 3);
			marker.top += UiTheme::ScaleForWindow(m_hWnd, 10);
			marker.bottom -= UiTheme::ScaleForWindow(m_hWnd, 10);
			dc.FillSolidRect(marker, UiTheme::Accent());
		}

		CRect label = item;
		label.left += UiTheme::ScaleForWindow(m_hWnd, 18);
		dc.SetTextColor(selected ? UiTheme::Accent() : UiTheme::TextPrimary());
		CString navigationText = Localization::Get(kNavigationKeys[i]);
		dc.DrawText(navigationText, label, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

		if (i == m_attentionPage && !selected)
		{
			const int dotSize = UiTheme::ScaleForWindow(m_hWnd, 7);
			CRect dot(
				item.right - UiTheme::ScaleForWindow(m_hWnd, 17),
				item.CenterPoint().y - dotSize / 2,
				item.right - UiTheme::ScaleForWindow(m_hWnd, 17) + dotSize,
				item.CenterPoint().y - dotSize / 2 + dotSize);
			CBrush dotBrush(UiTheme::Accent());
			CPen dotPen(PS_SOLID, 1, UiTheme::Accent());
			CBrush* oldDotBrush = dc.SelectObject(&dotBrush);
			CPen* oldDotPen = dc.SelectObject(&dotPen);
			dc.Ellipse(dot);
			dc.SelectObject(oldDotPen);
			dc.SelectObject(oldDotBrush);
		}
	}

	dc.SelectObject(oldFont);
}

BOOL CMainTab::OnEraseBkgnd(CDC*)
{
	return TRUE;
}

void CMainTab::OnSize(UINT type, int cx, int cy)
{
	CWnd::OnSize(type, cx, cy);
	PositionWnd();
}

void CMainTab::PositionWnd()
{
	if (!GetSafeHwnd())
		return;

	CRect content;
	GetClientRect(&content);
	int margin = UiTheme::ScaleForWindow(m_hWnd, 10);
	content.left = NavigationWidth() + margin;
	content.top += margin;
	content.right -= margin;
	content.bottom -= margin;

	if (content.Width() <= 0 || content.Height() <= 0)
		return;

	for (int i = 0; i < PAGE_COUNT; ++i)
	{
		if (m_pages[i] && m_pages[i]->GetSafeHwnd())
			m_pages[i]->MoveWindow(content);
	}

	if (m_sidebarStatus.GetSafeHwnd())
	{
		const int sidebarMargin = UiTheme::ScaleForWindow(m_hWnd, 10);
		const int sidebarStatusHeight = UiTheme::ScaleForWindow(m_hWnd,
			m_proxyRunning ? 56 : 34);
		m_sidebarStatus.MoveWindow(
			sidebarMargin,
			content.bottom - sidebarStatusHeight,
			NavigationWidth() - sidebarMargin * 2,
			sidebarStatusHeight);
	}

	if (m_transientStatus.GetSafeHwnd())
	{
		const int statusMargin = UiTheme::ScaleForWindow(m_hWnd, 12);
		const int statusHeight = UiTheme::ScaleForWindow(m_hWnd, 32);
		const int preferredWidth = UiTheme::ScaleForWindow(m_hWnd, 280);
		const int availableWidth = max(0, content.Width() - statusMargin * 2);
		const int statusWidth = min(preferredWidth, availableWidth);
		CRect statusRect(
			content.right - statusMargin - statusWidth,
			content.top + statusMargin,
			content.right - statusMargin,
			content.top + statusMargin + statusHeight);
		ClientToScreen(&statusRect);
		m_transientStatus.GetParent()->ScreenToClient(&statusRect);
		m_transientStatus.SetWindowPos(&wndTop,
			statusRect.left,
			statusRect.top,
			statusWidth,
			statusHeight,
			SWP_NOACTIVATE);
	}

	if (m_pages[m_currentPage])
		m_pages[m_currentPage]->PostMessage(WM_SIZE);
}

void CMainTab::SelectPage(int pageIndex)
{
	if (pageIndex < 0 || pageIndex >= PAGE_COUNT || pageIndex == m_currentPage)
		return;

	if (m_pages[m_currentPage])
		m_pages[m_currentPage]->ShowWindow(SW_HIDE);
	m_currentPage = pageIndex;
	if (m_attentionPage == pageIndex)
		m_attentionPage = -1;
	if (m_pages[m_currentPage])
	{
		m_pages[m_currentPage]->ShowWindow(SW_SHOW);
		m_pages[m_currentPage]->PostMessage(WM_SIZE);
		m_pages[m_currentPage]->RedrawWindow(
			NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
	}
	Invalidate(FALSE);
}

void CMainTab::SetPageAttention(int pageIndex, BOOL attention)
{
	if (pageIndex < 0 || pageIndex >= PAGE_COUNT)
		return;

	if (attention)
		m_attentionPage = pageIndex;
	else if (m_attentionPage == pageIndex)
		m_attentionPage = -1;

	Invalidate(FALSE);
}

void CMainTab::ShowTransientStatus(LPCTSTR text, CStatusLabel::Tone tone)
{
	if (!m_transientStatus.GetSafeHwnd())
		return;

	m_transientStatus.SetStatus(text, tone);
	m_transientStatus.ShowWindow(SW_SHOW);
	m_transientStatus.SetWindowPos(&wndTop, 0, 0, 0, 0,
		SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
	KillTimer(kTransientStatusTimer);
	SetTimer(kTransientStatusTimer, 3200, NULL);
}

void CMainTab::SetRunningProfile(LPCTSTR profileName, BOOL running)
{
	CString name(profileName ? profileName : _T(""));
	name.Trim();
	if (running && name.IsEmpty())
		name = Localization::Get(_T("nav.current_profile"));

	if (m_proxyRunning == running && m_runningProfileName == name)
		return;

	m_proxyRunning = running;
	m_runningProfileName = running ? name : _T("");
	if (m_sidebarStatus.GetSafeHwnd())
	{
		if (running)
			m_sidebarStatus.SetTwoLineStatus(Localization::Get(_T("status.proxy_running")), name,
				CStatusLabel::TONE_SUCCESS);
		else
			m_sidebarStatus.SetStatus(Localization::Get(_T("status.proxy_stopped")), CStatusLabel::TONE_NEUTRAL);

		if (m_sidebarTooltip.GetSafeHwnd())
		{
			CString tooltipText = running
				? Localization::Format(_T("nav.running_profile"), static_cast<LPCTSTR>(name))
				: Localization::Get(_T("status.proxy_stopped"));
			m_sidebarTooltip.UpdateTipText(tooltipText, &m_sidebarStatus);
		}
		PositionWnd();
	}
	Invalidate(FALSE);

	CWnd* mainWindow = GetTopLevelParent();
	if (mainWindow && mainWindow->GetSafeHwnd())
		mainWindow->PostMessage(WM_PROXY_STATUS_CHANGED);
}

void CMainTab::OnTimer(UINT_PTR eventId)
{
	if (eventId == kTransientStatusTimer)
	{
		KillTimer(kTransientStatusTimer);
		m_transientStatus.ShowWindow(SW_HIDE);
		return;
	}

	CWnd::OnTimer(eventId);
}

void CMainTab::OnLButtonDown(UINT flags, CPoint point)
{
	int page = HitTestNavigation(point);
	if (page >= 0)
		SelectPage(page);
	CWnd::OnLButtonDown(flags, point);
}

void CMainTab::OnMouseMove(UINT flags, CPoint point)
{
	int page = HitTestNavigation(point);
	if (page != m_hoverPage)
	{
		m_hoverPage = page;
		Invalidate(FALSE);
	}

	TRACKMOUSEEVENT track = { sizeof(track), TME_LEAVE, m_hWnd, 0 };
	_TrackMouseEvent(&track);
	CWnd::OnMouseMove(flags, point);
}

LRESULT CMainTab::OnMouseLeave(WPARAM, LPARAM)
{
	m_hoverPage = -1;
	Invalidate(FALSE);
	return 0;
}

void CMainTab::AddLogText(int, LPCTSTR text)
{
	m_page2.AddLogText(CString(text));
}

void CMainTab::CopyText()
{
	m_page2.CopyAll();
}

void CMainTab::ClearText()
{
	m_page2.ClearAll();
}
