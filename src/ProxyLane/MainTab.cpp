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
	const UINT_PTR kTrafficRateTimer = 0x100A;

	CString FormatTrafficRate(double bytesPerSecond)
	{
		LPCTSTR units[] = { _T("B/s"), _T("KB/s"), _T("MB/s"), _T("GB/s") };
		int unit = 0;
		while (bytesPerSecond >= 1024.0 && unit < 3)
		{
			bytesPerSecond /= 1024.0;
			++unit;
		}
		CString text;
		text.Format(unit == 0 ? _T("%.0f %s") : _T("%.1f %s"), bytesPerSecond, units[unit]);
		return text;
	}
	const UiTheme::Glyph kNavigationGlyphs[] =
	{
		UiTheme::GLYPH_APPS, UiTheme::GLYPH_PROXY, UiTheme::GLYPH_LOG,
		UiTheme::GLYPH_MONITOR, UiTheme::GLYPH_ABOUT
	};
	LPCTSTR kNavigationKeys[] =
	{
		_T("nav.apps"), _T("nav.proxy"), _T("nav.log"),
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
	, m_brandIcon(NULL)
{
	ZeroMemory(m_pages, sizeof(m_pages));
	g_MainTab = this;
}

CMainTab::~CMainTab()
{
	if (m_brandIcon) ::DestroyIcon(m_brandIcon);
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
	UiTheme::CreateUiFont(m_brandFont, m_hWnd, 13, FW_BOLD, _T("Tahoma"));
	m_brandIcon = static_cast<HICON>(::LoadImage(AfxGetResourceHandle(), MAKEINTRESOURCE(IDR_MAINFRAME),
		IMAGE_ICON, UiTheme::ScaleForWindow(m_hWnd, 30), UiTheme::ScaleForWindow(m_hWnd, 30), LR_DEFAULTCOLOR));

	if (!m_page1.Create(IDD_Page1, this)
		|| !m_page2.Create(IDD_Page2, this)
		|| !m_page3.Create(IDD_Page3, this)
		|| !m_page4.Create(IDD_Page4, this)
		|| !m_page5.Create(IDD_Page5, this))
	{
		return FALSE;
	}

	m_pages[PAGE_PROXY] = &m_page1;
	m_page4.SetQuicUdpWarningProvider([this]() { return m_page1.QuicUdpWarning(); });
	m_pages[PAGE_APPLICATIONS] = &m_page3;
	m_pages[PAGE_LOG] = &m_page2;
	m_pages[PAGE_MONITOR] = &m_page4;
	m_pages[PAGE_ABOUT] = &m_page5;

	// Keep every page hidden until all controls, profiles and dynamic cards
	// have finished initialization. Showing page 0 here can expose a partially
	// painted dialog when startup is slow.
	for (int i = 0; i < PAGE_COUNT; ++i)
		m_pages[i]->ShowWindow(SW_HIDE);

	CString stoppedText = Localization::Get(_T("status.proxy_stopped"));
	if (!m_sidebarStatus.Create(stoppedText,
		WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
		CRect(0, 0, 0, 0), this, kSidebarStatusId))
	{
		return FALSE;
	}
	m_sidebarStatus.SetFont(&m_navigationFont, FALSE);
	m_sidebarStatus.SetBackdropColor(UiTheme::SidebarBackground());
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

	if (m_page1.m_cfgls.GetCount() == 0)
		m_currentPage = PAGE_PROXY;
	if (m_currentPage == PAGE_APPLICATIONS)
		m_page3.OnPageActivated();
	FinalizeLayout(FALSE);
	// Hide focus rectangles until the keyboard is used, like standard dialogs do.
	if (CWnd* top = GetTopLevelParent())
		top->PostMessage(WM_CHANGEUISTATE, MAKEWPARAM(UIS_SET, UISF_HIDEFOCUS | UISF_HIDEACCEL), 0);
	// Run once more after WM_INITDIALOG returns and the normal message loop is
	// active. This covers delayed theme/font realization on a busy machine.
	PostMessage(WM_MAIN_TAB_FINALIZE_LAYOUT);
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
	ON_MESSAGE(WM_MAIN_TAB_FINALIZE_LAYOUT, OnFinalizeLayout)
END_MESSAGE_MAP()

int CMainTab::NavigationWidth() const
{
	const int width = Localization::CurrentLanguage().CompareNoCase(_T("en-US")) == 0
		? 196 : 164;
	return UiTheme::ScaleForWindow(m_hWnd, width);
}

CRect CMainTab::NavigationItemRect(int index) const
{
	int margin = UiTheme::ScaleForWindow(m_hWnd, 10);
	int top = UiTheme::ScaleForWindow(m_hWnd, 72);
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
	CPaintDC paint(this);
	CRect client;
	GetClientRect(&client);
	if (client.IsRectEmpty()) return;

	CDC dc;
	CBitmap bitmap;
	dc.CreateCompatibleDC(&paint);
	bitmap.CreateCompatibleBitmap(&paint, client.Width(), client.Height());
	CBitmap* oldBitmap = dc.SelectObject(&bitmap);

	dc.FillSolidRect(client, UiTheme::WindowBackground());
	CRect sidebar = client;
	sidebar.right = NavigationWidth();
	dc.FillSolidRect(sidebar, UiTheme::SidebarBackground());
	dc.FillSolidRect(sidebar.right - 1, sidebar.top, 1, sidebar.Height(), UiTheme::Border());

	dc.SetBkMode(TRANSPARENT);
	dc.SetTextColor(UiTheme::TextPrimary());

	// Brand: program icon, name and subtitle.
	const int iconSize = UiTheme::ScaleForWindow(m_hWnd, 30);
	const int brandLeft = UiTheme::ScaleForWindow(m_hWnd, 16);
	const int brandTop = UiTheme::ScaleForWindow(m_hWnd, 16);
	if (m_brandIcon)
		::DrawIconEx(dc.m_hDC, brandLeft, brandTop, m_brandIcon, iconSize, iconSize, 0, NULL, DI_NORMAL);
	const int textLeft = brandLeft + iconSize + UiTheme::ScaleForWindow(m_hWnd, 10);
	CFont* oldFont = dc.SelectObject(&m_brandFont);
	CRect brand(textLeft, UiTheme::ScaleForWindow(m_hWnd, 10),
		NavigationWidth() - UiTheme::ScaleForWindow(m_hWnd, 10), UiTheme::ScaleForWindow(m_hWnd, 34));
	dc.DrawText(_T("ProxyLane"), brand, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

	dc.SelectObject(&m_navigationFont);
	dc.SetTextColor(UiTheme::TextSecondary());
	CRect subtitle = brand;
	subtitle.top = UiTheme::ScaleForWindow(m_hWnd, 32);
	subtitle.bottom = UiTheme::ScaleForWindow(m_hWnd, 52);
	CString subtitleText = Localization::Get(_T("nav.subtitle"));
	dc.DrawText(subtitleText, subtitle, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

	for (int i = 0; i < PAGE_COUNT; ++i)
	{
		CRect item = NavigationItemRect(i);
		BOOL selected = i == m_currentPage;
		BOOL hot = i == m_hoverPage;
		if (selected || hot)
		{
			UiTheme::FillRoundRect(dc.m_hDC, item, UiTheme::ScaleForWindow(m_hWnd, 9),
				selected ? UiTheme::AccentSoft() : RGB(240, 243, 248), CLR_NONE);
		}

		const COLORREF ink = selected ? UiTheme::Accent() : UiTheme::TextPrimary();
		const int glyph = UiTheme::ScaleForWindow(m_hWnd, 18);
		CRect glyphRect(item.left + UiTheme::ScaleForWindow(m_hWnd, 12), item.CenterPoint().y - glyph / 2,
			item.left + UiTheme::ScaleForWindow(m_hWnd, 12) + glyph, item.CenterPoint().y - glyph / 2 + glyph);
		UiTheme::DrawGlyph(dc.m_hDC, kNavigationGlyphs[i], glyphRect, selected ? ink : UiTheme::TextSecondary(),
			max(1.4f, UiTheme::ScaleForWindow(m_hWnd, 3) / 2.0f));

		CRect label = item;
		label.left = glyphRect.right + UiTheme::ScaleForWindow(m_hWnd, 10);
		label.right -= UiTheme::ScaleForWindow(m_hWnd, 22);
		dc.SetTextColor(ink);
		CString navigationText = Localization::Get(kNavigationKeys[i]);
		dc.DrawText(navigationText, label, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

		const bool monitoring = i == PAGE_MONITOR && m_page4.IsMonitoring();
		if (monitoring || (i == m_attentionPage && !selected))
		{
			const int dotSize = UiTheme::ScaleForWindow(m_hWnd, 7);
			CRect dot(
				item.right - UiTheme::ScaleForWindow(m_hWnd, 17),
				item.CenterPoint().y - dotSize / 2,
				item.right - UiTheme::ScaleForWindow(m_hWnd, 17) + dotSize,
				item.CenterPoint().y - dotSize / 2 + dotSize);
			const COLORREF dotColor = monitoring ? UiTheme::Success() : UiTheme::Accent();
			CBrush dotBrush(dotColor);
			CPen dotPen(PS_SOLID, 1, dotColor);
			CBrush* oldDotBrush = dc.SelectObject(&dotBrush);
			CPen* oldDotPen = dc.SelectObject(&dotPen);
			dc.Ellipse(dot);
			dc.SelectObject(oldDotPen);
			dc.SelectObject(oldDotBrush);
		}
	}

	dc.SelectObject(oldFont);
	paint.BitBlt(0, 0, client.Width(), client.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBitmap);
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
			m_proxyRunning ? 104 : 34);
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

	if (m_pages[m_currentPage] && m_pages[m_currentPage]->GetSafeHwnd())
	{
		CRect pageClient;
		m_pages[m_currentPage]->GetClientRect(&pageClient);
		m_pages[m_currentPage]->SendMessage(WM_SIZE, SIZE_RESTORED,
			MAKELPARAM(pageClient.Width(), pageClient.Height()));
	}
}

void CMainTab::FinalizeLayout(BOOL updateNow)
{
	if (!GetSafeHwnd())
		return;
	PositionWnd();
	if (m_pages[m_currentPage] && m_pages[m_currentPage]->GetSafeHwnd())
		m_pages[m_currentPage]->ShowWindow(SW_SHOW);

	UINT redrawFlags = RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN;
	if (updateNow)
		redrawFlags |= RDW_UPDATENOW;
	RedrawWindow(NULL, NULL, redrawFlags);
}

LRESULT CMainTab::OnFinalizeLayout(WPARAM, LPARAM)
{
	FinalizeLayout(TRUE);
	return 0;
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
		if (m_currentPage == PAGE_APPLICATIONS)
			m_page3.OnPageActivated();
		CRect pageClient;
		m_pages[m_currentPage]->GetClientRect(&pageClient);
		m_pages[m_currentPage]->PostMessage(WM_SIZE, SIZE_RESTORED,
			MAKELPARAM(pageClient.Width(), pageClient.Height()));
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

void CMainTab::HideTransientStatus()
{
	KillTimer(kTransientStatusTimer);
	if (m_transientStatus.GetSafeHwnd()) m_transientStatus.ShowWindow(SW_HIDE);
}

void CMainTab::SetRunningProfile(LPCTSTR profileName, BOOL running)
{
	CString name(profileName ? profileName : _T(""));
	name.Trim();
	CString recentId;
	if (running && !name.IsEmpty() && !RecentApplications::EnsureProfileId(name, recentId))
		AddLogText(0, L"Could not initialize recent applications for the running profile.\r\n");
	if (running && name.IsEmpty())
		name = Localization::Get(_T("nav.current_profile"));

	if (m_proxyRunning == running && m_runningProfileName == name && m_runningRecentProfileId == recentId)
		return;

	const BOOL wasRunning = m_proxyRunning;
	m_proxyRunning = running;
	m_runningProfileName = running ? name : _T("");
	m_runningRecentProfileId = recentId;
	if (m_page1.GetSafeHwnd()) m_page1.SendMessage(WM_RECENT_APPLICATIONS_CHANGED);
	if (m_sidebarStatus.GetSafeHwnd())
	{
		if (running)
			m_sidebarStatus.SetTwoLineStatus(Localization::Get(_T("status.proxy_running")), name,
				CStatusLabel::TONE_SUCCESS);
		else
			m_sidebarStatus.SetStatus(Localization::Get(_T("status.proxy_stopped")), CStatusLabel::TONE_NEUTRAL);

		if (running)
		{
			UpdateTrafficRates(!wasRunning);
			SetTimer(kTrafficRateTimer, 1000, NULL);
		}
		else
		{
			KillTimer(kTrafficRateTimer);
			m_trafficSampler.Reset(0, 0, 0);
		}

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
	if (eventId == kTrafficRateTimer)
	{
		UpdateTrafficRates(FALSE);
		return;
	}
	if (eventId == kTransientStatusTimer)
	{
		HideTransientStatus();
		return;
	}

	CWnd::OnTimer(eventId);
}

void CMainTab::UpdateTrafficRates(BOOL reset)
{
	if (!m_proxyRunning || !g_GlobalProxy || !m_sidebarStatus.GetSafeHwnd())
		return;
	IProxyReceptionCentre* centre = g_GlobalProxy->GetPRCInstance();
	if (!centre)
		return;
	ULONGLONG upload = 0, download = 0;
	centre->GetTrafficTotals(upload, download);
	const DWORD now = GetTickCount();
	double uploadRate = 0, downloadRate = 0;
	if (reset)
		m_trafficSampler.Reset(upload, download, now);
	else
		m_trafficSampler.Sample(upload, download, now, uploadRate, downloadRate);
	m_sidebarStatus.SetTrafficRates(
		CString(_T("\u2191 ")) + FormatTrafficRate(uploadRate),
		CString(_T("\u2193 ")) + FormatTrafficRate(downloadRate));
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
