#include "stdafx.h"
#include "ProxyLane.h"
#include "DashboardPage.h"
#include "MainTab.h"
#include "Localization.h"
#include "..\ProxyLaneHook\ProcessIdentity.h"
#include <algorithm>

namespace
{
	const UINT_PTR kRefreshTimer = 1;
	const UINT kPowerId = 0x2001;
	const UINT kTestId = 0x2002;
	const UINT kAllProcessesId = 0x2003;
	const UINT kPickAppId = 0x2004;
	const UINT kChildToggleId = 0x2005;
	const UINT kIpv6ToggleId = 0x2006;
	const UINT kFirstProfileId = 0x2100;
	const UINT kFirstTileId = 0x2200;
	const size_t kMaxProfiles = 6;
	const size_t kMaxTiles = 3;
	const size_t kMaxConnections = 64;

	COLORREF DecoColor() { return UiTheme::IsDark() ? RGB(44, 45, 50) : RGB(232, 234, 240); }

	CString FormatBytes(double value, LPCTSTR suffix)
	{
		LPCTSTR units[] = { _T("B"), _T("KB"), _T("MB"), _T("GB"), _T("TB") };
		int unit = 0;
		while (value >= 1024.0 && unit < 4) { value /= 1024.0; ++unit; }
		CString text;
		text.Format(unit == 0 ? _T("%.0f %s%s") : _T("%.1f %s%s"), value, units[unit], suffix);
		return text;
	}

	void SplitValue(const CString& text, CString& value, CString& unit)
	{
		const int space = text.Find(_T(' '));
		value = space >= 0 ? text.Left(space) : text;
		unit = space >= 0 ? text.Mid(space + 1) : CString();
	}

	CString FileNameOf(const CString& path)
	{
		const int slash = path.ReverseFind(_T('\\'));
		return slash >= 0 ? path.Mid(slash + 1) : path;
	}

	CString FormatTarget(const PRCClient& client)
	{
		const u_short port = ntohs(*reinterpret_cast<const u_short*>(client.dstAddr.sa_data));
		CString text;
		if (client.szDomainName[0])
		{
			text.Format(_T("%s:%u"), static_cast<LPCTSTR>(CString(client.szDomainName)), port);
			return text;
		}
		wchar_t buffer[80] = { 0 };
		DWORD length = _countof(buffer);
		sockaddr_storage copy = { 0 };
		memcpy(&copy, &client.dstAddr, min(sizeof(copy), sizeof(client.dstAddr)));
		const int size = client.dstAddr.sa_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
		if (WSAAddressToStringW(reinterpret_cast<LPSOCKADDR>(&copy), size, NULL, buffer, &length) == 0)
			return CString(buffer);
		return CString(_T("-"));
	}

	// Copies live tasks under the manager's lock; only plain data leaves the callback.
	class CTaskCollector : public IProxyTaskMgr
	{
	public:
		CTaskCollector(std::vector<CDashboardPage::Connection>& out, LPCTSTR protocol)
			: m_out(out), m_protocol(protocol) {}
		void OnAddTask(const LPPRCClient, const LPProxyInfo) override {}
		void OnDelTask(const LPPRCClient) override {}
		void EnumTask(IProxyTaskMgr*) override {}
		BOOL GetTaskCount(DWORD*) override { return FALSE; }
		void OnEachTask(const LPPRCClient client, const LPProxyInfo) override
		{
			if (m_out.size() >= kMaxConnections) return;
			CDashboardPage::Connection row;
			row.pid = client->dwPid;
			row.protocol = m_protocol;
			row.target = FormatTarget(*client);
			row.createTime = client->processCreateTime;
			// Names are resolved after the task lock is released.
			m_out.push_back(row);
		}
	private:
		std::vector<CDashboardPage::Connection>& m_out;
		LPCTSTR m_protocol;
	};
}

void CPowerButton::SetRunning(BOOL running)
{
	if (m_running == running) return;
	m_running = running;
	Invalidate(FALSE);
}

void CPowerButton::DrawItem(LPDRAWITEMSTRUCT info)
{
	CDC target;
	target.Attach(info->hDC);
	CRect rect;
	GetClientRect(&rect);
	CDC dc;
	CBitmap buffer;
	dc.CreateCompatibleDC(&target);
	buffer.CreateCompatibleBitmap(&target, max(1, rect.Width()), max(1, rect.Height()));
	CBitmap* oldBuffer = dc.SelectObject(&buffer);
	dc.FillSolidRect(rect, DecoColor());
	const BOOL hot = m_hot || (info->itemState & ODS_SELECTED);
	const COLORREF fill = m_running ? (hot ? UiTheme::Hover() : UiTheme::Inner()) : (hot ? UiTheme::AccentHover() : UiTheme::Accent());
	UiTheme::FillRoundRect(dc.m_hDC, rect, rect.Width(), fill, CLR_NONE);
	const COLORREF ink = m_running ? UiTheme::TextPrimary() : RGB(255, 255, 255);
	const int side = rect.Width() * 3 / 8;
	CRect glyph(rect.CenterPoint().x - side / 2, rect.CenterPoint().y - side / 2, rect.CenterPoint().x - side / 2 + side, rect.CenterPoint().y - side / 2 + side);
	if (m_running)
		UiTheme::FillRoundRect(dc.m_hDC, glyph, side / 5, ink, CLR_NONE);
	else
		UiTheme::DrawFilledGlyph(dc.m_hDC, UiTheme::GLYPH_PLAY, glyph, ink);
	if ((info->itemState & ODS_FOCUS) && !(info->itemState & ODS_NOFOCUSRECT))
	{
		CRect ring = rect;
		ring.DeflateRect(2, 2);
		UiTheme::FillRoundRect(dc.m_hDC, ring, ring.Width(), CLR_NONE, m_running ? UiTheme::AccentText() : RGB(255, 255, 255));
	}
	target.BitBlt(0, 0, rect.Width(), rect.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBuffer);
	target.Detach();
}

void CAppTileButton::SetContent(const CString& name, const CString& detail, HICON icon)
{
	if (m_icon) ::DestroyIcon(m_icon);
	m_icon = icon;
	m_name = name;
	m_detail = detail;
	SetWindowText(name);
	Invalidate(FALSE);
}

void CAppTileButton::DrawItem(LPDRAWITEMSTRUCT info)
{
	CDC target;
	target.Attach(info->hDC);
	CRect rect;
	GetClientRect(&rect);
	CDC dc;
	CBitmap buffer;
	dc.CreateCompatibleDC(&target);
	buffer.CreateCompatibleBitmap(&target, max(1, rect.Width()), max(1, rect.Height()));
	CBitmap* oldBuffer = dc.SelectObject(&buffer);
	dc.FillSolidRect(rect, UiTheme::Surface());
	const BOOL hot = m_hot || (info->itemState & ODS_SELECTED);
	UiTheme::FillRoundRect(dc.m_hDC, rect, UiTheme::ScaleForWindow(m_hWnd, 10), hot ? UiTheme::Hover() : UiTheme::Inner(), CLR_NONE);
	const int pad = UiTheme::ScaleForWindow(m_hWnd, 8);
	const int iconSize = UiTheme::ScaleForWindow(m_hWnd, 24);
	const int iconTop = rect.CenterPoint().y - iconSize / 2;
	if (m_icon)
		::DrawIconEx(dc.m_hDC, rect.left + pad, iconTop, m_icon, iconSize, iconSize, 0, NULL, DI_NORMAL);
	CRect text(rect.left + pad * 2 + iconSize, rect.top, rect.right - pad, rect.bottom);
	dc.SetBkMode(TRANSPARENT);
	CFont* font = GetFont();
	CFont* oldFont = font ? dc.SelectObject(font) : NULL;
	CRect top = text, bottom = text;
	top.bottom = rect.CenterPoint().y + UiTheme::ScaleForWindow(m_hWnd, 1);
	bottom.top = top.bottom - UiTheme::ScaleForWindow(m_hWnd, 2);
	dc.SetTextColor(UiTheme::TextPrimary());
	dc.DrawText(m_name, top, DT_LEFT | DT_BOTTOM | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
	dc.SetTextColor(UiTheme::TextSecondary());
	dc.DrawText(m_detail, bottom, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
	if (oldFont) dc.SelectObject(oldFont);
	if ((info->itemState & ODS_FOCUS) && !(info->itemState & ODS_NOFOCUSRECT))
	{
		CRect ring = rect;
		ring.DeflateRect(1, 1);
		UiTheme::FillRoundRect(dc.m_hDC, ring, UiTheme::ScaleForWindow(m_hWnd, 9), CLR_NONE, UiTheme::AccentText());
	}
	target.BitBlt(0, 0, rect.Width(), rect.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBuffer);
	target.Detach();
}

IMPLEMENT_DYNAMIC(CDashboardPage, CModernDialog)

BEGIN_MESSAGE_MAP(CDashboardPage, CModernDialog)
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_SIZE()
	ON_WM_TIMER()
	ON_WM_SHOWWINDOW()
END_MESSAGE_MAP()

CDashboardPage::CDashboardPage(CWnd* parent)
	: CModernDialog(CDashboardPage::IDD, parent)
	, m_tcpCount(0), m_udpCount(0), m_hookedCount(0), m_runningSince(0), m_wasRunning(FALSE)
{
	ResetTraffic();
}

CDashboardPage::~CDashboardPage()
{
	for (size_t i = 0; i < m_profileButtons.size(); ++i) delete m_profileButtons[i];
	for (size_t i = 0; i < m_tileButtons.size(); ++i) delete m_tileButtons[i];
}

void CDashboardPage::ResetTraffic()
{
	ZeroMemory(&m_traffic, sizeof(m_traffic));
}

void CDashboardPage::SetTraffic(const DashboardTraffic& traffic)
{
	m_traffic = traffic;
}

COLORREF CDashboardPage::BackdropForChild(CWnd*)
{
	return UiTheme::Surface();
}

BOOL CDashboardPage::OnInitDialog()
{
	CModernDialog::OnInitDialog();
	ModifyStyle(0, WS_CLIPCHILDREN);

	UiTheme::CreateUiFont(m_bodyFont, m_hWnd, 10, FW_NORMAL);
	UiTheme::CreateUiFont(m_smallFont, m_hWnd, 8, FW_NORMAL);
	UiTheme::CreateUiFont(m_boldFont, m_hWnd, 10, FW_BOLD);
	UiTheme::CreateUiFont(m_headlineFont, m_hWnd, 14, FW_BOLD);
	UiTheme::CreateUiFont(m_kpiFont, m_hWnd, 23, FW_BOLD);
	UiTheme::CreateUiFont(m_kpiSmallFont, m_hWnd, 10, FW_NORMAL);

	const DWORD buttonStyle = WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW;
	m_power.Create(_T(""), buttonStyle, CRect(), this, kPowerId);
	m_testButton.Create(Localization::Get(_T("dashboard.test")), buttonStyle, CRect(), this, kTestId);
	m_testButton.SetVisualStyle(CModernButton::STYLE_PRIMARY);
	m_allProcesses.Create(Localization::Get(_T("dashboard.view")), buttonStyle, CRect(), this, kAllProcessesId);
	m_allProcesses.SetVisualStyle(CModernButton::STYLE_GHOST);
	m_pickApp.Create(Localization::Get(_T("dashboard.pick_app")), buttonStyle, CRect(), this, kPickAppId);
	m_childToggle.Create(_T(""), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, CRect(), this, kChildToggleId);
	m_ipv6Toggle.Create(_T(""), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, CRect(), this, kIpv6ToggleId);
	m_testButton.SetFont(&m_uiFont);
	m_allProcesses.SetFont(&m_uiFont);
	m_pickApp.SetFont(&m_uiFont);

	Refresh();
	Layout();
	return TRUE;
}

BOOL CDashboardPage::OnCommand(WPARAM wParam, LPARAM lParam)
{
	if (HIWORD(wParam) != BN_CLICKED || !g_MainTab)
		return CModernDialog::OnCommand(wParam, lParam);
	const UINT id = LOWORD(wParam);
	CPage1* settings = g_MainTab->GetPage1();
	if (id == kPowerId)
	{
		if (g_MainTab->IsProxyRunning()) settings->OnBnClickedCancel();
		else settings->OnBnClickedOk();
	}
	else if (id == kTestId)
	{
		settings->OnBnClickedTestproxy();
	}
	else if (id == kAllProcessesId)
	{
		g_MainTab->SelectPage(CMainTab::PAGE_APPLICATIONS);
	}
	else if (id == kPickAppId)
	{
		g_MainTab->GetPage3()->PickApplicationFromDashboard();
	}
	else if (id == kChildToggleId || id == kIpv6ToggleId)
	{
		// The toggle has already been flipped by its own click handler.
		const CToggleButton& toggle = id == kChildToggleId ? m_childToggle : m_ipv6Toggle;
		settings->QuickSetOption(id == kChildToggleId ? IDC_CHECK_HOOKCHILDPROCESS : IDC_CHECK_BLOCK_IPV6,
			const_cast<CToggleButton&>(toggle).GetCheck() == BST_CHECKED);
	}
	else if (id >= kFirstProfileId && id < kFirstProfileId + kMaxProfiles)
	{
		const size_t index = id - kFirstProfileId;
		if (index < m_profileNames.size())
			settings->SwitchProfile(m_profileNames[index]);
	}
	else if (id >= kFirstTileId && id < kFirstTileId + kMaxTiles)
	{
		g_MainTab->GetPage3()->PostMessage(WM_LAUNCH_PANEL_TILE, id - kFirstTileId);
	}
	else
	{
		return CModernDialog::OnCommand(wParam, lParam);
	}
	Refresh();
	return TRUE;
}

void CDashboardPage::RebuildProfiles()
{
	if (!g_MainTab || !g_MainTab->GetPage1()->GetSafeHwnd()) return;
	std::vector<CString> names;
	g_MainTab->GetPage1()->GetSavedProfileNames(names);
	if (names.size() > kMaxProfiles) names.resize(kMaxProfiles);
	const CString selected = g_MainTab->IsProxyRunning() ? g_MainTab->GetRunningProfileName() : g_MainTab->GetPage1()->GetSelectedProfileName();
	const BOOL changed = names != m_profileNames;
	if (changed)
	{
		m_profileNames = names;
		while (m_profileButtons.size() > names.size())
		{
			delete m_profileButtons.back();
			m_profileButtons.pop_back();
		}
		for (size_t i = 0; i < names.size(); ++i)
		{
			if (i == m_profileButtons.size())
			{
				CModernButton* button = new CModernButton;
				button->Create(names[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, CRect(), this, kFirstProfileId + static_cast<UINT>(i));
				button->SetFont(&m_uiFont);
				m_profileButtons.push_back(button);
			}
			else
			{
				m_profileButtons[i]->SetWindowText(names[i]);
			}
		}
		Layout();
	}
	for (size_t i = 0; i < m_profileButtons.size(); ++i)
		m_profileButtons[i]->SetVisualStyle(names[i].CompareNoCase(selected) == 0 ? CModernButton::STYLE_PILL_ACTIVE : CModernButton::STYLE_PILL);
}

void CDashboardPage::RebuildRecent()
{
	if (!g_MainTab || !g_MainTab->GetPage3()->GetSafeHwnd()) return;
	const std::vector<RecentApplications::Entry>& entries = g_MainTab->GetPage3()->RecentEntries();
	const size_t count = min(entries.size(), kMaxTiles);
	CString key;
	for (size_t i = 0; i < count; ++i) key += entries[i].id + _T("|");
	if (key == m_recentKey) return;
	m_recentKey = key;
	while (m_tileButtons.size() > count)
	{
		delete m_tileButtons.back();
		m_tileButtons.pop_back();
	}
	for (size_t i = 0; i < count; ++i)
	{
		if (i == m_tileButtons.size())
		{
			CAppTileButton* tile = new CAppTileButton;
			tile->Create(_T(""), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, CRect(), this, kFirstTileId + static_cast<UINT>(i));
			tile->SetFont(&m_uiFont);
			m_tileButtons.push_back(tile);
		}
		m_tileButtons[i]->SetContent(entries[i].app.name, RecentApplications::Description(entries[i]), RecentApplications::LoadIcon(entries[i]));
	}
	Layout();
}

void CDashboardPage::CollectConnections()
{
	m_connections.clear();
	m_tcpCount = m_udpCount = m_hookedCount = 0;
	if (!g_GlobalProxy || !g_MainTab || !g_MainTab->IsProxyRunning()) return;
	IProxyReceptionCentre* centre = g_GlobalProxy->GetPRCInstance();
	if (!centre) return;
	IProxyProcessRegistry* registry = g_GlobalProxy->GetProcessRegistry();
	if (registry) m_hookedCount = registry->SnapshotHooked(NULL, 0);
	if (IProxyTaskMgr* tcp = centre->GetPTMInstance(0))
	{
		tcp->GetTaskCount(&m_tcpCount);
		CTaskCollector collector(m_connections, _T("TCP"));
		tcp->EnumTask(&collector);
	}
	if (IProxyTaskMgr* udp = centre->GetPTMInstance(1))
	{
		udp->GetTaskCount(&m_udpCount);
		CTaskCollector collector(m_connections, _T("UDP"));
		udp->EnumTask(&collector);
	}
	for (size_t i = 0; i < m_connections.size(); ++i)
	{
		Connection& row = m_connections[i];
		HookProcessIdentityInfo identity;
		ZeroMemory(&identity, sizeof(identity));
		if (registry && registry->Get(row.pid, row.createTime, &identity))
			row.process = FileNameOf(identity.szAppPath);
		if (row.process.IsEmpty())
			row.process.Format(_T("PID %u"), row.pid);
	}
}

void CDashboardPage::Refresh()
{
	if (!GetSafeHwnd() || !g_MainTab) return;
	const BOOL running = g_MainTab->IsProxyRunning();
	if (running && !m_wasRunning) m_runningSince = GetTickCount();
	if (!running) ResetTraffic();
	m_wasRunning = running;
	m_testButton.SetBackdropColor(UiTheme::Inner());
	m_power.SetRunning(running);
	m_power.SetWindowText(Localization::Get(running ? _T("dashboard.stop") : _T("dashboard.start")));
	RebuildProfiles();
	RebuildRecent();
	CollectConnections();
	CPage1* settings = g_MainTab->GetPage1();
	if (settings->GetSafeHwnd())
	{
		m_childToggle.SetCheck(settings->IsDlgButtonChecked(IDC_CHECK_HOOKCHILDPROCESS));
		m_ipv6Toggle.SetCheck(settings->IsDlgButtonChecked(IDC_CHECK_BLOCK_IPV6));
	}
	Invalidate(FALSE);
}

void CDashboardPage::OnShowWindow(BOOL show, UINT status)
{
	CModernDialog::OnShowWindow(show, status);
	if (show)
	{
		Refresh();
		SetTimer(kRefreshTimer, 1000, NULL);
	}
	else
	{
		KillTimer(kRefreshTimer);
	}
}

void CDashboardPage::OnTimer(UINT_PTR timer)
{
	if (timer == kRefreshTimer) Refresh();
	else CModernDialog::OnTimer(timer);
}

void CDashboardPage::OnSize(UINT type, int cx, int cy)
{
	CModernDialog::OnSize(type, cx, cy);
	Layout();
}

void CDashboardPage::Layout()
{
	if (!m_power.GetSafeHwnd()) return;
	CRect client;
	GetClientRect(&client);
	if (client.Width() <= 0 || client.Height() <= 0) return;

	const int gap = Scale(10);
	const int left = client.left + Scale(8);
	const int right = client.right - Scale(8);
	int y = Scale(50);
	const int width = right - left;
	const int kpiWidth = (width - gap * 2) / 4;

	// Row 1: status and rates.
	const int row1 = Scale(164);
	m_downloadCard = CRect(right - kpiWidth, y, right, y + row1);
	m_uploadCard = CRect(m_downloadCard.left - gap - kpiWidth, y, m_downloadCard.left - gap, y + row1);
	m_statusCard = CRect(left, y, m_uploadCard.left - gap, y + row1);
	const int powerSize = Scale(76);
	m_power.MoveWindow(m_statusCard.right - powerSize - Scale(30), m_statusCard.CenterPoint().y - powerSize / 2, powerSize, powerSize);
	y += row1 + gap;

	// Row 2: profile switcher and quick switches.
	const int row2 = Scale(46);
	m_ipv6Card = CRect(right - kpiWidth, y, right, y + row2);
	m_childCard = CRect(m_ipv6Card.left - gap - kpiWidth, y, m_ipv6Card.left - gap, y + row2);
	m_profileCard = CRect(left, y, m_childCard.left - gap, y + row2);
	const int toggleWidth = Scale(32), toggleHeight = Scale(22);
	m_childToggle.MoveWindow(m_childCard.right - toggleWidth - Scale(14), m_childCard.CenterPoint().y - toggleHeight / 2, toggleWidth, toggleHeight);
	m_ipv6Toggle.MoveWindow(m_ipv6Card.right - toggleWidth - Scale(14), m_ipv6Card.CenterPoint().y - toggleHeight / 2, toggleWidth, toggleHeight);
	if (!m_profileButtons.empty())
	{
		const int labelWidth = Scale(84);
		const int area = m_profileCard.Width() - labelWidth - Scale(8);
		const int count = static_cast<int>(m_profileButtons.size());
		const int pillGap = Scale(4);
		const int pillWidth = (area - pillGap * (count - 1)) / count;
		for (int i = 0; i < count; ++i)
			m_profileButtons[i]->MoveWindow(m_profileCard.left + labelWidth + i * (pillWidth + pillGap), m_profileCard.top + Scale(7), pillWidth, row2 - Scale(14));
	}
	y += row2 + gap;

	// Row 3: upstream and hooked processes.
	const int row3 = Scale(118);
	const int half = (width - gap) / 2;
	m_upstreamCard = CRect(left, y, left + half, y + row3);
	m_hookedCard = CRect(m_upstreamCard.right + gap, y, right, y + row3);
	const int testWidth = Scale(62), testHeight = Scale(26);
	m_testButton.MoveWindow(m_upstreamCard.right - testWidth - Scale(22), m_upstreamCard.bottom - testHeight - Scale(13), testWidth, testHeight);
	m_allProcesses.MoveWindow(m_hookedCard.right - Scale(70) - Scale(10), m_hookedCard.top + Scale(8), Scale(70), Scale(26));
	y += row3 + gap;

	// Row 4: connections fill what is left.
	const int recentWidth = max(Scale(240), width / 3);
	const int bottom = max(y + Scale(120), client.bottom - Scale(2));
	m_recentCard = CRect(right - recentWidth, y, right, bottom);
	m_connectionsCard = CRect(left, y, m_recentCard.left - gap, bottom);

	const int tileHeight = Scale(44);
	int tileY = m_recentCard.top + Scale(38);
	const int pickHeight = Scale(30);
	const int tileBottom = m_recentCard.bottom - pickHeight - Scale(18);
	for (size_t i = 0; i < m_tileButtons.size(); ++i)
	{
		const BOOL fits = tileY + tileHeight <= tileBottom;
		m_tileButtons[i]->ShowWindow(fits ? SW_SHOW : SW_HIDE);
		m_tileButtons[i]->MoveWindow(m_recentCard.left + Scale(12), tileY, m_recentCard.Width() - Scale(24), tileHeight);
		tileY += tileHeight + Scale(6);
	}
	m_pickApp.MoveWindow(m_recentCard.left + Scale(12), m_recentCard.bottom - pickHeight - Scale(12), m_recentCard.Width() - Scale(24), pickHeight);
	Invalidate(FALSE);
}

void CDashboardPage::DrawLabel(CDC& dc, CFont& font, const CString& text, const CRect& rect, COLORREF color, UINT format)
{
	CFont* old = dc.SelectObject(&font);
	dc.SetTextColor(color);
	CRect box = rect;
	dc.DrawText(text, box, format | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
	dc.SelectObject(old);
}

void CDashboardPage::DrawHeading(CDC& dc, UiTheme::Glyph glyph, const CString& text, const CRect& card, COLORREF glyphColor)
{
	const int icon = Scale(16);
	const int x = card.left + Scale(16), y = card.top + Scale(14);
	UiTheme::DrawGlyph(dc.m_hDC, glyph, CRect(x, y, x + icon, y + icon), glyphColor, max(1.4f, Scale(3) / 2.0f));
	DrawLabel(dc, m_boldFont, text, CRect(x + icon + Scale(7), y - Scale(3), card.right - Scale(12), y + icon + Scale(3)), UiTheme::TextPrimary());
}

BOOL CDashboardPage::OnEraseBkgnd(CDC*)
{
	return TRUE;
}

void CDashboardPage::OnPaint()
{
	CPaintDC paint(this);
	CRect client;
	GetClientRect(&client);
	if (client.IsRectEmpty() || !g_MainTab) return;

	CDC dc;
	CBitmap buffer;
	dc.CreateCompatibleDC(&paint);
	buffer.CreateCompatibleBitmap(&paint, client.Width(), client.Height());
	CBitmap* oldBuffer = dc.SelectObject(&buffer);
	dc.FillSolidRect(client, UiTheme::PageBackground());
	dc.SetBkMode(TRANSPARENT);

	const BOOL running = g_MainTab->IsProxyRunning();
	const COLORREF primary = UiTheme::TextPrimary(), muted = UiTheme::TextSecondary();
	CPage1* settings = g_MainTab->GetPage1();

	// Title and overall state.
	CFont* oldFont = dc.SelectObject(&m_titleFont);
	dc.SetTextColor(primary);
	CRect title(client.left + Scale(8), 0, client.right - Scale(60), Scale(44));
	const CString titleText = Localization::Get(_T("nav.dashboard"));
	dc.DrawText(titleText, title, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
	dc.SelectObject(oldFont);
	const int dot = Scale(34);
	CRect dotRect(client.right - Scale(8) - dot, Scale(5), client.right - Scale(8), Scale(5) + dot);
	UiTheme::FillRoundRect(dc.m_hDC, dotRect, dot, running ? (UiTheme::IsDark() ? RGB(22, 115, 63) : RGB(18, 138, 82)) : UiTheme::Inner(), CLR_NONE);
	CRect dotGlyph = dotRect;
	dotGlyph.DeflateRect(Scale(9), Scale(9));
	UiTheme::DrawGlyph(dc.m_hDC, running ? UiTheme::GLYPH_CHECK : UiTheme::GLYPH_MINUS, dotGlyph, running ? RGB(255, 255, 255) : muted, max(1.6f, Scale(4) / 2.0f));

	const int radius = Scale(16);
	const CRect* cards[] = { &m_statusCard, &m_uploadCard, &m_downloadCard, &m_upstreamCard, &m_hookedCard, &m_connectionsCard, &m_recentCard };
	for (size_t i = 0; i < _countof(cards); ++i)
		UiTheme::FillRoundRect(dc.m_hDC, *cards[i], radius, UiTheme::Surface(), CLR_NONE);
	const CRect* pills[] = { &m_profileCard, &m_childCard, &m_ipv6Card };
	for (size_t i = 0; i < _countof(pills); ++i)
		UiTheme::FillRoundRect(dc.m_hDC, *pills[i], pills[i]->Height(), UiTheme::Surface(), CLR_NONE);

	// Status card with its decoration behind the power button.
	{
		CRgn clip;
		clip.CreateRoundRectRgn(m_statusCard.left, m_statusCard.top, m_statusCard.right + 1, m_statusCard.bottom + 1, radius * 2, radius * 2);
		dc.SelectClipRgn(&clip);
		const CPoint c = CPoint(m_statusCard.right - Scale(68), m_statusCard.CenterPoint().y);
		struct Blob { int x, y, r; } blobs[] = { { 0, 0, 86 }, { -74, -58, 26 }, { -92, -6, 24 }, { -68, 56, 26 }, { -20, 80, 24 }, { 48, 72, 28 }, { 50, -74, 28 }, { -22, -82, 24 }, { 14, -84, 28 }, { 14, 84, 28 } };
		for (size_t i = 0; i < _countof(blobs); ++i)
		{
			const int r = Scale(blobs[i].r);
			CRect circle(c.x + Scale(blobs[i].x) - r, c.y + Scale(blobs[i].y) - r, c.x + Scale(blobs[i].x) + r, c.y + Scale(blobs[i].y) + r);
			UiTheme::FillRoundRect(dc.m_hDC, circle, r, DecoColor(), CLR_NONE);
		}
		dc.SelectClipRgn(NULL);
	}
	DrawHeading(dc, UiTheme::GLYPH_MONITOR, Localization::Get(_T("dashboard.status")), m_statusCard, muted);
	{
		const CString stateText = Localization::Get(running ? _T("status.proxy_running") : _T("status.proxy_stopped"));
		const int headingWidth = Scale(62);
		CFont* old = dc.SelectObject(&m_smallFont);
		const int badgeWidth = dc.GetTextExtent(stateText).cx + Scale(16);
		dc.SelectObject(old);
		CRect badge(m_statusCard.left + Scale(16) + headingWidth, m_statusCard.top + Scale(12), m_statusCard.left + Scale(16) + headingWidth + badgeWidth, m_statusCard.top + Scale(32));
		UiTheme::FillRoundRect(dc.m_hDC, badge, badge.Height(), running ? UiTheme::SuccessSoft() : UiTheme::Inner(), CLR_NONE);
		DrawLabel(dc, m_smallFont, stateText, badge, running ? UiTheme::Success() : muted, DT_CENTER | DT_VCENTER);
	}
	const int textRight = m_power.GetSafeHwnd() ? m_statusCard.right - Scale(130) : m_statusCard.right;
	CString profile = running ? g_MainTab->GetRunningProfileName() : (settings->GetSafeHwnd() ? settings->GetSelectedProfileName() : CString());
	if (profile.IsEmpty()) profile = Localization::Get(_T("launch.profile_none"));
	DrawLabel(dc, m_headlineFont, profile, CRect(m_statusCard.left + Scale(16), m_statusCard.top + Scale(42), textRight, m_statusCard.top + Scale(72)), primary);
	CString summary = settings->GetSafeHwnd() ? settings->GetSelectedProfileSummary() : CString();
	{
		// The name is already the headline above.
		const int dot = summary.Find(_T(" \x00B7 "));
		if (dot >= 0 && summary.Left(dot).CompareNoCase(profile) == 0)
			summary = summary.Mid(dot + 3);
	}
	DrawLabel(dc, m_bodyFont, summary, CRect(m_statusCard.left + Scale(16), m_statusCard.top + Scale(72), textRight, m_statusCard.top + Scale(94)), muted);
	CString uptime = _T("-");
	if (running)
	{
		const DWORD seconds = (GetTickCount() - m_runningSince) / 1000;
		uptime.Format(_T("%02u:%02u:%02u"), seconds / 3600, seconds / 60 % 60, seconds % 60);
	}
	DrawLabel(dc, m_smallFont, Localization::Get(_T("dashboard.uptime")), CRect(m_statusCard.left + Scale(16), m_statusCard.top + Scale(108), textRight, m_statusCard.top + Scale(126)), muted);
	DrawLabel(dc, m_boldFont, uptime, CRect(m_statusCard.left + Scale(16), m_statusCard.top + Scale(126), textRight, m_statusCard.top + Scale(150)), primary);

	// Rates.
	struct Rate { const CRect* card; UiTheme::Glyph glyph; LPCTSTR key; double rate, peak; ULONGLONG total; COLORREF ink; };
	const Rate rates[] = {
		{ &m_uploadCard, UiTheme::GLYPH_ARROW_UP, _T("dashboard.upload"), m_traffic.uploadRate, m_traffic.uploadPeak, m_traffic.uploadTotal, muted },
		{ &m_downloadCard, UiTheme::GLYPH_ARROW_DOWN, _T("dashboard.download"), m_traffic.downloadRate, m_traffic.downloadPeak, m_traffic.downloadTotal, UiTheme::AccentText() },
	};
	for (size_t i = 0; i < _countof(rates); ++i)
	{
		const CRect& card = *rates[i].card;
		DrawHeading(dc, rates[i].glyph, Localization::Get(rates[i].key), card, rates[i].ink);
		CString value, unit;
		SplitValue(FormatBytes(rates[i].rate, _T("/s")), value, unit);
		CRect big(card.left + Scale(16), card.top + Scale(54), card.right - Scale(8), card.top + Scale(100));
		CFont* old = dc.SelectObject(&m_kpiFont);
		const int valueWidth = dc.GetTextExtent(value).cx;
		dc.SelectObject(old);
		DrawLabel(dc, m_kpiFont, value, big, primary);
		CRect unitRect = big;
		unitRect.left += valueWidth + Scale(4);
		unitRect.top += Scale(10);
		DrawLabel(dc, m_kpiSmallFont, unit, unitRect, muted);
		DrawLabel(dc, m_smallFont, Localization::Format(_T("dashboard.peak"), static_cast<LPCTSTR>(FormatBytes(rates[i].peak, _T("/s")))),
			CRect(card.left + Scale(16), card.top + Scale(106), card.right - Scale(8), card.top + Scale(124)), muted);
		DrawLabel(dc, m_smallFont, Localization::Format(_T("dashboard.total"), static_cast<LPCTSTR>(FormatBytes(static_cast<double>(rates[i].total), _T("")))),
			CRect(card.left + Scale(16), card.top + Scale(124), card.right - Scale(8), card.top + Scale(142)), muted);
	}

	// Profile strip and switches.
	DrawLabel(dc, m_boldFont, Localization::Get(_T("nav.current_profile")), CRect(m_profileCard.left + Scale(16), m_profileCard.top, m_profileCard.left + Scale(84), m_profileCard.bottom), primary);
	DrawLabel(dc, m_boldFont, Localization::Get(_T("dashboard.child")), CRect(m_childCard.left + Scale(16), m_childCard.top + Scale(5), m_childCard.right - Scale(50), m_childCard.top + Scale(25)), primary);
	DrawLabel(dc, m_smallFont, Localization::Get(m_childToggle.GetCheck() == BST_CHECKED ? _T("dashboard.on") : _T("dashboard.off")), CRect(m_childCard.left + Scale(16), m_childCard.top + Scale(24), m_childCard.right - Scale(50), m_childCard.bottom - Scale(4)), muted);
	DrawLabel(dc, m_boldFont, Localization::Get(_T("dashboard.ipv6")), CRect(m_ipv6Card.left + Scale(16), m_ipv6Card.top + Scale(5), m_ipv6Card.right - Scale(50), m_ipv6Card.top + Scale(25)), primary);
	DrawLabel(dc, m_smallFont, Localization::Get(m_ipv6Toggle.GetCheck() == BST_CHECKED ? _T("dashboard.on") : _T("dashboard.off")), CRect(m_ipv6Card.left + Scale(16), m_ipv6Card.top + Scale(24), m_ipv6Card.right - Scale(50), m_ipv6Card.bottom - Scale(4)), muted);

	// Upstream.
	DrawHeading(dc, UiTheme::GLYPH_GLOBE, Localization::Get(_T("dashboard.upstream")), m_upstreamCard, muted);
	const CString upstream = settings->GetSafeHwnd() ? settings->GetUpstreamText() : CString();
	DrawLabel(dc, m_headlineFont, upstream, CRect(m_upstreamCard.left + Scale(16), m_upstreamCard.top + Scale(36), m_upstreamCard.right - Scale(12), m_upstreamCard.top + Scale(62)), primary);
	CRect inner(m_upstreamCard.left + Scale(12), m_upstreamCard.bottom - Scale(44), m_upstreamCard.right - Scale(12), m_upstreamCard.bottom - Scale(8));
	UiTheme::FillRoundRect(dc.m_hDC, inner, Scale(10), UiTheme::Inner(), CLR_NONE);
	const CString testText = settings->GetSafeHwnd() ? settings->GetTestSummary() : CString();
	DrawLabel(dc, m_bodyFont, testText, CRect(inner.left + Scale(10), inner.top, inner.right - Scale(76), inner.bottom), muted);

	// Hooked processes.
	DrawHeading(dc, UiTheme::GLYPH_TABLE, Localization::Get(_T("dashboard.hooked")), m_hookedCard, muted);
	CString hookedValue;
	hookedValue.Format(_T("%u"), m_hookedCount);
	CRect bigHooked(m_hookedCard.left + Scale(16), m_hookedCard.top + Scale(36), m_hookedCard.right - Scale(8), m_hookedCard.top + Scale(72));
	DrawLabel(dc, m_headlineFont, hookedValue, bigHooked, primary);
	CString connText = Localization::Format(_T("page4.connections"), m_tcpCount, m_udpCount);
	CRect hookedInner(m_hookedCard.left + Scale(12), m_hookedCard.bottom - Scale(44), m_hookedCard.right - Scale(12), m_hookedCard.bottom - Scale(8));
	UiTheme::FillRoundRect(dc.m_hDC, hookedInner, Scale(10), UiTheme::Inner(), CLR_NONE);
	DrawLabel(dc, m_bodyFont, connText, CRect(hookedInner.left + Scale(10), hookedInner.top, hookedInner.right - Scale(10), hookedInner.bottom), muted);

	// Live connections.
	CString connHeading = Localization::Get(_T("dashboard.connections"));
	DrawHeading(dc, UiTheme::GLYPH_MONITOR, connHeading, m_connectionsCard, muted);
	CRect head(m_connectionsCard.left + Scale(10), m_connectionsCard.top + Scale(38), m_connectionsCard.right - Scale(10), m_connectionsCard.top + Scale(66));
	UiTheme::FillRoundRect(dc.m_hDC, head, Scale(8), UiTheme::Inner(), CLR_NONE);
	const int tableWidth = head.Width() - Scale(20);
	const int col2 = head.left + Scale(10) + tableWidth * 28 / 100;
	const int col3 = head.left + Scale(10) + tableWidth * 82 / 100;
	DrawLabel(dc, m_smallFont, Localization::Get(_T("dashboard.col_process")), CRect(head.left + Scale(10), head.top, col2, head.bottom), muted);
	DrawLabel(dc, m_smallFont, Localization::Get(_T("dashboard.col_target")), CRect(col2, head.top, col3, head.bottom), muted);
	DrawLabel(dc, m_smallFont, Localization::Get(_T("dashboard.col_protocol")), CRect(col3, head.top, head.right - Scale(8), head.bottom), muted);
	if (m_connections.empty())
	{
		DrawLabel(dc, m_bodyFont, Localization::Get(_T("dashboard.no_connections")),
			CRect(m_connectionsCard.left, head.bottom, m_connectionsCard.right, m_connectionsCard.bottom), muted, DT_CENTER | DT_VCENTER);
	}
	else
	{
		const int rowHeight = Scale(28);
		int rowTop = head.bottom + Scale(2);
		for (size_t i = 0; i < m_connections.size() && rowTop + rowHeight <= m_connectionsCard.bottom - Scale(6); ++i, rowTop += rowHeight)
		{
			const Connection& row = m_connections[i];
			DrawLabel(dc, m_bodyFont, row.process, CRect(head.left + Scale(10), rowTop, col2 - Scale(6), rowTop + rowHeight), primary);
			DrawLabel(dc, m_bodyFont, row.target, CRect(col2, rowTop, col3 - Scale(6), rowTop + rowHeight), primary);
			DrawLabel(dc, m_bodyFont, row.protocol, CRect(col3, rowTop, head.right - Scale(8), rowTop + rowHeight), muted);
		}
	}

	// Recent applications.
	DrawHeading(dc, UiTheme::GLYPH_APPS, Localization::Get(_T("dashboard.recent")), m_recentCard, muted);
	if (m_tileButtons.empty())
		DrawLabel(dc, m_bodyFont, Localization::Get(_T("dashboard.no_recent")),
			CRect(m_recentCard.left, m_recentCard.top + Scale(38), m_recentCard.right, m_recentCard.bottom - Scale(44)), muted, DT_CENTER | DT_VCENTER);

	paint.BitBlt(0, 0, client.Width(), client.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBuffer);
}
