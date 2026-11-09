#include "stdafx.h"
#include "ProxyLane.h"
#include "ApplicationPicker.h"
#include "Localization.h"
#include "ApplicationCatalogCache.h"
#include "MainTab.h"
#include "LaunchShortcut.h"
#include <algorithm>

static CString ApplicationSourceName(InstalledApplications::SourceKind kind)
{
	const LPCTSTR keys[] = { _T("apps.source_system"), _T("apps.source_user_menu"),
		_T("apps.source_common_menu"), _T("apps.source_shortcut"), _T("apps.source_shell") };
	return Localization::Get(kind >= 0 && static_cast<size_t>(kind) < _countof(keys) ?
		keys[kind] : _T("apps.source_unknown"));
}

CApplicationPicker::CApplicationPicker(CWnd* parent)
	: CModernDialog(IDD_APPLICATION_PICKER, parent), m_hoverRow(-1), m_load(NULL), m_loading(TRUE),
	  m_loadFailed(FALSE), m_recentReadFailed(FALSE), m_rebuilding(FALSE), m_recentLoad(NULL), m_recentConsumed(FALSE) {}

CApplicationPicker::~CApplicationPicker()
{
	InstalledApplications::ReleaseIcons(m_applications);
	InstalledApplications::ReleaseIcons(m_catalog);
	RecentApplications::ReleaseIcons(m_recentEntries);
}

void CApplicationPicker::DoDataExchange(CDataExchange* exchange)
{
	CModernDialog::DoDataExchange(exchange);
	DDX_Control(exchange, IDC_APP_SEARCH, m_search);
	DDX_Control(exchange, IDC_APP_LIST, m_list);
	DDX_Control(exchange, IDC_APP_EMPTY_STATE, m_emptyState);
	DDX_Control(exchange, IDOK, m_launch);
	DDX_Control(exchange, IDCANCEL, m_cancel);
	DDX_Control(exchange, IDC_APP_REFRESH, m_refresh);
	DDX_Control(exchange, IDC_APP_REMOVE_RECENT, m_recentActions);
}

BEGIN_MESSAGE_MAP(CApplicationPicker, CModernDialog)
	ON_EN_CHANGE(IDC_APP_SEARCH, &CApplicationPicker::OnSearchChanged)
	ON_BN_CLICKED(IDC_APP_REFRESH, &CApplicationPicker::OnRefresh)
	ON_BN_CLICKED(IDC_APP_REMOVE_RECENT, &CApplicationPicker::OnRecentActions)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_APP_LIST, &CApplicationPicker::OnSelectionChanged)
	ON_NOTIFY(NM_DBLCLK, IDC_APP_LIST, &CApplicationPicker::OnDoubleClick)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_APP_LIST, &CApplicationPicker::OnListCustomDraw)
	ON_MESSAGE(ProcessListAccessibility::ChangedMessage, &CApplicationPicker::OnAccessibilityChanged)
	ON_MESSAGE(ProcessListAccessibility::RequestMessage, &CApplicationPicker::OnAccessibilityRequest)
	ON_WM_TIMER()
	ON_WM_DESTROY()
	ON_WM_CONTEXTMENU()
END_MESSAGE_MAP()

BOOL CApplicationPicker::OnInitDialog()
{
	CModernDialog::OnInitDialog();
	SetWindowText(Localization::Get(L"apps.title"));
	m_launch.SetWindowText(Localization::Get(g_MainTab && g_MainTab->IsProxyRunning()
		? _T("apps.launch") : _T("apps.start_proxy_first")));
	m_launch.SetVisualStyle(CModernButton::STYLE_PRIMARY);
	m_launch.EnableWindow(FALSE);
	m_cancel.SetWindowText(Localization::Get(_T("apps.cancel")));
	m_refresh.SetWindowText(Localization::Get(_T("action.refresh")));
	m_recentActions.SetWindowText(Localization::Get(L"recent.actions"));
	m_recentActions.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_recentActions.ShowWindow(SW_HIDE);
	SetDlgItemText(IDC_APP_SEARCH_LABEL, Localization::Get(_T("apps.search")));
	SetDlgItemText(IDC_APP_HINT, Localization::Get(L"apps.hint"));
	SetDlgItemText(IDC_APP_STATUS, _T(""));
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
	m_list.EnableSnapshotAccessibility();
	m_list.SetBkColor(UiTheme::PageBackground());
	m_list.SetTextBkColor(UiTheme::PageBackground());
	LayoutPicker();
	m_list.InsertColumn(0, Localization::Get(_T("apps.name")), LVCFMT_LEFT,
		UiTheme::ScaleForWindow(m_hWnd, 190));
	m_list.InsertColumn(1, Localization::Get(L"apps.source"), LVCFMT_LEFT,
		UiTheme::ScaleForWindow(m_hWnd, 160));
	m_list.InsertColumn(2, Localization::Get(_T("apps.target_arguments")), LVCFMT_LEFT,
		UiTheme::ScaleForWindow(m_hWnd, 380));
	// There are no items to activate yet, and the launch button is disabled.
	// Keep the list enabled so Windows does not paint a grey disabled surface.
	SetEmptyState(Localization::Get(_T("apps.loading_list")));
	if (m_listTooltip.Create(this, TTS_ALWAYSTIP | TTS_NOPREFIX))
	{
		m_listTooltip.AddTool(&m_list, LPSTR_TEXTCALLBACK);
		m_listTooltip.AddTool(&m_recentActions, Localization::Get(L"recent.actions_hint"));
		m_listTooltip.SetMaxTipWidth(UiTheme::ScaleForWindow(m_hWnd, 640));
		m_listTooltip.SetDelayTime(TTDT_AUTOPOP, 30000);
		m_listTooltip.Activate(FALSE);
	}
	const int iconSize = UiTheme::ScaleForWindow(m_hWnd, 16);
	m_icons.Create(iconSize, iconSize, ILC_COLOR32 | ILC_MASK, 32, 32);
	m_list.SetImageList(&m_icons, LVSIL_SMALL);
	BeginLoad(FALSE);
	SetTimer(2, 500, NULL);
	m_search.SetFocus();
	return FALSE;
}

void CApplicationPicker::LayoutPicker()
{
	// Dialog units depend on the resource font and can produce a huge window.
	// Use DPI-scaled pixels and keep the modal smaller than its owner/work area.
	const auto scale = [this](int value) { return UiTheme::ScaleForWindow(m_hWnd, value); };
	CRect owner;
	CWnd* parent = GetParent();
	if (parent) parent = parent->GetTopLevelParent();
	if (parent) parent->GetWindowRect(&owner);
	else GetWindowRect(&owner);
	MONITORINFO monitor = {sizeof(monitor)};
	if (!GetMonitorInfo(MonitorFromRect(&owner, MONITOR_DEFAULTTONEAREST), &monitor))
		SystemParametersInfo(SPI_GETWORKAREA, 0, &monitor.rcWork, 0);
	CRect work(monitor.rcWork);
	CRect frame(0, 0, 0, 0);
	AdjustWindowRectEx(&frame, GetStyle(), FALSE, GetExStyle());
	const int width = min(scale(560), min(owner.Width() - scale(32), work.Width() - scale(32)) - frame.Width());
	const int height = min(scale(352), min(owner.Height() - scale(32), work.Height() - scale(32)) - frame.Height());
	const int outerWidth = width + frame.Width(), outerHeight = height + frame.Height();
	const int left = max(work.left, min(owner.CenterPoint().x - outerWidth / 2, work.right - outerWidth));
	const int top = max(work.top, min(owner.CenterPoint().y - outerHeight / 2, work.bottom - outerHeight));
	SetWindowPos(NULL, left, top, outerWidth, outerHeight, SWP_NOZORDER | SWP_NOACTIVATE);
	const int margin = scale(12), gap = scale(8), field = scale(26), button = scale(30);
	const int label = scale(76), hintHeight = scale(34);
	GetDlgItem(IDC_APP_SEARCH_LABEL)->MoveWindow(margin, margin + scale(4), label, scale(20));
	const int refreshWidth = scale(68);
	m_search.MoveWindow(margin + label + gap, margin,
		width - 2 * margin - label - 2 * gap - refreshWidth, field);
	m_refresh.MoveWindow(width - margin - refreshWidth, margin, refreshWidth, field);
	const int buttonTop = height - margin - button;
	const int hintTop = buttonTop - gap - hintHeight;
	const int listTop = margin + field + gap;
	const int listHeight = hintTop - gap - listTop;
	m_list.MoveWindow(margin, listTop, width - 2 * margin, listHeight);
	GetDlgItem(IDC_APP_HINT)->MoveWindow(margin, hintTop, width - 2 * margin, hintHeight);
	const int cancelWidth = scale(72), launchWidth = scale(144);
	const int cancelLeft = width - margin - cancelWidth;
	const int launchLeft = cancelLeft - gap - launchWidth;
	m_cancel.MoveWindow(cancelLeft, buttonTop, cancelWidth, button);
	m_launch.MoveWindow(launchLeft, buttonTop, launchWidth, button);
	const int removeWidth = scale(148);
	const int removeLeft = launchLeft - gap - removeWidth;
	m_recentActions.MoveWindow(removeLeft, buttonTop, removeWidth, button);
	GetDlgItem(IDC_APP_STATUS)->MoveWindow(margin, buttonTop + scale(6), max(1, removeLeft - margin - gap), scale(20));
}

void CApplicationPicker::SetEmptyState(const CString& text)
{
	m_emptyState.SetWindowText(text);
	if (text.IsEmpty()) m_emptyState.ShowWindow(SW_HIDE);
	else
	{
		CRect area;
		m_list.GetClientRect(&area);
		CPoint origin(0, 0);
		m_list.ClientToScreen(&origin);
		ScreenToClient(&origin);
		area.OffsetRect(origin);
		CHeaderCtrl* header = m_list.GetHeaderCtrl();
		if (header && header->GetSafeHwnd())
		{
			CRect headerRect;
			header->GetWindowRect(&headerRect);
			area.top += headerRect.Height();
		}
		area.DeflateRect(UiTheme::ScaleForWindow(m_hWnd, 12), 0);
		CClientDC dc(&m_emptyState);
		CFont* font = m_emptyState.GetFont();
		CFont* oldFont = font ? dc.SelectObject(font) : NULL;
		CRect textRect(0, 0, max(1, area.Width()), 0);
		dc.DrawText(text, &textRect, DT_CALCRECT | DT_CENTER | DT_WORDBREAK | DT_NOPREFIX);
		if (oldFont) dc.SelectObject(oldFont);
		const int height = max(1, textRect.Height());
		m_emptyState.MoveWindow(area.left, area.top + max(0, (area.Height() - height) / 2),
			max(1, area.Width()), height);
		m_emptyState.SetWindowPos(&wndTop, 0, 0, 0, 0,
			SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
	}
}

void CApplicationPicker::OnTimer(UINT_PTR timer)
{
	if ((timer == 1 || timer == 2) && RefreshProfileContext()) return;
	if (timer == 2 && RefreshRecentLoad(FALSE))
	{
		m_loading = TRUE;
		m_refresh.EnableWindow(FALSE);
		RebuildApplications();
		SetTimer(1, 100, NULL);
	}
	if (timer == 1 || timer == 2) FinishLoad();
	CModernDialog::OnTimer(timer);
}

void CApplicationPicker::BeginLoad(BOOL refresh)
{
	const CString profile = g_MainTab && g_MainTab->IsProxyRunning() ? g_MainTab->GetRunningProfileName() : CString();
	const CString identity = g_MainTab ? g_MainTab->GetRunningRecentProfileId() : CString();
	const BOOL changedProfile = m_profile != profile || m_profileId != identity;
	m_profile = profile; m_profileId = identity;
	KillTimer(1);
	if (m_load) m_load->Release();
	m_load = NULL;
	if (changedProfile)
	{
		if (m_recentLoad) { m_recentLoad->Release(); m_recentLoad = NULL; }
		RecentApplications::ReleaseIcons(m_recentEntries);
		m_recentEntries.clear();
	}
	RefreshRecentLoad(refresh);
	m_load = AcquireApplicationCatalog(refresh);
	ApplicationCatalogLoad* ready = AcquireReadyApplicationCatalog();
	if (ready)
	{
		InstalledApplications::Clone(ready->applications, m_catalog);
		ready->Release();
	}
	m_loading = TRUE;
	m_loadFailed = FALSE;
	m_recentReadFailed = FALSE;
	m_refresh.EnableWindow(FALSE);
	RebuildApplications();
	if (!FinishLoad()) SetTimer(1, 100, NULL);
}

BOOL CApplicationPicker::FinishLoad()
{
	BOOL changed = FALSE;
	// Recent entries are independently validated and become usable before the
	// potentially much slower installed-application enumeration finishes.
	if (m_recentLoad && !m_recentConsumed)
	{
		if (!RecentApplications::IsCurrentLoad(m_recentLoad)) changed = RefreshRecentLoad(FALSE);
		EnterCriticalSection(&m_recentLoad->lock);
		const BOOL done = m_recentLoad->done;
		LeaveCriticalSection(&m_recentLoad->lock);
		if (done)
		{
			m_recentReadFailed = !m_recentLoad->succeeded;
			if (!m_recentReadFailed && m_recentLoad->profileId == m_profileId && m_recentLoad->profile == m_profile)
				RecentApplications::Clone(m_recentLoad->entries, m_recentEntries);
			m_recentConsumed = TRUE;
			changed = TRUE;
		}
	}
	if (m_load)
	{
		EnterCriticalSection(&m_load->lock);
		const BOOL done = m_load->done;
		const HRESULT result = m_load->result;
		LeaveCriticalSection(&m_load->lock);
		if (done)
		{
			m_loadFailed = FAILED(result);
			if (!m_loadFailed)
			{
				RememberApplicationCatalog(m_load);
				InstalledApplications::Clone(m_load->applications, m_catalog);
			}
			m_load->Release(); m_load = NULL;
			changed = TRUE;
		}
	}
	m_loading = m_load || (m_recentLoad && !m_recentConsumed);
	if (changed) RebuildApplications();
	if (!m_loading) { KillTimer(1); m_refresh.EnableWindow(TRUE); }
	return !m_loading;
}

BOOL CApplicationPicker::RefreshRecentLoad(BOOL refresh)
{
	RecentApplications::Load* latest = RecentApplications::AcquireLoad(
		m_profile, RecentApplications::DefaultPath(), m_profileId, refresh);
	if (latest == m_recentLoad) { latest->Release(); return FALSE; }
	// Local history edits are published into Ready() before validation starts.
	{
		RecentApplications::Load* ready = RecentApplications::AcquireReadyLoad(
			m_profile, RecentApplications::DefaultPath(), m_profileId);
		if (ready) { RecentApplications::Clone(ready->entries, m_recentEntries); ready->Release(); }
	}
	if (m_recentLoad) m_recentLoad->Release();
	m_recentLoad = latest;
	m_recentConsumed = FALSE;
	return TRUE;
}

void CApplicationPicker::OnRefresh() { if (!m_loading) BeginLoad(TRUE); }

BOOL CApplicationPicker::RefreshProfileContext()
{
	UpdateSelectionActions();
	const CString profile = g_MainTab && g_MainTab->IsProxyRunning() ? g_MainTab->GetRunningProfileName() : CString();
	const CString identity = g_MainTab ? g_MainTab->GetRunningRecentProfileId() : CString();
	if (profile == m_profile && identity == m_profileId) return FALSE;
	BeginLoad(FALSE);
	return TRUE;
}

void CApplicationPicker::RebuildApplications()
{
	const CString selection = SelectionKey();
	// Both launch surfaces consume the same display-ordered cache snapshots.
	m_rebuilding = TRUE;
	m_list.DeleteAllItems();
	m_visibleRows.clear();
	++m_rowGeneration;
	InstalledApplications::ReleaseIcons(m_applications);
	m_applications.clear();
	m_applicationKeys.clear();
	for (size_t i = 0; i < m_recentEntries.size(); ++i)
	{
		InstalledApplications::Application app = m_recentEntries[i].app;
		app.icon = app.icon ? CopyIcon(app.icon) : NULL;
		m_applications.push_back(app);
		m_applicationKeys.push_back(L"recent:" + m_recentEntries[i].profileId + L":" + m_recentEntries[i].id);
	}
	// A slow/unavailable recent network path must not hold up a ready catalog.
	// Validated recents move to the top without changing the selected target.
	for (size_t i = 0; i < m_catalog.size(); ++i)
	{
		BOOL recent = FALSE;
		for (size_t j = 0; j < m_recentEntries.size() && !recent; ++j)
			recent = RecentApplications::MatchesCatalog(m_recentEntries[j], m_catalog[i]);
		if (recent) continue;
		InstalledApplications::Application app = m_catalog[i];
		app.icon = app.icon ? CopyIcon(app.icon) : NULL;
		m_applications.push_back(app);
		m_applicationKeys.push_back(L"catalog:" + app.path + L"\n" + app.aumid + L"\n" + app.arguments + L"\n" + app.workingDirectory);
	}
	m_icons.SetImageCount(0);
	m_elevationOverlayReady = FALSE;
	int iconWidth = 0, iconHeight = 0;
	if (ImageList_GetIconSize(m_icons.GetSafeHandle(), &iconWidth, &iconHeight))
	{
		HICON overlay = UiTheme::CreateElevationOverlay(min(iconWidth, iconHeight));
		if (overlay)
		{
			const int index = m_icons.Add(overlay);
			m_elevationOverlayReady = index >= 0 && m_icons.SetOverlayImage(index, 1);
			DestroyIcon(overlay);
		}
	}
	m_iconIndices.clear();
	for (size_t i = 0; i < m_applications.size(); ++i)
		m_iconIndices.push_back(m_applications[i].icon ? m_icons.Add(m_applications[i].icon) : -1);
	m_rebuilding = FALSE;
	FilterApplications(selection);
}

CString CApplicationPicker::RowKey(size_t index) const
{
	// Keep keys with the displayed snapshot: a newer recent snapshot may already
	// have arrived when RebuildApplications saves the old selection.
	return index < m_applicationKeys.size() ? m_applicationKeys[index] : CString();
}

CString CApplicationPicker::SelectionKey() const
{
	const int row = m_list.GetNextItem(-1, LVNI_SELECTED);
	return row >= 0 ? RowKey(m_list.GetItemData(row)) : CString();
}

void CApplicationPicker::FilterApplications(const CString& selection)
{
	const CString selected = selection.IsEmpty() ? SelectionKey() : selection;
	const int topRow = m_list.GetTopIndex();
	m_rebuilding = TRUE;
	if (m_listTooltip.GetSafeHwnd()) m_listTooltip.Activate(FALSE);
	m_hoverRow = -1;
	m_hoverText.Empty();
	CString search;
	m_search.GetWindowText(search);
	search.Trim();
	search.MakeLower();
	m_list.SetRedraw(FALSE);
	m_list.DeleteAllItems();
	m_visibleRows.clear();
	int selectedRow = -1;
	for (size_t i = 0; i < m_applications.size(); ++i)
	{
		const InstalledApplications::Application& app = m_applications[i];
		CString source = i < m_recentEntries.size() ? Localization::Get(m_recentEntries[i].available ?
			L"recent.title" : L"recent.unavailable_source") : SourceSummary(app);
		if (i < m_recentEntries.size() && m_recentEntries[i].pinned) source += L" (" + Localization::Get(L"recent.pinned") + L")";
		const BOOL elevated = i < m_recentEntries.size() && m_recentEntries[i].elevated;
		if (elevated) source += L" / " + Localization::Get(L"recent.admin_badge");
		CString searchable = app.name + L" " + app.path + L" " + app.aumid + L" " +
			app.arguments + L" " + app.workingDirectory + L" " + source;
		for (size_t source = 0; source < app.sources.size(); ++source)
			searchable += L" " + app.sources[source].path;
		searchable.MakeLower();
		if (!search.IsEmpty() && searchable.Find(search) < 0) continue;
		const CString target = LaunchText(app);
		const int row = m_list.InsertItem(static_cast<int>(m_visibleRows.size()), app.name, m_iconIndices[i]);
		if (row < 0) continue;
		m_list.SetItemText(row, 1, source);
		m_list.SetItemText(row, 2, target);
		m_list.SetItemData(row, i);
		if (elevated && m_elevationOverlayReady)
			m_list.SetItemState(row, INDEXTOOVERLAYMASK(1), LVIS_OVERLAYMASK);
		ProcessListAccessibility::Row cached;
		cached.pid = static_cast<DWORD>(i); cached.created = m_rowGeneration;
		cached.text[0] = app.name.GetString(); cached.text[1] = source.GetString(); cached.text[2] = target.GetString();
		cached.accessibleName = cached.text[0];
		if (elevated) cached.accessibleName += L", " + std::wstring(Localization::Get(L"recent.elevated").GetString());
		m_visibleRows.push_back(std::move(cached));
		if (RowKey(i) == selected) selectedRow = row;
	}
	if (m_list.GetItemCount() > 0)
		m_list.SetItemState(selectedRow >= 0 ? selectedRow : 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
	if (topRow > 0 && topRow < m_list.GetItemCount()) m_list.EnsureVisible(topRow, FALSE);
	m_list.SetRedraw(TRUE);
	m_list.Invalidate(FALSE);
	m_rebuilding = FALSE;
	UpdateSelectionActions();
	SetWindowText(Localization::Get(L"apps.title") + (m_loading && m_applications.empty() ? L" - " + Localization::Get(L"apps.loading_list") : CString()));
	const CString emptyText = Localization::Get(m_loading ? L"apps.loading_list" :
		(m_loadFailed ? L"apps.load_failed" : L"apps.no_matches"));
	SetEmptyState(m_list.GetItemCount() == 0 ? emptyText : CString());
	SetDlgItemText(IDC_APP_STATUS, m_loading ? Localization::Get(m_applications.empty() ? L"apps.loading_list" : L"apps.updating_list") :
		(m_recentReadFailed ? Localization::Get(L"recent.read_failed") :
		(m_loadFailed ? Localization::Get(L"apps.refresh_failed") : Localization::Format(L"apps.count", m_list.GetItemCount()))));
	PublishAccessibility(TRUE);
	if (m_list.AccessibilityBridge()) PostMessage(ProcessListAccessibility::RequestMessage);
}

CString CApplicationPicker::SourceSummary(const InstalledApplications::Application& application) const
{
	// Store activation is the important distinction here; exact catalog and
	// shortcut origins remain available in the row's detail tooltip.
	if (application.IsPackaged()) return Localization::Get(_T("apps.packaged"));
	CString text;
	std::vector<InstalledApplications::SourceKind> kinds;
	for (size_t i = 0; i < application.sources.size(); ++i)
	{
		const InstalledApplications::SourceKind kind = application.sources[i].kind;
		BOOL found = FALSE;
		for (size_t j = 0; j < kinds.size(); ++j) if (kinds[j] == kind) found = TRUE;
		if (found) continue;
		kinds.push_back(kind);
		if (!text.IsEmpty()) text += L" / ";
		text += ApplicationSourceName(kind);
	}
	return text.IsEmpty() ? Localization::Get(_T("apps.source_unknown")) : text;
}

CString CApplicationPicker::LaunchText(const InstalledApplications::Application& application) const
{
	return InstalledApplications::LaunchTargetAndArguments(application);
}

CString CApplicationPicker::ItemDetails(const InstalledApplications::Application& application) const
{
	CString text = application.name + L"\r\n" + Localization::Get(_T("apps.target_arguments")) +
		L": " + LaunchText(application) + L"\r\n" + Localization::Get(_T("apps.working_directory")) +
		L": " + (application.workingDirectory.IsEmpty() ?
			Localization::Get(_T("apps.default_directory")) : application.workingDirectory);
	text += L"\r\n" + Localization::Get(_T("apps.source")) + L": " + SourceSummary(application);
	for (size_t i = 0; i < application.sources.size(); ++i)
		text += L"\r\n" + ApplicationSourceName(application.sources[i].kind) + L": " + application.sources[i].path;
	return text;
}

BOOL CApplicationPicker::PreTranslateMessage(MSG* message)
{
	if (m_listTooltip.GetSafeHwnd())
	{
		if (message->message == WM_MOUSEMOVE)
		{
			int row = -1;
			if (message->hwnd == m_list.GetSafeHwnd())
			{
				LVHITTESTINFO hit = {0};
				hit.pt = CPoint(static_cast<short>(LOWORD(message->lParam)), static_cast<short>(HIWORD(message->lParam)));
				row = m_list.SubItemHitTest(&hit);
			}
			if (row != m_hoverRow)
			{
				m_listTooltip.Activate(FALSE);
				m_hoverRow = row;
				m_hoverText.Empty();
				if (row >= 0)
				{
					const size_t index = m_list.GetItemData(row);
					if (index < m_applications.size()) m_hoverText = index < m_recentEntries.size() ?
						RecentApplications::Description(m_recentEntries[index]) :
						ItemDetails(m_applications[index]);
				}
				m_listTooltip.Activate(!m_hoverText.IsEmpty());
			}
			if (message->hwnd == m_recentActions.GetSafeHwnd()) m_listTooltip.Activate(TRUE);
		}
		if (message->message == WM_LBUTTONDOWN || message->message == WM_NCLBUTTONDOWN ||
			message->message == WM_MOUSEWHEEL || message->message == WM_KEYDOWN)
		{
			m_listTooltip.Activate(FALSE);
			m_hoverRow = -1;
		}
		m_listTooltip.RelayEvent(message);
	}
	return CModernDialog::PreTranslateMessage(message);
}

BOOL CApplicationPicker::OnNotify(WPARAM wParam, LPARAM lParam, LRESULT* result)
{
	NMHDR* header = reinterpret_cast<NMHDR*>(lParam);
	if (header && m_listTooltip.GetSafeHwnd() && header->hwndFrom == m_listTooltip.GetSafeHwnd() &&
		header->code == TTN_NEEDTEXT)
	{
		// A callback avoids MFC's fixed UpdateTipText length limit. The member
		// buffer stays valid while the tip displays long commands/source paths.
		reinterpret_cast<NMTTDISPINFO*>(header)->lpszText = const_cast<LPTSTR>(static_cast<LPCTSTR>(m_hoverText));
		*result = 0;
		return TRUE;
	}
	return CModernDialog::OnNotify(wParam, lParam, result);
}

LRESULT CApplicationPicker::OnAccessibilityChanged(WPARAM force, LPARAM)
{
	m_list.AcknowledgeAccessibilityUpdate();
	if (!m_rebuilding || force) PublishAccessibility(FALSE);
	return 0;
}

void CApplicationPicker::PublishAccessibility(BOOL structureChanged)
{
	auto bridge = m_list.AccessibilityBridge();
	if (!bridge || !bridge->Available()) return;
	try {
		auto snapshot = std::make_shared<ProcessListAccessibility::Snapshot>();
		snapshot->name = Localization::Get(L"apps.title").GetString();
		snapshot->automationId = std::to_wstring(IDC_APP_LIST);
		snapshot->columnCount = 3;
		snapshot->canSelectMultiple = false;
		snapshot->sortableHeaders = false;
		snapshot->visible = m_list.IsWindowVisible() != FALSE;
		snapshot->enabled = m_list.IsWindowEnabled() != FALSE;
		snapshot->hasFocus = ::GetFocus() == m_list.m_hWnd;
		m_list.GetClientRect(&snapshot->client);
		CHeaderCtrl* header = m_list.GetHeaderCtrl();
		if (header) {
			snapshot->header = header->m_hWnd;
			header->GetWindowRect(&snapshot->headerRect);
			m_list.ScreenToClient(&snapshot->headerRect);
			for (int i = 0; i < snapshot->columnCount; ++i) {
				header->GetItemRect(i, &snapshot->columns[i]);
				header->ClientToScreen(&snapshot->columns[i]);
				m_list.ScreenToClient(&snapshot->columns[i]);
			}
		}
		snapshot->headings[0] = Localization::Get(L"apps.name").GetString();
		snapshot->headings[1] = Localization::Get(L"apps.source").GetString();
		snapshot->headings[2] = Localization::Get(L"apps.target_arguments").GetString();
		snapshot->top = m_list.GetTopIndex();
		CRect rect;
		if (!m_visibleRows.empty() && m_list.GetItemRect(snapshot->top, &rect, LVIR_BOUNDS)) {
			snapshot->rowTop = rect.top;
			snapshot->rowHeight = max(1, rect.Height());
		}
		SCROLLINFO info = { sizeof(info), SIF_ALL };
		if (m_list.GetScrollInfo(SB_HORZ, &info)) {
			snapshot->horizontalPosition = info.nPos;
			snapshot->horizontalMaximum = max(0, info.nMax - static_cast<int>(info.nPage) + 1);
		}
		snapshot->focused = m_list.GetNextItem(-1, LVNI_FOCUSED);
		const int selected = m_list.GetNextItem(-1, LVNI_SELECTED);
		snapshot->rows = m_visibleRows;
		if (selected >= 0 && selected < static_cast<int>(snapshot->rows.size()))
			snapshot->rows[selected].selected = true;
		bridge->Publish(snapshot, structureChanged != FALSE);
	} catch (...) {} // Preserve the last complete snapshot if allocation fails.
}

LRESULT CApplicationPicker::OnAccessibilityRequest(WPARAM, LPARAM)
{
	auto bridge = m_list.AccessibilityBridge();
	if (!bridge || m_rebuilding) return 0;
	const auto requests = bridge->TakeRequests();
	if (!m_list.IsWindowVisible() || !m_list.IsWindowEnabled()) return 0;
	for (const auto& request : requests) {
		using namespace ProcessListAccessibility;
		if (request.action == Sort) continue; // This picker preserves the user's display order.
		if (request.action == ScrollBy || request.action == ScrollTo) {
			const int top = m_list.GetTopIndex();
			CRect rect;
			if (!m_list.GetItemRect(top, &rect, LVIR_BOUNDS)) continue;
			const int height = max(1, rect.Height());
			int x = static_cast<int>(request.x), y = static_cast<int>(request.y) * height;
			if (request.action == ScrollTo) {
				SCROLLINFO info = { sizeof(info), SIF_ALL }; m_list.GetScrollInfo(SB_HORZ, &info);
				x = request.x < 0 ? 0 : static_cast<int>(request.x * max(0, info.nMax - static_cast<int>(info.nPage) + 1) / 100) - info.nPos;
				const int maximum = max(0, static_cast<int>(m_visibleRows.size()) - m_list.GetCountPerPage());
				y = request.y < 0 ? 0 : (static_cast<int>(request.y * maximum / 100) - top) * height;
			}
			m_list.Scroll(CSize(x, y));
			continue;
		}
		if (!request.hasRow) {
			if (request.action == Focus) m_list.SetFocus();
			continue;
		}
		// A filter can move rows; a catalog/profile rebuild can reuse indexes.
		// Resolve both token and generation before touching the native selection.
		int index = -1;
		for (size_t i = 0; i < m_visibleRows.size(); ++i)
			if (m_visibleRows[i].pid == request.pid && m_visibleRows[i].created == request.created) {
				index = static_cast<int>(i); break;
			}
		if (index < 0) continue;
		if (request.action == Select || request.action == AddSelection) {
			const int selected = m_list.GetNextItem(-1, LVNI_SELECTED);
			if (request.action == AddSelection && selected >= 0 && selected != index) continue;
			m_list.SetItemState(index, LVIS_SELECTED, LVIS_SELECTED);
		}
		if (request.action == RemoveSelection) m_list.SetItemState(index, 0, LVIS_SELECTED);
		if (request.action == Focus) {
			m_list.SetFocus();
			m_list.SetItemState(index, LVIS_FOCUSED, LVIS_FOCUSED);
		}
		if (request.action == Focus || request.action == Reveal) m_list.EnsureVisible(index, FALSE);
	}
	PublishAccessibility(FALSE);
	return 0;
}

void CApplicationPicker::OnSearchChanged() { if (m_list.GetSafeHwnd()) FilterApplications(); }

void CApplicationPicker::OnSelectionChanged(NMHDR*, LRESULT* result)
{
	if (!m_rebuilding) {
		UpdateSelectionActions();
		PostMessage(ProcessListAccessibility::ChangedMessage);
	}
	*result = 0;
}

void CApplicationPicker::UpdateSelectionActions()
{
	const int row = m_list.GetNextItem(-1, LVNI_SELECTED);
	const BOOL selected = row >= 0 && m_list.GetItemData(row) < m_applications.size();
	const BOOL recent = selected && m_list.GetItemData(row) < m_recentEntries.size();
	const BOOL available = selected && (!recent || m_recentEntries[m_list.GetItemData(row)].available);
	const BOOL running = g_MainTab && g_MainTab->IsProxyRunning();
	const CString caption = Localization::Get(running
		? _T("apps.launch") : _T("apps.start_proxy_first"));
	CString currentCaption;
	m_launch.GetWindowText(currentCaption);
	if (currentCaption != caption) m_launch.SetWindowText(caption);
	if (m_launch.IsWindowEnabled() != (available && running)) m_launch.EnableWindow(available && running);
	if (((m_recentActions.GetStyle() & WS_VISIBLE) != 0) != (recent != FALSE))
		m_recentActions.ShowWindow(recent ? SW_SHOW : SW_HIDE);
	if (m_recentActions.IsWindowEnabled() != recent) m_recentActions.EnableWindow(recent);
	const CString hint = Localization::Get(recent ? L"recent.actions_hint" : L"apps.hint");
	CString currentHint; GetDlgItemText(IDC_APP_HINT, currentHint);
	if (currentHint != hint) SetDlgItemText(IDC_APP_HINT, hint);
}

void CApplicationPicker::OnDoubleClick(NMHDR* header, LRESULT* result)
{
	*result = 0;
	if (reinterpret_cast<NMITEMACTIVATE*>(header)->iItem >= 0) OnOK();
}

void CApplicationPicker::OnListCustomDraw(NMHDR* header, LRESULT* result)
{
	NMLVCUSTOMDRAW* draw = reinterpret_cast<NMLVCUSTOMDRAW*>(header);
	*result = CDRF_DODEFAULT;
	if (draw->nmcd.dwDrawStage == CDDS_PREPAINT)
		*result = CDRF_NOTIFYITEMDRAW;
	else if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
	{
		const size_t index = static_cast<size_t>(draw->nmcd.lItemlParam);
		if (index < m_recentEntries.size() && !m_recentEntries[index].available)
			draw->clrText = UiTheme::TextSecondary();
	}
}

void CApplicationPicker::OnOK()
{
	if (RefreshProfileContext()) return;
	if (!g_MainTab || !g_MainTab->IsProxyRunning()) return;
	const int row = m_list.GetNextItem(-1, LVNI_SELECTED);
	if (row < 0) return;
	const size_t index = m_list.GetItemData(row);
	if (index >= m_applications.size()) return;
	if (index < m_recentEntries.size() && !m_recentEntries[index].available) return;
	m_selectedApplication = m_applications[index];
	m_selectedApplication.icon = NULL;
	if (index < m_recentEntries.size())
	{
		m_selectedRecent = m_recentEntries[index];
		m_selectedRecent.app.icon = NULL;
	}
	CModernDialog::OnOK();
}

void CApplicationPicker::OnContextMenu(CWnd* window, CPoint point)
{
	if (window != &m_list) return;
	int row = -1;
	if (point.x == -1 && point.y == -1)
	{
		row = m_list.GetNextItem(-1, LVNI_SELECTED);
		CRect rect;
		if (row >= 0) { m_list.GetItemRect(row, &rect, LVIR_BOUNDS); point = rect.CenterPoint(); m_list.ClientToScreen(&point); }
	}
	else { CPoint client(point); m_list.ScreenToClient(&client); row = m_list.HitTest(client); }
	if (row < 0) return;
	const size_t index = m_list.GetItemData(row);
	if (index >= m_recentEntries.size()) return;
	m_list.SetItemState(row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
	ShowRecentMenu(index, point);
}

void CApplicationPicker::ShowRecentMenu(size_t index, CPoint point)
{
	if (index >= m_recentEntries.size()) return;
	const RecentApplications::Entry entry = m_recentEntries[index];
	const CString profileId = m_profileId;
	CModernPopupMenu menu; menu.CreatePopupMenu();
	const BOOL canUp = index > 0 && m_recentEntries[index - 1].pinned == entry.pinned;
	const BOOL canDown = index + 1 < m_recentEntries.size() && m_recentEntries[index + 1].pinned == entry.pinned;
	menu.AppendMenu(MF_STRING | (canUp ? 0 : MF_GRAYED), 3, Localization::Get(L"recent.move_up"));
	menu.AppendMenu(MF_STRING | (canDown ? 0 : MF_GRAYED), 4, Localization::Get(L"recent.move_down"));
	menu.AppendMenu(MF_SEPARATOR);
	menu.AppendMenu(MF_STRING, entry.pinned ? 5 : 1, Localization::Get(entry.pinned ? L"recent.unpin" : L"recent.pin"));
	menu.AppendMenu(MF_STRING, 2, Localization::Get(L"recent.remove"));
	menu.AppendMenu(MF_SEPARATOR);
	menu.AppendMenu(MF_STRING | (entry.available ? 0 : MF_GRAYED), 6, Localization::Get(L"shortcut.create"));
	menu.SetItemIcon(3, CModernPopupMenu::MOVE_UP);
	menu.SetItemIcon(4, CModernPopupMenu::MOVE_DOWN);
	menu.SetItemIcon(entry.pinned ? 5 : 1, entry.pinned ? CModernPopupMenu::UNPIN : CModernPopupMenu::PIN);
	menu.SetItemIcon(2, CModernPopupMenu::REMOVE);
	menu.SetItemIcon(6, CModernPopupMenu::LINK);
	const UINT command = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_RIGHTBUTTON, point.x, point.y, this);
	// Popup menus pump messages: use a stable identity, never a possibly moved row.
	if (command && profileId == m_profileId) ChangeRecent(entry.id, command);
}

void CApplicationPicker::OnRecentActions()
{
	const int row = m_list.GetNextItem(-1, LVNI_SELECTED);
	if (row < 0) return;
	CRect rect; m_recentActions.GetWindowRect(&rect);
	ShowRecentMenu(m_list.GetItemData(row), CPoint(rect.left, rect.bottom));
}

void CApplicationPicker::ChangeRecent(const CString& id, UINT command)
{
	if (RefreshProfileContext()) return;
	size_t index = 0;
	while (index < m_recentEntries.size() && m_recentEntries[index].id != id) ++index;
	if (index == m_recentEntries.size()) return;
	if (command == 6)
	{
		// Modal dialogs can refresh the list. Keep owned values, not row references.
		RecentApplications::Entry entry = m_recentEntries[index]; entry.app.icon = NULL;
		const CString profile = m_profile, identity = m_profileId;
		CPage1* settings = g_MainTab ? g_MainTab->GetPage1() : NULL;
		if (settings && settings->GetSelectedProfileName() == profile && settings->HasUnsavedProfileChanges())
		{
			if (MessageBox(Localization::Get(L"shortcut.save_profile"), Localization::Get(L"shortcut.title"),
				MB_OKCANCEL | MB_ICONQUESTION) != IDOK) return;
			if (RefreshProfileContext() || profile != m_profile || identity != m_profileId ||
				settings->GetSelectedProfileName() != profile || !settings->SavePendingProfile()) return;
		}
		if (LaunchShortcut::PromptCreate(this, profile, entry, [this, profile, identity]() -> BOOL {
			return !RefreshProfileContext() && profile == m_profile && identity == m_profileId;
		})) SetDlgItemText(IDC_APP_STATUS, Localization::Get(L"shortcut.created"));
		return;
	}
	RecentApplications::Store store(m_profile, RecentApplications::DefaultPath(), m_profileId);
	BOOL updated = FALSE;
	if (command == 1 || command == 5) updated = store.SetPinned(id, command == 1);
	else if (command == 2) updated = store.Remove(id);
	else if (command == 3 || command == 4) updated = store.Move(id, command == 3 ? -1 : 1);
	if (!updated)
	{
		MessageBox(Localization::Get(L"recent.write_failed"), Localization::Get(L"recent.title"), MB_OK | MB_ICONWARNING);
		return;
	}
	// The store publishes a ready snapshot with cached icons before validation.
	RefreshRecentLoad(FALSE);
	RebuildApplications();
	const int selected = m_list.GetNextItem(-1, LVNI_SELECTED);
	if (selected >= 0) m_list.EnsureVisible(selected, FALSE);
	if (g_MainTab)
	{
		g_MainTab->GetPage1()->PostMessage(WM_RECENT_APPLICATIONS_CHANGED);
		g_MainTab->GetPage3()->PostMessage(WM_RECENT_APPLICATIONS_CHANGED);
	}
}

void CApplicationPicker::OnDestroy()
{
	KillTimer(1);
	KillTimer(2);
	if (m_listTooltip.GetSafeHwnd()) m_listTooltip.DestroyWindow();
	if (m_load)
	{
		m_load->Release();
		m_load = NULL;
	}
	if (m_recentLoad)
	{
		m_recentLoad->Release(); m_recentLoad = NULL;
	}
	CModernDialog::OnDestroy();
}
