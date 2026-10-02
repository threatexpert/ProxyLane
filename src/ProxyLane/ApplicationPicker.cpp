#include "stdafx.h"
#include "ProxyLane.h"
#include "ApplicationPicker.h"
#include "Localization.h"
#include "ApplicationCatalogCache.h"

static CString ApplicationSourceName(InstalledApplications::SourceKind kind)
{
	const LPCTSTR keys[] = { _T("apps.source_system"), _T("apps.source_user_menu"),
		_T("apps.source_common_menu"), _T("apps.source_shortcut"), _T("apps.source_shell") };
	return Localization::Get(kind >= 0 && static_cast<size_t>(kind) < _countof(keys) ?
		keys[kind] : _T("apps.source_unknown"));
}

CApplicationPicker::CApplicationPicker(CWnd* parent)
	: CModernDialog(IDD_APPLICATION_PICKER, parent), m_hoverRow(-1), m_load(NULL), m_loading(TRUE), m_loadFailed(FALSE) {}

CApplicationPicker::~CApplicationPicker()
{
	InstalledApplications::ReleaseIcons(m_applications);
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
}

BEGIN_MESSAGE_MAP(CApplicationPicker, CModernDialog)
	ON_EN_CHANGE(IDC_APP_SEARCH, &CApplicationPicker::OnSearchChanged)
	ON_BN_CLICKED(IDC_APP_REFRESH, &CApplicationPicker::OnRefresh)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_APP_LIST, &CApplicationPicker::OnSelectionChanged)
	ON_NOTIFY(NM_DBLCLK, IDC_APP_LIST, &CApplicationPicker::OnDoubleClick)
	ON_WM_TIMER()
	ON_WM_DESTROY()
END_MESSAGE_MAP()

BOOL CApplicationPicker::OnInitDialog()
{
	CModernDialog::OnInitDialog();
	SetWindowText(Localization::Get(_T("apps.title")));
	m_launch.SetWindowText(Localization::Get(_T("apps.launch")));
	m_launch.SetVisualStyle(CModernButton::STYLE_PRIMARY);
	m_launch.EnableWindow(FALSE);
	m_cancel.SetWindowText(Localization::Get(_T("apps.cancel")));
	m_refresh.SetWindowText(Localization::Get(_T("action.refresh")));
	SetDlgItemText(IDC_APP_SEARCH_LABEL, Localization::Get(_T("apps.search")));
	SetDlgItemText(IDC_APP_HINT, Localization::Get(_T("apps.hint")));
	SetDlgItemText(IDC_APP_STATUS, _T(""));
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
	m_list.SetBkColor(UiTheme::PageBackground());
	m_list.SetTextBkColor(UiTheme::PageBackground());
	LayoutPicker();
	m_list.InsertColumn(0, Localization::Get(_T("apps.name")), LVCFMT_LEFT,
		UiTheme::ScaleForWindow(m_hWnd, 190));
	m_list.InsertColumn(1, Localization::Get(_T("apps.source")), LVCFMT_LEFT,
		UiTheme::ScaleForWindow(m_hWnd, 160));
	m_list.InsertColumn(2, Localization::Get(_T("apps.target_arguments")), LVCFMT_LEFT,
		UiTheme::ScaleForWindow(m_hWnd, 380));
	// There are no items to activate yet, and the launch button is disabled.
	// Keep the list enabled so Windows does not paint a grey disabled surface.
	SetEmptyState(Localization::Get(_T("apps.loading_list")));
	if (m_listTooltip.Create(this, TTS_ALWAYSTIP | TTS_NOPREFIX))
	{
		m_listTooltip.AddTool(&m_list, LPSTR_TEXTCALLBACK);
		m_listTooltip.SetMaxTipWidth(UiTheme::ScaleForWindow(m_hWnd, 640));
		m_listTooltip.SetDelayTime(TTDT_AUTOPOP, 30000);
		m_listTooltip.Activate(FALSE);
	}
	const int iconSize = UiTheme::ScaleForWindow(m_hWnd, 16);
	m_icons.Create(iconSize, iconSize, ILC_COLOR32 | ILC_MASK, 32, 32);
	m_list.SetImageList(&m_icons, LVSIL_SMALL);
	BeginLoad(FALSE);
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
	GetDlgItem(IDC_APP_STATUS)->MoveWindow(margin, buttonTop + scale(6), launchLeft - margin - gap, scale(20));
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
	if (timer == 1) FinishLoad();
	CModernDialog::OnTimer(timer);
}

void CApplicationPicker::BeginLoad(BOOL refresh)
{
	KillTimer(1);
	if (m_load) m_load->Release();
	m_load = AcquireApplicationCatalog(refresh);
	m_loading = TRUE;
	m_loadFailed = FALSE;
	m_launch.EnableWindow(FALSE);
	m_refresh.EnableWindow(FALSE);
	if (m_listTooltip.GetSafeHwnd()) m_listTooltip.Activate(FALSE);
	m_hoverRow = -1;
	m_list.DeleteAllItems();
	SetDlgItemText(IDC_APP_STATUS, _T(""));
	SetEmptyState(Localization::Get(_T("apps.loading_list")));
	if (!FinishLoad()) SetTimer(1, 100, NULL);
}

BOOL CApplicationPicker::FinishLoad()
{
	if (!m_load) return TRUE;
	EnterCriticalSection(&m_load->lock);
	const BOOL done = m_load->done;
	const HRESULT result = m_load->result;
	LeaveCriticalSection(&m_load->lock);
	if (!done) return FALSE;
	KillTimer(1);
	if (SUCCEEDED(result))
	{
		RememberApplicationCatalog(m_load);
		InstalledApplications::Clone(m_load->applications, m_applications);
	}
	m_load->Release();
	m_load = NULL;
	m_loading = FALSE;
	m_loadFailed = FAILED(result) && m_applications.empty();
	m_iconIndices.clear();
	m_icons.SetImageCount(0);
	for (size_t i = 0; i < m_applications.size(); ++i)
		m_iconIndices.push_back(m_applications[i].icon ? m_icons.Add(m_applications[i].icon) : -1);
	m_refresh.EnableWindow(TRUE);
	FilterApplications();
	if (FAILED(result) && !m_applications.empty())
		SetDlgItemText(IDC_APP_STATUS, Localization::Get(_T("apps.refresh_failed")));
	return TRUE;
}

void CApplicationPicker::OnRefresh() { if (!m_loading) BeginLoad(TRUE); }

void CApplicationPicker::FilterApplications()
{
	if (m_loading) return;
	if (m_listTooltip.GetSafeHwnd()) m_listTooltip.Activate(FALSE);
	m_hoverRow = -1;
	m_hoverText.Empty();
	CString search;
	m_search.GetWindowText(search);
	search.Trim();
	search.MakeLower();
	m_list.SetRedraw(FALSE);
	m_list.DeleteAllItems();
	for (size_t i = 0; i < m_applications.size(); ++i)
	{
		const InstalledApplications::Application& app = m_applications[i];
		CString searchable = app.name + L" " + app.path + L" " + app.aumid + L" " +
			app.arguments + L" " + app.workingDirectory + L" " + SourceSummary(app);
		for (size_t source = 0; source < app.sources.size(); ++source)
			searchable += L" " + app.sources[source].path;
		searchable.MakeLower();
		if (!search.IsEmpty() && searchable.Find(search) < 0) continue;
		const int row = m_list.InsertItem(m_list.GetItemCount(), app.name, m_iconIndices[i]);
		m_list.SetItemText(row, 1, SourceSummary(app));
		m_list.SetItemText(row, 2, LaunchText(app));
		m_list.SetItemData(row, i);
	}
	if (m_list.GetItemCount() > 0)
		m_list.SetItemState(0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
	m_list.SetRedraw(TRUE);
	m_list.Invalidate(FALSE);
	m_launch.EnableWindow(m_list.GetSelectedCount() != 0);
	const CString emptyText = Localization::Get(m_loadFailed ? _T("apps.load_failed") : _T("apps.no_matches"));
	SetEmptyState(m_list.GetItemCount() == 0 ? emptyText : CString());
	SetDlgItemText(IDC_APP_STATUS, m_list.GetItemCount() == 0 ? emptyText :
		Localization::Format(_T("apps.count"), m_list.GetItemCount()));
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
					if (index < m_applications.size()) m_hoverText = ItemDetails(m_applications[index]);
				}
				m_listTooltip.Activate(!m_hoverText.IsEmpty());
			}
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

void CApplicationPicker::OnSearchChanged() { if (m_list.GetSafeHwnd()) FilterApplications(); }

void CApplicationPicker::OnSelectionChanged(NMHDR*, LRESULT* result)
{
	m_launch.EnableWindow(!m_loading && m_list.GetSelectedCount() != 0);
	*result = 0;
}

void CApplicationPicker::OnDoubleClick(NMHDR* header, LRESULT* result)
{
	*result = 0;
	if (reinterpret_cast<NMITEMACTIVATE*>(header)->iItem >= 0) OnOK();
}

void CApplicationPicker::OnOK()
{
	const int row = m_list.GetNextItem(-1, LVNI_SELECTED);
	if (m_loading || row < 0) return;
	const size_t index = m_list.GetItemData(row);
	if (index >= m_applications.size()) return;
	m_selectedApplication = m_applications[index];
	m_selectedApplication.icon = NULL;
	CModernDialog::OnOK();
}

void CApplicationPicker::OnDestroy()
{
	KillTimer(1);
	if (m_listTooltip.GetSafeHwnd()) m_listTooltip.DestroyWindow();
	if (m_load)
	{
		m_load->Release();
		m_load = NULL;
	}
	CModernDialog::OnDestroy();
}
