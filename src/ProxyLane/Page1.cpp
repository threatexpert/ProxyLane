// Page1.cpp : 实现文件
//

#include "stdafx.h"
#include "ConfigStorage.h"
#include "SshProfile.h"
#include "ProxyLane.h"
#include "Page1.h"
#include "MainTab.h"
#include "Page2.h"
#include "Page3.h"
#include "Page4.h"
#include "IniFile.h"
#include "Base64.h"
#include "Localization.h"
#include "..\ProxyLaneHook\DnsRedirectPolicy.h"
#include "..\ProxyLaneHook\ProxyTransportPolicy.h"
#include <vector>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")


CIniFile g_ini;

// 子进程注入过滤运行时快照（启动代理或“保存并应用”时由 UI 提交）
struct ChildInjectFilterSnapshot
{
	BOOL bEnabled;                       // 等同于 bHookChildProcess
	int  nMode;                          // CHILDFILTER_MODE_*
	std::vector<CString> patterns;       // 通配符行
};
ChildInjectFilterSnapshot g_ChildInjectFilter = { FALSE, CHILDFILTER_MODE_INCLUDE };

// 目标地址过滤运行时快照（每次新连接在 GetProxyInfo 中匹配）
struct TargetInjectFilterSnapshot
{
	int  nMode;                          // TARGETFILTER_MODE_*
	std::vector<CString> patterns;       // 通配符行（host:port 或 ip:port）
};
TargetInjectFilterSnapshot g_TargetInjectFilter = { TARGETFILTER_MODE_BYPASS };
CCriticalSection g_childFilterLock;


// 把多行规则文本拆为 patterns 数组（trim、跳空行、跳 '#' 注释）
static void SplitFilterPatterns(const CString& multi, std::vector<CString>& out)
{
	out.clear();
	int start = 0;
	int len = multi.GetLength();
	for (int i = 0; i <= len; i++)
	{
		TCHAR c = (i < len) ? multi[i] : _T('\n');
		if (c == _T('\r') || c == _T('\n') || i == len)
		{
			if (i > start)
			{
				CString line = multi.Mid(start, i - start);
				line.TrimLeft();
				line.TrimRight();
				if (!line.IsEmpty() && line[0] != _T('#'))
					out.push_back(line);
			}
			if (c == _T('\r') && i + 1 < len && multi[i + 1] == _T('\n'))
				i++;
			start = i + 1;
		}
	}
}

// CPage1 对话框

IMPLEMENT_DYNAMIC(CPage1, CModernDialog)

CPage1::CPage1(CWnd* pParent /*=NULL*/)
	: CModernDialog(CPage1::IDD, pParent)
	, m_runtimeSettingsValid(FALSE)
	, m_runtimeDirty(FALSE)
	, m_profileDirty(FALSE)
	, m_loadingProfile(TRUE)
	, m_profileStore(g_ini)
	, m_activeTab(0)
	, m_scrollY(0)
	, m_inLayout(FALSE)
{
	m_pTestProxy = 0;
	m_pProxyTester = 0;
	m_bIsTesting = FALSE;
	m_proxyTestPhase = PROXY_TEST_NONE;
	m_testIpv6Result = IPV6_TEST_NOT_RUN;
	m_testUdpRequested = FALSE;
	m_ProxyInfo.reserved = 0;
	memset(&m_runtimeSettings, 0, sizeof(m_runtimeSettings));
}

CPage1::~CPage1()
{
	if (m_pProxyTester)
	{
		m_pProxyTester->Release();
		m_pProxyTester = NULL;
	}
	if (m_pTestProxy)
	{
		ReleaseGlobalProxyInstance();
		m_pTestProxy = NULL;
	}
}

void CPage1::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDOK, m_OK);
	DDX_Control(pDX, IDCANCEL, m_Cancel);

	DDX_Control(pDX, IDC_CB_PROXYTYPE, m_cbProxyType);
	DDX_Control(pDX, IDC_EDIT_ADDR, m_edit_HostName);
	DDX_Control(pDX, IDC_EDIT_PORT, m_edit_Port);
	DDX_Control(pDX, IDC_EDIT_USER, m_edit_User);
	DDX_Control(pDX, IDC_EDIT_PASS, m_edit_Pass);
	DDX_Control(pDX, IDC_COMBO_TRANSPORT, m_cbTransport);
	DDX_Control(pDX, IDC_EDIT_TRANSPORT_PSK, m_editTransportPsk);
	DDX_Control(pDX, IDC_TestProxy, m_btnTest);
	DDX_Control(pDX, IDC_CHECK_HOOKTCP, m_btnHookTCP);
	DDX_Control(pDX, IDC_CHECK_HOOK_UDP, m_btnHookUDP);
	DDX_Control(pDX, IDC_CHECK_BLOCKUDP, m_btnBlockUDP);
	DDX_Control(pDX, IDC_CHECK_BLOCK_IPV6, m_btnBlockIPv6);
	DDX_Control(pDX, IDC_RADIO_DNSLOCAL, m_btnDNSLocal);
	DDX_Control(pDX, IDC_RADIO_DNSREMOTE, m_btnDNSRemote);
	DDX_Control(pDX, IDC_CHECK_REDIRECT_PRIVATE_DNS, m_btnRedirectPrivateDNS);
	DDX_Control(pDX, IDC_EDIT_REDIRECT_DNS, m_editRedirectDNS);
	DDX_Control(pDX, IDC_CHECK_HOOKCHILDPROCESS, m_btnHookChildProcess);
	DDX_Control(pDX, IDC_EDIT_CHILDFILTER, m_editChildFilter);
	DDX_Control(pDX, IDC_RADIO_CHILDFILTER_EXCLUDE, m_radioChildFilterExclude);
	DDX_Control(pDX, IDC_RADIO_CHILDFILTER_INCLUDE, m_radioChildFilterInclude);
	DDX_Control(pDX, IDC_EDIT_TARGETFILTER, m_editTargetFilter);
	DDX_Control(pDX, IDC_RADIO_TARGETFILTER_BYPASS, m_radioTargetFilterBypass);
	DDX_Control(pDX, IDC_RADIO_TARGETFILTER_PROXY, m_radioTargetFilterProxy);
	DDX_Control(pDX, IDC_RADIO_TAB_BASIC, m_radioTabBasic);
	DDX_Control(pDX, IDC_RADIO_TAB_CHILD, m_radioTabChild);
	DDX_Control(pDX, IDC_RADIO_TAB_TARGET, m_radioTabTarget);
	DDX_Control(pDX, IDC_STATIC_TestProxy, m_staticTestProxy);
	DDX_Control(pDX, IDC_COMBO_CFGS, m_cfgls);
	DDX_Control(pDX, IDC_BUTTON_SAVE_PROFILE, m_btnSaveProfile);
	DDX_Control(pDX, IDC_BUTTON_PROFILE_MENU, m_btnProfileMenu);
	DDX_Control(pDX, IDC_STATIC_PROXY_GROUP, m_cardProxy);
	DDX_Control(pDX, IDC_STATIC_GROUP_OTHER, m_cardOptions);
	DDX_Control(pDX, IDC_STATIC_CHILDFILTER_GROUP, m_cardChildFilter);
	DDX_Control(pDX, IDC_STATIC_TARGETFILTER_GROUP, m_cardTargetFilter);
}


BEGIN_MESSAGE_MAP(CPage1, CModernDialog)
 ON_COMMAND(0x2401, &CPage1::OnNewProfile)
 ON_BN_CLICKED(0x2402, &CPage1::OnToggleAdvanced)
	ON_COMMAND(0x240B, &CPage1::OnNewChainProfile)
	ON_BN_CLICKED(0x2406, &CPage1::OnChainAdd)
	ON_BN_CLICKED(0x2407, &CPage1::OnChainUp)
	ON_BN_CLICKED(0x2408, &CPage1::OnChainDown)
	ON_BN_CLICKED(0x2409, &CPage1::OnChainRemove)
	ON_NOTIFY(LVN_ITEMCHANGED, 0x2405, &CPage1::OnChainItemChanged)

	ON_WM_SIZE()
	ON_WM_VSCROLL()
	ON_WM_MOUSEWHEEL()
	ON_BN_CLICKED(IDOK, &CPage1::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CPage1::OnBnClickedCancel)
	ON_WM_DESTROY()
	ON_BN_CLICKED(IDC_TestProxy, &CPage1::OnBnClickedTestproxy)
	ON_BN_CLICKED(IDC_BUTTON_SAVE_PROFILE, &CPage1::OnCfgoptSave)
	ON_BN_CLICKED(IDC_BUTTON_PROFILE_MENU, &CPage1::OnProfileMenu)
	ON_COMMAND(IDC_BUTTON_IMPORT_CONFIG, &CPage1::OnImportAllConfig)
	ON_COMMAND(IDC_BUTTON_COPY_PROFILE, &CPage1::OnCopyProfile)
	ON_COMMAND(IDC_BUTTON_PASTE_PROFILE, &CPage1::OnPasteProfile)
	ON_EN_CHANGE(IDC_EDIT_ADDR, &CPage1::OnEnChangeEditAddr)
	ON_EN_CHANGE(IDC_EDIT_PORT, &CPage1::OnProfileFieldChanged)
	ON_EN_CHANGE(IDC_EDIT_USER, &CPage1::OnProfileFieldChanged)
	ON_EN_CHANGE(IDC_EDIT_PASS, &CPage1::OnProfileFieldChanged)
	ON_EN_CHANGE(IDC_EDIT_TRANSPORT_PSK, &CPage1::OnProfileFieldChanged)
	ON_EN_CHANGE(IDC_EDIT_CHILDFILTER, &CPage1::OnProfileFieldChanged)
	ON_EN_CHANGE(IDC_EDIT_TARGETFILTER, &CPage1::OnProfileFieldChanged)
	ON_CBN_SELCHANGE(IDC_CB_PROXYTYPE, &CPage1::OnProtocolChanged)
	ON_CBN_SELCHANGE(IDC_COMBO_TRANSPORT, &CPage1::OnProfileFieldChanged)
	ON_CBN_EDITCHANGE(IDC_COMBO_CFGS, &CPage1::OnCbnEditchangeComboCfgs)
	ON_BN_CLICKED(IDC_CHECK_HOOKTCP, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_CHECK_HOOK_UDP, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_CHECK_BLOCKUDP, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_CHECK_BLOCK_IPV6, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_RADIO_DNSLOCAL, &CPage1::OnDnsSettingsChanged)
	ON_BN_CLICKED(IDC_RADIO_DNSREMOTE, &CPage1::OnDnsSettingsChanged)
	ON_BN_CLICKED(IDC_CHECK_REDIRECT_PRIVATE_DNS, &CPage1::OnDnsSettingsChanged)
	ON_EN_CHANGE(IDC_EDIT_REDIRECT_DNS, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_RADIO_CHILDFILTER_EXCLUDE, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_RADIO_CHILDFILTER_INCLUDE, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_RADIO_TARGETFILTER_BYPASS, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_RADIO_TARGETFILTER_PROXY, &CPage1::OnProfileFieldChanged)
	ON_COMMAND(IDC_BUTTON_DELETE_PROFILE, &CPage1::OnCfgoptDelete)
	ON_CBN_SELCHANGE(IDC_COMBO_CFGS, &CPage1::OnCbnSelchangeComboCfgs)
	ON_CBN_DROPDOWN(IDC_COMBO_CFGS, &CPage1::OnCbnDropdownComboCfgs)
	ON_BN_CLICKED(IDC_CHECK_HOOKCHILDPROCESS, &CPage1::OnBnClickedHookChildProcess)
	ON_BN_CLICKED(IDC_RADIO_TAB_BASIC, &CPage1::OnBnClickedTabBasic)
	ON_BN_CLICKED(IDC_RADIO_TAB_CHILD, &CPage1::OnBnClickedTabChild)
	ON_BN_CLICKED(IDC_RADIO_TAB_TARGET, &CPage1::OnBnClickedTabTarget)
	ON_MESSAGE(WM_RECENT_APPLICATIONS_CHANGED, &CPage1::OnRecentApplicationsChanged)
	ON_WM_TIMER()
END_MESSAGE_MAP()

BOOL CPage1::OnInitDialog()
{
	CModernDialog::OnInitDialog();

 m_btnAdvanced.Create(L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, CRect(), this, 0x2402);
 m_btnAdvanced.SetFont(&m_uiFont);
 m_btnAdvanced.SetWindowPos(&m_edit_Port, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
 m_btnAdvanced.SetBackdropColor(UiTheme::PageBackground());
 m_btnAdvanced.SetVisualStyle(CModernButton::STYLE_GHOST);
 UpdateAdvancedCaption();

	// The chain editor, created hidden; layout shows it for chain profiles.
	// Tab order follows the optional-section toggle.
	{
		CWnd* after = &m_btnAdvanced;
		auto order = [&after](CWnd& control) {
			control.SetWindowPos(after, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
			after = &control;
		};
		m_listChain.Create(WS_CHILD | WS_TABSTOP | WS_BORDER | LVS_REPORT | LVS_SINGLESEL |
			LVS_SHOWSELALWAYS | LVS_NOSORTHEADER, CRect(), this, 0x2405);
		m_listChain.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
		m_listChain.InsertColumn(0, L"#", LVCFMT_LEFT, UiTheme::ScaleForWindow(m_hWnd, 36));
		m_listChain.InsertColumn(1, Localization::Get(L"page1.chain_column_profile"), LVCFMT_LEFT,
			UiTheme::ScaleForWindow(m_hWnd, 180));
		m_listChain.InsertColumn(2, Localization::Get(L"page1.chain_column_server"), LVCFMT_LEFT,
			UiTheme::ScaleForWindow(m_hWnd, 320));
		struct { CModernButton* button; UINT id; LPCWSTR key; } buttons[] = {
			{ &m_btnChainAdd, 0x2406, L"page1.chain_add" }, { &m_btnChainUp, 0x2407, L"page1.chain_up" },
			{ &m_btnChainDown, 0x2408, L"page1.chain_down" }, { &m_btnChainRemove, 0x2409, L"page1.chain_remove" } };
		m_listChain.SetFont(&m_uiFont);
		order(m_listChain);
		for (auto& entry : buttons)
		{
			entry.button->Create(Localization::Get(entry.key), WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
				CRect(), this, entry.id);
			entry.button->SetFont(&m_uiFont);
			entry.button->SetBackdropColor(UiTheme::PageBackground());
			entry.button->SetVisualStyle(CModernButton::STYLE_SECONDARY);
			order(*entry.button);
		}
	}

	m_OK.SetVisualStyle(CModernButton::STYLE_PRIMARY);
	m_Cancel.SetVisualStyle(CModernButton::STYLE_DANGER);
	m_staticTestProxy.SetInlineStyle(TRUE);
	m_btnTest.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_btnSaveProfile.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_btnProfileMenu.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	UpdateProxyStateUi();

	m_cbProxyType.AddString(_T("NOPROXY"));
	m_cbProxyType.AddString(_T("SOCKS5"));
	m_cbProxyType.AddString(L"SSH");
	m_cbProxyType.AddString(_T("HTTP"));
	m_cbTransport.AddString(Localization::Get(_T("transport.plain")));
	m_cbTransport.AddString(Localization::Get(_T("transport.gonc_tls_psk")));
	m_cbTransport.SetCurSel(PROXY_TRANSPORT_PLAIN);
	UpdateTransportEnable();

	g_ini.SetIniFileName(_T(""));

	list<CfgProxyItem> cfgls;
	CString lastSelectedName;
	m_profileStore.LoadAll(cfgls, lastSelectedName);

	for (list<CfgProxyItem>::iterator it=cfgls.begin(); it!=cfgls.end(); it++)
	{
		CfgProxyItem &item = *it;

		m_cfgls.AddString(item.strName);
	}
	RefreshProfileEntries();

	UILoadCfg(NULL);

	if (!lastSelectedName.IsEmpty())
	{
		int idx = m_cfgls.FindStringExact(-1, lastSelectedName);
		if (idx >= 0)
		{
			m_cfgls.SetCurSel(idx);
			OnCfgoptLoad();
		}
	}

	m_bHookLanIP = g_ini.GetInt(_T("options"), _T("HookLanIP"), 1);
	m_bDisableLLMNR = g_ini.GetInt(_T("options"), _T("DisableLLMNR"), 1);
	m_bDisableMDNS = g_ini.GetInt(_T("options"), _T("DisableMDNS"), 1);

	ShowTab(0);
	LayoutSettingsPage();
	m_loadingProfile = FALSE;
	SetProfileDirty(FALSE);

	// First run: offer a named draft that still has to be saved once.
	if (m_cfgls.GetCount() == 0)
	{
		m_draftProfileName = _T("proxy");
		m_cfgls.SetWindowText(m_draftProfileName);
		SetProfileDirty(TRUE);
	}

	// A freshly created settings file holds only the Test placeholder
	// (127.0.0.1:1080) and Direct. Point the user at the server fields until a
	// profile is saved or enabled; MainTab opens this page while the guide is on.
	if (ConfigStorage::CreatedDefaults() || m_cfgls.GetCount() == 0)
	{
		m_firstRunGuide = TRUE;
		UpdateTransportEnable();
		LayoutSettingsPage();
	}

	return TRUE;
}

void CPage1::OnSize(UINT nType, int cx, int cy)
{
	CModernDialog::OnSize(nType, cx, cy);
	LayoutSettingsPage();
}

LRESULT CPage1::OnRecentApplicationsChanged(WPARAM, LPARAM)
{
	// The applications page owns the recent-app view; this page only keeps the
	// shared cache warm for the profile that is about to run.
	PreloadRecentApplications();
	return 0;
}

void CPage1::PreloadRecentApplications()
{
	const BOOL running = g_MainTab && g_MainTab->IsProxyRunning();
	RecentApplications::Preload(running ? g_MainTab->GetRunningProfileName() : GetCurrentProfileName(),
		RecentApplications::DefaultPath(), running ? g_MainTab->GetRunningRecentProfileId() : CString());
}

void CPage1::OnTimer(UINT_PTR timer)
{
	if (timer == 0x311) { KillTimer(0x311); PreloadRecentApplications(); }
	CModernDialog::OnTimer(timer);
}

void CPage1::UpdateWorkflowCard()
{
	// Only the "apps need attention" marker of the navigation remains.
	if (g_MainTab)
		g_MainTab->SetPageAttention(CMainTab::PAGE_APPLICATIONS, m_proxyController.IsRunning());
}

void CPage1::LayoutSettingsPage()
{
	if (!GetSafeHwnd() || !m_cfgls.GetSafeHwnd() || !m_OK.GetSafeHwnd() || !m_btnAdvanced.GetSafeHwnd() || m_inLayout)
		return;
	CRect client;
	GetClientRect(&client);
	if (client.Width() <= 0 || client.Height() <= 0)
		return;
	m_inLayout = TRUE;
	// WM_SETREDRAW TRUE also sets WS_VISIBLE, so only use it on a page that is shown.
	const BOOL freezeRedraw = IsWindowVisible();
	if (freezeRedraw) SetRedraw(FALSE);
	const int scroll = m_scrollY;

	auto S = [this](int value) { return UiTheme::ScaleForWindow(m_hWnd, value); };
	auto place = [this](UINT id, int x, int y, int width, int height)
	{
		CWnd* control = GetDlgItem(id);
		// Positions are in content coordinates; the page may be scrolled.
		if (control && control->GetSafeHwnd())
			control->SetWindowPos(NULL, x, y - m_scrollY, max(0, width), max(0, height), SWP_NOZORDER | SWP_NOACTIVATE);
	};
	auto textWidth = [this](UINT id) -> int
	{
		CWnd* control = GetDlgItem(id);
		if (!control || !control->GetSafeHwnd()) return 0;
		CString text;
		control->GetWindowText(text);
		CClientDC dc(control);
		CFont* font = control->GetFont();
		CFont* oldFont = font ? dc.SelectObject(font) : NULL;
		const int width = dc.GetTextExtent(text).cx;
		if (oldFont) dc.SelectObject(oldFont);
		return width;
	};

	const int margin = S(8);
	const int gap = S(8);
	const int gapX = S(12);
	const int pad = S(16);
	const int fieldH = S(26);
	const int labelH = S(18);
	const int rowStep = labelH + S(2) + fieldH + S(8);
	const int contentW = min(client.Width() - margin * 2, S(780));
	const int x0 = margin;
	const int innerX = x0 + pad;
	const int innerW = contentW - pad * 2;
	int y = S(64);

	// Selected combo fields should line up with the edit controls.
	m_cfgls.SetItemHeight(-1, fieldH - S(6));
	m_cfgls.SetItemHeight(0, S(40));
	m_cbProxyType.SetItemHeight(-1, fieldH - S(6));
	m_cbTransport.SetItemHeight(-1, fieldH - S(6));

	// Profile row. With enough width it shares the title row to save height.
	{
		const int saveW = max(S(84), textWidth(IDC_BUTTON_SAVE_PROFILE) + S(24));
		const int menuW = max(S(92), textWidth(IDC_BUTTON_PROFILE_MENU) + S(30));
		const int labelW = textWidth(IDC_STATIC_CONFIG_LABEL) + S(6);
		const int menuX = x0 + contentW - menuW;
		const int saveX = menuX - gap - saveW;
		const int inlineLeft = x0 + S(228);
		// Decide on the width without the scroll bar, otherwise showing the bar
		// can push this row down, which in turn keeps the bar visible.
		const int barWidth = (GetStyle() & WS_VSCROLL) ? ::GetSystemMetrics(SM_CXVSCROLL) : 0;
		const BOOL inlineProfile = saveX + barWidth - gap - (inlineLeft + labelW + S(8)) >= S(120);
		const int rowY = inlineProfile ? S(10) : y;
		if (CWnd* title = GetDlgItem(IDC_STATIC_PAGE_TITLE))
		{
			CRect titleRect;
			title->GetWindowRect(&titleRect);
			ScreenToClient(&titleRect);
			const int titleRight = inlineProfile ? inlineLeft - S(12) : x0 + contentW;
			place(IDC_STATIC_PAGE_TITLE, titleRect.left, S(4), max(0, titleRight - titleRect.left), S(36));
			if (CWnd* subtitle = GetDlgItem(IDC_STATIC_PAGE_SUBTITLE))
			{
				CRect subtitleRect;
				subtitle->GetWindowRect(&subtitleRect);
				ScreenToClient(&subtitleRect);
				place(IDC_STATIC_PAGE_SUBTITLE, subtitleRect.left, S(38), subtitleRect.Width(), S(18));
			}
		}
		const int left = inlineProfile ? inlineLeft : x0 + S(2);
		place(IDC_STATIC_CONFIG_LABEL, left, rowY + (fieldH - labelH) / 2, labelW, labelH);
		const int comboX = left + labelW + S(8);
		place(IDC_COMBO_CFGS, comboX, rowY, saveX - gap - comboX, S(260));
		// Rows carry a detail line; give the list room for addresses.
		m_cfgls.SetDroppedWidth(max(saveX - gap - comboX, S(360)));
		place(IDC_BUTTON_SAVE_PROFILE, saveX, rowY, saveW, fieldH);
		place(IDC_BUTTON_PROFILE_MENU, menuX, rowY, menuW, fieldH);
		y = inlineProfile ? S(62) : y + fieldH + S(12);
	}

	// Proxy server card.
	const int serverTop = y;
	{
		int row = serverTop + S(34);
		if (CWnd* hint = GetDlgItem(IDC_STATIC_UPSTREAM_HINT))
		{
			CString text;
			hint->GetWindowText(text);
			hint->ShowWindow(text.IsEmpty() ? SW_HIDE : SW_SHOWNA);
			if (!text.IsEmpty())
			{
				CClientDC dc(hint);
				CFont* font = hint->GetFont();
				CFont* oldFont = font ? dc.SelectObject(font) : NULL;
				CRect bounds(0, 0, max(1, innerW), 0);
				dc.DrawText(text, bounds, DT_LEFT | DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT);
				if (oldFont) dc.SelectObject(oldFont);
				const int hintHeight = max(labelH, bounds.Height());
				place(IDC_STATIC_UPSTREAM_HINT, innerX, row, innerW, hintHeight);
				row += hintHeight + S(12);
			}
		}
		const UINT serverIds[] = { IDC_STATIC_TYPE_LABEL, IDC_CB_PROXYTYPE, IDC_STATIC_HOST_LABEL,
			IDC_EDIT_ADDR, IDC_STATIC_PORT_LABEL, IDC_EDIT_PORT, 0x2402 };
		const UINT chainIds[] = { 0x2405, 0x2406, 0x2407, 0x2408, 0x2409 };
		for (int i = 0; i < _countof(serverIds); ++i)
			if (CWnd* control = GetDlgItem(serverIds[i]))
				control->ShowWindow(m_chainMode ? SW_HIDE : SW_SHOW);
		for (int i = 0; i < _countof(chainIds); ++i)
			if (CWnd* control = GetDlgItem(chainIds[i]))
				control->ShowWindow(m_chainMode ? SW_SHOW : SW_HIDE);
		if (m_chainMode)
		{
			const UINT optionalIds[] = { IDC_STATIC_USER_LABEL, IDC_EDIT_USER, IDC_STATIC_PASSWORD_LABEL, IDC_EDIT_PASS,
				IDC_STATIC_TRANSPORT_LABEL, IDC_COMBO_TRANSPORT, IDC_STATIC_PSK_LABEL, IDC_EDIT_TRANSPORT_PSK };
			for (int i = 0; i < _countof(optionalIds); ++i)
				if (CWnd* control = GetDlgItem(optionalIds[i]))
					control->ShowWindow(SW_HIDE);
			// Hop list (header + four rows), then its buttons.
			const int listH = S(26) * 5 + S(4);
			place(0x2405, innerX, row, innerW, listH);
			row += listH + S(8);
			const int addW = textWidth(0x2406) + S(30);
			place(0x2406, innerX, row, addW, fieldH);
			const int removeW = textWidth(0x2409) + S(24);
			const int downW = textWidth(0x2408) + S(24);
			const int upW = textWidth(0x2407) + S(24);
			int x = innerX + innerW - removeW;
			place(0x2409, x, row, removeW, fieldH);
			x -= gap + downW;
			place(0x2408, x, row, downW, fieldH);
			x -= gap + upW;
			place(0x2407, x, row, upW, fieldH);
			row += fieldH + S(12);
		}
		const int typeW = S(92), portW = S(64), endpointGap = S(8);
		const int advancedW = textWidth(0x2402) + S(16);
		const int minHostW = max(S(112), textWidth(IDC_STATIC_HOST_LABEL) + S(8));
		const bool inlineAdvanced = innerW >= typeW + minHostW + portW + advancedW + endpointGap * 3;
		// Reserve room for the optional toggle before growing the address field.
		// Cap its width in both layouts so wrapping never creates an oversized edit.
		const int hostW = min(S(220), inlineAdvanced
			? innerW - typeW - portW - advancedW - endpointGap * 3
			: innerW - typeW - endpointGap);
		if (!m_chainMode)
		{
		place(IDC_STATIC_TYPE_LABEL, innerX, row, typeW, labelH);
		place(IDC_CB_PROXYTYPE, innerX, row + labelH + S(2), typeW, S(260));
		place(IDC_STATIC_HOST_LABEL, innerX + typeW + endpointGap, row, hostW, labelH);
		place(IDC_EDIT_ADDR, innerX + typeW + endpointGap, row + labelH + S(2), hostW, fieldH);
		// Keep the optional-section toggle beside the port, including at narrow
		// widths where the pair moves together to the next row.
		if (!inlineAdvanced) row += rowStep;
		const int portX = inlineAdvanced ? innerX + typeW + hostW + endpointGap * 2 : innerX;
		place(IDC_STATIC_PORT_LABEL, portX, row, portW, labelH);
		place(IDC_EDIT_PORT, portX, row + labelH + S(2), portW, fieldH);
		place(0x2402, portX + portW + endpointGap, row + labelH + S(2), advancedW, fieldH);

		// Combined optional section follows lijing6006/ProxyLane PR #3.
		row += rowStep;
		const UINT advancedIds[] = { IDC_STATIC_USER_LABEL, IDC_EDIT_USER, IDC_STATIC_PASSWORD_LABEL, IDC_EDIT_PASS,
			IDC_STATIC_TRANSPORT_LABEL, IDC_COMBO_TRANSPORT, IDC_STATIC_PSK_LABEL, IDC_EDIT_TRANSPORT_PSK };
		for (int i = 0; i < _countof(advancedIds); ++i)
			if (CWnd* control = GetDlgItem(advancedIds[i]))
				control->ShowWindow(m_advancedOpen && !m_chainMode ? SW_SHOW : SW_HIDE);
		if (m_advancedOpen && !m_chainMode)
		{
			const int half = (innerW - gapX) / 2;
			place(IDC_STATIC_USER_LABEL, innerX, row, half, labelH);
			place(IDC_EDIT_USER, innerX, row + labelH + S(2), half, fieldH);
			place(IDC_STATIC_PASSWORD_LABEL, innerX + half + gapX, row, half, labelH);
			place(IDC_EDIT_PASS, innerX + half + gapX, row + labelH + S(2), half, fieldH);

			row += rowStep;
			CString protocol; m_cbProxyType.GetWindowText(protocol);
            const bool ssh = protocol == L"SSH";
            GetDlgItem(IDC_STATIC_TRANSPORT_LABEL)->ShowWindow(ssh ? SW_HIDE : SW_SHOW);
            m_cbTransport.ShowWindow(ssh ? SW_HIDE : SW_SHOW);
            const int transportW = S(200);
            const int pskOffset = ssh ? 0 : transportW + gapX;
            const int pskW = innerW - pskOffset;
            if (!ssh) {
                place(IDC_STATIC_TRANSPORT_LABEL, innerX, row, transportW, labelH);
                place(IDC_COMBO_TRANSPORT, innerX, row + labelH + S(2), transportW, S(260));
            }
            place(IDC_STATIC_PSK_LABEL, innerX + pskOffset, row, pskW, labelH);
            place(IDC_EDIT_TRANSPORT_PSK, innerX + pskOffset, row + labelH + S(2), pskW, fieldH);
			row += rowStep;
		}
		}

		row += S(2);
		const int buttonH = S(30);
		const int testW = max(S(110), textWidth(IDC_TestProxy) + S(24));
		// Enable and Disable share one slot (only the one matching the state is
		// shown), sized for the wider caption so the row does not shift on toggle.
		const int stateW = max(S(88), max(textWidth(IDOK), textWidth(IDCANCEL)) + S(24));
		const int stateX = innerX + innerW - stateW;
		const int testX = stateX - gap - testW;
		// On a narrow page the test status gets its own line above the buttons.
		const BOOL statusOwnRow = testX - gap - innerX < S(120);
		if (statusOwnRow)
		{
			place(IDC_STATIC_TestProxy, innerX, row, innerW, S(28));
			row += S(34);
		}
		else
		{
			place(IDC_STATIC_TestProxy, innerX, row, testX - gap - innerX, buttonH);
		}
		place(IDC_TestProxy, max(innerX, testX), row, testW, buttonH);
		place(IDOK, max(innerX, stateX), row, stateW, buttonH);
		place(IDCANCEL, max(innerX, stateX), row, stateW, buttonH);
		y = row + buttonH + S(14);
		place(IDC_STATIC_PROXY_GROUP, x0, serverTop, contentW, y - serverTop);
		y += S(12);
	}

	// Section switcher.
	{
		const UINT ids[] = { IDC_RADIO_TAB_BASIC, IDC_RADIO_TAB_CHILD, IDC_RADIO_TAB_TARGET };
		int x = x0 + S(4);
		for (int i = 0; i < _countof(ids); ++i)
		{
			const int width = textWidth(ids[i]) + S(30);
			place(ids[i], x, y, width, S(24));
			x += width + S(14);
		}
		y += S(24) + S(6);
	}

	// Section card: the three option groups share one frame rectangle.
	{
		const int top = y;
		// 24px switches on a 38px pitch leave visible air between option rows.
		const int rowH = S(38);
		const int checkH = S(24);
		int row = top + S(34);
        // Size switches by their label plus the track; wrap whole controls on
        // narrow windows rather than losing the end of a setting's name.
        auto flow = [&](std::initializer_list<UINT> ids, int extra, int start) {
            int left = start;
            for (UINT id : ids) {
                const int w = min(innerW, textWidth(id) + S(extra));
                if (left > innerX && left + w > innerX + innerW) { row += rowH; left = innerX; }
                place(id, left, row, w, checkH); left += w + S(12);
            }
            row += rowH;
        };
        flow({IDC_CHECK_HOOKTCP, IDC_CHECK_HOOK_UDP, IDC_CHECK_HOOKCHILDPROCESS}, 44, innerX);
        flow({IDC_CHECK_BLOCKUDP, IDC_CHECK_BLOCK_IPV6}, 44, innerX);
        const int dnsLabelW = textWidth(IDC_STATIC_DNS_LABEL) + S(12);
        place(IDC_STATIC_DNS_LABEL, innerX, row + S(4), dnsLabelW, labelH);
        flow({IDC_RADIO_DNSLOCAL, IDC_RADIO_DNSREMOTE}, 24, innerX + dnsLabelW);
        const int redirectW = min(innerW, textWidth(IDC_CHECK_REDIRECT_PRIVATE_DNS) + S(44));
        place(IDC_CHECK_REDIRECT_PRIVATE_DNS, innerX, row, redirectW, checkH);
        if (innerW - redirectW - S(12) < S(120)) {
            row += rowH;
            place(IDC_EDIT_REDIRECT_DNS, innerX, row, innerW, fieldH);
        } else {
            place(IDC_EDIT_REDIRECT_DNS, innerX + redirectW + S(12), row - (fieldH - checkH) / 2,
                innerW - redirectW - S(12), fieldH);
        }
        const int height = m_activeTab == 0 ? row + max(fieldH, checkH) + S(16) - top
            : max(S(220), client.Height() - margin - top);
        const CRect frame(x0, top, x0 + contentW, top + height);
        place(IDC_STATIC_GROUP_OTHER, frame.left, frame.top, frame.Width(), frame.Height());
        place(IDC_STATIC_CHILDFILTER_GROUP, frame.left, frame.top, frame.Width(), frame.Height());
        place(IDC_STATIC_TARGETFILTER_GROUP, frame.left, frame.top, frame.Width(), frame.Height());

		// Child process and target filters share the same arrangement.
		const int filterRadioTop = top + S(34);
		const int hintH = S(36);
		const int hintY = frame.bottom - pad - hintH + S(4);
		const int editY = filterRadioTop + S(32);
		const int editH = max(S(48), hintY - S(6) - editY);
		place(IDC_RADIO_CHILDFILTER_EXCLUDE, innerX, filterRadioTop, S(190), checkH);
		place(IDC_RADIO_CHILDFILTER_INCLUDE, innerX + S(200), filterRadioTop, S(200), checkH);
		place(IDC_EDIT_CHILDFILTER, innerX, editY, innerW, editH);
		place(IDC_STATIC_CHILDFILTER_HINT, innerX, hintY, innerW, hintH);
		place(IDC_RADIO_TARGETFILTER_BYPASS, innerX, filterRadioTop, S(190), checkH);
		place(IDC_RADIO_TARGETFILTER_PROXY, innerX + S(200), filterRadioTop, S(200), checkH);
		place(IDC_EDIT_TARGETFILTER, innerX, editY, innerW, editH);
		place(IDC_STATIC_TARGETFILTER_HINT, innerX, hintY, innerW, hintH);
		y = frame.bottom + margin;
	}

	// Scroll range follows the content; showing or hiding the bar changes the
	// client width, which needs one more pass.
	const int maxScroll = max(0, y - client.Height());
	SCROLLINFO info = { sizeof(info), SIF_RANGE | SIF_PAGE | SIF_POS, 0, y - 1, static_cast<UINT>(client.Height()),
		min(scroll, maxScroll) };
	SetScrollInfo(SB_VERT, &info, TRUE);
	CRect after;
	GetClientRect(&after);
	if (freezeRedraw) SetRedraw(TRUE);
	m_inLayout = FALSE;
	if (scroll > maxScroll || after.Width() != client.Width())
	{
		m_scrollY = min(scroll, maxScroll);
		LayoutSettingsPage();
		return;
	}
	RedrawWindow(NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME);
}

void CPage1::OnVScroll(UINT code, UINT position, CScrollBar* scrollBar)
{
	SCROLLINFO info = { sizeof(info), SIF_ALL };
	GetScrollInfo(SB_VERT, &info);
	const int line = UiTheme::ScaleForWindow(m_hWnd, 40);
	int next = m_scrollY;
	switch (code)
	{
	case SB_LINEUP: next -= line; break;
	case SB_LINEDOWN: next += line; break;
	case SB_PAGEUP: next -= static_cast<int>(info.nPage) - line; break;
	case SB_PAGEDOWN: next += static_cast<int>(info.nPage) - line; break;
	case SB_THUMBTRACK:
	case SB_THUMBPOSITION: next = info.nTrackPos; break;
	case SB_TOP: next = 0; break;
	case SB_BOTTOM: next = info.nMax; break;
	default: CModernDialog::OnVScroll(code, position, scrollBar); return;
	}
	next = max(0, min(next, info.nMax - static_cast<int>(info.nPage) + 1));
	if (next != m_scrollY)
	{
		m_scrollY = next;
		LayoutSettingsPage();
	}
}

BOOL CPage1::OnMouseWheel(UINT flags, short delta, CPoint point)
{
	SCROLLINFO info = { sizeof(info), SIF_ALL };
	GetScrollInfo(SB_VERT, &info);
	const int maxScroll = max(0, info.nMax - static_cast<int>(info.nPage) + 1);
	if (maxScroll <= 0)
		return CModernDialog::OnMouseWheel(flags, delta, point);
	const int next = max(0, min(maxScroll, m_scrollY - delta * UiTheme::ScaleForWindow(m_hWnd, 60) / WHEEL_DELTA));
	if (next != m_scrollY)
	{
		m_scrollY = next;
		LayoutSettingsPage();
	}
	return TRUE;
}

BOOL CPage1::UsesSecondaryText(UINT controlId) const
{
	switch (controlId)
	{
	case IDC_STATIC_TYPE_LABEL:
	case IDC_STATIC_HOST_LABEL:
	case IDC_STATIC_PORT_LABEL:
	case IDC_STATIC_USER_LABEL:
	case IDC_STATIC_PASSWORD_LABEL:
	case IDC_STATIC_TRANSPORT_LABEL:
	case IDC_STATIC_PSK_LABEL:
	case IDC_STATIC_DNS_LABEL:
	case IDC_STATIC_CHILDFILTER_HINT:
	case IDC_STATIC_TARGETFILTER_HINT:
	case IDC_STATIC_UPSTREAM_HINT:
		return TRUE;
	}
	return CModernDialog::UsesSecondaryText(controlId);
}

BOOL CPage1::GetProxyInfo(const LPPRCClient pPRCC, LPProxyInfo lpPI)
{
	if (!pPRCC || !lpPI)
		return FALSE;

	CSingleLock runtimeLock(&m_runtimeLock, TRUE);
	if (!m_runtimeSettingsValid)
		return FALSE;

	*lpPI = m_ProxyInfo;

	// RFC 1928 permits an all-zero endpoint when the client cannot reliably
	// report the address and port used to reach a remote SOCKS server.  The
	// ProxyLane UDP relay uses a separate ephemeral socket, so its local
	// endpoint may be unusable across NAT or on a multi-homed host.
	if (pPRCC->sType == SOCK_DGRAM && lpPI->GetProxyType() == PROXYTYPE_SOCKS5)
	{
		pPRCC->uaFlag = UAF_SET_ADDR | UAF_SET_PORT;
		pPRCC->udpAddr.SetIPLong(0);
		pPRCC->udpAddr.SetPort(0);
	}

	// 目标地址过滤：按 UI 配置决定本连接是走代理还是直连（NOPROXY）
	if (!g_TargetInjectFilter.patterns.empty())
	{
		// 构造匹配 key：与日志一致 —— 有 hostname 用 hostname:port，否则 ip:port
		CString strKey;
		DWORD nIP = pPRCC->dstAddr.GetdwIP();
		const BYTE* p = (BYTE*)&nIP;
		int nPort = pPRCC->dstAddr.GetPort();
		if (pPRCC->szDomainName[0])
		{
			CString strHost(pPRCC->szDomainName);
			strKey.Format(_T("%s:%d"), (LPCTSTR)strHost, nPort);
		}
		else
		{
			if (pPRCC->dstAddr.IsIPv6())
			{
				TCHAR addressText[INET6_ADDRSTRLEN] = { 0 };
#ifdef _UNICODE
				ProxyInetNtopW(AF_INET6, (PVOID)pPRCC->dstAddr.GetAddr6(),
					addressText, _countof(addressText));
#else
				ProxyInetNtopA(AF_INET6, (PVOID)pPRCC->dstAddr.GetAddr6(),
					addressText, _countof(addressText));
#endif
				strKey.Format(_T("[%s]:%d"), addressText, nPort);
			}
			else
				strKey.Format(_T("%u.%u.%u.%u:%d"), p[0], p[1], p[2], p[3], nPort);
		}

		BOOL bMatched = FALSE;
		for (size_t i = 0; i < g_TargetInjectFilter.patterns.size(); i++)
		{
			CString pat = g_TargetInjectFilter.patterns[i];
#ifdef _UNICODE
			if (PathMatchSpecW(strKey, pat))
#else
			if (PathMatchSpecA(strKey, pat))
#endif
			{
				bMatched = TRUE;
				break;
			}
		}

		// BYPASS 模式：匹配的放行；PROXY 模式：仅匹配的走代理
		BOOL bGoProxy = (g_TargetInjectFilter.nMode == TARGETFILTER_MODE_PROXY) ? bMatched : !bMatched;
		if (!bGoProxy)
		{
			// 放行连接使用独立的直连配置，不继承代理的加密传输设置
			ProxyTransportPolicy::UseDirectConnection(*lpPI);
		}
	}

	return TRUE;
}

INT CPage1::GetProxyChain(const LPPRCClient pPRCC, LPProxyInfo lpHops, INT nCapacity)
{
	// The caller asks only for a connection GetProxyInfo routed through a
	// proxy, so the target filter has already had its say.
	if (!pPRCC || pPRCC->sType != SOCK_STREAM)
		return 0;
	CSingleLock runtimeLock(&m_runtimeLock, TRUE);
	if (!m_runtimeSettingsValid || m_runtimeChain.size() < 2)
		return 0;
	const INT hops = (INT)m_runtimeChain.size();
	if (lpHops && nCapacity >= hops)
		std::copy(m_runtimeChain.begin(), m_runtimeChain.end(), lpHops);
	return hops;
}

BOOL CPage1::GetProxySettings(LPProxySettingsInfo lpPSI)
{
	if (!lpPSI)
		return FALSE;

	CSingleLock runtimeLock(&m_runtimeLock, TRUE);
	if (!m_runtimeSettingsValid)
		return FALSE;

	*lpPSI = m_runtimeSettings;
	return TRUE;
}

BOOL CPage1::GetProxySettingsFromUi(LPProxySettingsInfo lpPSI)
{
	if (!lpPSI)
		return FALSE;

	ProxySettingsInfo psi;
	memset(&psi, 0, sizeof(psi));

	psi.bHookTCP = m_btnHookTCP.GetCheck() == BST_CHECKED;
	psi.bHookUDP = m_btnHookUDP.GetCheck() == BST_CHECKED;
	psi.bBlockUDP = m_btnBlockUDP.GetCheck() == BST_CHECKED;
	psi.bBlockIPv6 = m_btnBlockIPv6.GetCheck() == BST_CHECKED;
	psi.bHookCreateProcess = m_btnHookChildProcess.GetCheck();
	psi.nDNSOption = m_btnDNSLocal.GetCheck() ? PSI_DNSOPT_LOCAL : PSI_DNSOPT_REMOTE;
	psi.bHookLanIP = m_bHookLanIP;
	psi.bDisableLLMNR = m_bDisableLLMNR;
	psi.bDisableMDNS = m_bDisableMDNS;
	psi.bRedirectPrivateDNS = m_btnDNSRemote.GetCheck() == BST_CHECKED &&
		m_btnRedirectPrivateDNS.GetCheck() == BST_CHECKED;
	psi.redirectDNSAddr.Clear();
	CString redirectDNS;
	m_editRedirectDNS.GetWindowText(redirectDNS);
	CStringA redirectDNSA(redirectDNS);
	if (!psi.redirectDNSAddr.SetIP(redirectDNSA) ||
		!DnsRedirectPolicy::IsValidPublicResolver(psi.redirectDNSAddr))
	{
		psi.bRedirectPrivateDNS = FALSE;
		psi.redirectDNSAddr.Clear();
	}

	*lpPSI = psi;
	return TRUE;
}

BOOL CPage1::GetSettings(OUT LPProxyInfo lpPI)
{
	m_settingsValidationKey = _T("profile.invalid_endpoint");
	m_settingsValidationName.Empty();

	CString szType, szHost, szPort, szUser, szPass, szTransportPsk;

	const int typeIndex = m_cbProxyType.GetCurSel();
	if (typeIndex == CB_ERR)
	{
		m_settingsValidationKey = L"profile.unsupported_type";
		return FALSE;
	}
	m_cbProxyType.GetLBText(typeIndex, szType);
	if (szType != L"NOPROXY" && szType != L"SOCKS5" && szType != L"HTTP" && szType != L"SSH")
	{
		m_settingsValidationKey = L"profile.unsupported_type";
		return FALSE;
	}
	m_edit_HostName.GetWindowText(szHost);
	m_edit_Port.GetWindowText(szPort);
	m_edit_User.GetWindowText(szUser);
	m_edit_Pass.GetWindowText(szPass);
	m_editTransportPsk.GetWindowText(szTransportPsk);
	const int transportMode = m_cbTransport.GetCurSel() ==
		PROXY_TRANSPORT_GONC_TLS_PSK
		? PROXY_TRANSPORT_GONC_TLS_PSK : PROXY_TRANSPORT_PLAIN;
	ProxyInfo pi;
	pi.szItemName = _T("myproxy");
	pi.strProxyType = szType;
	pi.strProxyHost = szHost;
	pi.nProxyPort = _ttoi(szPort);
	pi.strProxyUser = szUser;
	pi.strProxyPass = szPass;
	pi.reserved = transportMode;

	if (szType.CompareNoCase(_T("NOPROXY")) == 0)
	{
		// Keep the explicit profile type, but discard irrelevant proxy settings.
		pi.strProxyHost = _T("");
		pi.nProxyPort = 0;
		pi.strProxyUser = _T("");
		pi.strProxyPass = _T("");
		pi.reserved = PROXY_TRANSPORT_PLAIN;
		SecureZeroMemory(pi.strTransportPsk.szbuf, sizeof(pi.strTransportPsk.szbuf));
		*lpPI = pi;
		return TRUE;
	}

	if (!szHost.GetLength() || !szPort.GetLength() || _ttoi(szPort) <= 0 || _ttoi(szPort) > 65535)
		return FALSE;
    if (szType == L"SSH") {
        szTransportPsk.Trim();
        if (szUser.IsEmpty() || !SshProfile::Encode(szUser, pi.strProxyUser.szbuf) ||
            !SshProfile::Encode(szPass, pi.strProxyPass.szbuf) ||
            !SshProfile::ValidFingerprint(szTransportPsk) ||
            !SshProfile::Encode(szTransportPsk, pi.strTransportPsk.szbuf)) {
            m_settingsValidationKey = L"profile.ssh_invalid"; return FALSE;
        }
    }
	if (transportMode == PROXY_TRANSPORT_GONC_TLS_PSK)
	{
		if (!ProxySupportsOptionalModules())
		{
			m_settingsValidationKey = _T("profile.secure_transport_unavailable");
			return FALSE;
		}
		if (!ProxyTransportPolicy::SupportsGoncTlsPsk(pi.GetProxyType()))
		{
			m_settingsValidationKey = _T("profile.secure_transport_unsupported");
			return FALSE;
		}
		if (szTransportPsk.IsEmpty())
		{
			m_settingsValidationKey = _T("profile.psk_required");
			return FALSE;
		}
	}
	if (transportMode == PROXY_TRANSPORT_GONC_TLS_PSK)
	{
#ifdef _UNICODE
		int required = WideCharToMultiByte(CP_UTF8, 0, szTransportPsk,
			szTransportPsk.GetLength(), NULL, 0, NULL, NULL);
		if (required <= 0 || required >= (int)sizeof(pi.strTransportPsk.szbuf))
			return FALSE;
		WideCharToMultiByte(CP_UTF8, 0, szTransportPsk,
			szTransportPsk.GetLength(), pi.strTransportPsk.szbuf, required,
			NULL, NULL);
		pi.strTransportPsk.szbuf[required] = '\0';
#else
		if (szTransportPsk.GetLength() >= (int)sizeof(pi.strTransportPsk.szbuf))
			return FALSE;
		strcpy_s(pi.strTransportPsk.szbuf, szTransportPsk);
#endif
	}

	*lpPI = pi;
	return TRUE;
}

BOOL CPage1::GetRoute(LPProxyInfo first, ProxyChain* chain)
{
	chain->clear();
	if (!m_chainMode)
		return GetSettings(first);

	m_settingsValidationName.Empty();
	if (!m_profileStore.ResolveChain(m_chainHops, *chain, m_settingsValidationKey,
		m_settingsValidationName))
		return FALSE;
	for (size_t i = 0; i < chain->size(); ++i)
	{
		if ((*chain)[i].reserved == PROXY_TRANSPORT_GONC_TLS_PSK && !ProxySupportsOptionalModules())
		{
			m_settingsValidationKey = _T("profile.secure_transport_unavailable");
			m_settingsValidationName = m_chainHops[i];
			chain->clear();
			return FALSE;
		}
	}
	*first = chain->front();
	return TRUE;
}

CString CPage1::SettingsValidationMessage() const
{
	// Chain errors name the hop; the others take no argument.
	return m_settingsValidationName.IsEmpty()
		? Localization::Get(m_settingsValidationKey)
		: Localization::Format(m_settingsValidationKey, (LPCTSTR)m_settingsValidationName);
}

void CPage1::OnBnClickedOk()
{
	StartProxy(TRUE);
}

BOOL CPage1::LoadProfileByName(LPCTSTR profileName, BOOL rememberSelection)
{
	if (!profileName || !profileName[0])
		return FALSE;

	int index = m_cfgls.FindStringExact(-1, profileName);
	if (index == CB_ERR)
		return FALSE;

	CfgProxyItem item;
	m_cfgls.GetLBText(index, item.strName);
	if (!m_profileStore.Load(item))
		return FALSE;

	m_cfgls.SetCurSel(index);
	UILoadCfg(&item);
	if (rememberSelection)
		m_profileStore.SetLastSelected(item.strName);
	return TRUE;
}

void CPage1::GetSavedProfileNames(std::vector<CString>& names)
{
	names.clear();
	const int count = m_cfgls.GetCount();
	for (int index = 0; index < count; ++index)
	{
		CString name;
		m_cfgls.GetLBText(index, name);
		if (!name.IsEmpty())
			names.push_back(name);
	}
}

void CPage1::SetProfileDirty(BOOL dirty)
{
	m_profileDirty = dirty;
	if (m_OK.GetSafeHwnd())
		UpdateProxyStateUi();
	else if (m_btnSaveProfile.GetSafeHwnd())
		m_btnSaveProfile.EnableWindow(dirty);

	if (!m_bIsTesting && m_staticTestProxy.GetSafeHwnd())
		UpdateProxyTestStatus();
}

void CPage1::SetRuntimeDirty(BOOL dirty)
{
	m_runtimeDirty = m_proxyController.IsRunning() ? dirty : FALSE;
	if (!m_bIsTesting && m_staticTestProxy.GetSafeHwnd())
		UpdateProxyTestStatus();
	if (m_OK.GetSafeHwnd())
		UpdateProxyStateUi();
}

void CPage1::OnProfileFieldChanged()
{
	UpdateTransportEnable();
	if (!m_loadingProfile)
	{
		SetProfileDirty(TRUE);
		SetRuntimeDirty(TRUE);
	}
}

void CPage1::OnProtocolChanged()
{
    // A TLS PSK and an SSH host-key pin have different meanings.
    const bool wasSsh = m_editTransportPsk.GetPasswordChar() == 0;
    CString protocol; m_cbProxyType.GetWindowText(protocol);
    ProxyInfo selectedProxy;
    selectedProxy.strProxyType = protocol;
    // Apply the default on a protocol selection, not on every UI refresh,
    // so users can still explicitly choose to allow direct UDP traffic.
    if (!m_loadingProfile && m_cbProxyType.GetCurSel() != CB_ERR &&
        !ProxyTransportPolicy::SupportsUdpProxy(selectedProxy.GetProxyType()))
        m_btnBlockUDP.SetCheck(BST_CHECKED);
    if (wasSsh || protocol == L"SSH") m_editTransportPsk.SetWindowText(L"");
    if (protocol == L"SSH") {
        m_advancedOpen = TRUE; UpdateAdvancedCaption();
        CString port; m_edit_Port.GetWindowText(port);
        if (port.IsEmpty() || port == L"1080" || port == L"8080") m_edit_Port.SetWindowText(L"22");
    }
    OnProfileFieldChanged(); LayoutSettingsPage();
}

void CPage1::UpdateTransportEnable()
{
	if (!m_editTransportPsk.GetSafeHwnd() || !m_cbTransport.GetSafeHwnd())
		return;
	CString proxyType;
	const int typeIndex = m_cbProxyType.GetCurSel();
	if (typeIndex != CB_ERR)
		m_cbProxyType.GetLBText(typeIndex, proxyType);
	ProxyInfo selectedProxy;
	selectedProxy.strProxyType = proxyType;
	const int selectedProxyType = selectedProxy.GetProxyType();
    const BOOL ssh = selectedProxyType == PROXYTYPE_SSH;
	// A chain's own (hidden) server fields do not describe the route.
	const BOOL direct = !m_chainMode && proxyType.CompareNoCase(_T("NOPROXY")) == 0;
	const CString group = Localization::Get(m_chainMode ? L"page1.chain_group" :
		direct ? L"page1.direct_group" : L"page1.proxy_group");
	const CString hint = m_chainMode ? Localization::Get(L"page1.chain_hint") :
		typeIndex == CB_ERR ? Localization::Get(L"profile.unsupported_type") :
		direct ? Localization::Get(L"page1.direct_hint") :
        ssh ? Localization::Get(L"page1.ssh_hint") :
		m_firstRunGuide ? Localization::Get(L"page1.first_run_hint") : CString();
	CString previousHint, previousGroup;
	GetDlgItemText(IDC_STATIC_UPSTREAM_HINT, previousHint);
	GetDlgItemText(IDC_STATIC_PROXY_GROUP, previousGroup);
	if (previousGroup != group) SetDlgItemText(IDC_STATIC_PROXY_GROUP, group);
	if (previousHint != hint) SetDlgItemText(IDC_STATIC_UPSTREAM_HINT, hint);
	m_edit_HostName.EnableWindow(!direct);
	m_edit_Port.EnableWindow(!direct);
	m_edit_User.EnableWindow(!direct);
	m_edit_Pass.EnableWindow(!direct);
	m_btnHookTCP.SetWindowText(Localization::Get(direct
		? _T("page1.direct_tcp") : _T("page1.proxy_tcp")));
	m_btnHookUDP.SetWindowText(Localization::Get(direct
		? _T("page1.direct_udp") : _T("page1.proxy_udp")));
	m_btnBlockUDP.SetWindowText(Localization::Get(direct
		? _T("page1.direct_block_udp") : _T("page1.block_udp")));
	const BOOL supportsSecureTransport =
		ProxyTransportPolicy::SupportsGoncTlsPsk(selectedProxyType);
	// Preserve an encrypted profile on unsupported hosts; never silently downgrade it.
	const BOOL supportsModules = ProxySupportsOptionalModules();
	if (direct || ssh || (typeIndex != CB_ERR && supportsModules && !supportsSecureTransport))
		m_cbTransport.SetCurSel(PROXY_TRANSPORT_PLAIN);
	m_cbTransport.EnableWindow(supportsModules && supportsSecureTransport);
	m_editTransportPsk.EnableWindow(ssh || (supportsModules && supportsSecureTransport &&
        m_cbTransport.GetCurSel() == PROXY_TRANSPORT_GONC_TLS_PSK));
    SetDlgItemText(IDC_STATIC_PSK_LABEL, Localization::Get(ssh ? L"ssh.host_key" : L"common.psk"));
    const TCHAR passwordChar = ssh ? 0 : L'\x25cf';
    if (m_editTransportPsk.GetPasswordChar() != passwordChar) {
        m_editTransportPsk.SetPasswordChar(passwordChar); m_editTransportPsk.Invalidate();
    }
	if (m_btnHookUDP.GetSafeHwnd())
	{
		// UDP never goes through a chain.
		const BOOL supportsUdp = !m_chainMode &&
			typeIndex != CB_ERR && ProxyTransportPolicy::SupportsUdpProxy(selectedProxyType);
		if ((typeIndex != CB_ERR || m_chainMode) && !supportsUdp)
			m_btnHookUDP.SetCheck(BST_UNCHECKED);
		m_btnHookUDP.EnableWindow(supportsUdp);
	}
	UpdateProfileTag();
	if (previousHint != hint) LayoutSettingsPage();
}

void CPage1::OnDnsSettingsChanged()
{
	UpdateDnsRedirectEnable();
	OnProfileFieldChanged();
}

void CPage1::UpdateDnsRedirectEnable()
{
	const BOOL remote = m_btnDNSRemote.GetCheck() == BST_CHECKED;
	m_btnRedirectPrivateDNS.EnableWindow(remote);
	m_editRedirectDNS.EnableWindow(remote &&
		m_btnRedirectPrivateDNS.GetCheck() == BST_CHECKED);
}

BOOL CPage1::ValidateDnsRedirectSettings(BOOL showError)
{
	if (m_btnDNSRemote.GetCheck() != BST_CHECKED ||
		m_btnRedirectPrivateDNS.GetCheck() != BST_CHECKED)
		return TRUE;

	CString resolver;
	m_editRedirectDNS.GetWindowText(resolver);
	resolver.Trim();
	CStringA resolverA(resolver);
	_SockAddr address;
	address.Clear();
	if (address.SetIP(resolverA) &&
		DnsRedirectPolicy::IsValidPublicResolver(address))
		return TRUE;

	if (showError)
	{
		MessageBox(Localization::Get(_T("profile.invalid_redirect_dns")),
			Localization::Get(_T("status.invalid_config")), MB_ICONERROR);
	}
	return FALSE;
}

void CPage1::OnCbnEditchangeComboCfgs()
{
	if (m_loadingProfile)
		return;
	m_cfgls.GetWindowText(m_draftProfileName);
	m_draftProfileName.Trim();
	SetProfileDirty(TRUE);
}

BOOL CPage1::SaveCurrentProfile(LPCTSTR profileName)
{
	CfgProxyItem item;
	if (profileName && profileName[0])
		item.strName = profileName;
	else
		m_cfgls.GetWindowText(item.strName);
	item.strName.Trim();

	if (item.strName.IsEmpty())
	{
		MessageBox(Localization::Get(_T("profile.name_required")),
			Localization::Get(_T("profile.save_failed_title")), MB_ICONINFORMATION);
		return FALSE;
	}
	// A profile keeps the type it was created with: never let a draft of the
	// other type overwrite it.
	{
		std::vector<CString> names;
		m_profileStore.ListNames(names);
		for (const CString& name : names)
		{
			if (name.CompareNoCase(item.strName) != 0)
				continue;
			CfgProxyItem existing;
			existing.strName = name;
			m_profileStore.Load(existing); // sets the type even for an invalid server profile
			if (!existing.bChain != !m_chainMode)
			{
				MessageBox(Localization::Format(_T("profile.type_conflict"), (LPCTSTR)item.strName),
					Localization::Get(_T("profile.save_failed_title")), MB_ICONINFORMATION);
				return FALSE;
			}
		}
	}
	// A chain may be saved before it is complete; it is checked when enabled.
	if (!m_chainMode && !GetSettings(&item.pi))
	{
		MessageBox(SettingsValidationMessage(),
			Localization::Get(_T("profile.save_failed_title")), MB_ICONERROR);
		return FALSE;
	}
	if (!ValidateDnsRedirectSettings(TRUE))
		return FALSE;

	UIGetCfg(&item);
	if (!m_profileStore.Save(item))
	{
		const CString reason = ConfigStorage::ErrorText(GetLastError());
		MessageBox(Localization::Format(L"storage.save_failed", (LPCTSTR)reason, (LPCTSTR)Localization::SettingsPath()),
			Localization::Get(L"profile.save_failed_title"), MB_ICONERROR);
		return FALSE;
	}

	int index = m_cfgls.FindStringExact(-1, item.strName);
	if (index == CB_ERR)
		index = m_cfgls.AddString(item.strName);
	RefreshProfileEntries();
	m_loadingProfile = TRUE;
	m_cfgls.SetCurSel(index);
	m_cfgls.SetWindowText(item.strName);
	m_loadingProfile = FALSE;
	m_loadedProfileName = item.strName;
	m_draftProfileName = item.strName;
	SetProfileDirty(FALSE);
	EndFirstRunGuide();
	return TRUE;
}

void CPage1::EndFirstRunGuide()
{
	if (!m_firstRunGuide)
		return;
	m_firstRunGuide = FALSE;
	UpdateTransportEnable();
	LayoutSettingsPage();
}

void CPage1::RestoreProfileSelection()
{
	m_loadingProfile = TRUE;
	int index = m_loadedProfileName.IsEmpty()
		? CB_ERR : m_cfgls.FindStringExact(-1, m_loadedProfileName);
	m_cfgls.SetCurSel(index);
	m_cfgls.SetWindowText(m_draftProfileName);
	m_loadingProfile = FALSE;
}

BOOL CPage1::ConfirmDiscardUnsavedChanges()
{
	if (!m_profileDirty)
		return TRUE;

	const int answer = MessageBox(
		Localization::Get(_T("profile.unsaved_prompt")),
		Localization::Get(_T("profile.unsaved_title")),
		MB_YESNOCANCEL | MB_ICONWARNING);
	if (answer == IDCANCEL)
		return FALSE;
	if (answer == IDYES)
		return SaveCurrentProfile(m_draftProfileName);
	return TRUE;
}

BOOL CPage1::StartProxy(BOOL showErrors)
{
	if (m_proxyController.IsRunning())
		return TRUE;

	// A newly created draft needs a saved identity before it can run.
	if (m_cfgls.FindStringExact(-1, GetCurrentProfileName()) == CB_ERR)
	{
		if (!showErrors)
			return FALSE;
		if (MessageBox(Localization::Get(_T("profile.save_before_start")),
			Localization::Get(_T("profile.save_before_start_title")), MB_OKCANCEL | MB_ICONINFORMATION) != IDOK)
			return FALSE;
		CString name;
		m_cfgls.GetWindowText(name);
		name.Trim();
		if (name.IsEmpty())
			name = _T("proxy");
		if (!SaveCurrentProfile(name))
			return FALSE;
	}

	ProxyInfo proxyInfo;
	ProxyChain chain;
	ProxySettingsInfo runtimeSettings;
	if (!GetRoute(&proxyInfo, &chain))
	{
		if (showErrors)
			MessageBox(SettingsValidationMessage(),
				Localization::Get(_T("proxy.start_failed_title")), MB_ICONERROR);
		return FALSE;
	}
	if (!ValidateDnsRedirectSettings(showErrors))
		return FALSE;

	CMainTab *pParent = g_MainTab;
	CPage2 *pPage2 = pParent->GetPage2();
	CPage3 *pPage3 = pParent->GetPage3();
	CPage4 *pPage4 = pParent->GetPage4();

	if (!GetProxySettingsFromUi(&runtimeSettings))
		return FALSE;
	// UDP never goes through a chain: it stays unhooked (direct or blocked).
	if (!ProxyTransportPolicy::SupportsUdpProxy(proxyInfo.GetProxyType()) || !chain.empty())
		runtimeSettings.bHookUDP = FALSE;

	PublishProfileSnapshots();
	{
		CSingleLock runtimeLock(&m_runtimeLock, TRUE);
		m_ProxyInfo = proxyInfo;
		m_runtimeChain = chain;
		m_runtimeSettings = runtimeSettings;
		m_runtimeSettingsValid = TRUE;
	}

	if (m_proxyController.Start(this, pPage2, pPage3))
	{
		CString runningProfileName = GetCurrentProfileName();
		pParent->SetRunningProfile(runningProfileName, TRUE);
		pPage4->UpdateMonitorStatus();
		m_runtimeDirty = FALSE;
		UpdateProxyStateUi();
		UpdateProxyTestStatus();
		return TRUE;
	}

	{
		CSingleLock runtimeLock(&m_runtimeLock, TRUE);
		m_runtimeSettingsValid = FALSE;
	}
	if (showErrors)
	{
		CString detail = m_proxyController.GetLastErrorText();
		CString message = detail.IsEmpty()
			? Localization::Get(_T("proxy.start_failed"))
			: Localization::Format(_T("proxy.start_failed_detail"),
				(LPCTSTR)detail);
		MessageBox(message, Localization::Get(_T("proxy.start_failed_title")),
			MB_ICONERROR);
	}

	return FALSE;
}

CString CPage1::GetCurrentProfileName()
{
	CString profileName;
	const int selectedProfile = m_cfgls.GetCurSel();
	if (selectedProfile != CB_ERR)
		m_cfgls.GetLBText(selectedProfile, profileName);
	else
		m_cfgls.GetWindowText(profileName);
	profileName.Trim();
	return profileName;
}

CString CPage1::GetSelectedProfileSummary()
{
	// Read the same draft that StartProxy uses, without validating or saving it.
	const CString name = GetCurrentProfileName();
	if (name.IsEmpty()) return CString();
	if (m_chainMode)
	{
		CString route;
		for (const CString& hop : m_chainHops)
			route += (route.IsEmpty() ? L"" : L" \x2192 ") + hop;
		return name + L" \x00b7 " + Localization::Format(L"launch.profile_chain",
			route.IsEmpty() ? L"\x2014" : (LPCTSTR)route);
	}
	CString type, host, port;
	m_cbProxyType.GetWindowText(type);
	if (type.CompareNoCase(L"NOPROXY") == 0)
		return name + L" \x00b7 " + Localization::Get(L"launch.profile_direct");
	m_edit_HostName.GetWindowText(host);
	m_edit_Port.GetWindowText(port);
	host.Trim(); port.Trim();
	if (host.Find(L':') >= 0 && host.Left(1) != L"[") host = L"[" + host + L"]";
	if (host.IsEmpty()) host = L"\x2014";
	if (port.IsEmpty()) port = L"\x2014";
	return name + L" \x00b7 " + type + L" " + host + L":" + port;
}

CString CPage1::GetSelectedRecentProfileId()
{
	const CString name = GetCurrentProfileName();
	// Preview existing history without creating an identity for an unsaved draft.
	return name.IsEmpty() ? CString() : g_ini.GetString(_T("proxy_") + name, _T("RecentAppsId"));
}

BOOL CPage1::ApplyRuntimeSettings()
{
	if (!m_proxyController.IsRunning())
		return FALSE;

	ProxyInfo proxyInfo;
	ProxyChain chain;
	ProxySettingsInfo runtimeSettings;
	if (!GetRoute(&proxyInfo, &chain))
	{
		MessageBox(SettingsValidationMessage(),
			Localization::Get(_T("apply.failed_title")), MB_ICONERROR);
		return FALSE;
	}
	if (!ValidateDnsRedirectSettings(TRUE))
		return FALSE;

	if (!GetProxySettingsFromUi(&runtimeSettings))
		return FALSE;
	if (!ProxyTransportPolicy::SupportsUdpProxy(proxyInfo.GetProxyType()) || !chain.empty())
		runtimeSettings.bHookUDP = FALSE;

	PublishProfileSnapshots();
	{
		CSingleLock runtimeLock(&m_runtimeLock, TRUE);
		m_ProxyInfo = proxyInfo;
		m_runtimeChain = chain;
		m_runtimeSettings = runtimeSettings;
		m_runtimeSettingsValid = TRUE;
	}

	if (g_MainTab)
		g_MainTab->SetRunningProfile(GetCurrentProfileName(), TRUE);
	m_runtimeDirty = FALSE;
	UpdateProxyStateUi();
	UpdateProxyTestStatus();

	return TRUE;
}

void CPage1::OnBnClickedCancel()
{
	StopProxy();
}

BOOL CPage1::StopProxy()
{
	if (!m_proxyController.IsRunning())
	{
		if (g_MainTab)
			g_MainTab->SetRunningProfile(NULL, FALSE);
		return TRUE;
	}

	CMainTab *pParent = g_MainTab;
	CPage4 *pPage4 = pParent->GetPage4();

	if (m_proxyController.Stop())
	{
		{
			CSingleLock runtimeLock(&m_runtimeLock, TRUE);
			m_runtimeSettingsValid = FALSE;
		}
		m_runtimeDirty = FALSE;
		pParent->SetRunningProfile(NULL, FALSE);
		pPage4->UpdateMonitorStatus();
		UpdateProxyStateUi();
		return TRUE;
	}
	return FALSE;
}

BOOL CPage1::IsProxyRunning() const
{
	return m_proxyController.IsRunning();
}

CString CPage1::QuicUdpWarning()
{
	if (!m_btnHookUDP.GetSafeHwnd()) return CString();
	BOOL blocked, hooked;
	int type;
	if (IsProxyRunning()) {
		CSingleLock runtimeLock(&m_runtimeLock, TRUE);
		if (!m_runtimeSettingsValid) return CString();
		blocked = m_runtimeSettings.bBlockUDP;
		hooked = m_runtimeSettings.bHookUDP;
		type = m_ProxyInfo.GetProxyType();
	} else {
		blocked = m_btnBlockUDP.GetCheck() == BST_CHECKED;
		hooked = m_btnHookUDP.GetCheck() == BST_CHECKED;
		const int selected = m_cbProxyType.GetCurSel();
		if (selected == CB_ERR) return CString();
		CString name; m_cbProxyType.GetLBText(selected, name);
		ProxyInfo info; info.strProxyType = name; type = info.GetProxyType();
	}
	if (blocked) return Localization::Get(L"mitm.quic_udp_blocked");
	if (!ProxyTransportPolicy::SupportsUdpProxy(type)) return Localization::Get(L"mitm.quic_udp_unsupported");
	if (!hooked) return Localization::Get(L"mitm.quic_udp_not_captured");
	return CString();
}

void CPage1::OnDestroy()
{
	CModernDialog::OnDestroy();

	// TODO: 在此处添加消息处理程序代码
	OnBnClickedCancel();
}


CString CPage1::GetProxyTestStatus(CStatusLabel::Tone& tone) const
{
	CString text;
	tone = CStatusLabel::TONE_NEUTRAL;
	if (m_staticTestProxy.GetSafeHwnd())
	{
		m_staticTestProxy.GetWindowText(text);
		tone = m_staticTestProxy.GetTone();
	}
	return text;
}

void CPage1::OnBnClickedTestproxy()
{
	// TODO: 在此添加控件通知处理程序代码
	if (m_pTestProxy == NULL)
	{
		m_pTestProxy = GetGlobalProxyInstance();
		if(m_pTestProxy == NULL)
		{
			ATLTRACE("OnBnClickedTestproxy -> GetGlobalProxyInstance,  failed.\r\n");
			return;
		}
	}

	if(m_bIsTesting && m_pProxyTester)
	{
		m_pProxyTester->Release();
		m_pProxyTester = NULL;
		m_bIsTesting = FALSE;
		UpdateChainButtons();
		m_proxyTestPhase = PROXY_TEST_NONE;
		m_testIpv6Result = IPV6_TEST_NOT_RUN;
		m_btnTest.SetWindowText(Localization::Get(_T("action.test_current")));
		UpdateProxyTestStatus();
		return;
	}

	if (m_pProxyTester)
		m_pProxyTester->Release();
	m_pProxyTester = NULL;
	m_bIsTesting = FALSE;
	UpdateChainButtons();
	m_proxyTestPhase = PROXY_TEST_NONE;
	m_testIpv6Result = IPV6_TEST_NOT_RUN;
	m_testUdpRequested = FALSE;

	ProxyInfo testProxyInfo;
	if (!GetRoute(&testProxyInfo, &m_testChain))
	{
		MessageBox(SettingsValidationMessage(),
			Localization::Get(_T("test.invalid_title")), MB_ICONERROR);
		m_staticTestProxy.SetStatus(Localization::Get(_T("status.invalid_config")), CStatusLabel::TONE_DANGER);
		m_proxyTestPhase = PROXY_TEST_NONE;
		return;
	}
	m_testProxyInfo = testProxyInfo;
	m_testChainNames = !m_testChain.empty() ? m_chainHops : std::vector<CString>();
	m_testUdpRequested = m_btnHookUDP.GetCheck() == BST_CHECKED &&
		testProxyInfo.GetProxyType() == PROXYTYPE_SOCKS5 && m_testChain.empty();

	PRCClient client;

	client.zero();
	client.sType = SOCK_STREAM;

	CString strTestHost = g_ini.GetString(_T("options"), _T("testhost"), _T("www.baidu.com"));
	int nTestPort = 80;
	int nposPort = strTestHost.Find(':');

	if (nposPort > 0)
	{
		nTestPort = _ttoi(strTestHost.Mid(nposPort+1));
		strTestHost = strTestHost.Left(nposPort);
	}

#ifdef _UNICODE
	WideCharToMultiByte(0, 0, strTestHost, -1, client.szDomainName, sizeof(client.szDomainName), 0, 0);
#else
	strncpy(client.szDomainName, strTestHost, 255);
#endif
	client.dstAddr.SetPort(nTestPort);

	if (!StartProxyTestPhase(client, PROXY_TEST_TCP, _T("status.testing")))
	{
		MessageBox(Localization::Get(_T("test.start_failed")),
			Localization::Get(_T("test.failed_title")), MB_ICONERROR);
		m_staticTestProxy.SetStatus(Localization::Get(_T("status.test_failed")), CStatusLabel::TONE_DANGER);
		ATLTRACE("OnBnClickedTestproxy -> Start failed.\r\n");
		m_proxyTestPhase = PROXY_TEST_NONE;
		return;
	}
	m_btnTest.SetWindowText(Localization::Get(_T("action.cancel_test")));
	m_bIsTesting = TRUE;
	UpdateChainButtons();

}

BOOL CPage1::StartProxyTestPhase(const PRCClient& client, int phase,
	LPCTSTR statusKey)
{
	if (!m_pTestProxy || m_pProxyTester)
	{
		WSASetLastError(WSAEINVAL);
		return FALSE;
	}

	m_pProxyTester = m_pTestProxy->CreateTester();
	if (!m_pProxyTester)
	{
		WSASetLastError(WSAENOBUFS);
		return FALSE;
	}
	WSASetLastError(0);

	m_proxyTestPhase = phase;
	PRCClient mutableClient = client;
	const BOOL started = m_testChain.size() > 1
		? m_pProxyTester->StartChain(this, &mutableClient, &m_testChain[0], (INT)m_testChain.size())
		: m_pProxyTester->Start(this, &mutableClient, &m_testProxyInfo);
	if (!started)
	{
		const int error = WSAGetLastError();
		m_pProxyTester->Release();
		m_pProxyTester = NULL;
		m_proxyTestPhase = PROXY_TEST_NONE;
		WSASetLastError(error);
		return FALSE;
	}

	if (statusKey && statusKey[0])
		m_staticTestProxy.SetStatus(Localization::Get(statusKey),
			CStatusLabel::TONE_INFO);
	return TRUE;
}

static CString ProxyTestErrorDescription(int error, BOOL direct)
{
	if (direct && (error == PROXYERROR_NOCONN || error == PROXYERROR_REQUESTFAILED))
		return Localization::Get(L"test.direct_connection_failed");
	// Proxy negotiation errors share numeric values with Win32 errors; do not
	// pass these application codes to the Windows system message table.
	LPCTSTR key = NULL;
	switch (error)
	{
	case PROXYERROR_NOCONN: key = _T("test.no_connection"); break;
	case PROXYERROR_REQUESTFAILED: key = _T("test.target_failed"); break;
	case PROXYERROR_AUTHREQUIRED: key = _T("test.auth_required"); break;
	case PROXYERROR_AUTHTYPEUNKNOWN: key = _T("test.auth_unknown"); break;
	case PROXYERROR_AUTHFAILED:
	case PROXYERROR_AUTHNOLOGON: key = _T("test.auth_failed"); break;
	case PROXYERROR_CANTRESOLVEHOST: key = _T("test.resolve_failed"); break;
	case PROXYERROR_SECURE_UNAVAILABLE: key = _T("test.secure_unavailable"); break;
	case PROXYERROR_SECURE_HANDSHAKE: key = _T("test.secure_handshake_failed"); break;
	case PROXYERROR_UDP_UNSUPPORTED: key = _T("test.udp_unsupported"); break;
	case PROXYERROR_UDP_RELAY_FAILED: key = _T("test.udp_relay_failed"); break;
	}
	if (key) return Localization::Get(key);

	LPTSTR buffer = NULL;
	CString description;
	if (::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS, NULL, static_cast<DWORD>(error), 0,
		reinterpret_cast<LPTSTR>(&buffer), 0, NULL))
	{
		description = buffer;
		description.Trim();
	}
	if (buffer) LocalFree(buffer);
	return description.IsEmpty() ? Localization::Get(_T("test.error_description_unavailable")) : description;
}

BOOL CPage1::SupportsIpv6ProxyTest()
{
	const int proxyType = m_testProxyInfo.GetProxyType();
	return proxyType == PROXYTYPE_NOPROXY || proxyType == PROXYTYPE_SOCKS5 ||
		proxyType == PROXYTYPE_HTTP11 || proxyType == PROXYTYPE_SSH;
}

BOOL CPage1::StartIpv6ProxyTest()
{
	m_testIpv6Error = 0;
	m_testIpv6Address.Empty();
	if (!SupportsIpv6ProxyTest())
	{
		m_testIpv6Result = IPV6_TEST_UNSUPPORTED;
		return FALSE;
	}

	PRCClient ipv6Client;
	ipv6Client.zero();
	ipv6Client.sType = SOCK_STREAM;
	// The default is a published Google Public DNS IPv6 resolver. Keep the
	// address configurable so deployments can replace the third-party probe
	// without rebuilding ProxyLane. A literal IPv6 address is required: using a
	// hostname could let the proxy select IPv4 and produce a false positive.
	CString ipv6TestAddress = g_ini.GetString(_T("options"),
		_T("IPv6TestAddress"), _T("2001:4860:4860::8888"));
	ipv6TestAddress.Trim();
	if (ipv6TestAddress.GetLength() > 2 && ipv6TestAddress[0] == _T('[') &&
		ipv6TestAddress[ipv6TestAddress.GetLength() - 1] == _T(']'))
	{
		ipv6TestAddress = ipv6TestAddress.Mid(1,
			ipv6TestAddress.GetLength() - 2);
	}
	CStringA ipv6TestAddressA(ipv6TestAddress);
	if (!ipv6Client.dstAddr.SetIP(ipv6TestAddressA) ||
		!ipv6Client.dstAddr.IsIPv6())
	{
		m_testIpv6Result = IPV6_TEST_INVALID_CONFIG;
		return FALSE;
	}
	ipv6Client.dstAddr.SetPort(53);
	m_testIpv6Address = ipv6TestAddress;
	if (StartProxyTestPhase(ipv6Client, PROXY_TEST_IPV6,
		_T("status.testing_ipv6")))
		return TRUE;
	// A direct connect may fail immediately (for example, no IPv6 route).
	m_testIpv6Error = WSAGetLastError();
	if (!m_testIpv6Error) m_testIpv6Error = WSAEFAULT;
	m_testIpv6Result = ClassifyIpv6TestResult(m_testIpv6Error);
	return FALSE;
}

int CPage1::ClassifyIpv6TestResult(int errorCode) const
{
	if (errorCode == 0)
		return IPV6_TEST_AVAILABLE;

	// Failure of one target is not proof that IPv6 is unsupported.
	if (errorCode == PROXYERROR_REQUESTFAILED ||
		errorCode == WSAEAFNOSUPPORT || errorCode == WSAENETUNREACH ||
		errorCode == WSAEHOSTUNREACH || errorCode == WSAECONNREFUSED ||
		errorCode == WSAEADDRNOTAVAIL || errorCode == WSAENETDOWN)
		return IPV6_TEST_TARGET_FAILED;

	// Timeouts and unrelated setup/transport errors remain inconclusive.
	return IPV6_TEST_UNKNOWN;
}

void CPage1::OnProxyTesterCallback(IProxyTester *pTester, int nErrorCode, WPARAM wParam, LPARAM lParam)
{
	ATLASSERT(pTester == m_pProxyTester);

	int nType = HIWORD(nErrorCode);
	int nCode = LOWORD(nErrorCode);

	CString szText;
	BOOL enabledIpv6Blocking = FALSE;

	if (nType == LAYERCALLBACK_STATECHANGE)
	{
		if (m_proxyTestPhase == PROXY_TEST_IPV6)
		{
			szText = Localization::Get(_T("status.testing_ipv6"));
		}
		else if (m_proxyTestPhase == PROXY_TEST_UDP)
		{
			szText = Localization::Get(_T("status.testing_udp"));
		}
		else if(nCode == connecting)
		{
			szText = Localization::Get(_T("status.connecting"));
		}else if (nCode == connected)
		{
			szText = Localization::Get(_T("status.negotiating"));
		}else
		{
			return;
		}
		m_staticTestProxy.SetStatus(szText, CStatusLabel::TONE_INFO);

		return;
	}else if (nType == LAYERCALLBACK_LAYERSPECIFIC)
	{
		const int completedPhase = m_proxyTestPhase;
		//关闭测试对象， 否则下面的MessageBox内部的消息循环可能导致pTester触发其他事件
		pTester->Stop();

		if (completedPhase == PROXY_TEST_IPV6)
		{
			m_testIpv6Error = nCode;
			m_testIpv6Result = ClassifyIpv6TestResult(nCode);
			// IPv6 capability is supplementary information. The ordinary proxy
			// test remains successful even when IPv6 is unavailable or unknown.
			nCode = 0;
		}
		else if (nCode == 0 && completedPhase == PROXY_TEST_TCP &&
			m_testUdpRequested)
		{
			pTester->Release();
			m_pProxyTester = NULL;

			PRCClient udpClient;
			udpClient.zero();
			udpClient.sType = SOCK_DGRAM;
			udpClient.dstAddr.SetIP("8.8.8.8");
			udpClient.dstAddr.SetPort(53);
			if (StartProxyTestPhase(udpClient, PROXY_TEST_UDP,
				_T("status.testing_udp")))
				return;
			nCode = PROXYERROR_UDP_RELAY_FAILED;
		}
		else if (nCode == 0 && (completedPhase == PROXY_TEST_TCP ||
			completedPhase == PROXY_TEST_UDP))
		{
			pTester->Release();
			m_pProxyTester = NULL;
			if (StartIpv6ProxyTest())
				return;
			// Unsupported protocols and a locally failed probe setup are both
			// reported with the otherwise successful base test below.
			nCode = 0;
		}

		if(nCode == 0)
		{
			const BOOL ipv6NeedsAttention =
				m_testIpv6Result == IPV6_TEST_TARGET_FAILED ||
				m_testIpv6Result == IPV6_TEST_UNSUPPORTED;
			const BOOL ipv6AlreadyBlocked =
				m_btnBlockIPv6.GetCheck() == BST_CHECKED;
			const BOOL suggestIpv6Blocking =
				ipv6NeedsAttention && !ipv6AlreadyBlocked;
			szText = Localization::Get(m_testUdpRequested
				? _T("test.success_tcp_udp") : _T("test.success"));
			switch (m_testIpv6Result)
			{
			case IPV6_TEST_AVAILABLE:
				szText += Localization::Get(_T("test.ipv6_available"));
				break;
			case IPV6_TEST_TARGET_FAILED:
				szText += Localization::Get(_T("test.ipv6_target_failed"));
				break;
			case IPV6_TEST_UNSUPPORTED:
				szText += Localization::Get(_T("test.ipv6_unsupported"));
				break;
			case IPV6_TEST_INVALID_CONFIG:
				szText += Localization::Get(_T("test.ipv6_invalid_config"));
				break;
			default:
				szText += Localization::Get(_T("test.ipv6_unknown"));
				break;
			}
			if (!m_testIpv6Address.IsEmpty())
			{
				CString detail;
				detail.Format(Localization::Get(_T("test.ipv6_target")),
					static_cast<LPCTSTR>(m_testIpv6Address));
				szText += detail;
				if (m_testIpv6Error)
				{
					const CString description = ProxyTestErrorDescription(m_testIpv6Error,
						m_testProxyInfo.GetProxyType() == PROXYTYPE_NOPROXY);
					detail.Format(Localization::Get(_T("test.ipv6_error")),
						static_cast<LPCTSTR>(description));
					szText += detail;
				}
			}
			if (m_profileDirty && m_runtimeDirty)
			{
				m_staticTestProxy.SetStatus(Localization::Get(_T("status.test_passed_unsaved_unapplied")), CStatusLabel::TONE_WARNING);
			}
			else if (m_runtimeDirty)
			{
				m_staticTestProxy.SetStatus(Localization::Get(_T("status.test_passed_unapplied")), CStatusLabel::TONE_WARNING);
			}
			else if (m_profileDirty)
			{
				m_staticTestProxy.SetStatus(Localization::Get(_T("status.test_passed_unsaved")), CStatusLabel::TONE_WARNING);
			}
			else if (m_testIpv6Result == IPV6_TEST_AVAILABLE)
				m_staticTestProxy.SetStatus(Localization::Get(_T("status.test_passed_saved")), CStatusLabel::TONE_SUCCESS);
			else if (ipv6NeedsAttention && ipv6AlreadyBlocked)
				m_staticTestProxy.SetStatus(Localization::Get(
					_T("status.test_passed_ipv6_blocked")),
					CStatusLabel::TONE_INFO);
			else
				m_staticTestProxy.SetStatus(Localization::Get(
					m_testIpv6Result == IPV6_TEST_UNSUPPORTED
						? _T("status.test_passed_ipv6_unsupported")
						: m_testIpv6Result == IPV6_TEST_TARGET_FAILED
							? _T("status.test_passed_ipv6_target_failed")
							: _T("status.test_passed_ipv6_unknown")),
					CStatusLabel::TONE_WARNING);

			if (suggestIpv6Blocking)
			{
				szText += Localization::Get(m_testIpv6Result == IPV6_TEST_UNSUPPORTED
					? _T("test.ipv6_block_suggestion")
					: _T("test.ipv6_failed_block_suggestion"));
				if (MessageBox(szText, Localization::Get(_T("test.title")),
					MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON1) == IDYES)
				{
					m_btnBlockIPv6.SetCheck(BST_CHECKED);
					OnProfileFieldChanged();
					enabledIpv6Blocking = TRUE;
				}
			}
			else
			{
				const UINT icon = m_testIpv6Result == IPV6_TEST_AVAILABLE ||
					(ipv6NeedsAttention && ipv6AlreadyBlocked)
						? MB_ICONINFORMATION : MB_ICONWARNING;
				MessageBox(szText, Localization::Get(_T("test.title")), icon);
			}
		}else
		{
			switch (nCode)
			{
			case PROXYERROR_SSH_UNAVAILABLE:
                szText = Localization::Get(L"test.ssh_unavailable"); break;
            case PROXYERROR_SSH_HOSTKEY_UNKNOWN:
                szText = Localization::Get(L"test.ssh_unknown_key"); break;
            case PROXYERROR_SSH_HOSTKEY_CHANGED:
                szText = Localization::Get(L"test.ssh_changed_key"); break;
            case PROXYERROR_NOCONN:
				szText = Localization::Get(m_testProxyInfo.GetProxyType() == PROXYTYPE_NOPROXY ?
					L"test.direct_connection_failed" : L"test.no_connection");
				break;
				/* fall through */
			case PROXYERROR_REQUESTFAILED:
				szText = Localization::Get(m_testProxyInfo.GetProxyType() == PROXYTYPE_NOPROXY ?
					L"test.direct_connection_failed" : L"test.target_failed");
				break;
			case PROXYERROR_AUTHREQUIRED:
				szText = Localization::Get(_T("test.auth_required"));
				break;
			case PROXYERROR_AUTHTYPEUNKNOWN:
				szText = Localization::Get(_T("test.auth_unknown"));
				break;
			case PROXYERROR_AUTHFAILED:
				szText = Localization::Get(_T("test.auth_failed"));
				break;
			case PROXYERROR_SECURE_UNAVAILABLE:
				szText = Localization::Get(_T("test.secure_unavailable"));
				break;
			case PROXYERROR_SECURE_HANDSHAKE:
				szText = Localization::Get(_T("test.secure_handshake_failed"));
				break;
			case PROXYERROR_UDP_UNSUPPORTED:
				szText = Localization::Get(_T("test.udp_unsupported"));
				break;
			case PROXYERROR_UDP_RELAY_FAILED:
				szText = Localization::Get(_T("test.udp_relay_failed"));
				break;

			default:
				szText = Localization::Format(_T("test.negotiation_failed"), nCode);
				break;
			}
			// In a chain, say which hop the failure belongs to.
			const int failedHop = m_testChain.size() > 1 ? pTester->GetFailedHop() : -1;
			if (failedHop >= 0 && failedHop < (int)m_testChainNames.size())
				szText = Localization::Format(_T("test.chain_hop"), failedHop + 1,
					(LPCTSTR)m_testChainNames[failedHop], (LPCTSTR)szText);
			LPCTSTR statusKey = _T("status.test_failed");
			if (m_profileDirty && m_runtimeDirty)
				statusKey = _T("status.test_failed_unsaved_unapplied");
			else if (m_runtimeDirty)
				statusKey = _T("status.test_failed_unapplied");
			else if (m_profileDirty)
				statusKey = _T("status.test_failed_unsaved");
			m_staticTestProxy.SetStatus(Localization::Get(statusKey), CStatusLabel::TONE_DANGER);
            if ((nCode == PROXYERROR_SSH_HOSTKEY_UNKNOWN || nCode == PROXYERROR_SSH_HOSTKEY_CHANGED) && lParam) {
                const CString fingerprint = SshProfile::Decode(reinterpret_cast<LPCSTR>(lParam));
                szText += L"\r\n\r\n" + fingerprint;
                if (nCode == PROXYERROR_SSH_HOSTKEY_UNKNOWN && SshProfile::ValidFingerprint(fingerprint)) {
                    ProxyInfo endpoint = failedHop >= 0 && failedHop < (int)m_testChain.size() ? m_testChain[failedHop] : m_testProxyInfo;
                    CString address; address.Format(L"\r\n%s:%d", (LPCTSTR)(CString)endpoint.strProxyHost, endpoint.nProxyPort);
                    szText += address + L"\r\n\r\n" + Localization::Get(L"test.ssh_trust_key");
                    if (MessageBox(szText, Localization::Get(L"test.title"), MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES) {
                        if (failedHop < 0) {
                            m_editTransportPsk.SetWindowText(fingerprint); OnProfileFieldChanged();
                        } else {
                            CfgProxyItem item; item.strName = m_testChainNames[failedHop];
                            if (m_profileStore.Load(item)) {
                                item.strTransportPsk = fingerprint;
                                if (!m_profileStore.Save(item)) MessageBox(Localization::Get(L"profile.save_failed_title"));
                                m_profileStore.SetLastSelected(m_loadedProfileName);
                                SetRuntimeDirty(TRUE);
                            }
                        }
                    }
                } else MessageBox(szText, Localization::Get(L"test.title"), MB_ICONERROR);
            } else MessageBox(szText);
		}

		if (m_pProxyTester)
		{
			m_pProxyTester->Release();
			m_pProxyTester = NULL;
		}
		m_btnTest.SetWindowText(Localization::Get(_T("action.test_current")));
		m_bIsTesting = FALSE;
		UpdateChainButtons();
		m_proxyTestPhase = PROXY_TEST_NONE;
		if (enabledIpv6Blocking)
			UpdateProxyTestStatus();

	}

}
void CPage1::OnEnChangeEditAddr()
{
	// Loading a full profile already supplies a separate port. Do not interpret
	// an IPv6 address as the interactive host:port shorthand while filling it.
	if (m_loadingProfile)
		return;
	CString strHost;
	m_edit_HostName.GetWindowText(strHost);

	int iPos = strHost.Find(':');
	if (iPos > 0)
	{
		CString strPort;

		strPort = strHost.Right(strHost.GetLength()-iPos-1);
		strHost = strHost.Left(iPos);

		m_edit_HostName.SetWindowText(strHost);
		m_edit_Port.SetWindowText(strPort);
	}
	OnProfileFieldChanged();
}

void CPage1::OnCfgoptLoad()
{
	CString name;
	m_cfgls.GetWindowText(name);
	SelectProfileFromDisk(name);
}

void CPage1::OnCfgoptSave()
{
	m_cfgls.GetWindowText(m_draftProfileName);
	m_draftProfileName.Trim();
	if (!SaveCurrentProfile(m_draftProfileName))
		return;

	if (m_proxyController.IsRunning() && ApplyRuntimeSettings())
	{
		MessageBox(Localization::Get(_T("apply.saved_success")),
			Localization::Get(_T("apply.saved_success_title")), MB_ICONINFORMATION);
	}
}

void CPage1::OnCfgoptDelete()
{
	CString strName;
	int idx = m_cfgls.GetCurSel();
	if (idx >= 0)
	{
		m_cfgls.GetLBText(idx, strName);
		if (strName.GetLength() > 0)
		{
			CString prompt = Localization::Format(_T("profile.delete_confirm"), (LPCTSTR)strName);
			// A hop of other chains: say which ones stop working.
			std::vector<CString> users;
			if (m_profileStore.ListChainUsers(strName, users) && !users.empty())
			{
				CString list;
				for (const CString& user : users)
					list += (list.IsEmpty() ? L"" : L", ") + user;
				prompt = Localization::Format(_T("profile.chain_used_by"), (LPCTSTR)strName, (LPCTSTR)list);
			}
			if (MessageBox(prompt, Localization::Get(_T("profile.delete_title")),
				MB_OKCANCEL | MB_ICONWARNING) != IDOK)
			{
				return;
			}

			if (!m_profileStore.Delete(strName))
			{
				MessageBox(Localization::Get(L"recent.write_failed"), Localization::Get(L"profile.delete_title"), MB_OK | MB_ICONWARNING);
				return;
			}
			m_cfgls.DeleteString(idx);
			m_loadingProfile = TRUE;
			m_cfgls.SetCurSel(-1);
			m_cfgls.SetWindowText(strName);
			m_loadingProfile = FALSE;
			m_loadedProfileName.Empty();
			m_draftProfileName = strName;
			SetProfileDirty(TRUE);
		}
	}
}

void CPage1::UILoadCfg( CfgProxyItem *item )
{
	m_loadingProfile = TRUE;
	if (item == NULL)
	{
		m_cbProxyType.SelectString(0, _T("SOCKS5"));
		m_edit_HostName.SetWindowText(_T(""));
		m_edit_Port.SetWindowText(_T("1080"));
		m_edit_User.SetWindowText(_T(""));
		m_edit_Pass.SetWindowText(_T(""));
		m_cbTransport.SetCurSel(PROXY_TRANSPORT_PLAIN);
		m_editTransportPsk.SetWindowText(_T(""));
		m_btnHookTCP.SetCheck(BST_CHECKED);
		m_btnHookUDP.SetCheck(BST_CHECKED);
		m_btnBlockUDP.SetCheck(BST_UNCHECKED);
		m_btnBlockIPv6.SetCheck(BST_UNCHECKED);
		m_btnDNSLocal.SetCheck(BST_UNCHECKED);
		m_btnDNSRemote.SetCheck(BST_CHECKED);
		m_btnRedirectPrivateDNS.SetCheck(BST_CHECKED);
		m_editRedirectDNS.SetWindowText(_T("8.8.8.8"));
		m_btnHookChildProcess.SetCheck(BST_CHECKED);
		m_editChildFilter.SetWindowText(_T(""));
		m_radioChildFilterInclude.SetCheck(BST_CHECKED);
		m_radioChildFilterExclude.SetCheck(BST_UNCHECKED);
		m_editTargetFilter.SetWindowText(_T(""));
		m_radioTargetFilterBypass.SetCheck(BST_CHECKED);
		m_radioTargetFilterProxy.SetCheck(BST_UNCHECKED);
		UpdateChildFilterEnable();
	}
	else
	{

		CString szType, szHost, szPort, szUser, szPass;

		szType = item->pi.strProxyType;
		szHost = item->pi.strProxyHost;
		szPort.Format(_T("%d"), item->pi.nProxyPort);
		if (szType.CompareNoCase(_T("NOPROXY")) == 0 && !item->pi.nProxyPort)
			szPort.Empty();
		szUser = item->pi.GetProxyType() == PROXYTYPE_SSH ? SshProfile::Decode(item->pi.strProxyUser.szbuf) : (CString)item->pi.strProxyUser;
		szPass = item->pi.GetProxyType() == PROXYTYPE_SSH ? SshProfile::Decode(item->pi.strProxyPass.szbuf) : (CString)item->pi.strProxyPass;

		// Retain unsupported legacy profiles for editing, but do not leave the
		// previous selection active (which would silently change their protocol).
		if (szType.CompareNoCase(L"HTTP10") == 0 || szType.CompareNoCase(L"HTTP11") == 0) szType = L"HTTP";
		m_cbProxyType.SetCurSel(m_cbProxyType.FindStringExact(-1, szType));
		m_edit_HostName.SetWindowText(szHost);
		m_edit_Port.SetWindowText(szPort);
		m_edit_User.SetWindowText(szUser);
		m_edit_Pass.SetWindowText(szPass);
		m_cbTransport.SetCurSel(item->nTransportMode ==
			PROXY_TRANSPORT_GONC_TLS_PSK ? PROXY_TRANSPORT_GONC_TLS_PSK :
			PROXY_TRANSPORT_PLAIN);
		m_editTransportPsk.SetWindowText(item->strTransportPsk);

		m_btnHookTCP.SetCheck(item->bHookTCP ? BST_CHECKED : BST_UNCHECKED);
		m_btnHookUDP.SetCheck(item->bHookUDP ? BST_CHECKED : BST_UNCHECKED);
		m_btnBlockUDP.SetCheck(item->bBlockUDP ? BST_CHECKED : BST_UNCHECKED);
		m_btnBlockIPv6.SetCheck(item->bBlockIPv6 ? BST_CHECKED : BST_UNCHECKED);
		m_btnHookChildProcess.SetCheck(item->bHookChildProcess ? BST_CHECKED : BST_UNCHECKED);
		m_btnDNSLocal.SetCheck(item->dnsOpt==PSI_DNSOPT_LOCAL ? BST_CHECKED : BST_UNCHECKED);
		m_btnDNSRemote.SetCheck(!m_btnDNSLocal.GetCheck());
		m_btnRedirectPrivateDNS.SetCheck(item->bRedirectPrivateDNS ? BST_CHECKED : BST_UNCHECKED);
		m_editRedirectDNS.SetWindowText(item->strRedirectDNS);

		m_editChildFilter.SetWindowText(item->strChildFilter);
		BOOL bInclude = (item->nChildFilterMode == CHILDFILTER_MODE_INCLUDE);
		m_radioChildFilterInclude.SetCheck(bInclude ? BST_CHECKED : BST_UNCHECKED);
		m_radioChildFilterExclude.SetCheck(bInclude ? BST_UNCHECKED : BST_CHECKED);
		m_editTargetFilter.SetWindowText(item->strTargetFilter);
		BOOL bTgtProxy = (item->nTargetFilterMode == TARGETFILTER_MODE_PROXY);
		m_radioTargetFilterProxy.SetCheck(bTgtProxy ? BST_CHECKED : BST_UNCHECKED);
		m_radioTargetFilterBypass.SetCheck(bTgtProxy ? BST_UNCHECKED : BST_CHECKED);
		UpdateChildFilterEnable();
	}
	m_chainMode = item ? item->bChain : FALSE;
	m_chainHops = item ? item->chainHops : std::vector<CString>();
	RefreshChainList();
	ExpandConfiguredOptions();
	UpdateDnsRedirectEnable();
	UpdateTransportEnable();
	SetTimer(0x311, 300, NULL); // Debounce profile selection; no Shell work on the UI thread.
	m_loadedProfileName = item ? item->strName : _T("");
	m_draftProfileName = m_loadedProfileName;
	m_loadingProfile = FALSE;
	SetProfileDirty(FALSE);
	if (m_proxyController.IsRunning())
		SetRuntimeDirty(TRUE);
	LayoutSettingsPage();
}

void CPage1::UIGetCfg( CfgProxyItem *item )
{

	if (m_chainMode || !GetSettings(&item->pi))
	{
		// A chain has no server of its own (the store writes it as Type=CHAIN);
		// keep a direct placeholder rather than half-entered values.
		ZeroMemory(&item->pi, sizeof(item->pi));
		item->pi.szItemName = _T("myproxy");
		item->pi.strProxyType = _T("NOPROXY");
	}
	item->bChain = m_chainMode;
	item->chainHops = m_chainHops;
	item->nTransportMode = m_cbTransport.GetCurSel() ==
		PROXY_TRANSPORT_GONC_TLS_PSK ? PROXY_TRANSPORT_GONC_TLS_PSK :
		PROXY_TRANSPORT_PLAIN;
	m_editTransportPsk.GetWindowText(item->strTransportPsk);
    if (item->pi.GetProxyType() == PROXYTYPE_SSH) item->strTransportPsk.Trim();
	if (item->pi.GetProxyType() == PROXYTYPE_NOPROXY)
	{
		item->nTransportMode = PROXY_TRANSPORT_PLAIN;
		item->strTransportPsk.Empty();
	}

	item->bHookTCP = m_btnHookTCP.GetCheck() == BST_CHECKED;
	item->bHookUDP = m_btnHookUDP.GetCheck() == BST_CHECKED;
	item->bBlockUDP = m_btnBlockUDP.GetCheck() == BST_CHECKED;
	item->bBlockIPv6 = m_btnBlockIPv6.GetCheck() == BST_CHECKED;
	item->bHookChildProcess = m_btnHookChildProcess.GetCheck() == BST_CHECKED;
	item->dnsOpt = m_btnDNSLocal.GetCheck() ? PSI_DNSOPT_LOCAL : PSI_DNSOPT_REMOTE;
	item->bRedirectPrivateDNS =
		m_btnRedirectPrivateDNS.GetCheck() == BST_CHECKED;
	m_editRedirectDNS.GetWindowText(item->strRedirectDNS);
	item->strRedirectDNS.Trim();

	CString strFilter;
	m_editChildFilter.GetWindowText(strFilter);
	item->strChildFilter = strFilter;
	item->nChildFilterMode = (m_radioChildFilterInclude.GetCheck() == BST_CHECKED)
		? CHILDFILTER_MODE_INCLUDE : CHILDFILTER_MODE_EXCLUDE;

	CString strTgt;
	m_editTargetFilter.GetWindowText(strTgt);
	item->strTargetFilter = strTgt;
	item->nTargetFilterMode = (m_radioTargetFilterProxy.GetCheck() == BST_CHECKED)
		? TARGETFILTER_MODE_PROXY : TARGETFILTER_MODE_BYPASS;
}

void CPage1::OnBnClickedHookChildProcess()
{
	UpdateChildFilterEnable();
	OnProfileFieldChanged();
}

void CPage1::UpdateChildFilterEnable()
{
	BOOL bOn = (m_btnHookChildProcess.GetCheck() == BST_CHECKED);
	m_editChildFilter.EnableWindow(bOn);
	m_radioChildFilterExclude.EnableWindow(bOn);
	m_radioChildFilterInclude.EnableWindow(bOn);
	if (CWnd* pHint = GetDlgItem(IDC_STATIC_CHILDFILTER_HINT))
		pHint->EnableWindow(bOn);
	if (CWnd* pGrp = GetDlgItem(IDC_STATIC_CHILDFILTER_GROUP))
		pGrp->EnableWindow(bOn);
}

// 把 UI 上当前的子进程过滤规则发布到运行时快照（界面所见即生效）
void CPage1::PublishChildFilterSnapshot()
{
	CfgProxyItem cur;
	UIGetCfg(&cur);
	CSingleLock filterLock(&g_childFilterLock, TRUE);
	g_ChildInjectFilter.bEnabled = cur.bHookChildProcess;
	g_ChildInjectFilter.nMode = cur.nChildFilterMode;
	SplitFilterPatterns(cur.strChildFilter, g_ChildInjectFilter.patterns);
}

// 把 UI 上当前的目标地址过滤规则发布到运行时快照（界面所见即生效）
void CPage1::PublishTargetFilterSnapshot()
{
	CfgProxyItem cur;
	UIGetCfg(&cur);
	CSingleLock runtimeLock(&m_runtimeLock, TRUE);
	g_TargetInjectFilter.nMode = cur.nTargetFilterMode;
	SplitFilterPatterns(cur.strTargetFilter, g_TargetInjectFilter.patterns);
}

// 一并发布所有 profile 相关的运行时快照
void CPage1::PublishProfileSnapshots()
{
	PublishChildFilterSnapshot();
	PublishTargetFilterSnapshot();
}

// 切换 tab：只显示当前 tab 对应的控件组
void CPage1::ShowTab(int nTab)
{
	static const int idsBasic[] = {
		IDC_CHECK_HOOKTCP, IDC_CHECK_HOOK_UDP, IDC_CHECK_HOOKCHILDPROCESS, IDC_CHECK_BLOCKUDP,
		IDC_CHECK_BLOCK_IPV6,
		IDC_RADIO_DNSLOCAL, IDC_RADIO_DNSREMOTE, IDC_STATIC_GROUP_OTHER, IDC_STATIC_DNS_LABEL,
		IDC_CHECK_REDIRECT_PRIVATE_DNS, IDC_EDIT_REDIRECT_DNS };
	static const int idsChild[] = {
		IDC_EDIT_CHILDFILTER, IDC_RADIO_CHILDFILTER_EXCLUDE, IDC_RADIO_CHILDFILTER_INCLUDE,
		IDC_STATIC_CHILDFILTER_HINT, IDC_STATIC_CHILDFILTER_GROUP };
	static const int idsTarget[] = {
		IDC_EDIT_TARGETFILTER, IDC_RADIO_TARGETFILTER_BYPASS, IDC_RADIO_TARGETFILTER_PROXY,
		IDC_STATIC_TARGETFILTER_HINT, IDC_STATIC_TARGETFILTER_GROUP };

	for (int i = 0; i < _countof(idsBasic);  i++) if (CWnd* w = GetDlgItem(idsBasic[i]))  w->ShowWindow(nTab == 0 ? SW_SHOW : SW_HIDE);
	for (int i = 0; i < _countof(idsChild);  i++) if (CWnd* w = GetDlgItem(idsChild[i]))  w->ShowWindow(nTab == 1 ? SW_SHOW : SW_HIDE);
	for (int i = 0; i < _countof(idsTarget); i++) if (CWnd* w = GetDlgItem(idsTarget[i])) w->ShowWindow(nTab == 2 ? SW_SHOW : SW_HIDE);

	m_radioTabBasic.SetCheck (nTab == 0 ? BST_CHECKED : BST_UNCHECKED);
	m_radioTabChild.SetCheck (nTab == 1 ? BST_CHECKED : BST_UNCHECKED);
	m_radioTabTarget.SetCheck(nTab == 2 ? BST_CHECKED : BST_UNCHECKED);
	m_activeTab = nTab;
	LayoutSettingsPage();
}

void CPage1::OnBnClickedTabBasic()  { ShowTab(0); }
void CPage1::OnBnClickedTabChild()  { ShowTab(1); UpdateChildFilterEnable(); }
void CPage1::OnBnClickedTabTarget() { ShowTab(2); }

void CPage1::OnCbnSelchangeComboCfgs()
{
	if (m_loadingProfile || m_cfgls.GetCurSel() == CB_ERR)
		return;
	CString name;
	m_cfgls.GetLBText(m_cfgls.GetCurSel(), name);
	SelectProfileFromDisk(name);
}

BOOL CPage1::RefreshProfileNames()
{
	std::vector<CString> names;
	if (!m_profileStore.ListNames(names))
	{
		ShowProfileNotice(Localization::Get(_T("profile.refresh_failed")), NULL, CStatusLabel::TONE_WARNING);
		return FALSE;
	}
	CString draft;
	m_cfgls.GetWindowText(draft);
	const BOOL selected = m_cfgls.GetCurSel() != CB_ERR;
	m_loadingProfile = TRUE;
	m_cfgls.ResetContent();
	for (const CString& name : names)
		m_cfgls.AddString(name);
	RefreshProfileEntries();
	const BOOL removed = !m_loadedProfileName.IsEmpty() &&
		m_cfgls.FindStringExact(-1, m_loadedProfileName) == CB_ERR;
	m_cfgls.SetCurSel(selected ? m_cfgls.FindStringExact(-1, draft) : -1);
	m_cfgls.SetWindowText(draft);
	m_loadingProfile = FALSE;
	if (removed)
	{
		m_loadedProfileName.Empty();
		m_draftProfileName = draft;
		SetProfileDirty(TRUE);
		ShowProfileNotice(Localization::Get(_T("profile.removed_elsewhere")),
			Localization::Get(_T("profile.draft_preserved")), CStatusLabel::TONE_WARNING);
	}
	else
		SetProfileDirty(m_profileDirty);
	return TRUE;
}

void CPage1::OnCbnDropdownComboCfgs()
{
	RefreshProfileNames();
}

void CPage1::SelectProfileFromDisk(const CString& name)
{
	CfgProxyItem item;
	item.strName = name;
	CString previousDraftName = m_draftProfileName;
	if (!m_profileStore.Load(item))
	{
		RestoreProfileSelection();
		RefreshProfileNames();
		MessageBox(Localization::Get(_T("profile.load_failed")),
			Localization::Get(_T("status.invalid_config")), MB_ICONWARNING);
		return;
	}
	if (!ConfirmDiscardUnsavedChanges())
	{
		m_draftProfileName = previousDraftName;
		RestoreProfileSelection();
		return;
	}

	// The prompt may have saved a profile, or another instance may have changed it.
	if (m_profileStore.Load(item))
	{
		m_loadingProfile = TRUE;
		m_cfgls.SetCurSel(m_cfgls.FindStringExact(-1, item.strName));
		m_cfgls.SetWindowText(item.strName);
		m_loadingProfile = FALSE;
		m_profileStore.SetLastSelected(item.strName);
		UILoadCfg(&item);
	}
	else
	{
		RestoreProfileSelection();
		RefreshProfileNames();
		MessageBox(Localization::Get(_T("profile.load_failed")),
			Localization::Get(_T("status.invalid_config")), MB_ICONWARNING);
	}
}

void CPage1::UpdateProxyTestStatus()
{
	if (m_bIsTesting || !m_staticTestProxy.GetSafeHwnd())
		return;

	if (m_profileDirty && m_runtimeDirty)
		m_staticTestProxy.SetStatus(Localization::Get(_T("status.changes_unsaved_unapplied")), CStatusLabel::TONE_WARNING);
	else if (m_runtimeDirty)
		m_staticTestProxy.SetStatus(Localization::Get(_T("status.changes_unapplied")), CStatusLabel::TONE_WARNING);
	else if (m_profileDirty)
		m_staticTestProxy.SetStatus(Localization::Get(_T("status.changes_unsaved")), CStatusLabel::TONE_WARNING);
	else
		m_staticTestProxy.SetStatus(Localization::Get(_T("status.test_not_run")), CStatusLabel::TONE_NEUTRAL);
}

void CPage1::UpdateProxyStateUi()
{
	if (g_MainTab) g_MainTab->RefreshSidebarStatus();
	BOOL running = m_proxyController.IsRunning();
	if (running)
		EndFirstRunGuide();
	m_OK.SetWindowText(Localization::Get(_T("action.start_proxy")));
	m_OK.EnableWindow(!running);
	m_Cancel.EnableWindow(running);
	// One state button: Enable while inactive, Disable while active. Both stay
	// real controls (IDOK/IDCANCEL) so automation and handlers are unchanged.
	CWnd* focus = GetFocus();
	m_OK.ShowWindow(running ? SW_HIDE : SW_SHOW);
	m_Cancel.ShowWindow(running ? SW_SHOW : SW_HIDE);
	if (focus == &m_OK || focus == &m_Cancel)
		(running ? m_Cancel : m_OK).SetFocus();
	if (m_btnSaveProfile.GetSafeHwnd())
	{
		m_btnSaveProfile.SetWindowText(Localization::Get(running
			? _T("action.save_apply") : _T("common.save_profile")));
		m_btnSaveProfile.EnableWindow(running
			? (m_profileDirty || m_runtimeDirty) : m_profileDirty);
	}
	UpdateWorkflowCard();
}

BOOL CPage1::SavePendingProfile() { return !m_profileDirty || SaveCurrentProfile(m_draftProfileName); }
void CPage1::ExpandConfiguredOptions()
{
 CString user, pass; m_edit_User.GetWindowText(user); m_edit_Pass.GetWindowText(pass);
 CString protocol; m_cbProxyType.GetWindowText(protocol);
 m_advancedOpen = protocol == L"SSH" || !user.IsEmpty() || !pass.IsEmpty() || m_cbTransport.GetCurSel() == PROXY_TRANSPORT_GONC_TLS_PSK;
 UpdateAdvancedCaption();
}
void CPage1::OnToggleAdvanced()
{
 m_advancedOpen = !m_advancedOpen; UpdateAdvancedCaption(); LayoutSettingsPage();
}
void CPage1::OnNewProfile() { NewProfile(FALSE); }
void CPage1::OnNewChainProfile() { NewProfile(TRUE); }
void CPage1::NewProfile(BOOL chain)
{
 if (m_bIsTesting || !ConfirmDiscardUnsavedChanges() || !RefreshProfileNames()) return;
 CString base = Localization::Get(chain ? L"profile.new_chain_name" : L"profile.new_name"), name = base;
 for (int i = 2; m_cfgls.FindStringExact(-1, name) != CB_ERR; ++i) name.Format(L"%s %d", (LPCWSTR)base, i);
 UILoadCfg(NULL);
	if (chain)
	{
		// Chain defaults: proxy TCP and child processes, block UDP (it is never
		// chained), resolve DNS through the chain, redirect private DNS.
		m_btnHookTCP.SetCheck(BST_CHECKED);
		m_btnHookChildProcess.SetCheck(BST_CHECKED);
		m_btnBlockUDP.SetCheck(BST_CHECKED);
		m_btnDNSLocal.SetCheck(BST_UNCHECKED);
		m_btnDNSRemote.SetCheck(BST_CHECKED);
		m_btnRedirectPrivateDNS.SetCheck(BST_CHECKED);
		m_editRedirectDNS.SetWindowText(_T("8.8.8.8"));
		UpdateChildFilterEnable();
		UpdateDnsRedirectEnable();
		SetChainMode(TRUE);
	}
 m_loadingProfile = TRUE; m_cfgls.SetCurSel(-1); m_cfgls.SetWindowText(name); m_loadingProfile = FALSE;
 m_draftProfileName = name; SetProfileDirty(TRUE); SetRuntimeDirty(TRUE);
 m_scrollY = 0; LayoutSettingsPage(); m_cfgls.SetFocus(); m_cfgls.SetEditSel(0, -1);
 UpdateProxyTestStatus();
}

void CPage1::UpdateAdvancedCaption()
{
 if (m_btnAdvanced.GetSafeHwnd())
  m_btnAdvanced.SetWindowText(Localization::Get(m_advancedOpen ? L"profile.advanced_hide" : L"profile.advanced_show"));
}

namespace
{
	// "SOCKS5 host:port" for a saved profile, as the chain list and menu show it.
	CString DescribeServer(const CfgProxyItem& item)
	{
		ProxyInfo pi = item.pi;
		const int type = pi.GetProxyType();
		CString host = (CString)pi.strProxyHost;
		if (host.Find(L':') >= 0) host = L"[" + host + L"]";
		CString text;
		text.Format(L"%s %s:%d", type == PROXYTYPE_SSH ? L"SSH" : type == PROXYTYPE_SOCKS5 ? L"SOCKS5" : L"HTTP", (LPCWSTR)host, pi.nProxyPort);
		return text;
	}
}

void CPage1::SetChainMode(BOOL chain)
{
	m_chainMode = chain;
	RefreshChainList();
	UpdateTransportEnable();
	LayoutSettingsPage();
}

void CPage1::RefreshProfileEntries()
{
	m_cfgls.ClearEntries();
	for (int i = 0; i < m_cfgls.GetCount(); ++i)
	{
		CfgProxyItem item;
		m_cfgls.GetLBText(i, item.strName);
		const BOOL valid = m_profileStore.Load(item);
		CProfileCombo::Entry entry;
		ProxyInfo pi = item.pi;
		if (item.bChain)
		{
			entry.tag = Localization::Get(L"profile.tag_chain");
			entry.accent = TRUE;
			for (const CString& hop : item.chainHops)
				entry.detail += (entry.detail.IsEmpty() ? L"" : L" \x2192 ") + hop;
		}
		else if (!valid)
			entry.tag = (CString)pi.strProxyType; // e.g. a retired SOCKS4 profile
		else if (pi.GetProxyType() == PROXYTYPE_NOPROXY)
			entry.tag = Localization::Get(L"profile.tag_direct");
		else
		{
			// "SOCKS5 host:port" -> tag "SOCKS5", detail "host:port".
			const CString server = DescribeServer(item);
			const int space = server.Find(L' ');
			entry.tag = server.Left(space);
			entry.detail = server.Mid(space + 1);
		}
		m_cfgls.SetEntry(item.strName, entry);
	}
	UpdateProfileTag();
}

void CPage1::UpdateProfileTag()
{
	if (!m_cfgls.GetSafeHwnd())
		return;
	CString tag;
	if (m_chainMode)
		tag = Localization::Get(L"profile.tag_chain");
	else if (m_cbProxyType.GetCurSel() != CB_ERR)
	{
		m_cbProxyType.GetLBText(m_cbProxyType.GetCurSel(), tag);
		if (tag.CompareNoCase(L"NOPROXY") == 0)
			tag = Localization::Get(L"profile.tag_direct");
	}
	m_cfgls.SetFieldTag(tag, m_chainMode);
}

void CPage1::RefreshChainList(int select)
{
	if (!m_listChain.GetSafeHwnd())
		return;
	m_listChain.SetRedraw(FALSE);
	m_listChain.DeleteAllItems();
	for (int i = 0; i < (int)m_chainHops.size(); ++i)
	{
		CfgProxyItem item;
		item.strName = m_chainHops[i];
		CString number;
		number.Format(L"%d", i + 1);
		m_listChain.InsertItem(i, number);
		m_listChain.SetItemText(i, 1, m_chainHops[i]);
		m_listChain.SetItemText(i, 2, !m_profileStore.Load(item) ? Localization::Get(L"page1.chain_hop_missing") :
			!CProxyProfileStore::IsChainHop(item) ? Localization::Get(L"page1.chain_hop_invalid") : DescribeServer(item));
	}
	if (select >= 0 && select < (int)m_chainHops.size())
		m_listChain.SetItemState(select, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
	m_listChain.SetRedraw(TRUE);
	m_listChain.Invalidate();
	UpdateChainButtons();
}

void CPage1::UpdateChainButtons()
{
	if (!m_listChain.GetSafeHwnd())
		return;
	const int selected = m_listChain.GetNextItem(-1, LVNI_SELECTED);
	const int count = (int)m_chainHops.size();
	m_btnChainAdd.EnableWindow(!m_bIsTesting);
	m_btnChainUp.EnableWindow(!m_bIsTesting && selected > 0);
	m_btnChainDown.EnableWindow(!m_bIsTesting && selected >= 0 && selected < count - 1);
	m_btnChainRemove.EnableWindow(!m_bIsTesting && selected >= 0);
}

void CPage1::OnChainItemChanged(NMHDR*, LRESULT* result)
{
	UpdateChainButtons();
	*result = 0;
}

void CPage1::OnChainAdd()
{
	// Offer saved Server-mode SOCKS5/HTTP profiles that are not already hops
	// (and not this profile itself).
	std::vector<CString> names, offered;
	m_profileStore.ListNames(names);
	const CString self = GetCurrentProfileName();
	CMenu menu;
	if (!menu.CreatePopupMenu()) return;
	for (const CString& name : names)
	{
		if (name.CompareNoCase(self) == 0) continue;
		BOOL used = FALSE;
		for (const CString& hop : m_chainHops) used = used || hop.CompareNoCase(name) == 0;
		CfgProxyItem item;
		item.strName = name;
		if (used || !m_profileStore.Load(item) || !CProxyProfileStore::IsChainHop(item)) continue;
		offered.push_back(name);
		menu.AppendMenu(MF_STRING, offered.size(), name + L"  \x00b7  " + DescribeServer(item));
	}
	if (offered.empty())
		menu.AppendMenu(MF_STRING | MF_GRAYED, 0, Localization::Get(L"page1.chain_add_none"));
	CRect anchor;
	m_btnChainAdd.GetWindowRect(&anchor);
	const UINT selected = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_LEFTALIGN | TPM_RIGHTBUTTON,
		anchor.left, anchor.bottom, this);
	if (!selected || selected > offered.size())
		return;
	m_chainHops.push_back(offered[selected - 1]);
	RefreshChainList((int)m_chainHops.size() - 1);
	OnProfileFieldChanged();
}

void CPage1::OnChainUp()
{
	const int selected = m_listChain.GetNextItem(-1, LVNI_SELECTED);
	if (selected <= 0) return;
	std::swap(m_chainHops[selected], m_chainHops[selected - 1]);
	RefreshChainList(selected - 1);
	OnProfileFieldChanged();
}

void CPage1::OnChainDown()
{
	const int selected = m_listChain.GetNextItem(-1, LVNI_SELECTED);
	if (selected < 0 || selected >= (int)m_chainHops.size() - 1) return;
	std::swap(m_chainHops[selected], m_chainHops[selected + 1]);
	RefreshChainList(selected + 1);
	OnProfileFieldChanged();
}

void CPage1::OnChainRemove()
{
	const int selected = m_listChain.GetNextItem(-1, LVNI_SELECTED);
	if (selected < 0) return;
	m_chainHops.erase(m_chainHops.begin() + selected);
	RefreshChainList(min(selected, (int)m_chainHops.size() - 1));
	OnProfileFieldChanged();
}
