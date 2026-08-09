// Page1.cpp : 实现文件
//

#include "stdafx.h"
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
	, m_filterEditBaseHeight(0)
{
	m_pTestProxy = 0;
	m_pProxyTester = 0;
	m_bIsTesting = FALSE;
	m_proxyTestPhase = 0;
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
	DDX_Control(pDX, IDC_BUTTON_DELETE_PROFILE, m_btnDeleteProfile);
}


BEGIN_MESSAGE_MAP(CPage1, CModernDialog)

	ON_WM_SIZE()
	ON_BN_CLICKED(IDOK, &CPage1::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CPage1::OnBnClickedCancel)
	ON_WM_DESTROY()
	ON_BN_CLICKED(IDC_TestProxy, &CPage1::OnBnClickedTestproxy)
	ON_BN_CLICKED(IDC_BUTTON_SAVE_PROFILE, &CPage1::OnCfgoptSave)
	ON_EN_CHANGE(IDC_EDIT_ADDR, &CPage1::OnEnChangeEditAddr)
	ON_EN_CHANGE(IDC_EDIT_PORT, &CPage1::OnProfileFieldChanged)
	ON_EN_CHANGE(IDC_EDIT_USER, &CPage1::OnProfileFieldChanged)
	ON_EN_CHANGE(IDC_EDIT_PASS, &CPage1::OnProfileFieldChanged)
	ON_EN_CHANGE(IDC_EDIT_TRANSPORT_PSK, &CPage1::OnProfileFieldChanged)
	ON_EN_CHANGE(IDC_EDIT_CHILDFILTER, &CPage1::OnProfileFieldChanged)
	ON_EN_CHANGE(IDC_EDIT_TARGETFILTER, &CPage1::OnProfileFieldChanged)
	ON_CBN_SELCHANGE(IDC_CB_PROXYTYPE, &CPage1::OnProfileFieldChanged)
	ON_CBN_SELCHANGE(IDC_COMBO_TRANSPORT, &CPage1::OnProfileFieldChanged)
	ON_CBN_EDITCHANGE(IDC_COMBO_CFGS, &CPage1::OnCbnEditchangeComboCfgs)
	ON_BN_CLICKED(IDC_CHECK_HOOKTCP, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_CHECK_HOOK_UDP, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_CHECK_BLOCKUDP, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_RADIO_DNSLOCAL, &CPage1::OnDnsSettingsChanged)
	ON_BN_CLICKED(IDC_RADIO_DNSREMOTE, &CPage1::OnDnsSettingsChanged)
	ON_BN_CLICKED(IDC_CHECK_REDIRECT_PRIVATE_DNS, &CPage1::OnDnsSettingsChanged)
	ON_EN_CHANGE(IDC_EDIT_REDIRECT_DNS, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_RADIO_CHILDFILTER_EXCLUDE, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_RADIO_CHILDFILTER_INCLUDE, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_RADIO_TARGETFILTER_BYPASS, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_RADIO_TARGETFILTER_PROXY, &CPage1::OnProfileFieldChanged)
	ON_BN_CLICKED(IDC_BUTTON_DELETE_PROFILE, &CPage1::OnCfgoptDelete)
	ON_CBN_SELCHANGE(IDC_COMBO_CFGS, &CPage1::OnCbnSelchangeComboCfgs)
	ON_BN_CLICKED(IDC_CHECK_HOOKCHILDPROCESS, &CPage1::OnBnClickedHookChildProcess)
	ON_BN_CLICKED(IDC_RADIO_TAB_BASIC, &CPage1::OnBnClickedTabBasic)
	ON_BN_CLICKED(IDC_RADIO_TAB_CHILD, &CPage1::OnBnClickedTabChild)
	ON_BN_CLICKED(IDC_RADIO_TAB_TARGET, &CPage1::OnBnClickedTabTarget)
	ON_BN_CLICKED(IDC_BTN_WORKFLOW_NEXT, &CPage1::OnBnClickedWorkflowNext)
END_MESSAGE_MAP()

BOOL CPage1::OnInitDialog()
{
	CModernDialog::OnInitDialog();

	m_OK.SetVisualStyle(CModernButton::STYLE_PRIMARY);
	m_Cancel.SetVisualStyle(CModernButton::STYLE_DANGER);
	m_btnTest.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_btnSaveProfile.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_btnDeleteProfile.SetVisualStyle(CModernButton::STYLE_DANGER);
	CreateWorkflowCard();
	UpdateProxyStateUi();

	CRect filterRect;
	m_editChildFilter.GetWindowRect(&filterRect);
	m_filterEditBaseHeight = filterRect.Height();

	m_cbProxyType.AddString(_T("NOPROXY"));
	m_cbProxyType.AddString(_T("SOCKS4"));
	m_cbProxyType.AddString(_T("SOCKS4A"));
	m_cbProxyType.AddString(_T("SOCKS5"));
	m_cbProxyType.AddString(_T("HTTP10"));
	m_cbProxyType.AddString(_T("HTTP11"));
	m_cbTransport.AddString(Localization::Get(_T("transport.plain")));
	m_cbTransport.AddString(Localization::Get(_T("transport.gonc_tls_psk")));
	m_cbTransport.SetCurSel(PROXY_TRANSPORT_PLAIN);
	UpdateTransportEnable();

	g_ini.SetIniFileName(_T(""));
#ifdef _WIN64
	{
		CString strIniPath = g_ini.GetIniFileName();
		if (strIniPath.Right(6).CompareNoCase(_T("64.ini")) == 0)
		{
			strIniPath = strIniPath.Left(strIniPath.GetLength() - 6) + _T(".ini");
			g_ini.SetIniFileName(strIniPath);
		}
	}
#endif

	list<CfgProxyItem> cfgls;
	CString lastSelectedName;
	m_profileStore.LoadAll(cfgls, lastSelectedName);

	for (list<CfgProxyItem>::iterator it=cfgls.begin(); it!=cfgls.end(); it++)
	{
		CfgProxyItem &item = *it;

		m_cfgls.AddString(item.strName);
	}

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
	m_loadingProfile = FALSE;
	SetProfileDirty(FALSE);

	return TRUE;
}

void CPage1::OnSize(UINT nType, int cx, int cy)
{
	CModernDialog::OnSize(nType, cx, cy);
	LayoutFilterEditor(IDC_STATIC_CHILDFILTER_GROUP,
		m_editChildFilter, IDC_STATIC_CHILDFILTER_HINT);
	LayoutFilterEditor(IDC_STATIC_TARGETFILTER_GROUP,
		m_editTargetFilter, IDC_STATIC_TARGETFILTER_HINT);
	LayoutWorkflowCard();
}

void CPage1::CreateWorkflowCard()
{
	const CRect emptyRect(0, 0, 0, 0);
	m_workflowGroup.Create(Localization::Get(_T("workflow.group")), WS_CHILD | BS_GROUPBOX,
		emptyRect, this, IDC_STATIC_WORKFLOW_GROUP);
	m_workflowStatus.Create(Localization::Get(_T("workflow.ready")), WS_CHILD | SS_OWNERDRAW,
		emptyRect, this, IDC_STATIC_WORKFLOW_STATUS);
	m_workflowText.Create(_T(""), WS_CHILD | SS_LEFT,
		emptyRect, this, IDC_STATIC_WORKFLOW_TEXT);
	m_workflowNext.Create(Localization::Get(_T("workflow.next")),
		WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
		emptyRect, this, IDC_BTN_WORKFLOW_NEXT);

	m_workflowGroup.SetFont(&m_uiFont, FALSE);
	m_workflowStatus.SetFont(&m_uiFont, FALSE);
	m_workflowText.SetFont(&m_uiFont, FALSE);
	m_workflowNext.SetFont(&m_uiFont, FALSE);
	m_workflowNext.SetVisualStyle(CModernButton::STYLE_PRIMARY);
	LayoutWorkflowCard();
}

void CPage1::LayoutWorkflowCard()
{
	if (!m_workflowGroup.GetSafeHwnd())
		return;

	CWnd* optionsGroup = GetDlgItem(IDC_STATIC_GROUP_OTHER);
	if (!optionsGroup || !m_cfgls.GetSafeHwnd())
		return;

	CRect clientRect;
	CRect optionsRect;
	CRect configRect;
	GetClientRect(&clientRect);
	optionsGroup->GetWindowRect(&optionsRect);
	m_cfgls.GetWindowRect(&configRect);
	ScreenToClient(&optionsRect);
	ScreenToClient(&configRect);

	const int gap = UiTheme::ScaleForWindow(m_hWnd, 16);
	const int outerMargin = UiTheme::ScaleForWindow(m_hWnd, 8);
	const int cardLeft = optionsRect.right + gap;
	const int cardRight = clientRect.right - outerMargin;
	const int cardTop = max(outerMargin,
		configRect.top - UiTheme::ScaleForWindow(m_hWnd, 12));
	const int cardBottom = min(clientRect.bottom - outerMargin, optionsRect.bottom);
	// cardRight/cardLeft are already expressed in the page's client coordinates.
	// Do not DPI-scale this threshold again, otherwise 125%/150% displays hide
	// a card that physically has enough room.
	const BOOL showCard = cardRight - cardLeft >= 150
		&& cardBottom - cardTop >= UiTheme::ScaleForWindow(m_hWnd, 180);

	m_workflowGroup.ShowWindow(showCard ? SW_SHOW : SW_HIDE);
	m_workflowStatus.ShowWindow(showCard ? SW_SHOW : SW_HIDE);
	m_workflowText.ShowWindow(showCard ? SW_SHOW : SW_HIDE);
	if (!showCard)
	{
		m_workflowNext.ShowWindow(SW_HIDE);
		return;
	}

	m_workflowGroup.MoveWindow(cardLeft, cardTop,
		cardRight - cardLeft, cardBottom - cardTop);

	const int inner = UiTheme::ScaleForWindow(m_hWnd, 8);
	const int statusTop = cardTop + UiTheme::ScaleForWindow(m_hWnd, 24);
	const int statusHeight = UiTheme::ScaleForWindow(m_hWnd, 28);
	const int statusWidth = min(cardRight - cardLeft - inner * 2,
		UiTheme::ScaleForWindow(m_hWnd, 170));
	m_workflowStatus.MoveWindow(cardLeft + inner, statusTop,
		statusWidth, statusHeight);

	const int buttonWidth = min(cardRight - cardLeft - inner * 2,
		UiTheme::ScaleForWindow(m_hWnd, 180));
	const int buttonHeight = UiTheme::ScaleForWindow(m_hWnd, 34);
	const int buttonTop = cardBottom - inner - buttonHeight;
	m_workflowNext.MoveWindow(cardLeft + inner, buttonTop,
		buttonWidth, buttonHeight);

	const int textTop = statusTop + statusHeight + UiTheme::ScaleForWindow(m_hWnd, 14);
	const int textBottom = m_proxyController.IsRunning()
		? buttonTop - UiTheme::ScaleForWindow(m_hWnd, 12)
		: cardBottom - inner;
	m_workflowText.MoveWindow(cardLeft + inner, textTop,
		cardRight - cardLeft - inner * 2, max(0, textBottom - textTop));

	m_workflowNext.ShowWindow(m_proxyController.IsRunning() ? SW_SHOW : SW_HIDE);
}

void CPage1::UpdateWorkflowCard()
{
	const BOOL running = m_proxyController.IsRunning();
	if (running)
	{
		if (m_runtimeDirty)
		{
			m_workflowStatus.SetStatus(Localization::Get(_T("workflow.unapplied")), CStatusLabel::TONE_WARNING);
			m_workflowText.SetWindowText(Localization::Get(_T("workflow.unapplied_text")));
		}
		else
		{
			m_workflowStatus.SetStatus(Localization::Get(_T("workflow.running")), CStatusLabel::TONE_SUCCESS);
			m_workflowText.SetWindowText(Localization::Get(_T("workflow.running_text")));
		}
	}
	else
	{
		m_workflowStatus.SetStatus(Localization::Get(_T("workflow.ready")), CStatusLabel::TONE_INFO);
		m_workflowText.SetWindowText(Localization::Get(_T("workflow.steps")));
	}

	if (g_MainTab)
		g_MainTab->SetPageAttention(CMainTab::PAGE_APPLICATIONS, running);
	LayoutWorkflowCard();
}

void CPage1::LayoutFilterEditor(UINT groupId, CEdit& editor, UINT hintId)
{
	if (m_filterEditBaseHeight <= 0 || !editor.GetSafeHwnd())
		return;

	CWnd* group = GetDlgItem(groupId);
	CWnd* hint = GetDlgItem(hintId);
	if (!group || !hint)
		return;

	CRect clientRect;
	GetClientRect(&clientRect);

	CRect editRect;
	CRect hintRect;
	CRect groupRect;
	editor.GetWindowRect(&editRect);
	hint->GetWindowRect(&hintRect);
	group->GetWindowRect(&groupRect);
	ScreenToClient(&editRect);
	ScreenToClient(&hintRect);
	ScreenToClient(&groupRect);

	const int hintGap = max(0, hintRect.top - editRect.bottom);
	const int groupPadding = max(0, groupRect.bottom - hintRect.bottom);
	const int bottomMargin = UiTheme::ScaleForWindow(m_hWnd, 24);
	const int desiredHeight = m_filterEditBaseHeight * 2;
	const int maxHeight = clientRect.bottom - bottomMargin - editRect.top
		- hintGap - hintRect.Height() - groupPadding;
	const int targetHeight = max(m_filterEditBaseHeight,
		min(desiredHeight, maxHeight));

	editRect.bottom = editRect.top + targetHeight;
	hintRect.OffsetRect(0, editRect.bottom + hintGap - hintRect.top);
	groupRect.bottom = hintRect.bottom + groupPadding;

	editor.MoveWindow(&editRect);
	hint->MoveWindow(&hintRect);
	group->MoveWindow(&groupRect);
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
			// 命中放行 → 把代理类型清空，PRC 服务器层会按 NOPROXY 直转到原目标
			lpPI->strProxyType = _T("");
		}
	}

	return TRUE;
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

	CString szType, szHost, szPort, szUser, szPass, szTransportPsk;

	m_cbProxyType.GetLBText(m_cbProxyType.GetCurSel(), szType);
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

	if (!szHost.GetLength() || !szPort.GetLength() || !_ttoi(szPort))
		return FALSE;
	if (transportMode == PROXY_TRANSPORT_GONC_TLS_PSK)
	{
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

void CPage1::OnBnClickedOk()
{
	StartProxy(TRUE);
}

BOOL CPage1::LoadProfileByName(LPCTSTR profileName)
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
	return TRUE;
}

void CPage1::SetProfileDirty(BOOL dirty)
{
	m_profileDirty = dirty;
	if (m_btnDeleteProfile.GetSafeHwnd())
		m_btnDeleteProfile.EnableWindow(m_cfgls.GetCurSel() != CB_ERR);
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
	const BOOL supportsSecureTransport =
		ProxyTransportPolicy::SupportsGoncTlsPsk(selectedProxyType);
	if (!supportsSecureTransport)
		m_cbTransport.SetCurSel(PROXY_TRANSPORT_PLAIN);
	m_cbTransport.EnableWindow(supportsSecureTransport);
	m_editTransportPsk.EnableWindow(supportsSecureTransport &&
		m_cbTransport.GetCurSel() == PROXY_TRANSPORT_GONC_TLS_PSK);
	if (m_btnHookUDP.GetSafeHwnd())
	{
		const BOOL supportsUdp =
			ProxyTransportPolicy::SupportsUdpProxy(selectedProxyType);
		if (!supportsUdp)
			m_btnHookUDP.SetCheck(BST_UNCHECKED);
		m_btnHookUDP.EnableWindow(supportsUdp);
	}
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
	if (!GetSettings(&item.pi))
	{
		MessageBox(Localization::Get(m_settingsValidationKey),
			Localization::Get(_T("profile.save_failed_title")), MB_ICONERROR);
		return FALSE;
	}
	if (!ValidateDnsRedirectSettings(TRUE))
		return FALSE;

	m_profileStore.SetLastSelected(item.strName);
	UIGetCfg(&item);
	m_profileStore.Save(item);

	int index = m_cfgls.FindStringExact(-1, item.strName);
	if (index == CB_ERR)
		index = m_cfgls.AddString(item.strName);
	m_loadingProfile = TRUE;
	m_cfgls.SetCurSel(index);
	m_cfgls.SetWindowText(item.strName);
	m_loadingProfile = FALSE;
	m_loadedProfileName = item.strName;
	m_draftProfileName = item.strName;
	SetProfileDirty(FALSE);
	return TRUE;
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

	ProxyInfo proxyInfo;
	ProxySettingsInfo runtimeSettings;
	if (!GetSettings(&proxyInfo))
	{
		if (showErrors)
			MessageBox(Localization::Get(m_settingsValidationKey),
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
	if (!ProxyTransportPolicy::SupportsUdpProxy(proxyInfo.GetProxyType()))
		runtimeSettings.bHookUDP = FALSE;

	PublishProfileSnapshots();
	{
		CSingleLock runtimeLock(&m_runtimeLock, TRUE);
		m_ProxyInfo = proxyInfo;
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

BOOL CPage1::ApplyRuntimeSettings()
{
	if (!m_proxyController.IsRunning())
		return FALSE;

	ProxyInfo proxyInfo;
	ProxySettingsInfo runtimeSettings;
	if (!GetSettings(&proxyInfo))
	{
		MessageBox(Localization::Get(m_settingsValidationKey),
			Localization::Get(_T("apply.failed_title")), MB_ICONERROR);
		return FALSE;
	}
	if (!ValidateDnsRedirectSettings(TRUE))
		return FALSE;

	if (!GetProxySettingsFromUi(&runtimeSettings))
		return FALSE;
	if (!ProxyTransportPolicy::SupportsUdpProxy(proxyInfo.GetProxyType()))
		runtimeSettings.bHookUDP = FALSE;

	PublishProfileSnapshots();
	{
		CSingleLock runtimeLock(&m_runtimeLock, TRUE);
		m_ProxyInfo = proxyInfo;
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

void CPage1::OnDestroy()
{
	CModernDialog::OnDestroy();

	// TODO: 在此处添加消息处理程序代码
	OnBnClickedCancel();
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
		m_proxyTestPhase = 0;
		m_btnTest.SetWindowText(Localization::Get(_T("action.test_current")));
		UpdateProxyTestStatus();
		return;
	}

	if (m_pProxyTester)
		m_pProxyTester->Release();
	m_bIsTesting = FALSE;
	m_proxyTestPhase = 0;
	m_testUdpRequested = FALSE;
	m_pProxyTester = m_pTestProxy->CreateTester();
	
	if (m_pProxyTester == NULL)
	{
		ATLTRACE("OnBnClickedTestproxy -> CreateTester failed.\r\n");
		return;
	}

	ProxyInfo testProxyInfo;
	if (!GetSettings(&testProxyInfo))
	{
		MessageBox(Localization::Get(m_settingsValidationKey),
			Localization::Get(_T("test.invalid_title")), MB_ICONERROR);
		m_staticTestProxy.SetStatus(Localization::Get(_T("status.invalid_config")), CStatusLabel::TONE_DANGER);
		m_pProxyTester->Release();
		m_pProxyTester = NULL;
		m_proxyTestPhase = 0;
		return;
	}
	m_testProxyInfo = testProxyInfo;
	m_proxyTestPhase = 1;
	m_testUdpRequested = m_btnHookUDP.GetCheck() == BST_CHECKED &&
		testProxyInfo.GetProxyType() == PROXYTYPE_SOCKS5;

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

	if (!m_pProxyTester->Start(this, &client, &testProxyInfo))
	{
		MessageBox(Localization::Get(_T("test.start_failed")),
			Localization::Get(_T("test.failed_title")), MB_ICONERROR);
		m_staticTestProxy.SetStatus(Localization::Get(_T("status.test_failed")), CStatusLabel::TONE_DANGER);
		ATLTRACE("OnBnClickedTestproxy -> Start failed.\r\n");
		m_pProxyTester->Release();
		m_pProxyTester = NULL;
		m_proxyTestPhase = 0;
		return;
	}
	m_btnTest.SetWindowText(Localization::Get(_T("action.cancel_test")));
	m_staticTestProxy.SetStatus(Localization::Get(_T("status.testing")), CStatusLabel::TONE_INFO);
	m_bIsTesting = TRUE;

}

void CPage1::OnProxyTesterCallback(IProxyTester *pTester, int nErrorCode, WPARAM wParam, LPARAM lParam)
{
	ATLASSERT(pTester == m_pProxyTester);

	int nType = HIWORD(nErrorCode);
	int nCode = LOWORD(nErrorCode);

	CString szText;

	if (nType == LAYERCALLBACK_STATECHANGE)
	{
		if(nCode == connecting)
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
		//关闭测试对象， 否则下面的MessageBox内部的消息循环可能导致pTester触发其他事件
		pTester->Stop();

		if (nCode == 0 && m_proxyTestPhase == 1 && m_testUdpRequested)
		{
			pTester->Release();
			m_pProxyTester = NULL;
			m_proxyTestPhase = 2;

			PRCClient udpClient;
			udpClient.zero();
			udpClient.sType = SOCK_DGRAM;
			udpClient.dstAddr.SetIP("8.8.8.8");
			udpClient.dstAddr.SetPort(53);
			m_pProxyTester = m_pTestProxy->CreateTester();
			if (m_pProxyTester && m_pProxyTester->Start(this, &udpClient,
				&m_testProxyInfo))
			{
				m_staticTestProxy.SetStatus(
					Localization::Get(_T("status.testing_udp")),
					CStatusLabel::TONE_INFO);
				return;
			}
			if (m_pProxyTester)
			{
				m_pProxyTester->Release();
				m_pProxyTester = NULL;
			}
			nCode = PROXYERROR_UDP_RELAY_FAILED;
		}

		if(nCode == 0)
		{
			szText = Localization::Get(m_proxyTestPhase == 2
				? _T("test.success_tcp_udp") : _T("test.success"));
			if (m_profileDirty && m_runtimeDirty)
			{
				m_staticTestProxy.SetStatus(Localization::Get(_T("status.test_passed_unsaved_unapplied")), CStatusLabel::TONE_WARNING);
				szText += Localization::Get(_T("test.not_saved_or_applied"));
			}
			else if (m_runtimeDirty)
			{
				m_staticTestProxy.SetStatus(Localization::Get(_T("status.test_passed_unapplied")), CStatusLabel::TONE_WARNING);
				szText += Localization::Get(_T("test.not_applied"));
			}
			else if (m_profileDirty)
			{
				m_staticTestProxy.SetStatus(Localization::Get(_T("status.test_passed_unsaved")), CStatusLabel::TONE_WARNING);
				szText += Localization::Get(_T("test.not_saved"));
			}
			else
				m_staticTestProxy.SetStatus(Localization::Get(_T("status.test_passed_saved")), CStatusLabel::TONE_SUCCESS);
			MessageBox(szText, Localization::Get(_T("test.title")), MB_ICONINFORMATION);
		}else
		{
			switch (nCode)
			{
			case PROXYERROR_NOCONN:
				szText = Localization::Get(_T("test.no_connection"));
				break;
				/* fall through */
			case PROXYERROR_REQUESTFAILED:
				szText = Localization::Get(_T("test.target_failed"));
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
			LPCTSTR statusKey = _T("status.test_failed");
			if (m_profileDirty && m_runtimeDirty)
				statusKey = _T("status.test_failed_unsaved_unapplied");
			else if (m_runtimeDirty)
				statusKey = _T("status.test_failed_unapplied");
			else if (m_profileDirty)
				statusKey = _T("status.test_failed_unsaved");
			m_staticTestProxy.SetStatus(Localization::Get(statusKey), CStatusLabel::TONE_DANGER);
			MessageBox(szText);
		}

		if (m_pProxyTester)
		{
			m_pProxyTester->Release();
			m_pProxyTester = NULL;
		}
		m_btnTest.SetWindowText(Localization::Get(_T("action.test_current")));
		m_bIsTesting = FALSE;
		m_proxyTestPhase = 0;

	}

}
void CPage1::OnEnChangeEditAddr()
{
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
	CfgProxyItem item;
	CString previousDraftName = m_draftProfileName;
	m_cfgls.GetWindowText(item.strName);
	if (!ConfirmDiscardUnsavedChanges())
	{
		m_draftProfileName = previousDraftName;
		RestoreProfileSelection();
		return;
	}

	if (m_profileStore.Load(item))
	{
		m_profileStore.SetLastSelected(item.strName);
		UILoadCfg(&item);
	}
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
			if (MessageBox(prompt, Localization::Get(_T("profile.delete_title")),
				MB_OKCANCEL | MB_ICONWARNING) != IDOK)
			{
				return;
			}

			m_profileStore.Delete(strName);
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
		m_btnDNSLocal.SetCheck(BST_CHECKED);
		m_btnDNSRemote.SetCheck(BST_UNCHECKED);
		m_btnRedirectPrivateDNS.SetCheck(BST_CHECKED);
		m_editRedirectDNS.SetWindowText(_T("8.8.8.8"));
		m_btnHookChildProcess.SetCheck(BST_UNCHECKED);
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
		szUser = item->pi.strProxyUser;
		szPass = item->pi.strProxyPass;

		m_cbProxyType.SelectString(0, szType);
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
	UpdateDnsRedirectEnable();
	UpdateTransportEnable();
	m_loadedProfileName = item ? item->strName : _T("");
	m_draftProfileName = m_loadedProfileName;
	m_loadingProfile = FALSE;
	SetProfileDirty(FALSE);
	if (m_proxyController.IsRunning())
		SetRuntimeDirty(TRUE);
}

void CPage1::UIGetCfg( CfgProxyItem *item )
{

	GetSettings(&item->pi);
	item->nTransportMode = m_cbTransport.GetCurSel() ==
		PROXY_TRANSPORT_GONC_TLS_PSK ? PROXY_TRANSPORT_GONC_TLS_PSK :
		PROXY_TRANSPORT_PLAIN;
	m_editTransportPsk.GetWindowText(item->strTransportPsk);

	item->bHookTCP = m_btnHookTCP.GetCheck() == BST_CHECKED;
	item->bHookUDP = m_btnHookUDP.GetCheck() == BST_CHECKED;
	item->bBlockUDP = m_btnBlockUDP.GetCheck() == BST_CHECKED;
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
}

void CPage1::OnBnClickedTabBasic()  { ShowTab(0); }
void CPage1::OnBnClickedTabChild()  { ShowTab(1); UpdateChildFilterEnable(); }
void CPage1::OnBnClickedTabTarget() { ShowTab(2); }

void CPage1::OnBnClickedWorkflowNext()
{
	if (g_MainTab)
		g_MainTab->SelectPage(CMainTab::PAGE_APPLICATIONS);
}

void CPage1::OnCbnSelchangeComboCfgs()
{
	CfgProxyItem item;
	CString previousDraftName = m_draftProfileName;
	m_cfgls.GetLBText(m_cfgls.GetCurSel(), item.strName);
	if (!ConfirmDiscardUnsavedChanges())
	{
		m_draftProfileName = previousDraftName;
		RestoreProfileSelection();
		return;
	}

	if (m_profileStore.Load(item))
	{
		m_profileStore.SetLastSelected(item.strName);
		UILoadCfg(&item);
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
	BOOL running = m_proxyController.IsRunning();
	m_OK.SetWindowText(Localization::Get(_T("action.start_proxy")));
	m_OK.EnableWindow(!running);
	m_Cancel.EnableWindow(running);
	if (m_btnSaveProfile.GetSafeHwnd())
	{
		m_btnSaveProfile.SetWindowText(Localization::Get(running
			? _T("action.save_apply") : _T("common.save_profile")));
		m_btnSaveProfile.EnableWindow(running
			? (m_profileDirty || m_runtimeDirty) : m_profileDirty);
	}
	UpdateWorkflowCard();
}
