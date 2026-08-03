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
#include <vector>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")


CIniFile g_ini;

// 子进程注入过滤运行时快照（OnBnClickedOk 时由 UI 提交）
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
CRITICAL_SECTION g_csTargetFilter;
BOOL g_bTargetFilterCsInit = FALSE;


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
	, m_profileStore(g_ini)
	, m_filterEditBaseHeight(0)
{
	m_pTestProxy = 0;
	m_pProxyTester = 0;
	m_bIsTesting = FALSE;
	m_ProxyInfo.reserved = 0;
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
	DDX_Control(pDX, IDC_TestProxy, m_btnTest);
	DDX_Control(pDX, IDC_CHECK_HOOKTCP, m_btnHookTCP);
	DDX_Control(pDX, IDC_CHECK_HOOK_UDP, m_btnHookUDP);
	DDX_Control(pDX, IDC_CHECK_BLOCKUDP, m_btnBlockUDP);
	DDX_Control(pDX, IDC_RADIO_DNSLOCAL, m_btnDNSLocal);
	DDX_Control(pDX, IDC_RADIO_DNSREMOTE, m_btnDNSRemote);
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
}


BEGIN_MESSAGE_MAP(CPage1, CModernDialog)

	ON_WM_SIZE()
	ON_BN_CLICKED(IDOK, &CPage1::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CPage1::OnBnClickedCancel)
	ON_WM_DESTROY()
	ON_BN_CLICKED(IDC_TestProxy, &CPage1::OnBnClickedTestproxy)
	ON_EN_CHANGE(IDC_EDIT_ADDR, &CPage1::OnEnChangeEditAddr)
	ON_BN_CLICKED(IDC_BUTTON_CfgOpt, &CPage1::OnBnClickedButtonCfgopt)
	ON_COMMAND(ID_CFGOPT_Load, &CPage1::OnCfgoptLoad)
	ON_COMMAND(ID_CFGOPT_Save, &CPage1::OnCfgoptSave)
	ON_COMMAND(ID_CFGOPT_Delete, &CPage1::OnCfgoptDelete)
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

	ShowTab(0);

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
	m_workflowGroup.Create(_T("使用流程"), WS_CHILD | BS_GROUPBOX,
		emptyRect, this, IDC_STATIC_WORKFLOW_GROUP);
	m_workflowStatus.Create(_T("3 步完成设置"), WS_CHILD | SS_OWNERDRAW,
		emptyRect, this, IDC_STATIC_WORKFLOW_STATUS);
	m_workflowText.Create(_T(""), WS_CHILD | SS_LEFT,
		emptyRect, this, IDC_STATIC_WORKFLOW_TEXT);
	m_workflowNext.Create(_T("前往应用与进程"),
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
		m_workflowStatus.SetStatus(_T("代理服务已启动"), CStatusLabel::TONE_SUCCESS);
		m_workflowText.SetWindowText(
			_T("下一步，请选择需要走代理的应用。\r\n\r\n")
			_T("可从进程列表选择，也可以直接拖入程序或快捷方式。"));
	}
	else
	{
		m_workflowStatus.SetStatus(_T("3 步完成设置"), CStatusLabel::TONE_INFO);
		m_workflowText.SetWindowText(
			_T("1. 配置代理服务器\r\n\r\n")
			_T("2. 启动代理服务\r\n\r\n")
			_T("3. 选择需要走代理的应用"));
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
	ProxySettingsInfo psi;

	psi.bHookTCP = m_btnHookTCP.GetCheck() == BST_CHECKED;
	psi.bHookUDP = m_btnHookUDP.GetCheck() == BST_CHECKED;
	psi.bBlockUDP = m_btnBlockUDP.GetCheck() == BST_CHECKED;
	psi.bHookCreateProcess = m_btnHookChildProcess.GetCheck();
	psi.nDNSOption = m_btnDNSLocal.GetCheck() ? PSI_DNSOPT_LOCAL : PSI_DNSOPT_REMOTE;
	psi.bHookLanIP = m_bHookLanIP;
	psi.bDisableLLMNR = m_bDisableLLMNR;

	*lpPSI = psi;
	return TRUE;
}

BOOL CPage1::GetSettings(OUT LPProxyInfo lpPI)
{

	CString szType, szHost, szPort, szUser, szPass;

	m_cbProxyType.GetLBText(m_cbProxyType.GetCurSel(), szType);
	m_edit_HostName.GetWindowText(szHost);
	m_edit_Port.GetWindowText(szPort);
	m_edit_User.GetWindowText(szUser);
	m_edit_Pass.GetWindowText(szPass);

	if (!szHost.GetLength() || !szPort.GetLength() || !_ttoi(szPort))
		return FALSE;

	ProxyInfo pi;
	pi.reserved = 0;

	pi.szItemName = _T("myproxy");
	pi.strProxyType = szType;
	pi.strProxyHost = szHost;
	pi.nProxyPort = _ttoi(szPort);
	pi.strProxyUser = szUser;
	pi.strProxyPass = szPass;

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

BOOL CPage1::StartProxy(BOOL showErrors)
{
	if (m_proxyController.IsRunning())
		return TRUE;

	if (!GetSettings(&m_ProxyInfo))
	{
		if (showErrors)
			MessageBox(_T("请检查代理地址和端口是否填写正确。"), _T("无法启动代理"), MB_ICONERROR);
		return FALSE;
	}

	CMainTab *pParent = g_MainTab;
	CPage2 *pPage2 = pParent->GetPage2();
	CPage3 *pPage3 = pParent->GetPage3();
	CPage4 *pPage4 = pParent->GetPage4();

	if (m_ProxyInfo.GetProxyType() != PROXYTYPE_SOCKS5)
	{
		m_btnHookUDP.SetCheck(BST_UNCHECKED);
	}

	PublishProfileSnapshots();

	if (m_proxyController.Start(this, pPage2, pPage3))
	{
		CString runningProfileName;
		const int selectedProfile = m_cfgls.GetCurSel();
		if (selectedProfile != CB_ERR)
			m_cfgls.GetLBText(selectedProfile, runningProfileName);
		else
			m_cfgls.GetWindowText(runningProfileName);
		pParent->SetRunningProfile(runningProfileName, TRUE);
		pPage4->UpdateMonitorStatus();
		UpdateProxyStateUi();
		return TRUE;
	}

	m_staticTestProxy.SetStatus(_T("启动失败"), CStatusLabel::TONE_DANGER);
	return FALSE;
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
		m_btnTest.SetWindowText(_T("测试连接"));
		UpdateProxyStateUi();
		return;
	}

	// 测试按钮也以界面所见为准，更新内存中的过滤快照（即便已启动也能即时生效）
	PublishProfileSnapshots();

	if (m_pProxyTester)
		m_pProxyTester->Release();
	m_bIsTesting = FALSE;
	m_pProxyTester = m_pTestProxy->CreateTester();
	
	if (m_pProxyTester == NULL)
	{
		ATLTRACE("OnBnClickedTestproxy -> CreateTester failed.\r\n");
		return;
	}

	if (!GetSettings(&m_ProxyInfo))
	{
		MessageBox(_T("请检查代理地址和端口是否填写正确。"), _T("无法测试连接"), MB_ICONERROR);
		m_staticTestProxy.SetStatus(_T("配置无效"), CStatusLabel::TONE_DANGER);
		return;
	}

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

	if (!m_pProxyTester->Start(this, &client, &m_ProxyInfo))
	{
		MessageBox(_T("无法开始连接测试，请检查当前网络。"), _T("测试失败"), MB_ICONERROR);
		m_staticTestProxy.SetStatus(_T("测试失败"), CStatusLabel::TONE_DANGER);
		ATLTRACE("OnBnClickedTestproxy -> Start failed.\r\n");
		return;
	}

	m_btnTest.SetWindowText(_T("取消测试"));
	m_staticTestProxy.SetStatus(_T("正在测试"), CStatusLabel::TONE_INFO);
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
			szText.Format(_T("正在连接"));
		}else if (nCode == connected)
		{
			szText.Format(_T("正在协商"));
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

		if(nCode == 0)
		{
			szText = _T("代理服务器工作正常");
			m_staticTestProxy.SetStatus(_T("测试通过"), CStatusLabel::TONE_SUCCESS);
			MessageBox(szText);
		}else
		{
			switch (nCode)
			{
			case PROXYERROR_NOCONN:
				szText.Format(_T("连接代理服务器失败"));
				break;
				/* fall through */
			case PROXYERROR_REQUESTFAILED:
				szText.Format(_T("代理服务器连不上目标服务器"));
				break;
			case PROXYERROR_AUTHREQUIRED:
				szText.Format(_T("代理服务器需要身份验证"));
				break;
			case PROXYERROR_AUTHTYPEUNKNOWN:
				szText.Format(_T("不支持代理服务器的验证方式"));
				break;
			case PROXYERROR_AUTHFAILED:
				szText.Format(_T("身份验证失败"));
				break;

			default:
				szText.Format(_T("和代理服务器协商失败，错误号: %d"), nCode);
				break;
			}
			m_staticTestProxy.SetStatus(_T("测试失败"), CStatusLabel::TONE_DANGER);
			MessageBox(szText);
		}

		pTester->Release();
		m_pProxyTester = NULL;
		m_btnTest.SetWindowText(_T("测试连接"));
		m_bIsTesting = FALSE;

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
}

void CPage1::OnBnClickedButtonCfgopt()
{
	CMenu menu;

	if (menu.LoadMenu(MAKEINTRESOURCE(IDR_MENU_CFGS)))
	{
		POINT pt;
		GetCursorPos(&pt);
		menu.GetSubMenu(0)->TrackPopupMenu(TPM_LEFTBUTTON, 
			pt.x, 
			pt.y,
			this
			);
	}
}

void CPage1::OnCfgoptLoad()
{
	CfgProxyItem item;
	
	m_cfgls.GetWindowText(item.strName);

	if (m_profileStore.Load(item))
	{
		m_profileStore.SetLastSelected(item.strName);
		UILoadCfg(&item);
	}
}

void CPage1::OnCfgoptSave()
{
	CfgProxyItem item;

	m_cfgls.GetWindowText(item.strName);
	item.strName.Trim();
	if (item.strName.IsEmpty())
	{
		MessageBox(_T("请先输入一个配置名称。"), _T("无法保存配置"), MB_ICONINFORMATION);
		return;
	}
	m_profileStore.SetLastSelected(item.strName);

	UIGetCfg(&item);
	m_profileStore.Save(item);

	if (m_cfgls.FindStringExact(-1, item.strName) == CB_ERR)
	{
		m_cfgls.AddString(item.strName);
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
			m_profileStore.Delete(strName);
			m_cfgls.DeleteString(idx);
		}
	}
}

void CPage1::UILoadCfg( CfgProxyItem *item )
{
	if (item == NULL)
	{
		m_cbProxyType.SelectString(0, _T("SOCKS5"));
		m_edit_HostName.SetWindowText(_T(""));
		m_edit_Port.SetWindowText(_T("1080"));
		m_edit_User.SetWindowText(_T(""));
		m_edit_Pass.SetWindowText(_T(""));
		GetSettings(&m_ProxyInfo);

		m_btnHookTCP.SetCheck(BST_CHECKED);
		m_btnHookUDP.SetCheck(BST_CHECKED);
		m_btnBlockUDP.SetCheck(BST_UNCHECKED);
		m_btnDNSLocal.SetCheck(BST_CHECKED);
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

		GetSettings(&m_ProxyInfo);

		m_btnHookTCP.SetCheck(item->bHookTCP ? BST_CHECKED : BST_UNCHECKED);
		m_btnHookUDP.SetCheck(item->bHookUDP ? BST_CHECKED : BST_UNCHECKED);
		m_btnBlockUDP.SetCheck(item->bBlockUDP ? BST_CHECKED : BST_UNCHECKED);
		m_btnHookChildProcess.SetCheck(item->bHookChildProcess ? BST_CHECKED : BST_UNCHECKED);
		m_btnDNSLocal.SetCheck(item->dnsOpt==PSI_DNSOPT_LOCAL ? BST_CHECKED : BST_UNCHECKED);
		m_btnDNSRemote.SetCheck(!m_btnDNSLocal.GetCheck());

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

}

void CPage1::UIGetCfg( CfgProxyItem *item )
{

	GetSettings(&item->pi);

	item->bHookTCP = m_btnHookTCP.GetCheck() == BST_CHECKED;
	item->bHookUDP = m_btnHookUDP.GetCheck() == BST_CHECKED;
	item->bBlockUDP = m_btnBlockUDP.GetCheck() == BST_CHECKED;
	item->bHookChildProcess = m_btnHookChildProcess.GetCheck() == BST_CHECKED;
	item->dnsOpt = m_btnDNSLocal.GetCheck() ? PSI_DNSOPT_LOCAL : PSI_DNSOPT_REMOTE;

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
	g_ChildInjectFilter.bEnabled = cur.bHookChildProcess;
	g_ChildInjectFilter.nMode = cur.nChildFilterMode;
	SplitFilterPatterns(cur.strChildFilter, g_ChildInjectFilter.patterns);
}

// 把 UI 上当前的目标地址过滤规则发布到运行时快照（界面所见即生效）
void CPage1::PublishTargetFilterSnapshot()
{
	CfgProxyItem cur;
	UIGetCfg(&cur);
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
		IDC_RADIO_DNSLOCAL, IDC_RADIO_DNSREMOTE, IDC_STATIC_GROUP_OTHER, IDC_STATIC_DNS_LABEL };
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

	m_cfgls.GetLBText(m_cfgls.GetCurSel(), item.strName);

	if (m_profileStore.Load(item))
	{
		m_profileStore.SetLastSelected(item.strName);
		UILoadCfg(&item);
	}
}

void CPage1::UpdateProxyStateUi()
{
	BOOL running = m_proxyController.IsRunning();
	m_OK.EnableWindow(!running);
	m_Cancel.EnableWindow(running);
	if (running)
		m_staticTestProxy.SetStatus(_T("代理运行中"), CStatusLabel::TONE_SUCCESS);
	else
		m_staticTestProxy.SetStatus(_T("代理未启动"), CStatusLabel::TONE_NEUTRAL);
	UpdateWorkflowCard();
}
