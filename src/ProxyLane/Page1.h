#pragma once
#include "ChainRouteView.h"

#include "..\ProxyLaneHook\ProxyModule.h"
#include "..\ProxyLaneHook\ProxyDataHandle.h"
#include "afxwin.h"
#include "ModernUI.h"
#include "ProxyController.h"
#include "ProxyProfileStore.h"
#include "SshAuthControls.h"
#include "RecentApplications.h"
#include <afxmt.h>
#include <vector>


// CPage1 对话框

class CPage1 : public CModernDialog
	, public IProxySettings
	, public IProxyTesterCallback
{
	DECLARE_DYNAMIC(CPage1)

public:
	void PreloadRecentApplications();
	CPage1(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CPage1();

// 对话框数据
	enum { IDD = IDD_Page1 };

	CProfileCombo m_cfgls;
	CSoftCombo m_cbProxyType;
	CSoftEdit     m_edit_HostName;
	CSoftEdit     m_edit_Port;
	CSoftEdit     m_edit_User;
	CSoftEdit     m_edit_Pass;
	CSoftCombo m_cbTransport;
	CSoftEdit     m_editTransportPsk;
    CSshAuthControls m_sshAuth;
    afx_msg void OnSshAuthChanged();
    afx_msg void OnImportSshKey();
	CModernButton m_OK;
	CModernButton m_Cancel;
	CModernButton m_btnSaveProfile;
	CModernButton m_btnProfileMenu;
 CModernButton m_btnAdvanced;
 bool m_advancedOpen = false;
	// Profile type, fixed when the profile is created: one server, or a chain
	// of saved server profiles in order.
	BOOL m_chainMode = FALSE;
	std::vector<CString> m_chainHops;
	CChainRouteView m_chainView;
	CModernButton m_btnChainAdd;
	afx_msg void OnChainAdd();
	afx_msg void OnChainEdit();
	afx_msg void OnChainRemove();
	void OnChainMove(int from, int to);
	CChainRouteView::Node ChainNode(int index) const;
	void SetChainMode(BOOL chain);
	void RefreshChainView(int select = -1);
	void UpdateChainButtons();
	void ClearChainProgress();
	void UpdateChainProgress(bool follow = false);
	CString ChainStageText(int index, int stage) const;
	bool ChainNodeNegotiated(int index) const;
	bool ChainLinkFailed(int index) const;
	CString ChainLinkText(int index) const;
	std::vector<ProxyTestHopProgress> m_chainProgress;
	std::vector<CString> m_chainErrors;
	DWORD m_chainStarted = 0, m_chainElapsed = 0;
	bool m_chainProgressRunning = false;
	int m_chainFollowed = -1;
	int m_chainFailureCode = 0;
    int m_singleTestStage = PTS_WAITING;
	CString m_chainConclusion;
	// The current UI's route: the first hop in `first`; chain is empty for one server.
	BOOL GetRoute(LPProxyInfo first, ProxyChain* chain);
 afx_msg void OnNewProfile();
	afx_msg void OnNewChainProfile();
	void NewProfile(BOOL chain);
	// Type tags and detail lines of the picker rows, and the edited profile's tag.
	void RefreshProfileEntries();
	void UpdateProfileTag();
 afx_msg void OnToggleAdvanced();
 void ExpandConfiguredOptions();
 void UpdateAdvancedCaption();
 BOOL SavePendingProfile();

private:
	enum ProxyTestPhase
	{
		PROXY_TEST_NONE = 0,
		PROXY_TEST_TCP,
		PROXY_TEST_UDP,
		PROXY_TEST_IPV6
	};

	enum Ipv6TestResult
	{
		IPV6_TEST_NOT_RUN = 0,
		IPV6_TEST_AVAILABLE,
		IPV6_TEST_TARGET_FAILED,
		IPV6_TEST_UNKNOWN,
		IPV6_TEST_UNSUPPORTED,
		IPV6_TEST_INVALID_CONFIG
	};

	ProxyInfo m_ProxyInfo;
	ProxyChain m_runtimeChain;	// empty = single upstream; guarded by m_runtimeLock
	ProxySettingsInfo m_runtimeSettings;
	CCriticalSection m_runtimeLock;
	BOOL m_runtimeSettingsValid;
	CString m_settingsValidationKey;
	CString m_settingsValidationName;	// the chain hop a validation error is about
	CString SettingsValidationMessage() const;
	BOOL m_runtimeDirty;

	IGlobalProxy* m_pTestProxy;
	IProxyTester* m_pProxyTester;
	// Same deferred completion pattern as the node editor: never enter a
	// modal result loop while a transport callback still owns the stack.
	enum { ProxyTestCompletedMessage = WM_APP + 51 };
	UINT_PTR m_testGeneration = 0;
	bool m_testCompletionPending = false;
	int m_testCompletionCode = 0;
	WPARAM m_testCompletionParam = 0;
	CStringA m_testCompletionDetail;
	afx_msg LRESULT OnProxyTestCompleted(WPARAM generation, LPARAM);
	void HandleProxyTesterCallback(IProxyTester*, int, WPARAM, LPARAM);
	BOOL m_bIsTesting;
	int m_proxyTestPhase;
	int m_testIpv6Result;
	int m_testIpv6Error = 0;
	CString m_testIpv6Address;
	BOOL m_testUdpRequested;
	BOOL m_testTcpPassed = FALSE;
	BOOL m_testUdpPassed = FALSE;
	int m_testUdpError = 0;
	CString m_testTcpTarget;
    bool m_testDohQuerying = false;
	INT_PTR ShowProxyTestResult(const CString& details, LPCTSTR actionKey = NULL);
	ProxyInfo m_testProxyInfo;
	ProxyChain m_testChain;	// empty = testing a single upstream
	std::vector<CString> m_testChainNames;
	BOOL m_profileDirty;
	BOOL m_loadingProfile;
	CString m_loadedProfileName;
	CString m_draftProfileName;
	// Fresh settings file: guide the user until a profile is saved or enabled.
	BOOL m_firstRunGuide = FALSE;
	void EndFirstRunGuide();

	BOOL m_bDisableLLMNR;
	BOOL m_bDisableMDNS;
	BOOL m_bHookLanIP;
	CProxyController m_proxyController;
	CProxyProfileStore m_profileStore;
	int m_activeTab;
	int m_scrollY;
	BOOL m_inLayout;
	CCardFrame m_cardProxy;
	CCardFrame m_cardOptions;
	CCardFrame m_cardChildFilter;
	CCardFrame m_cardTargetFilter;
	void LayoutSettingsPage();
	void UpdateWorkflowCard();
	void SetProfileDirty(BOOL dirty);
	void SetRuntimeDirty(BOOL dirty);
	BOOL GetProxySettingsFromUi(LPProxySettingsInfo lpPSI);
	BOOL ApplyRuntimeSettings();
	CString GetCurrentProfileName();
	BOOL SaveCurrentProfile(LPCTSTR profileName = NULL);
	void RestoreProfileSelection();
	void ShowProfileNotice(LPCTSTR primary, LPCTSTR secondary, CStatusLabel::Tone tone);
	BOOL RefreshProfileNames();
	void SelectProfileFromDisk(const CString& name);
	BOOL StartProxyTestPhase(const PRCClient& client, int phase,
		LPCTSTR statusKey);
	BOOL StartIpv6ProxyTest();
	BOOL SupportsIpv6ProxyTest();
	int ClassifyIpv6TestResult(int errorCode) const;

public:

	BOOL GetSettings(OUT LPProxyInfo lpPI);
	BOOL LoadProfileByName(LPCTSTR profileName, BOOL rememberSelection = FALSE);
	BOOL StartProxy(BOOL showErrors);
	BOOL StopProxy();
	BOOL IsProxyRunning() const;
	CString QuicUdpWarning(); // UI thread: active settings, or selected draft while stopped.
	BOOL ConfirmDiscardUnsavedChanges();
	BOOL HasUnsavedProfileChanges() const { return m_profileDirty; }
	BOOL IsFirstRunGuideActive() const { return m_firstRunGuide; }
	CString GetSelectedProfileName() { return GetCurrentProfileName(); }
	CString GetSelectedProfileSummary();
	// Connection test of the selected profile, mirrored by the applications page.
	BOOL IsProxyTesting() const { return m_bIsTesting; }
	CString GetProxyTestStatus(CStatusLabel::Tone& tone) const;
	CString GetSelectedRecentProfileId();
	void GetSavedProfileNames(std::vector<CString>& names);

	//重载IProxySettings的成员函数////////////////////////////////////////////
	BOOL GetProxyInfo(const LPPRCClient pPRCC, LPProxyInfo lpPI);
	BOOL GetProxySettings(LPProxySettingsInfo lpPSI);
	INT GetProxyChain(const LPPRCClient pPRCC, LPProxyInfo lpHops, INT nCapacity);

	//IProxyTesterCallback
	void OnProxyTesterCallback(IProxyTester *pTester, int nErrorCode, WPARAM wParam, LPARAM lParam);
	//////////////////////////////////////////////////////////////////////////

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual BOOL OnInitDialog();
	virtual BOOL UsesSecondaryText(UINT controlId) const;
	afx_msg LRESULT OnRecentApplicationsChanged(WPARAM, LPARAM);
	afx_msg void OnTimer(UINT_PTR timer);

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnVScroll(UINT code, UINT position, CScrollBar* scrollBar);
	afx_msg BOOL OnMouseWheel(UINT flags, short delta, CPoint point);
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnDestroy();
	CModernButton m_btnTest;
	afx_msg void OnBnClickedTestproxy();
	CToggleButton m_btnHookTCP;
	CToggleButton m_btnHookUDP;
	CToggleButton m_btnBlockUDP;
	CToggleButton m_btnBlockIPv6;
	CToggleButton m_btnDNSLocal;
	CToggleButton m_btnDNSRemote;
    CToggleButton m_btnDNSDoh;
    CModernButton m_btnDohPreset;
    CSoftEdit m_editDohUrl, m_editDohBootstrap;
    BOOL ApplyDohSettings(ProxyInfo& proxy);
	CToggleButton m_btnRedirectPrivateDNS;
	CSoftEdit   m_editRedirectDNS;
	CToggleButton m_btnHookChildProcess;
	CSoftEdit   m_editChildFilter;
	CToggleButton m_radioChildFilterExclude;
	CToggleButton m_radioChildFilterInclude;
	CSoftEdit   m_editTargetFilter;
	CToggleButton m_radioTargetFilterBypass;
	CToggleButton m_radioTargetFilterProxy;
	CToggleButton m_radioTabBasic;
	CToggleButton m_radioTabChild;
	CToggleButton m_radioTabTarget;
	CStatusLabel m_staticTestProxy;
	afx_msg void OnEnChangeEditAddr();
	afx_msg void OnProfileFieldChanged();
    afx_msg void OnProtocolChanged();
	afx_msg void OnDnsSettingsChanged();
    afx_msg void OnDohPreset();
	afx_msg void OnCbnEditchangeComboCfgs();
	afx_msg void OnCfgoptLoad();
	afx_msg void OnCfgoptSave();
	afx_msg void OnCfgoptDelete();
	afx_msg void OnProfileMenu();
	afx_msg void OnImportAllConfig();
 void ImportConfigFile(const CString& path);
	BOOL CanImportAllConfig();
	afx_msg void OnCopyProfile();
	afx_msg void OnPasteProfile();
	void UILoadCfg(CfgProxyItem *item);
	void UIGetCfg(CfgProxyItem *item);
	afx_msg void OnCbnSelchangeComboCfgs();
	afx_msg void OnCbnDropdownComboCfgs();
	afx_msg void OnBnClickedHookChildProcess();
	void UpdateChildFilterEnable();
	void UpdateDnsRedirectEnable();
	BOOL ValidateDnsRedirectSettings(BOOL showError);
	void PublishChildFilterSnapshot();
	void PublishTargetFilterSnapshot();
	void PublishProfileSnapshots();
	afx_msg void OnBnClickedTabBasic();
	afx_msg void OnBnClickedTabChild();
	afx_msg void OnBnClickedTabTarget();
	void ShowTab(int nTab);
	void UpdateProxyTestStatus();
	void UpdateProxyStateUi();
	void UpdateTransportEnable();
};
