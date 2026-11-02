#pragma once

#include "..\ProxyLaneHook\ProxyModule.h"
#include "..\ProxyLaneHook\ProxyDataHandle.h"
#include "afxwin.h"
#include "ModernUI.h"
#include "ProxyController.h"
#include "ProxyProfileStore.h"
#include "RecentApplications.h"
#include <afxmt.h>
#include <vector>


// CPage1 对话框

// Saved profiles with a one-line summary under each name.
class CProfileListBox : public CListBox
{
public:
	void SetSummaries(const std::vector<CString>& summaries) { m_summaries = summaries; }
	CFont* m_nameFont = NULL;
	CFont* m_summaryFont = NULL;

protected:
	virtual void MeasureItem(LPMEASUREITEMSTRUCT measure);
	virtual void DrawItem(LPDRAWITEMSTRUCT draw);
	virtual int CompareItem(LPCOMPAREITEMSTRUCT) { return 0; }
	std::vector<CString> m_summaries;
};

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

	CSoftCombo m_cfgls;
	CSoftCombo m_cbProxyType;
	CSoftEdit     m_edit_HostName;
	CSoftEdit     m_edit_Port;
	CSoftEdit     m_edit_User;
	CSoftEdit     m_edit_Pass;
	CSoftCombo m_cbTransport;
	CSoftEdit     m_editTransportPsk;
	CModernButton m_OK;
	CModernButton m_Cancel;
	CModernButton m_btnSaveProfile;
	CModernButton m_btnProfileMenu;

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
	ProxySettingsInfo m_runtimeSettings;
	CCriticalSection m_runtimeLock;
	BOOL m_runtimeSettingsValid;
	CString m_settingsValidationKey;
	BOOL m_runtimeDirty;

	IGlobalProxy* m_pTestProxy;
	IProxyTester* m_pProxyTester;
	BOOL m_bIsTesting;
	DWORD m_testStartTick = 0;
	int m_testLatencyMs = -1;
	int m_proxyTestPhase;
	int m_testIpv6Result;
	int m_testIpv6Error = 0;
	CString m_testIpv6Address;
	BOOL m_testUdpRequested;
	ProxyInfo m_testProxyInfo;
	BOOL m_profileDirty;
	BOOL m_loadingProfile;
	CString m_loadedProfileName;
	CString m_draftProfileName;

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
	CCardFrame m_cardProfiles;
	CProfileListBox m_profileList;
	CModernButton m_btnNewProfile;
	CModernButton m_btnPasteProfile;
	CModernButton m_btnAdvanced;
	BOOL m_advancedOpen = FALSE;
	CString m_profileListKey;
	CString m_profileNamesKey;
	CFont m_listNameFont;
	CFont m_listSummaryFont;
	void SyncProfileList();
	void UpdateAdvancedCaption();
	afx_msg void OnProfileListSelect();
	afx_msg void OnNewProfile();
	afx_msg void OnToggleAdvanced();
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
	CString GetSelectedProfileName() { return GetCurrentProfileName(); }
	CString GetSelectedProfileSummary();
	CString GetSelectedRecentProfileId();
	void GetSavedProfileNames(std::vector<CString>& names);
	// Dashboard shortcuts.
	void SwitchProfile(const CString& name);
	void ImportConfigFromFile(const CString& path);
	void QuickSetOption(UINT checkId, BOOL checked);
	CString GetUpstreamText();
	CString GetTestSummary();

	//重载IProxySettings的成员函数////////////////////////////////////////////
	BOOL GetProxyInfo(const LPPRCClient pPRCC, LPProxyInfo lpPI);
	BOOL GetProxySettings(LPProxySettingsInfo lpPSI);

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
	afx_msg void OnDnsSettingsChanged();
	afx_msg void OnCbnEditchangeComboCfgs();
	afx_msg void OnCfgoptLoad();
	afx_msg void OnCfgoptSave();
	afx_msg void OnCfgoptDelete();
	afx_msg void OnProfileMenu();
	afx_msg void OnImportAllConfig();
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
