#pragma once

#include "..\ProxyLaneHook\ProxyModule.h"
#include "..\ProxyLaneHook\ProxyDataHandle.h"
#include "afxwin.h"
#include "ModernUI.h"
#include "ProxyController.h"
#include "ProxyProfileStore.h"


// CPage1 对话框

class CPage1 : public CModernDialog
	, public IProxySettings
	, public IProxyTesterCallback
{
	DECLARE_DYNAMIC(CPage1)

public:
	CPage1(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CPage1();

// 对话框数据
	enum { IDD = IDD_Page1 };

	CComboBox m_cfgls;
	CComboBox m_cbProxyType;
	CEdit     m_edit_HostName;
	CEdit     m_edit_Port;
	CEdit     m_edit_User;
	CEdit     m_edit_Pass;
	CModernButton m_OK;
	CModernButton m_Cancel;
	CModernButton m_btnSaveProfile;
	CModernButton m_btnDeleteProfile;

private:

	ProxyInfo m_ProxyInfo;

	IGlobalProxy* m_pTestProxy;
	IProxyTester* m_pProxyTester;
	BOOL m_bIsTesting;
	BOOL m_profileDirty;
	BOOL m_loadingProfile;
	CString m_loadedProfileName;
	CString m_draftProfileName;

	BOOL m_bDisableLLMNR;
	BOOL m_bHookLanIP;
	CProxyController m_proxyController;
	CProxyProfileStore m_profileStore;
	int m_filterEditBaseHeight;
	CButton m_workflowGroup;
	CStatusLabel m_workflowStatus;
	CStatic m_workflowText;
	CModernButton m_workflowNext;

	void LayoutFilterEditor(UINT groupId, CEdit& editor, UINT hintId);
	void CreateWorkflowCard();
	void LayoutWorkflowCard();
	void UpdateWorkflowCard();
	void SetProfileDirty(BOOL dirty);
	BOOL SaveCurrentProfile(LPCTSTR profileName = NULL);
	void RestoreProfileSelection();

public:

	BOOL GetSettings(OUT LPProxyInfo lpPI);
	BOOL LoadProfileByName(LPCTSTR profileName);
	BOOL StartProxy(BOOL showErrors);
	BOOL StopProxy();
	BOOL IsProxyRunning() const;
	BOOL ConfirmDiscardUnsavedChanges();

	//重载IProxySettings的成员函数////////////////////////////////////////////
	BOOL GetProxyInfo(const LPPRCClient pPRCC, LPProxyInfo lpPI);
	BOOL GetProxySettings(LPProxySettingsInfo lpPSI);

	//IProxyTesterCallback
	void OnProxyTesterCallback(IProxyTester *pTester, int nErrorCode, WPARAM wParam, LPARAM lParam);
	//////////////////////////////////////////////////////////////////////////

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual BOOL OnInitDialog();

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnDestroy();
	CModernButton m_btnTest;
	afx_msg void OnBnClickedTestproxy();
	CButton m_btnHookTCP;
	CButton m_btnHookUDP;
	CButton m_btnBlockUDP;
	CButton m_btnDNSLocal;
	CButton m_btnDNSRemote;
	CButton m_btnHookChildProcess;
	CEdit   m_editChildFilter;
	CButton m_radioChildFilterExclude;
	CButton m_radioChildFilterInclude;
	CEdit   m_editTargetFilter;
	CButton m_radioTargetFilterBypass;
	CButton m_radioTargetFilterProxy;
	CButton m_radioTabBasic;
	CButton m_radioTabChild;
	CButton m_radioTabTarget;
	CStatusLabel m_staticTestProxy;
	afx_msg void OnEnChangeEditAddr();
	afx_msg void OnProfileFieldChanged();
	afx_msg void OnCbnEditchangeComboCfgs();
	afx_msg void OnCfgoptLoad();
	afx_msg void OnCfgoptSave();
	afx_msg void OnCfgoptDelete();
	void UILoadCfg(CfgProxyItem *item);
	void UIGetCfg(CfgProxyItem *item);
	afx_msg void OnCbnSelchangeComboCfgs();
	afx_msg void OnBnClickedHookChildProcess();
	void UpdateChildFilterEnable();
	void PublishChildFilterSnapshot();
	void PublishTargetFilterSnapshot();
	void PublishProfileSnapshots();
	afx_msg void OnBnClickedTabBasic();
	afx_msg void OnBnClickedTabChild();
	afx_msg void OnBnClickedTabTarget();
	afx_msg void OnBnClickedWorkflowNext();
	void ShowTab(int nTab);
	void UpdateProxyStateUi();
};
