#pragma once
#include "afxwin.h"
#include "afxmt.h"
#include "..\ProxyLaneHook\ProxyModule.h"
#include "ListCtrlEx.h"
#include "ModernUI.h"
#include <map>
#include <set>
#include <vector>

// CPage3 对话框

BOOL IsWow64(HANDLE hProc);
BOOL is64Process(HANDLE hProc);
CString ChooseProxyLaneHookModule(HANDLE hProc);
CString ChooseRundll32(CString &strDllPath);
BOOL myWow64DisableWow64FsRedirection( PVOID *OldValue);
BOOL myWow64RevertWow64FsRedirection(  PVOID OldValue);


struct _myPROCESSINFO
{
	DWORD pid;
	DWORD parentPid;
	TCHAR proname[MAX_PATH];
	TCHAR propath[MAX_PATH];
	BOOL hasStartTime;
	ULONGLONG startTimeValue;
	TCHAR startTimeText[32];
	int defaultOrder;
	int treeOrder;
};

enum AppLaunchResult
{
	APP_LAUNCH_SUCCESS = 0,
	APP_LAUNCH_INVALID_TARGET,
	APP_LAUNCH_CREATE_PROCESS_FAILED,
	APP_LAUNCH_INJECTION_FAILED
};

class CPage3 : public CModernDialog
	, public IProxyLog
{
	DECLARE_DYNAMIC(CPage3)

#define TIMER_PSLIST 0x100
#define WM_ON_REFRESHPS 0x101

public:
	CPage3(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CPage3();


// 对话框数据
	enum { IDD = IDD_Page3 };

	CListCtrlEx m_ListCtrl;
	CModernButton m_btnRefresh;
	CModernButton m_btnInject;
	CEvent m_evlock;
	//CButton m_btnAuto;

	// 自适应布局快照
	CSize m_szInit;
	CRect m_rcListInit;
	CRect m_rcBtnInjectInit;
	CRect m_rcHintInit;

private:
	// 进程列表排序状态：不排序、升序、降序。
	enum ProcessSortState
	{
		PROCESS_SORT_NONE = 0,
		PROCESS_SORT_ASCENDING,
		PROCESS_SORT_DESCENDING
	};

	int m_sortColumn;
	ProcessSortState m_sortState;
	std::map<DWORD, _myPROCESSINFO> m_processSortData;
	std::map<DWORD, ULONGLONG> m_displayedStartTimes;
	std::map<DWORD, CString> m_processTreePrefixes;
	CString m_processNameSearchText;
	DWORD m_processNameSearchTick;

	static int CALLBACK CompareProcessItems(LPARAM leftParam, LPARAM rightParam, LPARAM sortParam);
	void BuildProcessTree();
	void AppendProcessTree(
		DWORD pid,
		const CString& displayPrefix,
		const CString& childPrefix,
		std::map<DWORD, std::vector<DWORD> >& children,
		std::set<DWORD>& visited,
		int& treeOrder);
	void ApplyProcessSort();
	void UpdateProcessNameDisplay();
	void UpdateSortIndicator();
	BOOL SelectFirstProcessByNamePrefix(const CString& prefix);

public:

	int UpdatePslist(BOOL bRefresh);
	BOOL ProxyProcess(DWORD dwPid);

	void OnDropAppFile(TCHAR *pFileName);
	AppLaunchResult LaunchAndProxyApp(
		LPCTSTR fileName,
		const std::vector<CString>& extraArguments,
		BOOL strictInjection);
	BOOL InjectNewProcess(LPHookNewProcessInfo lphnpi);

	//////////////////////////////////////////////////////////////////////////

	////重载IProxyLog的成员函数
	void LogText(LPCWSTR lpText);
	void LogNewProxyTask(const LPPRCClient lpC);
	void OnNewProcess(LPHookNewProcessInfo lphnpi);
	void OnHookWsock(LPHookWSockResult res){};
	void OnHookLogtext(LPHookLogtext log) {};



protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual BOOL OnInitDialog();
	virtual BOOL PreTranslateMessage(MSG* message);



	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnSize(UINT nType, int cx, int cy);

	afx_msg LRESULT OnRefreshPslist( WPARAM, LPARAM );

	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnBnClickedRefresh();
	afx_msg void OnBnClickedInjectdll();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnLvnColumnClickProcessList(NMHDR* notifyHeader, LRESULT* result);
	afx_msg void OnNMCustomdrawProcessList(NMHDR* notifyHeader, LRESULT* result);
};
