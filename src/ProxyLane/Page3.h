#pragma once
#include "afxwin.h"
#include "afxmt.h"
#include "..\ProxyLaneHook\ProxyModule.h"
#include "ListCtrlEx.h"
#include "ModernUI.h"
#include "RecentApplications.h"
#include "BrowserLaunchWatch.h"
#include "LaunchPanel.h"
#include "AsyncSnapshot.h"
#include <list>
#include <map>
#include <set>
#include <vector>

#define WM_WINDOW_FINDER_BEGIN    (WM_APP + 201)
#define WM_WINDOW_FINDER_UPDATE   (WM_APP + 202)
#define WM_WINDOW_FINDER_COMPLETE (WM_APP + 203)
#define WM_PROCESS_LIST_REQUEST (WM_APP + 205)

#define WM_WINDOW_FINDER_CANCEL   (WM_APP + 204)

class CWindowFinderOverlay : public CWnd
{
public:
	CWindowFinderOverlay();
	BOOL ShowForWindow(HWND targetWindow, CWnd* ownerWindow);
	void HideOverlay();

protected:
	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC* dc);
	afx_msg LRESULT OnNcHitTest(CPoint point);

	COLORREF m_transparentColor;

	DECLARE_MESSAGE_MAP()
};

class CWindowFinderButton : public CModernButton
{
	DECLARE_DYNAMIC(CWindowFinderButton)

public:
	CWindowFinderButton();
	BOOL IsTracking() const;
	void CancelTracking();

protected:
	virtual void DrawItem(LPDRAWITEMSTRUCT drawItemStruct);
	afx_msg void OnLButtonDown(UINT flags, CPoint point);
	afx_msg void OnLButtonUp(UINT flags, CPoint point);
	afx_msg void OnMouseMove(UINT flags, CPoint point);
	afx_msg void OnCaptureChanged(CWnd* window);
	afx_msg void OnKeyDown(UINT character, UINT repeatCount, UINT flags);
	afx_msg BOOL OnSetCursor(CWnd* window, UINT hitTest, UINT message);

	BOOL m_tracking;

	DECLARE_MESSAGE_MAP()
};

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
	APP_LAUNCH_INJECTION_FAILED,
	APP_LAUNCH_UAC_CANCELLED,
	APP_LAUNCH_ELEVATED_HELPER_FAILED,
	APP_LAUNCH_PACKAGED_INJECTION_FAILED
};

enum AppLaunchElevationMode
{
	APP_LAUNCH_ELEVATION_AUTO = 0,
	APP_LAUNCH_ELEVATION_FORCE_ADMIN
};

class CPage3 : public CModernDialog
	, public IProxyLog
{
	DECLARE_DYNAMIC(CPage3)

#define TIMER_PSLIST 0x100
#define TIMER_LAUNCHED_PROCESS 0x101
#define TIMER_PROCESS_REGISTRY 0x102
#define TIMER_BROWSER_LAUNCH 0x103
#define TIMER_LAUNCH_PANEL 0x104
#define TIMER_PROCESS_RESULT 0x105

public:
	CPage3(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CPage3();


// 对话框数据
	enum { IDD = IDD_Page3 };

	CListCtrlEx m_ListCtrl;
	CWindowFinderButton m_btnWindowFinder;
	CModernButton m_btnInject;
	CModernButton m_btnSelectApp;
	CModernButton m_btnTerminate;
	CToolTipCtrl m_windowFinderToolTip;
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

	AsyncSnapshot<std::list<_myPROCESSINFO>> m_processQuery;
	std::map<DWORD, _myPROCESSINFO> m_pendingProcessRows;
	BOOL m_applyingProcesses = FALSE;
	BOOL m_pollingProcesses = FALSE;
	BOOL m_processSlowShown = FALSE;
	BOOL m_processStatusShown = FALSE;
	int m_processApplyIndex = 0;
	DWORD m_processQueryTick = 0;
	HWND m_pendingFinderTarget = NULL;
	DWORD m_pendingFinderPid = 0;
	ULONGLONG m_pendingFinderTime = 0;
	CSoftEdit m_processSearch;
 CToggleButton m_onlyHooked;
 CStatic m_filterEmpty;
 CString m_filterText;
 bool m_filterHooked = false;
 afx_msg void OnProcessFilterChanged();
 void BeginFilteredUpdate();
 void PollProcessList();
	void ApplyProcessBatch();
	void CancelProcessRefresh();
	void SortDisplayedProcesses();
	void PublishProcessAccessibility(bool structureChanged);
	afx_msg LRESULT OnProcessAccessibilityChanged(WPARAM force, LPARAM);
	afx_msg LRESULT OnProcessAccessibilityRequest(WPARAM, LPARAM);
	CString ProcessDisplayName(const _myPROCESSINFO& info) const;
	LRESULT FinishWindowFinder(HWND targetWindow, DWORD expectedPid, ULONGLONG expectedTime);
	afx_msg void OnShowWindow(BOOL show, UINT status);
	afx_msg void OnDestroy();
	afx_msg LRESULT OnProcessListRequest(WPARAM, LPARAM);
	int m_sortColumn;
	ProcessSortState m_sortState;
	std::map<DWORD, _myPROCESSINFO> m_processSortData;
	struct DisplayedProcess {
		DWORD pid;
		ULONGLONG startTime;
		CString columns[3];
	};
	// Mirrors native row order. Refresh comparisons must not send a message for
	// every cell: UI Automation hooks can make even same-thread SendMessage slow.
	std::vector<DisplayedProcess> m_displayedProcesses;
	std::map<DWORD, CString> m_processTreePrefixes;
	CString m_processNameSearchText;
	DWORD m_processNameSearchTick;
	HWND m_finderTargetWindow;
	CWindowFinderOverlay m_finderOverlay;
	BOOL m_terminating;
	DWORD m_launchedProcessId;
	ULONGLONG m_launchedProcessTime;
	DWORD m_launchSelectionTick;
	IProxyProcessRegistry* m_processRegistry;
	std::vector<BrowserLaunchWatch::Observation> m_browserLaunches;
	std::vector<BrowserLaunchWatch::Observation> m_browserNotifications;
	BOOL m_browserNotificationActive = FALSE;
	BOOL m_showingBrowserWarning = FALSE;
	BOOL IsBrowserCandidateHooked(const BrowserLaunchWatch::Identity& identity) const;
	BrowserLaunchWatch::Observation CaptureBrowserCandidates(LPCTSTR path);
	void WatchBrowserLaunch(BrowserLaunchWatch::Observation observation, DWORD pid, ULONGLONG time, DWORD started);
	void CheckBrowserLaunches();
	void ApplyBrowserProcessAction(const CString& name,
		const std::vector<BrowserLaunchWatch::Identity>& targets, BOOL terminate);

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
	void ClearWindowFinderHighlight();
	void UpdateWindowFinderHighlight(HWND targetWindow);
	BOOL SelectProcessByPid(DWORD processId);
	BOOL SelectProcessesByPid(const std::vector<DWORD>& processIds);
	void CollectDescendantProcessIds(
		DWORD rootProcessId,
		std::vector<DWORD>& descendants) const;
	void RestoreProcessPageSubtitle();
	void RefreshLaunchedProcess(DWORD pid, HANDLE process = NULL, ULONGLONG creationTime = 0);
	BOOL TrySelectLaunchedProcess();
	void CancelLaunchSelection();
	void LayoutProcessPage();

	// Launch area: one-click recent apps and the main launch action.
	CLaunchPanel m_launchPanel;
	CModernButton m_processToggle;
	CModernButton m_btnStopProxy;
	BOOL m_processesExpanded;
	std::vector<RecentApplications::Entry> m_recentEntries;
	RecentApplications::Load* m_recentLoad;
	BOOL m_recentConsumed;
	BOOL m_recentReadFailed;
	BOOL m_recentLaunching;
	CString m_recentProfileId;
	void ReloadRecentApplications(BOOL force);
	void RefreshLaunchPanel();
	BOOL HasConfiguredProxy() const;
	void SetProcessesExpanded(BOOL expanded);

public:

	void OnPageActivated();
	int UpdatePslist(BOOL bRefresh);
	BOOL ProxyProcess(DWORD dwPid);
	BOOL GetRunningHookedProcesses(std::vector<_myPROCESSINFO>& processes);
	BOOL HasBrowserNotification() const { return m_browserNotificationActive; }
	void OpenBrowserNotification();
	void DismissBrowserNotification();
	void ClearBrowserNotifications();

	void OnDropAppFile(TCHAR *pFileName);
	AppLaunchResult LaunchAndProxyApp(
		LPCTSTR fileName,
		const std::vector<CString>& extraArguments,
		BOOL strictInjection,
		AppLaunchElevationMode elevationMode = APP_LAUNCH_ELEVATION_AUTO,
		const CString& initialArguments = CString(),
		const CString& initialWorkingDirectory = CString());
	AppLaunchResult LaunchPackagedAppById(LPCTSTR aumid, const CString& arguments, AppLauncherResult* outcome = NULL);
	BOOL GetAppLauncherHostInfo(AppLauncherHostInfo* info) override;
	BOOL LaunchAppFromShell(const AppLauncherRequest& request, AppLauncherResult& result) override;
	AppLaunchResult LaunchInteractiveApplication(const InstalledApplications::Application& app,
		AppLaunchElevationMode elevationMode = APP_LAUNCH_ELEVATION_AUTO,
		const RecentApplications::Entry* saved = NULL);
	void LaunchRecentApplication(const RecentApplications::Entry& entry);
	void ShowApplicationLaunchResult(const CString& name, AppLaunchResult result);
	AppLaunchResult LaunchPackagedAppAndProxy(
		LPCTSTR fileName,
		const CString& manifestDir,
		const std::vector<CString>& extraArguments,
		const CString& initialArguments = CString());
	BOOL InjectNewProcess(LPHookNewProcessInfo lphnpi);
	BOOL ShouldProxyChildProcess(LPHookNewProcessInfo lphnpi);

	//////////////////////////////////////////////////////////////////////////

	////重载IProxyLog的成员函数
	void LogText(LPCWSTR lpText);
	void LogNewProxyTask(const LPPRCClient lpC);
	BOOL ShouldInjectNewProcess(LPHookNewProcessInfo lphnpi);
	void OnChildInjectionResult(LPHookNewProcessInfo lphnpi, BOOL succeeded) {};
	void OnHookWsock(LPHookWSockResult res);
	void OnHookLogtext(LPHookLogtext log) {};



protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual BOOL OnInitDialog();
	virtual BOOL PreTranslateMessage(MSG* message);



	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnSize(UINT nType, int cx, int cy);

	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnBnClickedInjectdll();
	afx_msg void OnBnClickedSelectApp();
	afx_msg void OnBnClickedTerminateProcess();
	afx_msg void OnProcessSelectionChanged(NMHDR* header, LRESULT* result);
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg LRESULT OnLaunchPanelTile(WPARAM index, LPARAM);
	afx_msg LRESULT OnLaunchPanelProfile(WPARAM, LPARAM);
	afx_msg void OnBnClickedProcessToggle();
	afx_msg void OnBnClickedStopProxy();
	afx_msg LRESULT OnRecentApplicationsChanged(WPARAM, LPARAM);
	afx_msg void OnLvnColumnClickProcessList(NMHDR* notifyHeader, LRESULT* result);
	afx_msg void OnNMCustomdrawProcessList(NMHDR* notifyHeader, LRESULT* result);
	afx_msg LRESULT OnWindowFinderBegin(WPARAM, LPARAM);
	afx_msg LRESULT OnWindowFinderUpdate(WPARAM, LPARAM);
	afx_msg LRESULT OnWindowFinderComplete(WPARAM, LPARAM);
	afx_msg LRESULT OnWindowFinderCancel(WPARAM, LPARAM);
};
