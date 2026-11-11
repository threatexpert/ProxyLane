// ProxyLaneDlg.h : 头文件
//

#pragma once

#include "MainTab.h"
#include "ModernUI.h"
#include "InstalledApplications.h"
#include <vector>
#include <deque>
#include <functional>

class CProxyLaneFileDropTarget;
class CAdminDropOverlay;
class CNormalDropBanner;

// CProxyLaneDlg 对话框
class CProxyLaneDlg : public CModernDialog
{
// 构造
public:
	CProxyLaneDlg(CWnd* pParent = NULL);	// 标准构造函数
	BOOL ShowBrowserNotification(const CString& name);
	void HideBrowserNotification();
	void NotifyShortcutLaunch(const AutomationOptions& options);
	// Runs the normal exit confirmations, then launchInstaller; closes only
	// when both succeed.
	BOOL ExitForUpdate(const std::function<BOOL()>& launchInstaller);

// 对话框数据
	enum { IDD = IDD_PROXYLANE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	friend class CProxyLaneFileDropTarget;

	HICON m_hIcon;
	HICON m_hInactiveIcon;

	CMainTab m_MainTab;
	std::vector<CProxyLaneFileDropTarget*> m_fileDropTargets;
	CAdminDropOverlay* m_adminDropOverlay;
	CNormalDropBanner* m_normalDropBanner;
	UINT m_fileDragGeneration;
	BOOL m_confirmingExit = FALSE;
	BOOL m_stayInTray = FALSE;
	enum TrayNoticeKind { TRAY_NOTICE_NONE, TRAY_NOTICE_LAUNCH, TRAY_NOTICE_BROWSER };
	TrayNoticeKind m_trayNoticeKind = TRAY_NOTICE_NONE;
	CString m_pendingBrowserNotice;
	std::deque<CString> m_pendingLaunchNotices;
	void ShowNextTrayNotification();


	BOOL AddTaskbarIcons();
	CString BuildTaskbarTooltip() const;
	HICON GetTaskbarIcon() const;
	void UpdateTaskbarIcon();
	void ShowTaskbarMenu();
	void StartProxyFromTaskbarProfile(LPCTSTR profileName);
	void ShowAndActivate();
	void FailAutomation(int exitCode);
	BOOL PrepareExit();
	BOOL RefreshProfileCommandServer();
	BOOL RegisterFileDropTarget(CWnd* window);
	void BeginFileDrag();
	void ScheduleFileDragLeave();
	void EndFileDrag();
	void PositionAdminDropOverlay();
	void PositionNormalDropBanner();
	BOOL IsPointInAdminDropOverlay(CPoint clientPoint) const;
	BOOL HandleDroppedFiles(HDROP dropInfo, AppLaunchElevationMode elevationMode);
	BOOL HandleDroppedShellItems(HGLOBAL data, AppLaunchElevationMode elevationMode);
	void LaunchDroppedApplication(const InstalledApplications::Application& application,
		AppLaunchElevationMode elevationMode);

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	virtual void OnCancel();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnDestroy();
	afx_msg LRESULT OnPreloadApplications(WPARAM, LPARAM);
	afx_msg LRESULT OnConfigImportRestart(WPARAM, LPARAM);
	afx_msg LRESULT OnShellIconNotify( WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnTaskbarRestartNotify( WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnAutomationStart(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnProxyStatusChanged(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnProfileCommandRequest(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnDeferredFileDragLeave(WPARAM wParam, LPARAM lParam);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnWindowPosChanging(WINDOWPOS* position);
	afx_msg void OnGetMinMaxInfo(MINMAXINFO* minMaxInfo);
	afx_msg void OnDropFiles(HDROP dropInfo);
};


//////////////////////////////////////////////////////////////////////////
// ShellNotifyIcon
BOOL
ShellNotifyIcon_Add(
	HWND hWnd,
	UINT nID,
	UINT nCallbackMessage,
	HICON hIcon,
	PCTSTR szTip,
	UINT nFlags = NIF_MESSAGE|NIF_ICON|NIF_TIP);

BOOL
ShellNotifyIcon_Delete(
	HWND hWnd,
	UINT nID);

BOOL
ShellNotifyIcon_Modify(
	HWND hWnd,
	UINT nID,
	UINT nCallbackMessage,
	HICON hIcon,
	PCTSTR szTip,
	UINT nFlags);
