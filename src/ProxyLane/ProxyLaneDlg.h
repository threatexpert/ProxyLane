// ProxyLaneDlg.h : 头文件
//

#pragma once

#include "MainTab.h"
#include "ModernUI.h"


// CProxyLaneDlg 对话框
class CProxyLaneDlg : public CModernDialog
{
// 构造
public:
	CProxyLaneDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_PROXYLANE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	CMainTab m_MainTab;


	BOOL AddTaskbarIcons();
	CString BuildTaskbarTooltip() const;
	void UpdateTaskbarTooltip();
	void ShowAndActivate();
	void FailAutomation(int exitCode);

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	virtual void OnCancel();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnDestroy();
	afx_msg LRESULT OnShellIconNotify( WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnTaskbarRestartNotify( WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnAutomationStart(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnProxyStatusChanged(WPARAM wParam, LPARAM lParam);
	afx_msg void OnSize(UINT nType, int cx, int cy);
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

BOOL
ShellNotifyIcon_AddInfo(
	HWND hWnd,
	UINT nID,
	UINT nCallbackMessage,
	HICON hIcon,
	PCTSTR szInfo,
	UINT nFlags = NIF_MESSAGE|NIF_INFO|NIF_ICON);
	
