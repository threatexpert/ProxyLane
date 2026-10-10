#pragma once

#include "..\ProxyLaneHook\ProxyModule.h"
#include "BoundedLogQueue.h"
#include "ModernUI.h"
#include <afxmt.h>
#include <deque>


using namespace std;
// CPage2 对话框

class CPage2 : public CModernDialog
	, public IProxyLog
{
	DECLARE_DYNAMIC(CPage2)

#define WM_PRINTLOGTEXT WM_USER+10

public:
	enum
	{
		MAX_LOG_LINES = 10000,
		MAX_PENDING_LOGS = 5000,
		MAX_LOGS_PER_BATCH = 500
	};

	CPage2(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CPage2();

	////重载IProxyLog的成员函数
	void LogText(LPCWSTR lpText);
	void LogNewProxyTask(const LPPRCClient lpC){}
	BOOL ShouldInjectNewProcess(LPHookNewProcessInfo lphnpi){ return TRUE; }
	void OnChildInjectionResult(LPHookNewProcessInfo lphnpi, BOOL succeeded);
	void OnHookWsock(LPHookWSockResult res);
	void OnHookLogtext(LPHookLogtext log);
	void OnConnectionFailure(const LPPRCClient client, LPCWSTR processName,
		ConnectionStage stage, DWORD error);
	void OnConnectionEvent(ConnectionEvent event, const LPPRCClient client,
		LPCWSTR processName);
	void LogProcessEvent(DWORD processId, LPCTSTR processPath, LPCTSTR messageKey);

public:
	CEdit m_Edit;
	CModernButton m_btnCopy;
	CModernButton m_btnClear;

	// 自适应布局快照
	CSize m_szInit;
	CRect m_rcEditInit;


	CCriticalSection m_logLock;
	struct LogEntry
	{
		CString text;
		SYSTEMTIME time;
	};
	CBoundedLogQueue<LogEntry> m_logQueue;
// 对话框数据
	enum { IDD = IDD_Page2 };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual BOOL OnInitDialog();

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	afx_msg void OnBnClickedCopy();
	afx_msg void OnBnClickedClear();


	void AddLogText(const CString &lpText);
	void CopyAll();
	void ClearAll();
	LRESULT OnPrintLogText(WPARAM wParam, LPARAM lParam);

private:
	struct LogDateMarker
	{
		int offset;
		CString header;
	};
	CString m_lastLogDate;
	std::deque<LogDateMarker> m_logDates;
	void AppendLogEntry(const LogEntry& entry, CString& output, int baseOffset);
	void QueueLogText(const CString &text);
	void PostPrintLogMessageLocked();
	void TrimLogLines();
};
