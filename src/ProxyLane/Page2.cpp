// Page2.cpp : 实现文件
//

#include "stdafx.h"
#include "ProxyLane.h"
#include "Page2.h"



// CPage2 对话框

IMPLEMENT_DYNAMIC(CPage2, CModernDialog)

CPage2::CPage2(CWnd* pParent /*=NULL*/)
	: CModernDialog(CPage2::IDD, pParent)
	, m_logQueue(MAX_PENDING_LOGS, MAX_LOGS_PER_BATCH)
{

}

CPage2::~CPage2()
{
}

void CPage2::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_Edit);
	DDX_Control(pDX, IDC_BTN_COPY_LOG, m_btnCopy);
	DDX_Control(pDX, IDC_BTN_CLEAR_LOG, m_btnClear);

}


BOOL CPage2::OnInitDialog()
{
	CModernDialog::OnInitDialog();
	m_btnCopy.SetVisualStyle(CModernButton::STYLE_SECONDARY);
	m_btnClear.SetVisualStyle(CModernButton::STYLE_SECONDARY);

	//
	m_Edit.SetLimitText(0);

	// 缓存初始客户区与子控件位置，供 OnSize 自适应使用
	CRect rcClient;
	GetClientRect(&rcClient);
	m_szInit = rcClient.Size();

	if (m_Edit.GetSafeHwnd())
	{
		CRect rc;
		m_Edit.GetWindowRect(&rc);
		ScreenToClient(&rc);
		m_rcEditInit = rc;
	}

	return TRUE;
}

BEGIN_MESSAGE_MAP(CPage2, CModernDialog)
	ON_WM_SIZE()
	//ON_WM_ERASEBKGND()

	ON_MESSAGE(WM_PRINTLOGTEXT, OnPrintLogText)
	ON_BN_CLICKED(IDC_BTN_COPY_LOG, &CPage2::OnBnClickedCopy)
	ON_BN_CLICKED(IDC_BTN_CLEAR_LOG, &CPage2::OnBnClickedClear)
END_MESSAGE_MAP()


// CPage2 消息处理程序

void CPage2::OnSize(UINT nType, int cx, int cy)
{
	CModernDialog::OnSize(nType, cx, cy);
	CRect rcClient;
	GetClientRect(&rcClient);
	if (rcClient.Width() <= 0 || rcClient.Height() <= 0)
		return;

	if (m_Edit.GetSafeHwnd())
	{
		int margin = UiTheme::ScaleForWindow(m_hWnd, 8);
		int top = UiTheme::ScaleForWindow(m_hWnd, 58);
		CRect rc(margin, top, rcClient.right - margin, rcClient.bottom - margin);
		m_Edit.MoveWindow(&rc);
	}

	int margin = UiTheme::ScaleForWindow(m_hWnd, 8);
	int gap = UiTheme::ScaleForWindow(m_hWnd, 6);
	int buttonWidth = UiTheme::ScaleForWindow(m_hWnd, 78);
	int buttonHeight = UiTheme::ScaleForWindow(m_hWnd, 30);
	int buttonTop = UiTheme::ScaleForWindow(m_hWnd, 12);
	if (m_btnClear.GetSafeHwnd())
		m_btnClear.MoveWindow(rcClient.right - margin - buttonWidth, buttonTop, buttonWidth, buttonHeight);
	if (m_btnCopy.GetSafeHwnd())
		m_btnCopy.MoveWindow(rcClient.right - margin - buttonWidth * 2 - gap, buttonTop, buttonWidth, buttonHeight);
}

BOOL CPage2::OnEraseBkgnd(CDC* pDC)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值

	CWnd *pParent = GetParent();

	CRect   rc;   
	GetClientRect(&rc);   
	pDC->FillSolidRect(&rc, pParent->GetDC()->GetBkColor());//填充红色
	return   TRUE;   

}

void CPage2::LogText(LPCWSTR lpText)
{
	QueueLogText(CString(lpText));
}

LRESULT CPage2::OnPrintLogText(WPARAM wParam, LPARAM lParam)
{
	CBoundedLogQueue<CString>::Batch batch;
	{
		CSingleLock lock(&m_logLock, TRUE);
		batch = m_logQueue.TakeBatch();
	}

	if (batch.entries.empty() && batch.dropped == 0)
		return 0;

	CString text;
	if (batch.dropped > 0)
	{
		CString warning;
		warning.Format(_T("[日志过快，已丢弃 %Iu 条较旧日志]\r\n"),
			batch.dropped);
		text += warning;
	}

	for (std::list<CString>::const_iterator it = batch.entries.begin();
		it != batch.entries.end(); ++it)
	{
		text += *it;
	}

	m_Edit.SetRedraw(FALSE);
	int nLen = m_Edit.GetWindowTextLength();
	m_Edit.SetSel(nLen, nLen);
	m_Edit.ReplaceSel(text, FALSE);
	TrimLogLines();
	nLen = m_Edit.GetWindowTextLength();
	m_Edit.SetSel(nLen, nLen);
	m_Edit.LineScroll(m_Edit.GetLineCount());
	m_Edit.SetRedraw(TRUE);
	m_Edit.Invalidate(FALSE);

	if (batch.hasMore)
	{
		CSingleLock lock(&m_logLock, TRUE);
		PostPrintLogMessageLocked();
	}

	return 0;
}

void CPage2::AddLogText(const CString &lpText)
{
	QueueLogText(lpText);
}

void CPage2::CopyAll()
{
	if (!m_Edit.GetSafeHwnd() || m_Edit.GetWindowTextLength() == 0)
		return;
	int start = 0;
	int end = 0;
	m_Edit.GetSel(start, end);
	m_Edit.SetSel(0, -1);
	m_Edit.Copy();
	m_Edit.SetSel(start, end);
}

void CPage2::ClearAll()
{
	m_Edit.SetWindowText(_T(""));
}

void CPage2::OnBnClickedCopy()
{
	CopyAll();
}

void CPage2::OnBnClickedClear()
{
	ClearAll();
}

void CPage2::QueueLogText(const CString &text)
{
	CSingleLock lock(&m_logLock, TRUE);
	if (m_logQueue.Push(text))
		PostPrintLogMessageLocked();
}

void CPage2::PostPrintLogMessageLocked()
{
	if (PostMessage(WM_PRINTLOGTEXT))
		return;

	m_logQueue.OnNotificationPostFailed();
}

void CPage2::TrimLogLines()
{
	int lineCount = m_Edit.GetLineCount();
	if (lineCount <= MAX_LOG_LINES)
		return;

	int firstLineToKeep = lineCount - MAX_LOG_LINES;
	int firstCharToKeep = m_Edit.LineIndex(firstLineToKeep);
	if (firstCharToKeep <= 0)
		return;

	m_Edit.SetSel(0, firstCharToKeep);
	m_Edit.ReplaceSel(_T(""), FALSE);
}

void CPage2::OnHookWsock(LPHookWSockResult res)
{
	if (res->err != 0)
	{
		CString str;

		str.Format(_T("HookWSock Failed. pid=%lu\r\n"), res->dwProcessId);

		AddLogText(str);
	}
}

void CPage2::OnHookLogtext(LPHookLogtext log)
{
	CString str;

#ifdef _UNICODE
	str.Format(_T("pid=%lu: %s\r\n"), log->dwProcessId, log->str);
#else
	str.Format(_T("pid=%lu: %S\r\n"), log->dwProcessId, log->str);
#endif
	AddLogText(str);
}
