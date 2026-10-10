// Page2.cpp : 实现文件
//

#include "stdafx.h"
#include "ProxyLane.h"
#include "Page2.h"
#include "Localization.h"

namespace
{
	CString LogProcessName(LPCTSTR path)
	{
		CString name(path ? path : _T(""));
		const int slash = name.ReverseFind(_T('\\'));
		if (slash >= 0)
			name = name.Mid(slash + 1);
		return name.IsEmpty() ? Localization::Get(_T("log.unknown_process")) : name;
	}

	CString LogEndpoint(const PRCClient& client)
	{
		CString endpoint;
		if (client.szDomainName[0])
		{
			CString host(client.szDomainName);
			endpoint.Format(_T("%s:%d"), static_cast<LPCTSTR>(host), client.dstAddr.GetPort());
		}
		else if (client.dstAddr.IsIPv6())
		{
			TCHAR address[INET6_ADDRSTRLEN] = { 0 };
#ifdef _UNICODE
			ProxyInetNtopW(AF_INET6, (PVOID)client.dstAddr.GetAddr6(), address, _countof(address));
#else
			ProxyInetNtopA(AF_INET6, (PVOID)client.dstAddr.GetAddr6(), address, _countof(address));
#endif
			endpoint.Format(_T("[%s]:%d"), address, client.dstAddr.GetPort());
		}
		else
		{
			DWORD ip = client.dstAddr.GetdwIP();
			const BYTE* bytes = reinterpret_cast<const BYTE*>(&ip);
			endpoint.Format(_T("%u.%u.%u.%u:%d"), bytes[0], bytes[1], bytes[2], bytes[3],
				client.dstAddr.GetPort());
		}
		return endpoint;
	}
}


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
	int buttonTop = UiTheme::ScaleForWindow(m_hWnd, 8);
	const int toolbarLeft = rcClient.right - margin - buttonWidth * 2 - gap;
	if (CWnd* title = GetDlgItem(IDC_STATIC_PAGE_TITLE))
	{
		CRect titleRect;
		title->GetWindowRect(&titleRect);
		ScreenToClient(&titleRect);
		title->MoveWindow(titleRect.left, titleRect.top,
			max(0, toolbarLeft - gap - titleRect.left), titleRect.Height());
	}
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
	CBoundedLogQueue<LogEntry>::Batch batch;
	{
		CSingleLock lock(&m_logLock, TRUE);
		batch = m_logQueue.TakeBatch();
	}

	if (batch.entries.empty() && batch.dropped == 0)
		return 0;

	CString text;
	const int baseOffset = m_Edit.GetWindowTextLength();
	if (batch.dropped > 0)
	{
		LogEntry warning;
		warning.text = Localization::Format(_T("page2.dropped_logs"), batch.dropped);
		// The dropped entries precede the first retained entry in this batch.
		if (!batch.entries.empty())
			warning.time = batch.entries.front().time;
		else
			GetLocalTime(&warning.time);
		AppendLogEntry(warning, text, baseOffset);
	}

	for (std::list<LogEntry>::const_iterator it = batch.entries.begin();
		it != batch.entries.end(); ++it)
	{
		AppendLogEntry(*it, text, baseOffset);
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
	m_lastLogDate.Empty();
	m_logDates.clear();
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
	if (text.IsEmpty())
		return;
	CSingleLock lock(&m_logLock, TRUE);
	LogEntry entry;
	entry.text = text;
	GetLocalTime(&entry.time);
	if (m_logQueue.Push(entry))
		PostPrintLogMessageLocked();
}

void CPage2::AppendLogEntry(const LogEntry& entry, CString& output, int baseOffset)
{
	CString message(entry.text);
	message.Replace(_T("\r\n"), _T("\n"));
	message.Replace(_T("\r"), _T("\n"));
	message.TrimRight(_T("\n"));
	if (message.IsEmpty())
		return;

	CString date;
	date.Format(_T("%04u-%02u-%02u"), entry.time.wYear, entry.time.wMonth, entry.time.wDay);
	if (date != m_lastLogDate)
	{
		LogDateMarker marker;
		marker.offset = baseOffset + output.GetLength();
		marker.header = _T("-- ") + date + _T(" --\r\n");
		m_logDates.push_back(marker);
		output += marker.header;
		m_lastLogDate = date;
	}

	CString timestamp;
	timestamp.Format(_T("[%02u:%02u:%02u] "),
		entry.time.wHour, entry.time.wMinute, entry.time.wSecond);
	int start = 0;
	while (start < message.GetLength())
	{
		int end = message.Find(_T('\n'), start);
		if (end < 0)
			end = message.GetLength();
		if (end > start)
			output += timestamp + message.Mid(start, end - start);
		output += _T("\r\n");
		start = end + 1;
	}
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

	// Reserve one line for a date heading restored below.
	int firstLineToKeep = lineCount - MAX_LOG_LINES + 1;
	int firstCharToKeep = m_Edit.LineIndex(firstLineToKeep);
	if (firstCharToKeep <= 0)
		return;

	// Keep the date of the first remaining entry even when its original
	// heading was trimmed. Character offsets also work with wrapped lines.
	while (m_logDates.size() > 1 && m_logDates[1].offset <= firstCharToKeep)
		m_logDates.pop_front();
	CString header;
	if (!m_logDates.empty() && m_logDates.front().offset < firstCharToKeep)
	{
		header = m_logDates.front().header;
		m_logDates.pop_front();
	}
	for (std::deque<LogDateMarker>::iterator it = m_logDates.begin();
		it != m_logDates.end(); ++it)
		it->offset += header.GetLength() - firstCharToKeep;
	if (!header.IsEmpty())
	{
		LogDateMarker marker;
		marker.offset = 0;
		marker.header = header;
		m_logDates.push_front(marker);
	}
	m_Edit.SetSel(0, firstCharToKeep);
	m_Edit.ReplaceSel(header, FALSE);
}

void CPage2::OnHookWsock(LPHookWSockResult res)
{
	if (res->err != 0)
	{
		CString str;

		str = Localization::Format(_T("log.hook_failed"),
			static_cast<LPCTSTR>(LogProcessName(NULL)), res->dwProcessId, res->err);

		AddLogText(str);
	}
}

void CPage2::OnChildInjectionResult(
	LPHookNewProcessInfo lphnpi,
	BOOL succeeded)
{
	LogProcessEvent(lphnpi->dwProcessId, lphnpi->szAppPath,
		succeeded ? _T("log.process_injected") : _T("log.process_injection_failed"));
}

void CPage2::LogProcessEvent(DWORD processId, LPCTSTR processPath, LPCTSTR messageKey)
{
	AddLogText(Localization::Format(messageKey,
		static_cast<LPCTSTR>(LogProcessName(processPath)), processId));
}

void CPage2::OnConnectionEvent(ConnectionEvent event, const LPPRCClient client,
	LPCWSTR processName)
{
	if (!client)
		return;
	LPCTSTR key;
	switch (event)
	{
	case ROUTE_PROXY: key = _T("log.connection_proxy"); break;
	case ROUTE_DIRECT: key = _T("log.connection_direct"); break;
	case ROUTE_BLOCKED: key = _T("log.connection_blocked"); break;
	case IPV6_BLOCKED: key = _T("log.connection_ipv6_blocked"); break;
	case TASK_FAILED: key = _T("log.connection_task_failed"); break;
	case SETTINGS_FAILED: key = _T("log.connection_settings_failed"); break;
	default: return;
	}
	CString name = LogProcessName(CString(processName ? processName : L""));
	CString endpoint = LogEndpoint(*client);
	AddLogText(Localization::Format(key, static_cast<LPCTSTR>(name), client->dwPid,
		static_cast<LPCTSTR>(endpoint), client->sType == SOCK_DGRAM ? _T("UDP") :
		client->sType == SOCK_STREAM ? _T("TCP") : _T("Socket")));
}

void CPage2::OnConnectionFailure(const LPPRCClient client, LPCWSTR processName,
	ConnectionStage stage, DWORD error)
{
	if (!client)
		return;
	LPCTSTR stageKey = _T("log.stage_allocate");
	switch (stage)
	{
	case STAGE_TRANSPORT: stageKey = _T("log.stage_transport"); break;
	case STAGE_SOCKET: stageKey = _T("log.stage_socket"); break;
	case STAGE_CONNECT: stageKey = _T("log.stage_connect"); break;
	case STAGE_ATTACH: stageKey = _T("log.stage_attach"); break;
	}
	CString name = LogProcessName(CString(processName ? processName : L""));
	CString endpoint = LogEndpoint(*client);
	CString stageText = Localization::Get(stageKey);
	AddLogText(Localization::Format(_T("log.connection_task_detail"),
		static_cast<LPCTSTR>(name), client->dwPid, static_cast<LPCTSTR>(endpoint),
		client->sType == SOCK_DGRAM ? _T("UDP") : _T("TCP"),
		static_cast<LPCTSTR>(stageText), error));
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
