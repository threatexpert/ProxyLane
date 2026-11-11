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

	CString HookResultProcessName(const HookWSockResult& result)
	{
		// Best effort for legacy result messages. The detailed diagnostic carries
		// the sender's own name even if the process has already exited.
		WCHAR path[MAX_PATH] = {};
		typedef BOOL (WINAPI *QueryImageName)(HANDLE, DWORD, LPWSTR, PDWORD);
		QueryImageName query = reinterpret_cast<QueryImageName>(GetProcAddress(
			GetModuleHandleW(L"kernel32.dll"), "QueryFullProcessImageNameW"));
		HANDLE process = query ? OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */,
			FALSE, result.dwProcessId) : NULL;
		if (process)
		{
			FILETIME created, exited, kernel, user;
			if (GetProcessTimes(process, &created, &exited, &kernel, &user) &&
				(!result.processCreateTime || result.processCreateTime ==
				((static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime)))
			{
				DWORD length = _countof(path);
				if (!query(process, 0, path, &length)) path[0] = L'\0';
			}
			CloseHandle(process);
		}
		path[_countof(path) - 1] = L'\0';
		return LogProcessName(CString(path));
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
	m_loaderCapture.Stop();
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
	ON_WM_TIMER()
	ON_WM_DESTROY()
	//ON_WM_ERASEBKGND()

	ON_MESSAGE(WM_PRINTLOGTEXT, OnPrintLogText)
	ON_BN_CLICKED(IDC_BTN_COPY_LOG, &CPage2::OnBnClickedCopy)
	ON_BN_CLICKED(IDC_BTN_CLEAR_LOG, &CPage2::OnBnClickedClear)
	ON_BN_CLICKED(IDC_CHECK_LOADER_CAPTURE, &CPage2::OnBnClickedLoaderCapture)
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
	const int copyLeft = rcClient.right - margin - buttonWidth * 2 - gap;
	int toolbarLeft = copyLeft;
	if (CWnd* capture = GetDlgItem(IDC_CHECK_LOADER_CAPTURE))
	{
		CString label;
		capture->GetWindowText(label);
		CClientDC dc(capture);
		CFont* font = capture->GetFont();
		CFont* oldFont = font ? dc.SelectObject(font) : NULL;
		const int width = max(UiTheme::ScaleForWindow(m_hWnd, 110),
			dc.GetTextExtent(label).cx + UiTheme::ScaleForWindow(m_hWnd, 46));
		if (oldFont) dc.SelectObject(oldFont);
		toolbarLeft = copyLeft - gap - width;
		capture->MoveWindow(toolbarLeft, buttonTop, width, buttonHeight);
	}
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
	ScheduleLogFlush();
	return 0;
}

void CPage2::ScheduleLogFlush()
{
	// One notification starts a bounded, low-priority timer. Continuations must
	// not repost WM_PRINTLOGTEXT: a busy producer would starve input/painting.
	if (!m_logTimer)
	{
		m_logTimer = SetTimer(1, LOG_REFRESH_MS, NULL);
		if (!m_logTimer)
		{
			CSingleLock lock(&m_logLock, TRUE);
			m_logQueue.OnNotificationPostFailed();
		}
	}
}

void CPage2::OnTimer(UINT_PTR timer)
{
	if (m_captureTimer && timer == m_captureTimer) { FlushLoaderDiagnostics(); return; }
	if (m_logTimer && timer == m_logTimer)
	{
		KillTimer(m_logTimer);
		m_logTimer = 0;
		FlushLogText();
		return;
	}
	CModernDialog::OnTimer(timer);
}

void CPage2::OnDestroy()
{
	if (m_captureTimer) KillTimer(m_captureTimer);
	m_captureTimer = 0;
	m_loaderCapture.Stop();
	if (m_logTimer) KillTimer(m_logTimer);
	m_logTimer = 0;
	CModernDialog::OnDestroy();
}

void CPage2::FlushLogText()
{
	CBoundedLogQueue<LogEntry>::Batch batch;
	{
		CSingleLock lock(&m_logLock, TRUE);
		batch = m_logQueue.TakeBatch();
	}

	if (batch.entries.empty() && batch.dropped == 0)
		return;

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

	int selectionStart = 0, selectionEnd = 0;
	m_Edit.GetSel(selectionStart, selectionEnd);
	const int firstVisibleChar = m_Edit.LineIndex(m_Edit.GetFirstVisibleLine());
	SCROLLINFO scroll = { sizeof(scroll), SIF_RANGE | SIF_PAGE | SIF_POS };
	m_Edit.GetScrollInfo(SB_VERT, &scroll);
	const bool follow = selectionStart == selectionEnd &&
		scroll.nPos + static_cast<int>(scroll.nPage) >= scroll.nMax;
	// WM_SETREDRAW(TRUE) adds WS_VISIBLE; don't accidentally reveal a hidden page.
	const bool visible = m_Edit.IsWindowVisible() != FALSE;
	if (visible) m_Edit.SetRedraw(FALSE);
	int nLen = m_Edit.GetWindowTextLength();
	m_Edit.SetSel(nLen, nLen);
	m_Edit.ReplaceSel(text, FALSE);
	const int removed = TrimLogLines();
	if (follow)
	{
		nLen = m_Edit.GetWindowTextLength();
		m_Edit.SetSel(nLen, nLen);
		m_Edit.LineScroll(m_Edit.GetLineCount());
	}
	else
	{
		m_Edit.SetSel(max(0, selectionStart - removed), max(0, selectionEnd - removed), TRUE);
		const int firstLine = m_Edit.LineFromChar(max(0, firstVisibleChar - removed));
		m_Edit.LineScroll(firstLine - m_Edit.GetFirstVisibleLine());
	}
	if (visible)
	{
		m_Edit.SetRedraw(TRUE);
		m_Edit.Invalidate(FALSE);
	}

	if (batch.hasMore)
	{
		ScheduleLogFlush();
	}
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
	{
		CSingleLock lock(&m_logLock, TRUE);
		m_logQueue.Clear();
	}
	if (m_logTimer) KillTimer(m_logTimer);
	m_logTimer = 0;
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

int CPage2::TrimLogLines()
{
	int lineCount = m_Edit.GetLineCount();
	const int chars = m_Edit.GetWindowTextLength();
	if (lineCount <= MAX_LOG_LINES && chars <= MAX_LOG_CHARS)
		return 0;

	// Trim with headroom so small batches don't repeatedly relayout the entire
	// edit control. A character bound also covers very long/wrapped log lines.
	int firstCharToKeep = 0;
	if (lineCount > MAX_LOG_LINES)
		firstCharToKeep = m_Edit.LineIndex(lineCount - LOG_LINES_TO_KEEP + 1);
	if (chars > MAX_LOG_CHARS)
	{
		const int cut = chars - LOG_CHARS_TO_KEEP;
		const int nextLine = m_Edit.LineIndex(m_Edit.LineFromChar(cut) + 1);
		firstCharToKeep = max(firstCharToKeep, nextLine >= 0 ? nextLine : cut);
	}
	if (firstCharToKeep <= 0)
		return 0;

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
	return firstCharToKeep - header.GetLength();
}

void CPage2::OnHookWsock(LPHookWSockResult res)
{
	if (res->err != 0)
	{
		CString str;

		str = Localization::Format(_T("log.hook_failed"),
			static_cast<LPCTSTR>(HookResultProcessName(*res)), res->dwProcessId, res->err);

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
	case UDP_BLOCKED: key = _T("log.connection_udp_blocked"); break;
	case TASK_FAILED: key = _T("log.connection_task_failed"); break;
	case SETTINGS_FAILED: key = _T("log.connection_settings_failed"); break;
	default: return;
	}
	CString name = LogProcessName(CString(processName ? processName : L""));
	CString endpoint = LogEndpoint(*client);
	if (event == UDP_BLOCKED && client->dstAddr.sa_family == AF_UNSPEC)
		endpoint = Localization::Get(_T("common.unknown"));
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
	case STAGE_IPV6_ROUTE: stageKey = _T("log.stage_ipv6_route"); break;
	}
	CString name = LogProcessName(CString(processName ? processName : L""));
	CString endpoint = LogEndpoint(*client);
	CString stageText = Localization::Get(stageKey);
	AddLogText(Localization::Format(_T("log.connection_task_detail"),
		static_cast<LPCTSTR>(name), client->dwPid, static_cast<LPCTSTR>(endpoint),
		client->sType == SOCK_DGRAM ? _T("UDP") : _T("TCP"),
		static_cast<LPCTSTR>(stageText), error));
}

void CPage2::OnProxyFailure(const LPPRCClient client, LPCWSTR processName,
	LPCWSTR target, BOOL connectingProxy, DWORD error, LPCWSTR detail)
{
	if (!client) return;
	CString name = LogProcessName(processName);
	CString reason = Localization::Get(error == WSAETIMEDOUT ?
		_T("log.connection_timeout") : connectingProxy ?
		_T("log.proxy_connect_failed") : _T("log.proxy_request_failed"));
	CString text = Localization::Format(_T("log.proxy_failure"),
		(LPCTSTR)name, client->dwPid, target ? target : L"",
		client->sType == SOCK_DGRAM ? _T("UDP") : _T("TCP"), (LPCTSTR)reason);
	if (error)
		text += Localization::Format(_T("log.error_code_suffix"), error);
	if (detail && detail[0])
		text += _T(" \x00b7 ") + CString(detail);
	text.Replace(_T('\r'), _T(' '));
	text.Replace(_T('\n'), _T(' '));
	AddLogText(text + _T("\r\n"));
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

void CPage2::OnBnClickedLoaderCapture()
{
    if (IsDlgButtonChecked(IDC_CHECK_LOADER_CAPTURE) != BST_CHECKED) {
        if (m_captureTimer) KillTimer(m_captureTimer);
        m_captureTimer = 0;
        FlushLoaderDiagnostics();
        m_loaderCapture.Stop();
        LogText(Localization::Get(_T("page2.loader_capture_stopped")));
        return;
    }
    DWORD error = m_loaderCapture.Start();
    if (!error) {
        m_captureTimer = SetTimer(2, LOG_REFRESH_MS, NULL);
        if (!m_captureTimer) error = ERROR_NOT_ENOUGH_MEMORY;
    }
    if (error) {
        m_loaderCapture.Stop();
        CheckDlgButton(IDC_CHECK_LOADER_CAPTURE, BST_UNCHECKED);
        LogText(error == ERROR_ALREADY_EXISTS ?
            Localization::Get(_T("page2.loader_capture_busy")) :
            Localization::Format(_T("page2.loader_capture_failed"), error));
    } else {
        LogText(Localization::Get(_T("page2.loader_capture_started")));
    }
}

void CPage2::FlushLoaderDiagnostics()
{
    LoaderDiagnosticCapture::Record records[100];
    unsigned dropped = 0;
    unsigned count = m_loaderCapture.Drain(records, _countof(records), dropped);
    for (unsigned i = 0; i < count; ++i) {
        WCHAR description[512];
        DWORD length = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, records[i].error, 0, description, _countof(description), NULL);
        CString detail = length ? CString(description) : Localization::Get(_T("page2.loader_error_unknown"));
        detail.Trim();
        if (records[i].hookFailure) {
            CString stage(records[i].stage), module(records[i].module), api(records[i].api);
            LogText(Localization::Format(_T("page2.hook_failure"), records[i].processId,
                static_cast<LPCTSTR>(stage), static_cast<LPCTSTR>(module),
                static_cast<LPCTSTR>(api), records[i].error, static_cast<LPCTSTR>(detail)));
            continue;
        }
        LogText(Localization::Format(_T("page2.loader_failure"), records[i].processId,
            records[i].error, static_cast<LPCTSTR>(detail)));
    }
    if (dropped) LogText(Localization::Format(_T("page2.loader_capture_dropped"), dropped));
}
