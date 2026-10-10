#include "stdafx.h"
#include "ProxyLog.h"
#include "ProxyReceptionCentre.h"
#include <stdio.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

CProxyLog *g_pProxyLog = NULL;

CProxyLog::CProxyLog(void)
{
	ATLASSERT(g_pProxyLog == NULL);
	g_pProxyLog = this;
	m_pNext = NULL;
}

CProxyLog::~CProxyLog(void)
{
	g_pProxyLog = NULL;
}

void CProxyLog::LogText(LPCWSTR lpText)
{
	IProxyLog *p = IProxyLog::m_pNext;
	while(p)
	{
		p->LogText(lpText);
		p = p->m_pNext;
	}
}

void CProxyLog::LogNewProxyTask(const LPPRCClient lpC)
{
	IProxyLog *p = IProxyLog::m_pNext;
	while(p)
	{
		p->LogNewProxyTask(lpC);
		p = p->m_pNext;
	}
}

BOOL CProxyLog::ShouldInjectNewProcess(LPHookNewProcessInfo lphnpi)
{
	BOOL shouldProxy = TRUE;
	IProxyLog *p = IProxyLog::m_pNext;
	while(p)
	{
		if (!p->ShouldInjectNewProcess(lphnpi))
			shouldProxy = FALSE;
		p = p->m_pNext;
	}
	return shouldProxy;
}

void CProxyLog::OnChildInjectionResult(LPHookNewProcessInfo lphnpi, BOOL succeeded)
{
	IProxyLog *p = IProxyLog::m_pNext;
	while(p)
	{
		p->OnChildInjectionResult(lphnpi, succeeded);
		p = p->m_pNext;
	}
}

void CProxyLog::OnHookWsock(LPHookWSockResult res)
{
	IProxyLog *p = IProxyLog::m_pNext;
	while (p)
	{
		p->OnHookWsock(res);
		p = p->m_pNext;
	}
}

void CProxyLog::OnHookLogtext(LPHookLogtext log)
{
	IProxyLog *p = IProxyLog::m_pNext;
	while (p)
	{
		p->OnHookLogtext(log);
		p = p->m_pNext;
	}
}

void CProxyLog::OnConnectionEvent(ConnectionEvent event, const LPPRCClient client,
	LPCWSTR processName)
{
	for (IProxyLog* p = m_pNext; p; p = p->m_pNext)
		p->OnConnectionEvent(event, client, processName);
}

void LogConnectionEvent(IProxyLog::ConnectionEvent event, const LPPRCClient client,
	LPCWSTR processName)
{
	if (g_pProxyLog && client)
		g_pProxyLog->OnConnectionEvent(event, client, processName);
}

void CProxyLog::OnConnectionFailure(const LPPRCClient client, LPCWSTR processName,
	ConnectionStage stage, DWORD error)
{
	for (IProxyLog* p = m_pNext; p; p = p->m_pNext)
		p->OnConnectionFailure(client, processName, stage, error);
}

void LogConnectionFailure(const LPPRCClient client, LPCWSTR processName,
	IProxyLog::ConnectionStage stage, DWORD error)
{
	if (g_pProxyLog && client)
		g_pProxyLog->OnConnectionFailure(client, processName, stage, error);
}

void PrintText(const TCHAR *fmt, ...)
{
	if(!g_pProxyLog)
		return;
	va_list args;
	int n;
	TCHAR szBuf[2048];
	va_start(args, fmt);
	n = _vstprintf(szBuf, fmt, args);
	va_end(args);

	g_pProxyLog->LogText(szBuf);
}

void LogNewProxyTask(const LPPRCClient lpC)
{
	g_pProxyLog->LogNewProxyTask(lpC);
}

static LPWSTR GetUdpProcessName(CProxyReceptionCentre *receptionCentre,
	DWORD processId, LPWSTR processPath, DWORD pathLength)
{
	if (!processPath || pathLength == 0)
		return NULL;
	processPath[0] = L'\0';

	if (!receptionCentre ||
		!receptionCentre->GetProcessIdentity(processId, processPath, pathLength))
	{
		HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE, processId);
		if (process)
		{
			GetModuleFileNameExW(process, NULL, processPath, pathLength);
			processPath[pathLength - 1] = L'\0';
			CloseHandle(process);
		}
	}

	LPWSTR name = wcsrchr(processPath, L'\\');
	return name ? name + 1 : processPath;
}

void LogUdpFirstDatagram(CProxyReceptionCentre *receptionCentre,
	const LPPRCClient lpC, const LPProxyInfo lpPI)
{
	if (!lpC || !lpPI)
		return;

	WCHAR processPath[MAX_PATH];
	LPWSTR processName = GetUdpProcessName(receptionCentre, lpC->dwPid,
		processPath, _countof(processPath));
	LogConnectionEvent(lpPI->GetProxyType() == PROXYTYPE_NOPROXY
		? IProxyLog::ROUTE_DIRECT : IProxyLog::ROUTE_PROXY, lpC, processName);
	LogDnsRedirect(lpC);
}

static CString FormatDnsEndpoint(const _SockAddr& address)
{
	TCHAR text[INET6_ADDRSTRLEN] = { 0 };
	if (address.IsIPv6())
	{
#ifdef _UNICODE
		ProxyInetNtopW(AF_INET6, (PVOID)address.GetAddr6(), text, _countof(text));
#else
		ProxyInetNtopA(AF_INET6, (PVOID)address.GetAddr6(), text, _countof(text));
#endif
		CString endpoint;
		endpoint.Format(_T("[%s]:%d"), text, address.GetPort());
		return endpoint;
	}
	DWORD ipv4 = address.GetdwIP();
	const BYTE *bytes = reinterpret_cast<const BYTE *>(&ipv4);
	CString endpoint;
	endpoint.Format(_T("%u.%u.%u.%u:%d"), bytes[0], bytes[1], bytes[2],
		bytes[3], address.GetPort());
	return endpoint;
}

void LogDnsRedirect(const LPPRCClient lpC)
{
	if (!lpC || !lpC->HasProxyDestination())
		return;
	CString original = FormatDnsEndpoint(lpC->dstAddr);
	CString effective = FormatDnsEndpoint(lpC->proxyDstAddr);
	PrintText(_T("DNS target redirected: PID %d, %s -> %s.\r\n"),
		lpC->dwPid, (LPCTSTR)original, (LPCTSTR)effective);
}
