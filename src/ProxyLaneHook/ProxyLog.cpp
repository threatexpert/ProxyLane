#include "stdafx.h"
#include "ProxyLog.h"
#include "ProxyReceptionCentre.h"
#include <stdio.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

CProxyLog *g_pProxyLog = NULL;

BOOL CProxyLog::GetAppLauncherHostInfo(AppLauncherHostInfo* info)
{
    for (IProxyLog* p = m_pNext; p; p = p->m_pNext)
        if (p->GetAppLauncherHostInfo(info)) return TRUE;
    return FALSE;
}

BOOL CProxyLog::LaunchAppFromShell(const AppLauncherRequest& request, AppLauncherResult& result)
{
    for (IProxyLog* p = m_pNext; p; p = p->m_pNext)
        if (p->LaunchAppFromShell(request, result)) return TRUE;
    return FALSE;
}

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

static LPWSTR GetLogProcessName(CProxyReceptionCentre *receptionCentre,
	DWORD processId, LPWSTR processPath, DWORD pathLength, ULONGLONG expectedCreateTime = 0)
{
	if (!processPath || pathLength == 0)
		return NULL;
	processPath[0] = L'\0';

	if (!receptionCentre ||
		!receptionCentre->GetProcessIdentity(processId, processPath, pathLength, expectedCreateTime))
	{
		HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE, processId);
		if (process)
		{
			FILETIME created, exited, kernel, user;
			if (!expectedCreateTime || (GetProcessTimes(process, &created, &exited, &kernel, &user) &&
				((static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime) == expectedCreateTime))
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
	LPWSTR processName = GetLogProcessName(receptionCentre, lpC->dwPid,
		processPath, _countof(processPath));
	LogConnectionEvent(lpPI->GetProxyType() == PROXYTYPE_NOPROXY
		? IProxyLog::ROUTE_DIRECT : IProxyLog::ROUTE_PROXY, lpC, processName);
	LogDnsRedirect(lpC, processName);
}

static CString FormatLogEndpoint(const _SockAddr& address, bool includePort = true)
{
	TCHAR text[INET6_ADDRSTRLEN] = { 0 };
	if (address.IsIPv6())
	{
#ifdef _UNICODE
		ProxyInetNtopW(AF_INET6, (PVOID)address.GetAddr6(), text, _countof(text));
#else
		ProxyInetNtopA(AF_INET6, (PVOID)address.GetAddr6(), text, _countof(text));
#endif
		if (!includePort) return CString(text);
		CString endpoint;
		endpoint.Format(_T("[%s]:%d"), text, address.GetPort());
		return endpoint;
	}
	DWORD ipv4 = address.GetdwIP();
	const BYTE *bytes = reinterpret_cast<const BYTE *>(&ipv4);
	CString endpoint;
	endpoint.Format(includePort ? _T("%u.%u.%u.%u:%d") : _T("%u.%u.%u.%u"), bytes[0], bytes[1], bytes[2],
		bytes[3], address.GetPort());
	return endpoint;
}

void LogDohTargetSelection(CProxyReceptionCentre* receptionCentre,
    const PRCClient* client, size_t attempt, size_t total)
{
    if (!g_pProxyLog || !client || !(client->routingFlags & PRC_CLIENT_FLAG_DOH_RESOLVED)) return;
    const int savedError = WSAGetLastError();
    WCHAR path[MAX_PATH] = {};
    LPCWSTR process = GetLogProcessName(receptionCentre, client->dwPid, path, _countof(path));
    CStringA domain(client->szDomainName);
    domain.Replace('\r', ' '); domain.Replace('\n', ' '); domain.Replace('\t', ' ');
    if (domain.GetLength() > 1 && domain.Right(1) == ".")
        domain.Truncate(domain.GetLength() - 1);
    CString endpoint = FormatLogEndpoint(client->proxyDstAddr);
    CString detail;
    if (client->sType == SOCK_STREAM)
        detail.Format(_T("connecting; attempt=%Iu/%Iu"), attempt, total);
    else
        detail = _T("target selected");
    PrintText(_T("[Proxy] %s (%lu) : %s %hs:%d -> %s; %s\r\n"),
        process && *process ? process : L"Unknown", client->dwPid,
        client->sType == SOCK_STREAM ? L"TCP" : L"UDP", (LPCSTR)domain,
        client->dstAddr.GetPort(), (LPCTSTR)endpoint, (LPCTSTR)detail);
    WSASetLastError(savedError);
}

void LogDnsRedirect(const LPPRCClient lpC, LPCWSTR processName, CProxyReceptionCentre* receptionCentre)
{
	if (!lpC || !lpC->HasProxyDestination())
		return;
	CString original = FormatLogEndpoint(lpC->dstAddr);
	CString effective = FormatLogEndpoint(lpC->proxyDstAddr);
	CString name(processName && processName[0] ? processName : L"Unknown");
    if (lpC->routingFlags & PRC_CLIENT_FLAG_DOH_RESOLVED) {
        // The owning request logs completion once, with cache/shared metadata.
        // Starting (or retrying) a business connection is not another DNS result.
        return;
    }
	PrintText(_T("[DNS] %s (%lu) \x00b7 %s \x2192 %s\r\n"),
		(LPCTSTR)name, lpC->dwPid, (LPCTSTR)original, (LPCTSTR)effective);
}

CString GetDnsLogProcessName(CProxyReceptionCentre* receptionCentre, const PRCClient& client)
{
    const int savedError = WSAGetLastError();
    WCHAR path[MAX_PATH] = {};
    LPCWSTR name = GetLogProcessName(receptionCentre, client.dwPid, path, _countof(path), client.processCreateTime);
    CString result(name && *name ? name : L"Unknown");
    WSASetLastError(savedError);
    return result;
}

void LogDnsRelay(DWORD pid, LPCSTR name, LPCSTR type, LPCSTR result, LPCWSTR processName)
{
    const int savedError = WSAGetLastError();
    WCHAR path[MAX_PATH] = {};
    LPCWSTR process = processName ? processName : GetLogProcessName(NULL, pid, path, _countof(path));
    CStringA displayName(name ? name : "");
    if (displayName.GetLength() > 1 && displayName.Right(1) == ".")
        displayName.Truncate(displayName.GetLength() - 1);
    PrintText(_T("[DoH] %s (%lu) : %hs %hs -> %hs\r\n"), process && *process ? process : L"Unknown", pid, (LPCSTR)displayName, type, result);
    WSASetLastError(savedError);
}

void LogDnsRelayRoute(const PRCClient* client, LPCSTR result, CProxyReceptionCentre* receptionCentre)
{
    if (!client) return;
    const int savedError = WSAGetLastError();
    CString process = GetDnsLogProcessName(receptionCentre, *client);
    CString endpoint = FormatLogEndpoint(client->dstAddr);
    PrintText(_T("[DoH] %s (%lu) : %s DNS %s -> %hs\r\n"),
        (LPCWSTR)process, client->dwPid,
        client->sType == SOCK_DGRAM ? L"UDP" : L"TCP", (LPCTSTR)endpoint, result);
    WSASetLastError(savedError);
}

void CProxyLog::OnProxyFailure(const LPPRCClient client, LPCWSTR processName,
	LPCWSTR target, BOOL connectingProxy, DWORD error, LPCWSTR detail)
{
	for (IProxyLog* p = m_pNext; p; p = p->m_pNext)
		p->OnProxyFailure(client, processName, target, connectingProxy, error, detail);
}

void LogProxyFailure(CProxyReceptionCentre* receptionCentre, const LPPRCClient client,
	BOOL connectingProxy, int socketError, LPCSTR detail)
{
	if (!g_pProxyLog || !client)
		return;
	// Diagnostics must not change the error observed by the connection code.
	const int savedError = WSAGetLastError();
	WCHAR path[MAX_PATH] = {};
	if (receptionCentre)
		receptionCentre->GetProcessIdentity(client->dwPid, path, _countof(path));
	path[_countof(path) - 1] = L'\0';
	LPCWSTR name = wcsrchr(path, L'\\');
	CString processName(name ? name + 1 : path);

	// Match ConnectProxy: use the domain instead of a fake IP, unless routing
	// selected an explicit upstream destination (for example DNS redirection).
	CString target;
	if (client->IsDNValid() && !client->HasProxyDestination())
	{
		CString host(CStringA(client->szDomainName,
			(int)strnlen_s(client->szDomainName, sizeof(client->szDomainName))));
		target.Format(_T("%s:%d"), (LPCTSTR)host, client->dstAddr.GetPort());
	}
	else
		target = FormatLogEndpoint(client->GetProxyDestination());

	// Callback strings are borrowed; copy only a bounded description before
	// returning. Never include proxy credentials or entire HTTP headers.
	CString description;
	if (detail && detail[0])
		description = CString(CStringA(detail, (int)strnlen_s(detail, 256)));
	g_pProxyLog->OnProxyFailure(client, CStringW(processName), CStringW(target),
		connectingProxy, (DWORD)socketError, CStringW(description));
	WSASetLastError(savedError);
}
