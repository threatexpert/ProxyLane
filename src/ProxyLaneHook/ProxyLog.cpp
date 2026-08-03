#include "stdafx.h"
#include "ProxyLog.h"
#include <stdio.h>

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

void CProxyLog::OnNewProcess(LPHookNewProcessInfo lphnpi)
{
	IProxyLog *p = IProxyLog::m_pNext;
	while(p)
	{
		p->OnNewProcess(lphnpi);
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