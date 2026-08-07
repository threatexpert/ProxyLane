/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "asynsocket\AsyncSocketEx.h"
#include "PRCTcpServer.h"
#include "ProxyReceptionCentre.h"
#include "GlobalProxy.h"
#include "ProxyLog.h"
#include "ProxySettings.h"
#include <psapi.h>

#pragma comment(lib, "psapi.lib")


static BOOL ResolveProcPath(
	CProxyReceptionCentre* receptionCentre,
	DWORD dwPid,
	LPWSTR szOut,
	DWORD cchOut,
	LPWSTR &ppszName)
{
	if (!receptionCentre || !szOut || cchOut == 0)
		return FALSE;

	szOut[0] = L'\0';
	ppszName = NULL;

	// Hooked processes report their path during initialization, so connections use the cached identity first.
	if (!receptionCentre->GetProcessIdentity(dwPid, szOut, cchOut))
	{
		typedef BOOL(WINAPI* PFN_QFIN)(HANDLE, DWORD, LPWSTR, PDWORD);
		static PFN_QFIN s_pQFIN = (PFN_QFIN)-1;
		if (s_pQFIN == (PFN_QFIN)-1)
		{
			HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
			s_pQFIN = hK32
				? (PFN_QFIN)GetProcAddress(hK32, "QueryFullProcessImageNameW")
				: NULL;
		}

		HANDLE hProc = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE,
			dwPid);
		if (!hProc && s_pQFIN)
		{
			// Vista and later can use reduced query access; XP never enters this branch.
			const DWORD kProcessQueryLimitedInformation = 0x1000;
			hProc = OpenProcess(kProcessQueryLimitedInformation, FALSE, dwPid);
			if (!hProc)
				hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
		}
		if (!hProc)
			return FALSE;

		BOOL resolved = FALSE;
		if (s_pQFIN)
		{
			DWORD cch = cchOut;
			resolved = s_pQFIN(hProc, 0, szOut, &cch) && szOut[0];
		}

		if (!resolved)
		{
			szOut[0] = L'\0';
			resolved = GetModuleFileNameExW(hProc, NULL, szOut, cchOut) > 0;
			szOut[cchOut - 1] = L'\0';
		}
		CloseHandle(hProc);
		if (!resolved || !szOut[0])
			return FALSE;

		HookProcessIdentityInfo identity = { 0 };
		identity.dwProcessId = dwPid;
		HANDLE identityProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
		if (identityProcess)
		{
			FILETIME created, exited, kernel, user;
			if (GetProcessTimes(identityProcess, &created, &exited, &kernel, &user))
				identity.processCreateTime =
					((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
			CloseHandle(identityProcess);
		}
		wcsncpy(identity.szAppPath, szOut, _countof(identity.szAppPath) - 1);
		receptionCentre->RegisterProcessIdentity(&identity);
	}

	ppszName = wcsrchr(szOut, L'\\');
	ppszName = ppszName ? ppszName + 1 : szOut;
	return ppszName[0] != L'\0';
}

CPRCTcpServer::CPRCTcpServer(CProxyReceptionCentre *pPRC)
	: CPRCXServer(pPRC)
	, m_ProxyTaskMgr(pPRC)
{
}

CPRCTcpServer::~CPRCTcpServer(void)
{
}

BOOL CPRCTcpServer::StartupServer()
{
	UINT nSocketPort = INADDR_ANY;

#ifdef _DEBUG
	//nSocketPort = 248;
#endif
	if(!Create(nSocketPort, SOCK_STREAM,
		FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE,
		"127.0.0.1"))
		return FALSE;

	int socketbufsize=1024*16;
	SetSockOpt(SO_RCVBUF, &socketbufsize,sizeof(socketbufsize));

	if(!Listen())
		return FALSE;

	_SockAddr tcpaddr;
	INT addlen = sizeof(tcpaddr);
	if(!GetSockName(&tcpaddr, &addlen))
	{
		Close();
		return FALSE;
	}

	PrintText(_T("PRCTcpServer listening on port: %d\r\n"), tcpaddr.GetPort());

	return TRUE;
}


BOOL CPRCTcpServer::ShutdownServer()
{
	m_ProxyTaskMgr.RemoveAllTasks();
	Close();

	PrintText(_T("PRCTcpServer stopped.\r\n"));
	return TRUE;
}

BOOL isLLMNR(const char *name)
{
	int len = strlen(name);
	if (len)
	{
		if (strchr(name, '.') != NULL)
			return FALSE;

		int i;
		for (i=0; i<len; i++)
		{
			if (!isalpha(name[i]))
				break;
		}

		if (i == len)
		{
			return TRUE;
		}
	}

	return FALSE;
}

void CPRCTcpServer::OnAccept(int nErrorCode)
{
	_SockAddr sa;
	int len = sizeof(sa);
	SOCKET sClient = accept(m_SocketData.hSocket, &sa, &len);
	if (sClient == INVALID_SOCKET)
		return;

	// When CHookWinsock intercepts a connection, it registers the socket and the actual destination with the PRC.
	// GetClientInfo retrieves that original destination through the PRC interface.
	// It uses getpeername on the accepted socket to identify the original IP and port, then matches them against the PRC registration.
	PRCClient PRCC;
	if(!m_pPRC->GetClientInfo(sClient, &PRCC, TRUE))
	{
		PrintText(_T("PRCTcpServer received a task that cannot be proxied.\r\n"));
		closesocket(sClient);
		return;
	}
	PRCC.sAccept = sClient;

	WCHAR szChildAppPath[MAX_PATH] = L"\0";
	LPWSTR ppszName = NULL;

	ResolveProcPath(m_pPRC, PRCC.dwPid, szChildAppPath, _countof(szChildAppPath), ppszName);

	DWORD nIP = PRCC.dstAddr.GetdwIP();
	const BYTE* pucIP = (BYTE*)&nIP;

	ProxyInfo pisetting;
	ProxySettingsInfo psi;
	memset(&pisetting, 0, sizeof(pisetting));
	memset(&psi, 0, sizeof(psi));

	IProxySettings *pProxySettings = m_pGlobalProxy->GetSettingsInstance();
	if(!pProxySettings->GetProxyInfo(&PRCC, &pisetting))
	{
		PrintText(_T("ERR: GetProxyInfo\r\n"));
		closesocket(sClient);
		return;
	}

	if (!pProxySettings->GetProxySettings(&psi))
	{
		PrintText(_T("ERR: GetProxySettings\r\n"));
		closesocket(sClient);
		return;
	}

	if (psi.bDisableLLMNR)
	{
		if (isLLMNR(PRCC.szDomainName))
		{
#ifdef _UNICODE
			PrintText(_T("PID: %d(%s), refused: %S:%d\r\n"), PRCC.dwPid, ppszName ? ppszName : L"", PRCC.szDomainName, PRCC.dstAddr.GetPort());
#else
			PrintText(_T("PID: %d(%s), refused: %s:%d\r\n"), PRCC.dwPid, ppszName ? ppszName : L"", PRCC.szDomainName, PRCC.dstAddr.GetPort());
#endif
			closesocket(sClient);
			return;
		}
	}

	if(!m_ProxyTaskMgr.OnNewTask(sClient, &PRCC, &pisetting))
	{
#ifdef _UNICODE
		PrintText(_T("Failed to add proxy task. PID: %d(%s), %u.%u.%u.%u:%d, domain: %S:%d\r\n"), PRCC.dwPid, ppszName ? ppszName : L"", pucIP[0], pucIP[1], pucIP[2], pucIP[3], PRCC.dstAddr.GetPort(), PRCC.szDomainName, PRCC.dstAddr.GetPort());
#else
		PrintText(_T("Failed to add proxy task. PID: %d(%s), %u.%u.%u.%u:%d, domain: %s:%d\r\n"), PRCC.dwPid, ppszName ? ppszName : L"", pucIP[0], pucIP[1], pucIP[2], pucIP[3], PRCC.dstAddr.GetPort(), PRCC.szDomainName, PRCC.dstAddr.GetPort());
#endif
		closesocket(sClient);
		return;
	}

	LogNewProxyTask(&PRCC);

	LPCTSTR szTag = (pisetting.GetProxyType() == PROXYTYPE_NOPROXY) ? _T("[Bypassed] ") : _T("[Hooked] ");
	if(PRCC.IsDNValid())
	{
#ifdef _UNICODE
		PrintText(_T("%sPID: %d(%s), connect to: %S:%d\r\n"), szTag, PRCC.dwPid, ppszName ? ppszName : L"", PRCC.szDomainName, PRCC.dstAddr.GetPort());
#else
		PrintText(_T("%sPID: %d(%s), connect to: %s:%d\r\n"), szTag, PRCC.dwPid, ppszName ? ppszName : L"", PRCC.szDomainName, PRCC.dstAddr.GetPort());
#endif
	}else
	{
		PrintText(_T("%sPID: %d(%s), connect to: %u.%u.%u.%u:%d\r\n"), szTag, PRCC.dwPid, ppszName ? ppszName : L"", pucIP[0], pucIP[1], pucIP[2], pucIP[3], PRCC.dstAddr.GetPort());
	}


}

IProxyTaskMgr *CPRCTcpServer::GetPTMInstance()
{
	return &m_ProxyTaskMgr;
}
