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


static BOOL ResolveProcPath(DWORD dwPid, LPWSTR szOut, DWORD cchOut, LPWSTR &ppszName)
{
	if (!szOut || cchOut == 0)
		return FALSE;

	szOut[0] = L'\0';
	ppszName = szOut;

	HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);

	typedef BOOL(WINAPI* PFN_QFIN)(HANDLE, DWORD, LPWSTR, PDWORD);
	static PFN_QFIN s_pQFIN = (PFN_QFIN)-1;
	if (s_pQFIN == (PFN_QFIN)-1)
	{
		HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
		s_pQFIN = hK32 ? (PFN_QFIN)GetProcAddress(hK32, "QueryFullProcessImageNameW") : NULL;
	}
	if (s_pQFIN)
	{
		DWORD cch = cchOut;
		if (s_pQFIN(hProc, 0, szOut, &cch) && szOut[0]) {
			if (ppszName)
			{
				ppszName = wcsrchr(szOut, L'\\');
				if (ppszName)
					(ppszName)++;
				else
					ppszName = szOut;
			}
			CloseHandle(hProc);
			return TRUE;
		}
		szOut[0] = L'\0';
	}
	CloseHandle(hProc);
	return FALSE;
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
	if(!Create(nSocketPort))
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

	PrintText(_T("PRCTcpServer 监听端口: %d\r\n"), tcpaddr.GetPort());

	return TRUE;
}


BOOL CPRCTcpServer::ShutdownServer()
{
	m_ProxyTaskMgr.RemoveAllTasks();
	Close();

	PrintText(_T("PRCTcpServer 关闭.\r\n"));
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

	//CHookWinsock 拦截到一个连接时会将套接字和真正的请求地址登记到PRC,
	//这里通过PRC的接口GetClientInfo得到原来的该连接的真正请求地址,
	//GetClientInfo内部通过这里接受到的套接字查询(getpeername)连接的原ip和端口，并从PRC登记的数据中查找匹配的地址、端口信息.
	PRCClient PRCC;
	if(!m_pPRC->GetClientInfo(sClient, &PRCC, TRUE))
	{
		PrintText(_T("PRCTcpServer接受到一个无法代理的任务.\r\n"));
		closesocket(sClient);
		return;
	}
	PRCC.sAccept = sClient;

	WCHAR szChildAppPath[MAX_PATH] = L"\0";
	LPWSTR ppszName = NULL;

	ResolveProcPath(PRCC.dwPid, szChildAppPath, _countof(szChildAppPath), ppszName);

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
		PrintText(_T("添加一个代理任务失败. PID: %d(%s), %u.%u.%u.%u:%d, 域名: %S:%d\r\n"), PRCC.dwPid, ppszName ? ppszName : L"", pucIP[0], pucIP[1], pucIP[2], pucIP[3], PRCC.dstAddr.GetPort(), PRCC.szDomainName, PRCC.dstAddr.GetPort());
#else
		PrintText(_T("添加一个代理任务失败. PID: %d(%s), %u.%u.%u.%u:%d, 域名: %s:%d\r\n"), PRCC.dwPid, ppszName ? ppszName : L"", pucIP[0], pucIP[1], pucIP[2], pucIP[3], PRCC.dstAddr.GetPort(), PRCC.szDomainName, PRCC.dstAddr.GetPort());
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