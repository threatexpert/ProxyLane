/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "ProxyReceptionCentre.h"
#include "GlobalProxy.h"
#include "ProxyDataHandle.h"

#define TIMER_CHECK_REGISTERED_CLIENT 0x100
#define TIMER_CHECK_REGISTERED_CLIENT_INTERVAL 30*1000

CProxyReceptionCentre::CProxyReceptionCentre(CGlobalProxy *pGlobalProxy)
{
	InitializeCriticalSection(&m_ProcessIdentityLock);
	m_hPRCThread = NULL;
	m_dwPRCThreadId = 0;
	m_PRCWnd = NULL;
	m_hTestEvent = NULL;
	m_pTcpServer = NULL;
	m_pUdpServer = NULL;
	m_pPipeServer = NULL;

	m_pGlobalProxy = pGlobalProxy;
	m_pProxyDataHandle = new CProxyDataHandle;
}

CProxyReceptionCentre::~CProxyReceptionCentre(void)
{
	delete m_pProxyDataHandle;
	DeleteCriticalSection(&m_ProcessIdentityLock);
}
//
//BOOL CProxyReceptionCentre::InitPRCWnd()
//{
//	WNDCLASS wndclass;
//	memset(&wndclass, 0, sizeof(wndclass));
//	wndclass.lpfnWndProc = CProxyReceptionCentre::PRCWndProc;
//	wndclass.lpszClassName = _T("PRC_WndClass");
//
//	RegisterClass(&wndclass);
//
//	m_PRCWnd = CreateWindow(_T("PRC_WndClass"), _T("PRC_Wnd"),
//		WS_OVERLAPPEDWINDOW, 0, 0, 0, 0,
//		NULL, NULL, NULL, NULL);
//
//	if(m_PRCWnd == NULL)
//		return FALSE;
//
//	return TRUE;
//}
//
//BOOL CProxyReceptionCentre::ClosePRCWnd()
//{
//	if(::IsWindow(m_PRCWnd))
//	{
//		SendMessage(m_PRCWnd, WM_CLOSE, 0, 0);
//		ATLASSERT(!::IsWindow(m_PRCWnd));
//		m_PRCWnd = NULL;
//		return TRUE;
//	}
//	return FALSE;
//}

void CProxyReceptionCentre::SetThreadStatus(threadstatus status)
{
	m_ThreadStatus = status;
	SetEvent(m_hTestEvent); 
}

LRESULT CALLBACK CProxyReceptionCentre::PRCWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{

	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;

	}
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

BOOL CProxyReceptionCentre::CreatePRC()
{
	ATLASSERT(m_hTestEvent == NULL);

	m_ThreadStatus = threadstatus_inactive;

	WSADATA wsaData;
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		return FALSE;

	m_hTestEvent = CreateEvent(0, 0, 0, 0);
	if(m_hTestEvent == NULL)
	{
		WSACleanup();
		return FALSE;
	}

	m_hPRCThread = CreateThread(0, 0, _PRCThreadProc, this, CREATE_SUSPENDED, &m_dwPRCThreadId);

	if(m_hPRCThread == NULL)
	{
		//szError
		CloseHandle(m_hTestEvent);
		m_hTestEvent = NULL;
		WSACleanup();
		return FALSE;
	}

	if (ResumeThread(m_hPRCThread) == (DWORD)-1)
	{
		if (TerminateThread(m_hPRCThread, 0))
			WaitForSingleObject(m_hPRCThread, INFINITE);
		CloseHandle(m_hPRCThread);
		m_hPRCThread = NULL;
		CloseHandle(m_hTestEvent);
		m_hTestEvent = NULL;
		WSACleanup();
		return FALSE;
	}
	WaitForSingleObject(m_hTestEvent, INFINITE);

	if(m_ThreadStatus != threadstatus_running)
	{
		CloseHandle(m_hPRCThread);
		m_hPRCThread = NULL;
		CloseHandle(m_hTestEvent);
		m_hTestEvent = NULL;
		WSACleanup();
		return FALSE;
	}


	return TRUE;
}

BOOL CProxyReceptionCentre::DestroyPRC()
{
	//close xxxx

	if (m_dwPRCThreadId == GetCurrentThreadId())
	{
		//避免在回调中试图等待自己退出
		ATLASSERT(FALSE);
		return FALSE;
	}

	KillTimer(TIMER_CHECK_REGISTERED_CLIENT);

	//if(!ClosePRCWnd())
	//{
	//	//szError
	//	return FALSE;
	//}
	::PostThreadMessage(m_dwPRCThreadId, WM_QUIT, 0, 0);

	if(m_hTestEvent)
	{
		WaitForSingleObject(m_hTestEvent, INFINITE);
		CloseHandle(m_hTestEvent);
		m_hTestEvent = NULL;
	}

	if(m_hPRCThread)
	{
		WaitForSingleObject(m_hPRCThread, INFINITE);
		CloseHandle(m_hPRCThread);
		m_hPRCThread = NULL;
	}

	ShutdownPRCServer();

	WSACleanup();

	return m_ThreadStatus == threadstatus_end;
}

DWORD WINAPI CProxyReceptionCentre::_PRCThreadProc(LPVOID lParam)
{
	CProxyReceptionCentre *_this = (CProxyReceptionCentre*)lParam;

	return _this->InternalPRCThreadProc();
}

DWORD WINAPI CProxyReceptionCentre::InternalPRCThreadProc()
{
	//if(!InitPRCWnd())
	//{
	//	//szErr
	//	SetThreadStatus(threadstatus_error);
	//	return -1;
	//}

	if(!StartupPRCServer())
	{
		//ClosePRCWnd();
		SetThreadStatus(threadstatus_error);
		return -1;
	}

	SetTimer(TIMER_CHECK_REGISTERED_CLIENT, TIMER_CHECK_REGISTERED_CLIENT_INTERVAL);

	SetThreadStatus(threadstatus_running);

	BOOL bRet;
	MSG msg;

	while( (bRet = GetMessage( &msg, NULL, 0, 0 )) != 0)
	{ 
		if (bRet == -1)
		{
			break;
		}
		else
		{
			TranslateMessage(&msg); 
			DispatchMessage(&msg); 
		}
	}

	SetThreadStatus(threadstatus_end);
	return 0;
}

BOOL CProxyReceptionCentre::StartupPRCServer()
{
	ATLASSERT(m_pTcpServer == NULL && m_pUdpServer == NULL);

	if(!m_pProxyDataHandle)
		return FALSE;

	do 
	{
		m_pTcpServer = new CPRCTcpServer(this);
		if(m_pTcpServer == NULL)
		{
			m_szLastError = _T("创建 PRCTcpServer 失败");
			break;
		}

		if(!m_pTcpServer->StartupServer())
		{
			m_szLastError = _T("启动 PRCTcpServer 失败");
			break;
		}

		m_pUdpServer = new CPRCUdpServer(this);
		if(m_pUdpServer == NULL)
		{
			m_szLastError = _T("创建 CPRCUdpServer 失败");
			break;
		}

		if(!m_pUdpServer->StartupServer())
		{
			m_szLastError = _T("启动 CPRCUdpServer 失败");
			break;
		}

		m_pPipeServer = new CPRCPipeServer(this);
		if(m_pPipeServer == NULL)
		{
			m_szLastError = _T("创建 CPRCPipeServer 失败");
			break;
		}

		if(!m_pPipeServer->StartupServer())
		{
			m_szLastError = _T("启动 CPRCPipeServer 失败");
			break;
		}

		return TRUE;

	} while(FALSE);

	ShutdownPRCServer();

	return FALSE;
}

BOOL CProxyReceptionCentre::ShutdownPRCServer()
{
	if(m_pPipeServer)
	{
		m_pPipeServer->ShutdownServer();
		delete m_pPipeServer;
		m_pPipeServer = NULL;
	}
	if(m_pTcpServer)
	{
		m_pTcpServer->ShutdownServer();
		//m_pTcpServer->xxxx
		delete m_pTcpServer;
		m_pTcpServer = NULL;
	}
	if(m_pUdpServer)
	{
		m_pUdpServer->ShutdownServer();
		delete m_pUdpServer;
		m_pUdpServer = NULL;
	}

	return TRUE;
}

BOOL CProxyReceptionCentre::GetPRCPipeName(LPSTR lpBuf, int bufsize)
{
	if(!m_pPipeServer)
		return FALSE;

	CStringA szPipeName = (CStringA)m_pPipeServer->GetPipeName();
	if(!szPipeName.GetLength() || szPipeName.GetLength()>=bufsize)
		return FALSE;

	strcpy(lpBuf, szPipeName.GetBuffer());
	return TRUE;
}

IProxyTaskMgr* CProxyReceptionCentre::GetPTMInstance(int type)
{
	if(type == 0)//tcp
	{
		if(m_pTcpServer)
			return m_pTcpServer->GetPTMInstance();
		else
			return NULL;
	}else if(type == 1)//udp
	{
		if(m_pUdpServer)
			return m_pUdpServer->GetPTMInstance();
		else
			return NULL;
	}else
		return NULL;
}

IProxyDataHandle* CProxyReceptionCentre::GetPDHInstance()
{
	return m_pProxyDataHandle;
}

BOOL CProxyReceptionCentre::RegisterProcessIdentity(
	LPHookProcessIdentityInfo identity)
{
	if (!identity || !identity->dwProcessId || !identity->szAppPath[0])
		return FALSE;

	HookProcessIdentityInfo safeIdentity = *identity;
	safeIdentity.szAppPath[_countof(safeIdentity.szAppPath) - 1] = L'\0';

	EnterCriticalSection(&m_ProcessIdentityLock);
	m_ProcessIdentities[safeIdentity.dwProcessId] = safeIdentity;
	LeaveCriticalSection(&m_ProcessIdentityLock);
	return TRUE;
}

BOOL CProxyReceptionCentre::GetProcessIdentity(
	DWORD processId,
	LPWSTR appPath,
	DWORD appPathCount)
{
	if (!processId || !appPath || appPathCount == 0)
		return FALSE;
	appPath[0] = L'\0';

	BOOL found = FALSE;
	EnterCriticalSection(&m_ProcessIdentityLock);
	std::map<DWORD, HookProcessIdentityInfo>::const_iterator it =
		m_ProcessIdentities.find(processId);
	if (it != m_ProcessIdentities.end())
	{
		wcsncpy(appPath, it->second.szAppPath, appPathCount - 1);
		appPath[appPathCount - 1] = L'\0';
		found = appPath[0] != L'\0';
	}
	LeaveCriticalSection(&m_ProcessIdentityLock);
	return found;
}


BOOL CProxyReceptionCentre::GetStartupInfo(LPPRCINFO lpStartupInfo)
{
	if(m_pTcpServer == NULL)
	{
		m_szLastError = _T("未创建 PRCTcpServer");
		return FALSE;
	}

	INT addlen = sizeof(lpStartupInfo->tcpaddr);
	if(!m_pTcpServer->GetSockName(&lpStartupInfo->tcpaddr, &addlen))
	{
		m_szLastError = _T("GetSockName 失败.");
		return FALSE;
	}

	//udp

	return TRUE;
}

BOOL CProxyReceptionCentre::IsFiltered(LPPRCClient lpClient)
{
	return FALSE;
}

BOOL CProxyReceptionCentre::IsFiltered(LPPRCClientInfo lpClientInfo)
{
	return FALSE;
}

BOOL CProxyReceptionCentre::RegisterClient(LPPRCClient lpClientInfo)
{
	if(lpClientInfo->sType == SOCK_STREAM)
		return RegisterTCPClient(lpClientInfo);
	else if(lpClientInfo->sType == SOCK_DGRAM)
		return RegisterUDPClient(lpClientInfo);
	else
		return FALSE;
}

BOOL CProxyReceptionCentre::RegisterTCPClient(LPPRCClient lpClientInfo)
{
	if(IsFiltered(lpClientInfo))
		return FALSE;

	CTSList<PRCClient>::critical lc = m_RegisteredClient;
	lpClientInfo->reserved = GetTickCount();
	for(list<PRCClient>::iterator it=m_RegisteredClient.begin(); it!=m_RegisteredClient.end(); it++)
	{
		//may be?
		if(lpClientInfo->dwPid == it->dwPid && lpClientInfo->s == it->s)
		{
			*it = *lpClientInfo;
			return TRUE;
		}

	}

	m_RegisteredClient.push_back(*lpClientInfo);
	return TRUE;
}

BOOL CProxyReceptionCentre::RegisterUDPClient(LPPRCClient lpClientInfo)
{
	return m_pUdpServer->OnRegister(lpClientInfo);
}

BOOL CProxyReceptionCentre::GetUDPClientPortState(UDPLocalProxyAddrInfo *pLPAI)
{
	return m_pUdpServer->GetUDPPortState(pLPAI);
}

BOOL CProxyReceptionCentre::UnregisterClient(LPPRCClient lpClientInfo)
{
	if(lpClientInfo->sType == SOCK_STREAM)
	{
		CTSList<PRCClient>::critical lc = m_RegisteredClient;
		for(list<PRCClient>::iterator it=m_RegisteredClient.begin(); it!=m_RegisteredClient.end(); )
		{
			if(lpClientInfo->s == it->s && lpClientInfo->dwPid == it->dwPid)
			{
				m_RegisteredClient.erase(it++);
			}else
			{
				it++;
			}

		}
	}
	else if(lpClientInfo->sType == SOCK_DGRAM)
	{
		return m_pUdpServer->OnUnregister(lpClientInfo);
	}
	
	return FALSE;
}

BOOL CProxyReceptionCentre::GetClientInfo(SOCKET accepted, LPPRCClient lpClientInfo, BOOL bpop/* =FALSE */)
{
	_SockAddr sa1;
	int len = sizeof(_SockAddr);
	if(getpeername(accepted, &sa1, &len) != 0)
		return FALSE;

	CTSList<PRCClient>::critical lc = m_RegisteredClient;
	for(list<PRCClient>::iterator it=m_RegisteredClient.begin(); it!=m_RegisteredClient.end(); it++)
	{
		//端口一致
		if(sa1.GetPort() == it->srcAddr.GetPort())
		{
			//bind的时候地址为0则不匹配地址
			if(it->srcAddr.GetdwIP() == 0 || sa1.GetdwIP() == it->srcAddr.GetdwIP())
			{
				*lpClientInfo = *it;
				if(bpop)
					m_RegisteredClient.erase(it);
				return TRUE;
			}
		}
		/////////////////////////////////////////////
		//_SockAddr sa2;
		//len = sizeof(_SockAddr);
		//if(getsockname(it->s, &sa2, &len) == 0)
		//{
		//	if(sa1 == sa2)
		//	{
		//		lpClientInfo->zero();
		//		lpClientInfo->s = it->s;
		//		lpClientInfo->dstAddr = it->dstAddr;
		//		strncpy(lpClientInfo->szDomainName, it->szDomainName, sizeof(lpClientInfo->szDomainName));

		//		if(bpop)
		//			m_RegisteredClient.erase(it);
		//		return TRUE;
		//	}
		//}
		/////////////////////////////////////////////

	}

	return FALSE;
	//return m_pPipeServer->GetClientInfo(accepted, lpClientInfo, bpop);
}

VOID CProxyReceptionCentre::OnTimer(UINT_PTR nIDEvent)
{

	switch(nIDEvent)
	{
	case TIMER_CHECK_REGISTERED_CLIENT:
		{
			CTSList<PRCClient>::critical lc = m_RegisteredClient;
			for(list<PRCClient>::iterator it=m_RegisteredClient.begin(); it!=m_RegisteredClient.end();)
			{
				PRCClient &prcclient = *it;

				if(GetTickCount() - prcclient.reserved > 60*1000)
				{
					//kick out
					it = m_RegisteredClient.erase(it);
				}else
				{
					it++;
				}

			}
		}
		break;

	default:
		break;
	}


}

BOOL CProxyReceptionCentre::GetProxySettingsInfo(LPProxySettingsInfo lpPSI)
{
	IProxySettings* pPS = m_pGlobalProxy->GetSettingsInstance();

	if (!pPS)
	{
		return FALSE;
	}

	return pPS->GetProxySettings(lpPSI);
}


BOOL CProxyReceptionCentre::GetProxyInfo(LPPRCClient lpClientInfo, LPProxyInfo lpPI)
{
	IProxySettings* pPS = m_pGlobalProxy->GetSettingsInstance();

	if (!pPS)
	{
		return FALSE;
	}

	return pPS->GetProxyInfo(lpClientInfo, lpPI);
}
