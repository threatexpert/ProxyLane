/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "ProxyTaskMgr.h"
#include "PRCTcpPeer.h"
#include "ProxyLog.h"
//#include "PRCUdpPeer.h"

#define TIMER_TCPPERTASK 100
#define TIMER_TCPPERTASK_INTERVAL 1000

#define TIMER_IS_TASK_ALIVE 101
#define TIMER_IS_TASK_ALIVE_INTERVAL 30000

//////////////////////////////////////////////////////////////////////////

CProxyXTaskMgr::CProxyXTaskMgr(CProxyReceptionCentre *pPRC)
{
	m_pPRC = pPRC;
}

CProxyXTaskMgr::~CProxyXTaskMgr(void)
{

}

void CProxyXTaskMgr::OnAddTask(const LPPRCClient lpC, const LPProxyInfo lpPI)
{
	IProxyTaskMgr *p = IProxyTaskMgr::m_pNext;
	while(p)
	{
		p->OnAddTask(lpC, lpPI);
		p = p->m_pNext;
	}
}

void CProxyXTaskMgr::OnDelTask(const LPPRCClient lpC)
{
	IProxyTaskMgr *p = IProxyTaskMgr::m_pNext;
	while(p)
	{
		p->OnDelTask(lpC);
		p = p->m_pNext;
	}
}

void CProxyXTaskMgr::EnumTask(IProxyTaskMgr *pCallBack)
{

}

void CProxyXTaskMgr::OnEachTask(const LPPRCClient lpC, const LPProxyInfo lpPI)
{

}

BOOL CProxyXTaskMgr::GetTaskCount(DWORD *pCount)
{
	*pCount = 0;
	return FALSE;
}

BOOL CProxyXTaskMgr::TestTaskByPid(DWORD dwPid, ULONGLONG processCreateTime)
{
	HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, dwPid);

	if (!hProcess)
	{
		if (GetLastError() == ERROR_ACCESS_DENIED)
			return TRUE;

		return FALSE;
	}
	FILETIME created, exited, kernel, user;
	BOOL queried = GetProcessTimes(hProcess, &created, &exited, &kernel, &user);
	CloseHandle(hProcess);
	if (!queried)
		return FALSE;
	ULONGLONG actual = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
	return processCreateTime == 0 || actual == processCreateTime;
}


//////////////////////////////////////////////////////////////////////////


CProxyTCPTaskMgr::CProxyTCPTaskMgr(CProxyReceptionCentre *pPRC)
	: CProxyXTaskMgr(pPRC)
{
}

CProxyTCPTaskMgr::~CProxyTCPTaskMgr(void)
{
}


BOOL CProxyTCPTaskMgr::OnNewTask(SOCKET sClient, LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo)
{
	CTcpProxyTask *pTask = new CTcpProxyTask(this);
	if(pTask == NULL)
		return FALSE;

	if(!pTask->SetTaskInfo(sClient, lpPRCClient, lpProxyInfo))
	{
		delete pTask;
		return FALSE;
	}

	CTSList<CTcpProxyTask*>::critical lc = m_tasklist;
	OnAddTask(lpPRCClient, lpProxyInfo);
	if(m_tasklist.size() == 0)
	{
		SetTimer(TIMER_TCPPERTASK, TIMER_TCPPERTASK_INTERVAL);
		SetTimer(TIMER_IS_TASK_ALIVE, TIMER_IS_TASK_ALIVE_INTERVAL);
	}
	m_tasklist.push_back(pTask);
	return TRUE;
}

BOOL CProxyTCPTaskMgr::OnDeleteTask(CTcpProxyTask *pTask)
{
	CTSList<CTcpProxyTask*>::critical lc = m_tasklist;
	OnDelTask(&pTask->m_PRCClient);
	m_tasklist.remove(pTask);
	if(m_tasklist.size() == 0)
	{
		KillTimer(TIMER_TCPPERTASK);
		KillTimer(TIMER_IS_TASK_ALIVE);
	}
	delete pTask;
	return TRUE;
}

VOID CProxyTCPTaskMgr::RemoveAllTasks()
{
	CTSList<CTcpProxyTask*>::critical lc = m_tasklist;
	for(list<CTcpProxyTask*>::iterator it = m_tasklist.begin(); it!=m_tasklist.end(); it++)
	{
		CTcpProxyTask *pObj = *it;
		pObj->EndTask();
		//notify call back
		OnDelTask(&pObj->m_PRCClient);
		delete pObj;
	}
	m_tasklist.clear();
}

VOID CProxyTCPTaskMgr::OnTimer(UINT_PTR nIDEvent)
{
	switch(nIDEvent)
	{
	case TIMER_TCPPERTASK:
		{
			CTSList<CTcpProxyTask*>::critical lc = m_tasklist;
			for(list<CTcpProxyTask*>::iterator it = m_tasklist.begin(); it!=m_tasklist.end(); )
			{
				CTcpProxyTask *pObj = *it;
				if(pObj->m_pClient && pObj->m_pClient->GetSocketHandle() != INVALID_SOCKET)
					pObj->m_pClient->OnTimer();
				if(pObj->m_pServer && pObj->m_pServer->GetSocketHandle() != INVALID_SOCKET)
					pObj->m_pServer->OnTimer();
				if (pObj->IsDeletePending())
				{
					OnDelTask(&pObj->m_PRCClient);
					it = m_tasklist.erase(it);
					delete pObj;
				}
				else
				{
					++it;
				}
			}
			if (m_tasklist.empty())
			{
				KillTimer(TIMER_TCPPERTASK);
				KillTimer(TIMER_IS_TASK_ALIVE);
			}

			ATLTRACE("tasklist.size() = %d\r\n", (INT)m_tasklist.size());
		}
		break;

	case TIMER_IS_TASK_ALIVE:
		{
			CTSList<CTcpProxyTask*>::critical lc = m_tasklist;
			for(list<CTcpProxyTask*>::iterator it = m_tasklist.begin(); it!=m_tasklist.end(); )
			{
				CTcpProxyTask *pObj = *it;
				if (!TestTaskByPid(pObj->m_PRCClient.dwPid,
					pObj->m_PRCClient.processCreateTime))
				{
					pObj->EndTask();
					OnDelTask(&pObj->m_PRCClient);
					delete pObj;
					m_tasklist.erase(it++);
				}else
				{
					it++;
				}
			}
		}
		break;
	}
}


void CProxyTCPTaskMgr::EnumTask(IProxyTaskMgr *pCallBack)
{
	CTSList<CTcpProxyTask*>::critical lc = m_tasklist;
	for(list<CTcpProxyTask*>::iterator it = m_tasklist.begin(); it!=m_tasklist.end(); it++)
	{
		CTcpProxyTask *pObj = *it;
		pCallBack->OnEachTask(&pObj->m_PRCClient, &pObj->m_ProxyInfo);
	}
}

BOOL CProxyTCPTaskMgr::GetTaskCount(DWORD *pCount)
{
	CTSList<CTcpProxyTask*>::critical lc = m_tasklist;
	*pCount = (DWORD)m_tasklist.size();
	return TRUE;
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

CProxyUDPTaskMgr::CProxyUDPTaskMgr(CProxyReceptionCentre *pPRC)
	: CProxyXTaskMgr(pPRC)
{
	memset(m_PortState, 0, sizeof(m_PortState));
}

CProxyUDPTaskMgr::~CProxyUDPTaskMgr(void)
{
}

BOOL CProxyUDPTaskMgr::OnNewTask(LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo)
{
	if (!lpPRCClient || !lpProxyInfo)
		return FALSE;
	CTSList<CUdpProxyTask*>::critical lc = m_tasklist;
	for(list<CUdpProxyTask*>::iterator it = m_tasklist.begin(); it != m_tasklist.end(); )
	{
		CUdpProxyTask *existing = *it;
		if (existing->MatchesAssociation(lpPRCClient, lpProxyInfo) &&
			existing->IsClosed())
		{
			// A closed task may remain in the list until the maintenance timer.
			// It must never return its stale route port to a new registration.
			it = m_tasklist.erase(it);
			RemoveTask(existing);
			continue;
		}
		++it;
	}

	// First prefer the task which already owns this destination.  This keeps
	// repeated registrations on their original SOCKS5 UDP association even
	// when several associations exist for the same application socket.
	for(list<CUdpProxyTask*>::iterator it = m_tasklist.begin();
		it != m_tasklist.end(); ++it)
	{
		CUdpProxyTask *existing = *it;
		if (existing->MatchesAssociation(lpPRCClient, lpProxyInfo) &&
			existing->HasRoute(lpPRCClient))
		{
			if (!existing->AddRoute(lpPRCClient))
				return FALSE;
			RegisterRoutePort(lpPRCClient);
			return TRUE;
		}
	}

	BOOL requiresSeparateAssociation = FALSE;
	for(list<CUdpProxyTask*>::iterator it = m_tasklist.begin();
		it != m_tasklist.end(); ++it)
	{
		CUdpProxyTask *existing = *it;
		if (!existing->MatchesAssociation(lpPRCClient, lpProxyInfo))
			continue;
		if (!existing->CanAcceptRoute(lpPRCClient))
		{
			requiresSeparateAssociation = TRUE;
			continue;
		}
		if (!existing->AddRoute(lpPRCClient))
			return FALSE;
		RegisterRoutePort(lpPRCClient);
		return TRUE;
	}

	CUdpProxyTask *pTask = new CUdpProxyTask(this);
	if(pTask == NULL)
		return FALSE;

	if(!pTask->SetTaskInfo(lpPRCClient, lpProxyInfo))
	{
		delete pTask;
		return FALSE;
	}

	RegisterRoutePort(lpPRCClient);
	if (requiresSeparateAssociation)
	{
		PrintText(_T("UDP route split: PID %d, socket %Iu, destination port %d uses a separate SOCKS5 association.\r\n"),
			lpPRCClient->dwPid, (ULONG_PTR)lpPRCClient->s,
			lpPRCClient->dstAddr.GetPort());
	}

	OnAddTask(lpPRCClient, lpProxyInfo);
	if(m_tasklist.size() == 0)
	{
		SetTimer(TIMER_TCPPERTASK, TIMER_TCPPERTASK_INTERVAL);
		SetTimer(TIMER_IS_TASK_ALIVE, TIMER_IS_TASK_ALIVE_INTERVAL);
	}

	m_tasklist.push_back(pTask);
	return TRUE;
}

BOOL CProxyUDPTaskMgr::OnDeleteTask(CUdpProxyTask *pTask)
{
	CTSList<CUdpProxyTask*>::critical lc = m_tasklist;
	m_tasklist.remove(pTask);
	if(m_tasklist.size() == 0)
	{
		KillTimer(TIMER_TCPPERTASK);
		KillTimer(TIMER_IS_TASK_ALIVE);
	}
	RemoveTask(pTask);
	return TRUE;
}

INT  CProxyUDPTaskMgr::KillTasks(LPPRCClient lpPRCClient)
{
	if (!lpPRCClient)
		return 0;
	CTSList<CUdpProxyTask*>::critical lc = m_tasklist;
	int nCount = 0;
	for(list<CUdpProxyTask*>::iterator it = m_tasklist.begin(); it!=m_tasklist.end(); it++)
	{
		CUdpProxyTask *pObj = *it;

		if (pObj->m_PRCClient.dwPid == lpPRCClient->dwPid &&
			pObj->m_PRCClient.processCreateTime == lpPRCClient->processCreateTime &&
			pObj->m_PRCClient.socketGeneration == lpPRCClient->socketGeneration &&
			pObj->m_PRCClient.s == lpPRCClient->s)
		{
			ClearTaskPortStates(pObj);
			pObj->CloseTask();
			nCount ++;
		}
	}

	return nCount;
}

VOID CProxyUDPTaskMgr::RemoveAllTasks()
{
	CTSList<CUdpProxyTask*>::critical lc = m_tasklist;
	while (!m_tasklist.empty())
	{
		CUdpProxyTask *pObj = m_tasklist.front();
		m_tasklist.pop_front();
		RemoveTask(pObj);
	}
	KillTimer(TIMER_TCPPERTASK);
	KillTimer(TIMER_IS_TASK_ALIVE);
}

VOID CProxyUDPTaskMgr::RemoveTask(CUdpProxyTask* pTask)
{
	if (!pTask)
		return;
	ClearTaskPortStates(pTask);
	OnDelTask(&pTask->m_PRCClient);
	delete pTask;
}

VOID CProxyUDPTaskMgr::RegisterRoutePort(const LPPRCClient lpPRCClient)
{
	if (!lpPRCClient)
		return;
	WORD routePort = lpPRCClient->udpAddr.GetPort();
	m_PortState[routePort].clientip = lpPRCClient->srcAddr.GetdwIP();
	m_PortState[routePort].clientport = lpPRCClient->srcAddr.GetPort();
	m_PortState[routePort].proxyport = routePort;
}

VOID CProxyUDPTaskMgr::ClearTaskPortStates(CUdpProxyTask *pTask)
{
	if (!pTask)
		return;
	for (CUdpProxyTask::UdpRouteList::iterator it = pTask->m_routes.begin();
		it != pTask->m_routes.end(); ++it)
	{
		WORD routePort = it->client.udpAddr.GetPort();
		if (m_PortState[routePort].proxyport == routePort)
			ZeroMemory(&m_PortState[routePort], sizeof(m_PortState[routePort]));
	}
}

VOID CProxyUDPTaskMgr::OnTimer(UINT_PTR nIDEvent)
{
	switch(nIDEvent)
	{
	case TIMER_TCPPERTASK:
		{
			CTSList<CUdpProxyTask*>::critical lc = m_tasklist;
			for(list<CUdpProxyTask*>::iterator it = m_tasklist.begin();
				it != m_tasklist.end(); )
			{
				CUdpProxyTask *pObj = *it;
				pObj->OnMaintenanceTimer();
				if (pObj->IsClosed())
				{
					it = m_tasklist.erase(it);
					RemoveTask(pObj);
				}
				else
				{
					++it;
				}
			}
			if (m_tasklist.empty())
			{
				KillTimer(TIMER_TCPPERTASK);
				KillTimer(TIMER_IS_TASK_ALIVE);
			}
		}
		break;
	case TIMER_IS_TASK_ALIVE:
		{
			CTSList<CUdpProxyTask*>::critical lc = m_tasklist;
			for(list<CUdpProxyTask*>::iterator it = m_tasklist.begin(); it!=m_tasklist.end(); )
			{
				CUdpProxyTask *pObj = *it;

				if (!TestTaskByPid(pObj->m_PRCClient.dwPid,
					pObj->m_PRCClient.processCreateTime))
				{
					it = m_tasklist.erase(it);
					RemoveTask(pObj);
				}else if (pObj->IsClosed())
				{
					it = m_tasklist.erase(it);
					RemoveTask(pObj);
				}else
				{
					it++;
				}

			}
		}
		break;
	}
}

void CProxyUDPTaskMgr::EnumTask(IProxyTaskMgr *pCallBack)
{
	CTSList<CUdpProxyTask*>::critical lc = m_tasklist;
	for(list<CUdpProxyTask*>::iterator it = m_tasklist.begin(); it!=m_tasklist.end(); it++)
	{
		CUdpProxyTask *pObj = *it;
		pCallBack->OnEachTask(&pObj->m_PRCClient, &pObj->m_ProxyInfo);
	}
}

BOOL CProxyUDPTaskMgr::GetUDPPortState(UDPLocalProxyAddrInfo *pLPAI)
{
	if (!m_PortState[pLPAI->proxyport].proxyport)
		return FALSE;

	return (m_PortState[pLPAI->proxyport].clientip == pLPAI->clientip && m_PortState[pLPAI->proxyport].clientport == pLPAI->clientport);
}

BOOL CProxyUDPTaskMgr::GetTaskCount(DWORD *pCount)
{
	CTSList<CUdpProxyTask*>::critical lc = m_tasklist;
	*pCount = (DWORD)m_tasklist.size();
	return TRUE;
}
