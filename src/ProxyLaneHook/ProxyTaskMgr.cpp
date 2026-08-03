/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "ProxyTaskMgr.h"
#include "PRCTcpPeer.h"
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

BOOL CProxyXTaskMgr::TestTaskByPid(DWORD dwPid)
{
	HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, dwPid);

	if (!hProcess)
	{
		if (GetLastError() == ERROR_ACCESS_DENIED)
			return TRUE;

		return FALSE;
	}
	CloseHandle(hProcess);

	return TRUE;
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
			for(list<CTcpProxyTask*>::iterator it = m_tasklist.begin(); it!=m_tasklist.end(); it++)
			{
				CTcpProxyTask *pObj = *it;
				if(pObj->m_pClient && pObj->m_pClient->GetSocketHandle() != INVALID_SOCKET)
					pObj->m_pClient->OnTimer();
				if(pObj->m_pServer && pObj->m_pServer->GetSocketHandle() != INVALID_SOCKET)
					pObj->m_pServer->OnTimer();
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
				if (!TestTaskByPid(pObj->m_PRCClient.dwPid))
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
	CUdpProxyTask *pTask = new CUdpProxyTask(this);
	if(pTask == NULL)
		return FALSE;

	if(!pTask->SetTaskInfo(lpPRCClient, lpProxyInfo))
	{
		delete pTask;
		return FALSE;
	}

	m_PortState[pTask->m_LocalProxyUdpPort].clientip = lpPRCClient->srcAddr.GetdwIP();
	m_PortState[pTask->m_LocalProxyUdpPort].clientport = lpPRCClient->srcAddr.GetPort();
	m_PortState[pTask->m_LocalProxyUdpPort].proxyport = lpPRCClient->udpAddr.GetPort();

	CTSList<CUdpProxyTask*>::critical lc = m_tasklist;
	OnAddTask(lpPRCClient, lpProxyInfo);
	if(m_tasklist.size() == 0)
	{
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
		KillTimer(TIMER_IS_TASK_ALIVE);
	}
	RemoveTask(pTask);
	return TRUE;
}

INT  CProxyUDPTaskMgr::KillTasks(LPPRCClient lpPRCClient)
{
	CTSList<CUdpProxyTask*>::critical lc = m_tasklist;
	int nCount = 0;
	for(list<CUdpProxyTask*>::iterator it = m_tasklist.begin(); it!=m_tasklist.end(); it++)
	{
		CUdpProxyTask *pObj = *it;

		if (pObj->m_PRCClient.dwPid == lpPRCClient->dwPid && pObj->m_PRCClient.s == lpPRCClient->s)
		{
			pObj->CloseTask();
			m_PortState[pObj->m_LocalProxyUdpPort].proxyport = 0;
			nCount ++;
		}
	}

	return nCount;
}

VOID CProxyUDPTaskMgr::RemoveAllTasks()
{
	CTSList<CUdpProxyTask*>::critical lc = m_tasklist;
	for(list<CUdpProxyTask*>::iterator it = m_tasklist.begin(); it!=m_tasklist.end(); it++)
	{
		CUdpProxyTask *pObj = *it;
		pObj->EndTask();
		//notify call back
		RemoveTask(pObj);

	}
	KillTimer(TIMER_IS_TASK_ALIVE);
	m_tasklist.clear();
}

VOID CProxyUDPTaskMgr::RemoveTask(CUdpProxyTask* pTask)
{
	m_PortState[pTask->m_LocalProxyUdpPort].proxyport = 0;
	OnDelTask(&pTask->m_PRCClient);
	delete pTask;
}

VOID CProxyUDPTaskMgr::OnTimer(UINT_PTR nIDEvent)
{
	switch(nIDEvent)
	{
	case TIMER_IS_TASK_ALIVE:
		{
			CTSList<CUdpProxyTask*>::critical lc = m_tasklist;
			for(list<CUdpProxyTask*>::iterator it = m_tasklist.begin(); it!=m_tasklist.end(); )
			{
				CUdpProxyTask *pObj = *it;

				if (!TestTaskByPid(pObj->m_PRCClient.dwPid))
				{
					pObj->EndTask();
					RemoveTask(pObj);

					m_tasklist.erase(it++);
				}else if (pObj->IsClosed())
				{
					RemoveTask(pObj);
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
	return FALSE;
}