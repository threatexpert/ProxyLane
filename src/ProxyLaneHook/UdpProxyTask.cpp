/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "UdpProxyTask.h"
#include "ProxyTaskMgr.h"
#include "PRCUdpPeer.h"

CUdpProxyTask::CUdpProxyTask(CProxyUDPTaskMgr *pTaskmgr)
{
	m_pTaskmgr = pTaskmgr;

	m_pClient = NULL;
	m_pServer = NULL;

	m_LocalProxyUdpPort = 0;
}

CUdpProxyTask::~CUdpProxyTask(void)
{
	EndTask();
}

BOOL CUdpProxyTask::IsClosed()
{
	if(m_pClient)
	{
		if(m_pClient->GetSocketHandle() != INVALID_SOCKET)
			return FALSE;
	}

	if(m_pServer)
	{
		if(m_pServer->GetSocketHandle() != INVALID_SOCKET)
			return FALSE;
	}
	
	return TRUE;
}

BOOL CUdpProxyTask::SetTaskInfo(LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo)
{
	do 
	{
		m_pClient = new CPRCUdpPeer(this);
		if(m_pClient == NULL)
			break;

		m_pServer = new CPRCUdpPeer(this);
		if(m_pServer == NULL)
			break;

		m_PRCClient = *lpPRCClient;
		m_ProxyInfo = *lpProxyInfo;
		m_pClient->SetPartner(m_pServer);
		m_pServer->SetPartner(m_pClient);

		//CLIENT 1
		//SERVER 2
		m_pClient->SetIdentity(1);
		m_pServer->SetIdentity(2);

		DWORD nIP = lpPRCClient->srcAddr.GetdwIP();
		INT   nPort = lpPRCClient->srcAddr.GetPort();
		const BYTE* pucIP = (BYTE*)&nIP;

		ATLTRACE("lpPRCClient->srcAddr: %u.%u.%u.%u:%d\r\n", pucIP[0], pucIP[1], pucIP[2], pucIP[3], nPort);
		nIP = lpPRCClient->dstAddr.GetdwIP();
		nPort = lpPRCClient->dstAddr.GetPort();
		ATLTRACE("lpPRCClient->dstAddr: %u.%u.%u.%u:%d\r\n", pucIP[0], pucIP[1], pucIP[2], pucIP[3], nPort);

		CPRCUdpPeer::_CSAddrInfo csai;
		csai.zero();
		csai.srcAddr = lpPRCClient->srcAddr;
		csai.dstAddr = lpPRCClient->dstAddr;
		strncpy(csai.szDomainName, lpPRCClient->szDomainName, sizeof(csai.szDomainName));
		m_pClient->SetAddrInfo(&csai);

		csai.zero();
		csai.srcAddr = lpPRCClient->dstAddr;
		csai.dstAddr = lpPRCClient->srcAddr;
		m_pServer->SetAddrInfo(&csai);

		_SockAddr addrname;
		int namelen = sizeof(SOCKADDR);

		if(!m_pClient->CreateUDPSocket(&addrname, &namelen))
			break;

		if(!m_pServer->ConnectProxy(lpPRCClient, lpProxyInfo))
			break;

		//告知PRC m_pClient绑定的地址
		//if(addrname.GetdwIP() == 0)
		//	addrname.SetIP("127.0.0.1");

		lpPRCClient->udpAddr = addrname;

		m_LocalProxyUdpPort = addrname.GetPort();
		return TRUE;

	} while(FALSE);

	delete m_pClient;
	delete m_pServer;
	m_pClient = NULL;
	m_pServer = NULL;

	return FALSE;
}

VOID CUdpProxyTask::OnPeerClosed(CPRCUdpPeer *pPeer)
{
	if(m_pClient->GetSocketHandle() == INVALID_SOCKET && m_pServer->GetSocketHandle() == INVALID_SOCKET)
	{
		m_pTaskmgr->OnDeleteTask(this);
	}
}

VOID CUdpProxyTask::EndTask()
{
	if(m_pClient)
	{
		m_pClient->Close();
		delete m_pClient;
		m_pClient = NULL;
	}
	if(m_pServer)
	{
		m_pServer->Close();
		delete m_pServer;
		m_pServer = NULL;
	}
}

VOID CUdpProxyTask::CloseTask()
{
	if(m_pClient)
	{
		m_pClient->Close();
	}
	if(m_pServer)
	{
		m_pServer->Close();
	}
}
