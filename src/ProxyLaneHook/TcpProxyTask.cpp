/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "TcpProxyTask.h"
#include "ProxyTaskMgr.h"
#include "PRCTcpPeer.h"

CTcpProxyTask::CTcpProxyTask(CProxyTCPTaskMgr *pTaskmgr)
{
	m_pTaskmgr = pTaskmgr;

	m_pClient = NULL;
	m_pServer = NULL;
}

CTcpProxyTask::~CTcpProxyTask(void)
{
	EndTask();
}

/*
参数1：sClient 来自 PRC Server accept到的客户端，也就是给Hook拦截后转向到PRC的请求，
参数2：lpPRCClient 为原请求的地址信息，
参数3：lpProxyInfo 为GlobalProxy设置的代理信息

CTcpProxyTask 只是负责创建并管理两个CPRCTcpPeer对象分别为m_pClient，m_pServer，这组对象代表一个代理任务

在m_pServer通过代理(lpProxyInfo)与原请求的地址(lpPRCClient)建立连接后， 将和m_pClient 进行纯粹的数据转发。

================
基本流程：

一个正常的连接请求connect -> HookWinsock.connect, 这里HookWinsock记录下原请求的信息并将其socket登记到ProxyReceptionCentre (PRC), 然后修改目的地址到PRC

PRC Server OnAccept 接收到一个sClient，通过地址信息到PRC查询原请求地址, 并将GlobalProxy当前设置的代理服务器信息传递给CTcpProxyTask.SetTaskInfo
*/
BOOL CTcpProxyTask::SetTaskInfo(SOCKET sClient, LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo)
{
	do 
	{
		m_pClient = new CPRCTcpPeer(this);
		if(m_pClient == NULL)
			break;

		m_pServer = new CPRCTcpPeer(this);
		if(m_pServer == NULL)
			break;

		m_PRCClient = *lpPRCClient;
		m_ProxyInfo = *lpProxyInfo;
		m_pClient->SetPartner(m_pServer);
		m_pServer->SetPartner(m_pClient);

		int socketbufsize=1024*16;
		m_pServer->SetSockOpt(SO_SNDBUF, &socketbufsize,sizeof(socketbufsize));
		m_pServer->SetSockOpt(SO_RCVBUF, &socketbufsize,sizeof(socketbufsize));

		if(!m_pServer->ConnectProxy(lpPRCClient, lpProxyInfo))
			break;

		//先不关注client的读写， 等代理建立成功后再重新设置
		if(!m_pClient->Attach(sClient, FD_CLOSE))
			break;

		m_pClient->SetSockOpt(SO_SNDBUF, &socketbufsize,sizeof(socketbufsize));
		m_pClient->SetSockOpt(SO_RCVBUF, &socketbufsize,sizeof(socketbufsize));

		return TRUE;
	} while(FALSE);

	delete m_pClient;
	delete m_pServer;
	m_pClient = NULL;
	m_pServer = NULL;

	return FALSE;
}

VOID CTcpProxyTask::OnPeerClosed(CPRCTcpPeer *pPeer)
{

	if(m_pClient->GetSocketHandle() == INVALID_SOCKET && m_pServer->GetSocketHandle() == INVALID_SOCKET)
	{
		m_pTaskmgr->OnDeleteTask(this);
	}

}

VOID CTcpProxyTask::EndTask()
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
