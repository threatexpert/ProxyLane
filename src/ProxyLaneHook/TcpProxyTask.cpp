/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "TcpProxyTask.h"
#include "ProxyTaskMgr.h"
#include "PRCTcpPeer.h"
#include "MitmBridge.h"
#include "DohPolicy.h"
#include "ProxyLog.h"

CTcpProxyTask::CTcpProxyTask(CProxyTCPTaskMgr *pTaskmgr)
{
	m_pTaskmgr = pTaskmgr;
    m_dohWake = std::make_shared<CDohWakeup>(GetHwnd(), [this] { m_bDeletePending = TRUE; });

	m_pClient = NULL;
	m_pServer = NULL;
	m_bDeletePending = FALSE;
	m_pMitm = NULL;
	m_pProtocol = NULL;
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
BOOL CTcpProxyTask::SetTaskInfo(SOCKET sClient, LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo,
	IProxyLog::ConnectionStage& stage, const ProxyChain *lpChain)
{
	stage = IProxyLog::STAGE_ALLOCATE;
    if (DohPolicy::Intercept(*lpPRCClient, *lpProxyInfo)) {
        m_PRCClient = *lpPRCClient; m_ProxyInfo = *lpProxyInfo;
        m_dnsTcp.reset(new CDnsDohTcp(m_PRCClient, m_ProxyInfo, lpChain, m_pTaskmgr->m_pPRC));
        if (!m_dnsTcp->StartDeadline()) { WSASetLastError(WSAENOBUFS); return FALSE; }
        return m_dnsTcp->Attach(sClient, FD_READ | FD_WRITE | FD_CLOSE);
    }
	do 
	{
		m_pClient = new CPRCTcpPeer(this);
		if(m_pClient == NULL)
		{
			WSASetLastError(WSAENOBUFS);
			break;
		}

		m_pServer = new CPRCTcpPeer(this);
		if(m_pServer == NULL)
		{
			WSASetLastError(WSAENOBUFS);
			break;
		}

		m_PRCClient = *lpPRCClient;
		m_ProxyInfo = *lpProxyInfo;
		m_pClient->SetPartner(m_pServer);
		m_pServer->SetPartner(m_pClient);
        if (DohPolicy::Needed(m_PRCClient, m_ProxyInfo)) {
            if (!m_pClient->Attach(sClient, FD_CLOSE)) break;
            if (lpChain) m_dohChain = *lpChain;
            m_doh = CDohQuery::Resolve(m_PRCClient, m_ProxyInfo, lpChain, false, &m_dohLog, {}, m_pTaskmgr->m_pPRC);
            if (!m_doh->NotifyWhenReady(m_dohWake)) { WSASetLastError(WSAENOBUFS); break; }
            return TRUE;
        }
		if (CMitmBridge::Enabled())
		{
			m_pMitm = new CMitmBridge(this);
			if (!m_pMitm->Initialize())
			{
				WSASetLastError(WSAEPROTONOSUPPORT);
				break;
			}
		}

		else if (CProtocolTap::Enabled()) m_pProtocol = new CProtocolTap(this);

		int socketbufsize=1024*16;
		m_pServer->SetSockOpt(SO_SNDBUF, &socketbufsize,sizeof(socketbufsize));
		m_pServer->SetSockOpt(SO_RCVBUF, &socketbufsize,sizeof(socketbufsize));

		if(!m_pServer->ConnectProxy(lpPRCClient, lpProxyInfo, stage, lpChain))
			break;

		stage = IProxyLog::STAGE_ATTACH;
		//先不关注client的读写， 等代理建立成功后再重新设置
		if(!m_pClient->Attach(sClient, FD_CLOSE))
			break;

		m_pClient->SetSockOpt(SO_SNDBUF, &socketbufsize,sizeof(socketbufsize));
		m_pClient->SetSockOpt(SO_RCVBUF, &socketbufsize,sizeof(socketbufsize));

		return TRUE;
	} while(FALSE);

	const int error = WSAGetLastError();
    if (m_pProtocol) m_pProtocol->Connected(error ? error : WSAECONNABORTED);
    if (m_pMitm) m_pMitm->Connected(error ? error : WSAECONNABORTED);
	delete m_pProtocol;
	m_pProtocol = NULL;
	delete m_pMitm;
	m_pMitm = NULL;
	delete m_pClient;
	delete m_pServer;
	m_pClient = NULL;
	m_pServer = NULL;
	WSASetLastError(error);

	return FALSE;
}

VOID CTcpProxyTask::OnPeerClosed(CPRCTcpPeer *pPeer)
{

	if(m_pClient && m_pServer &&
		m_pClient->GetSocketHandle() == INVALID_SOCKET &&
		m_pServer->GetSocketHandle() == INVALID_SOCKET)
	{
		// This callback runs inside CPRCTcpPeer::OnClose. Defer destruction so
		// the peer is not deleted while its member function is still executing.
		m_bDeletePending = TRUE;
	}

}

VOID CTcpProxyTask::EndTask()
{
    m_dohWake->Cancel();
    m_doh.reset();
    m_dnsTcp.reset();
	if (m_pProtocol) m_pProtocol->CloseReason("TCP forwarding task released");
	delete m_pProtocol;
	m_pProtocol = NULL;
	delete m_pMitm;
	m_pMitm = NULL;
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

BOOL CTcpProxyTask::ConnectResolved() {
    m_PRCClient.proxyDstAddr = m_dohAddresses[m_dohAddress];
    m_PRCClient.proxyDstAddr.SetPort(m_PRCClient.dstAddr.GetPort());
    m_PRCClient.routingFlags |= PRC_CLIENT_FLAG_DOH_RESOLVED;
    // Capture metadata is created only after an effective address is known.
    if (CMitmBridge::Enabled()) {
        m_pMitm = new CMitmBridge(this);
        if (!m_pMitm->Initialize()) return FALSE;
    } else if (CProtocolTap::Enabled()) m_pProtocol = new CProtocolTap(this);
    IProxyLog::ConnectionStage stage = IProxyLog::STAGE_CONNECT;
    LogDohTargetSelection(m_pTaskmgr->m_pPRC, &m_PRCClient, m_dohAddress + 1, m_dohAddresses.size());
    return m_pServer->ConnectProxy(&m_PRCClient, &m_ProxyInfo, stage, m_dohChain.empty() ? NULL : &m_dohChain);
}
bool CTcpProxyTask::RetryDohAddress(CPRCTcpPeer* peer, int error) {
    if (!error || peer != m_pServer || m_dohAddress + 1 >= m_dohAddresses.size()) return false;
    m_dohRetry = true;
    return m_dohWake->Notify();
}
void CTcpProxyTask::OnMessage(UINT message, WPARAM low, LPARAM high, BOOL& handled) {
    if (!m_dohWake->Accept(message, low, high)) return;
    handled = TRUE;
    if (m_bDeletePending) { m_doh.reset(); return; }
    if (m_doh && !m_doh->Done()) return;
    if (m_doh) {
        m_doh->LogAddressResult(m_PRCClient, m_dohLog);
        if (!m_doh->Succeeded()) {
            EndTask(); m_bDeletePending = TRUE; return;
        }
        m_dohAddresses = m_doh->Addresses(); m_doh.reset();
    }
    if (m_dohRetry) {
        m_dohRetry = false; ++m_dohAddress;
        delete m_pProtocol; m_pProtocol = NULL;
        delete m_pMitm; m_pMitm = NULL;
        delete m_pServer; m_pServer = new CPRCTcpPeer(this);
        m_pClient->SetPartner(m_pServer); m_pServer->SetPartner(m_pClient);
    }
    if (!ConnectResolved()) {
        if (RetryDohAddress(m_pServer, WSAECONNREFUSED)) return;
        PrintText(_T("DoH resolved %hs, but the selected proxy route could not connect to the answer IP.\r\n"), m_PRCClient.szDomainName);
        EndTask(); m_bDeletePending = TRUE;
    }
}
