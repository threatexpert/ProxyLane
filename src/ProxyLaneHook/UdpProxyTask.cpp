/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "UdpProxyTask.h"
#include "ProxyTaskMgr.h"
#include "PRCUdpPeer.h"
#include "ProxyLog.h"

CUdpProxyTask::CUdpProxyTask(CProxyUDPTaskMgr *pTaskmgr)
{
	m_pTaskmgr = pTaskmgr;

	m_pServer = NULL;
	m_pendingBytes = 0;
	m_serverReconnectPending = FALSE;
	m_nextServerReconnect = 0;
	m_serverReconnectDelay = 250;
	m_lastServerError = 0;
	m_taskClosing = FALSE;

	m_LocalProxyUdpPort = 0;
}

CUdpProxyTask::~CUdpProxyTask(void)
{
	EndTask();
}

BOOL CUdpProxyTask::IsClosed()
{
	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
	{
		if(it->peer && it->peer->GetSocketHandle() != INVALID_SOCKET)
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
		m_PRCClient = *lpPRCClient;
		m_ProxyInfo = *lpProxyInfo;
		if(!CreateServerPeer())
			break;
		if (!AddRoute(lpPRCClient))
			break;
		return TRUE;

	} while(FALSE);

	delete m_pServer;
	m_pServer = NULL;

	return FALSE;
}

BOOL CUdpProxyTask::CreateServerPeer()
{
	ATLASSERT(m_pServer == NULL);
	CPRCUdpPeer *server = new CPRCUdpPeer(this);
	if (!server)
		return FALSE;
	server->SetIdentity(SERVER);

	CPRCUdpPeer::_CSAddrInfo csai;
	csai.zero();
	csai.srcAddr = m_PRCClient.dstAddr;
	csai.dstAddr = m_PRCClient.srcAddr;
	server->SetAddrInfo(&csai);

	if (!server->ConnectProxy(&m_PRCClient, &m_ProxyInfo))
	{
		delete server;
		return FALSE;
	}

	m_pServer = server;
	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
	{
		if (it->peer && it->peer->GetSocketHandle() != INVALID_SOCKET)
		{
			it->peer->SetPartner(m_pServer);
			if (m_pServer->GetSocketHandle() != INVALID_SOCKET)
				m_pServer->SetPartner(it->peer);
		}
	}
	m_serverReconnectPending = FALSE;
	m_serverReconnectDelay = 250;
	m_lastServerError = 0;
	return TRUE;
}

BOOL CUdpProxyTask::AddRoute(LPPRCClient lpPRCClient)
{
	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
	{
		BOOL sameDestination = FALSE;
		if (lpPRCClient->IsDNValid())
			sameDestination = it->client.IsDNValid() &&
				_stricmp(it->client.szDomainName, lpPRCClient->szDomainName) == 0 &&
				it->client.dstAddr.GetPort() == lpPRCClient->dstAddr.GetPort();
		else
			sameDestination = !it->client.IsDNValid() &&
				it->client.dstAddr.GetdwIP() == lpPRCClient->dstAddr.GetdwIP() &&
				it->client.dstAddr.GetPort() == lpPRCClient->dstAddr.GetPort();
		if (sameDestination)
		{
			if (it->peer && it->peer->GetSocketHandle() != INVALID_SOCKET)
			{
				lpPRCClient->udpAddr = it->client.udpAddr;
				PrintText(_T("UDP route reused: PID %d, socket %Iu, route 127.0.0.1:%d.\r\n"),
					lpPRCClient->dwPid, (ULONG_PTR)lpPRCClient->s,
					lpPRCClient->udpAddr.GetPort());
				return TRUE;
			}

			// Never return a route address whose socket has already closed.
			if (it->peer)
				delete it->peer;
			m_routes.erase(it);
			break;
		}
	}

	CPRCUdpPeer *peer = new CPRCUdpPeer(this);
	if (!peer)
		return FALSE;
	peer->SetIdentity(1);
	peer->SetPartner(m_pServer);

	CPRCUdpPeer::_CSAddrInfo csai;
	csai.zero();
	csai.srcAddr = lpPRCClient->srcAddr;
	csai.dstAddr = lpPRCClient->dstAddr;
	strncpy(csai.szDomainName, lpPRCClient->szDomainName,
		sizeof(csai.szDomainName) - 1);
	peer->SetAddrInfo(&csai);

	_SockAddr routeAddress;
	int routeAddressLength = sizeof(routeAddress);
	if (!peer->CreateUDPSocket(&routeAddress, &routeAddressLength))
	{
		delete peer;
		return FALSE;
	}
	lpPRCClient->udpAddr = routeAddress;

	UdpRoute route;
	route.client = *lpPRCClient;
	route.peer = peer;
	m_routes.push_back(route);
	if (m_routes.size() == 1)
	{
		m_pServer->SetPartner(peer);
		m_LocalProxyUdpPort = routeAddress.GetPort();
	}
	PrintText(_T("UDP route created: PID %d, socket %Iu, route 127.0.0.1:%d.\r\n"),
		lpPRCClient->dwPid, (ULONG_PTR)lpPRCClient->s, routeAddress.GetPort());
	return TRUE;
}

BOOL CUdpProxyTask::MatchesAssociation(const LPPRCClient lpPRCClient,
	const LPProxyInfo lpProxyInfo)
{
	return lpPRCClient && lpProxyInfo &&
		m_PRCClient.dwPid == lpPRCClient->dwPid &&
		m_PRCClient.s == lpPRCClient->s &&
		m_ProxyInfo.GetProxyType() == lpProxyInfo->GetProxyType() &&
		m_ProxyInfo.nProxyPort == lpProxyInfo->nProxyPort &&
		_stricmp(m_ProxyInfo.strProxyHost.szbuf, lpProxyInfo->strProxyHost.szbuf) == 0;
}

VOID CUdpProxyTask::OnPeerClosed(CPRCUdpPeer *pPeer, int errorCode)
{
	if (pPeer == m_pServer)
	{
		if (m_taskClosing)
			return;
		// Keep every application-facing route bound.  Deletion/recreation of
		// the closed server peer is deferred to the task timer so this callback
		// never deletes the object currently executing OnClose().
		ScheduleServerReconnect(errorCode);
		return;
	}

	// A local route itself failed.  It cannot safely be handed out again;
	// close the task and let the manager remove it.
	CloseTask();
}

VOID CUdpProxyTask::ScheduleServerReconnect(int errorCode)
{
	if (m_taskClosing)
		return;
	if (!m_serverReconnectPending)
	{
		m_serverReconnectPending = TRUE;
		m_nextServerReconnect = GetTickCount() + m_serverReconnectDelay;
		m_lastServerError = errorCode;
		PrintText(_T("UDP SOCKS5 association closed (error: %d); local route %d remains open, reconnecting.\r\n"),
			errorCode, m_LocalProxyUdpPort);
	}
	if (m_pServer && m_pServer->GetSocketHandle() != INVALID_SOCKET)
	{
		m_pServer->AsyncSelect(0);
		m_pServer->Close();
	}
}

VOID CUdpProxyTask::OnServerWritable()
{
	if (m_taskClosing)
		return;
	const DWORD now = GetTickCount();
	if (m_serverReconnectPending)
	{
		if ((LONG)(now - m_nextServerReconnect) < 0)
			return;

		CPRCUdpPeer *oldServer = m_pServer;
		m_pServer = NULL;
		if (oldServer)
			delete oldServer;

		if (!CreateServerPeer())
		{
			m_serverReconnectPending = TRUE;
			m_serverReconnectDelay = min(m_serverReconnectDelay * 2, (DWORD)5000);
			m_nextServerReconnect = now + m_serverReconnectDelay;
			return;
		}

		PrintText(_T("UDP SOCKS5 association restarting; local route %d was preserved.\r\n"),
			m_LocalProxyUdpPort);
	}

	if (!m_pServer || m_pServer->GetSocketHandle() == INVALID_SOCKET)
		return;

	while (!m_pending.empty())
	{
		PendingDatagram &packet = m_pending.front();
		if (now - packet.queuedAt > 5000)
		{
			m_pendingBytes -= (DWORD)packet.data.size();
			m_pending.pop_front();
			continue;
		}

		int sent;
		const char *packetData = packet.data.empty() ? "" : &packet.data[0];
		if (packet.target.IsDNValid())
		{
			CString destination(packet.target.szDomainName);
			sent = m_pServer->SendTo(packetData, (int)packet.data.size(),
				packet.target.dstAddr.GetPort(), destination);
		}
		else
		{
			sent = m_pServer->SendTo(packetData, (int)packet.data.size(),
				&packet.target.dstAddr, sizeof(_SockAddr));
		}
		if (sent == SOCKET_ERROR)
		{
			int errorCode = WSAGetLastError();
			if (errorCode != WSAEWOULDBLOCK)
				ScheduleServerReconnect(errorCode);
			break;
		}
		m_pendingBytes -= (DWORD)packet.data.size();
		m_pending.pop_front();
	}

	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
	{
		if (it->peer && it->peer->GetValidDataLen() > 0)
			it->peer->TransferSend();
	}
}

BOOL CUdpProxyTask::ForwardClientDatagram(CPRCUdpPeer::_CSAddrInfo target,
	const char *data, int length)
{
	if (!data || length < 0)
		return FALSE;

	if (!m_serverReconnectPending && m_pServer &&
		m_pServer->GetSocketHandle() != INVALID_SOCKET && m_pending.empty())
	{
		int sent;
		if (target.IsDNValid())
		{
			CString destination(target.szDomainName);
			sent = m_pServer->SendTo(data, length, target.dstAddr.GetPort(), destination);
		}
		else
		{
			sent = m_pServer->SendTo(data, length, &target.dstAddr, sizeof(_SockAddr));
		}
		if (sent != SOCKET_ERROR)
			return TRUE;
		if (WSAGetLastError() != WSAEWOULDBLOCK)
			ScheduleServerReconnect(WSAGetLastError());
	}

	return QueueDatagram(target, data, length);
}

BOOL CUdpProxyTask::QueueDatagram(CPRCUdpPeer::_CSAddrInfo target,
	const char *data, int length)
{
	const DWORD maxPackets = 128;
	const DWORD maxBytes = 1024 * 1024;
	while (!m_pending.empty() &&
		(m_pending.size() >= maxPackets || m_pendingBytes + length > maxBytes))
	{
		m_pendingBytes -= (DWORD)m_pending.front().data.size();
		m_pending.pop_front();
	}
	if ((DWORD)length > maxBytes)
		return FALSE;

	PendingDatagram packet;
	packet.target = target;
	packet.data.assign(data, data + length);
	packet.queuedAt = GetTickCount();
	m_pendingBytes += length;
	m_pending.push_back(packet);
	return TRUE;
}

VOID CUdpProxyTask::EndTask()
{
	m_taskClosing = TRUE;
	m_serverReconnectPending = FALSE;
	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
	{
		if (it->peer)
		{
			it->peer->Close();
			delete it->peer;
			it->peer = NULL;
		}
	}
	m_routes.clear();
	m_pending.clear();
	m_pendingBytes = 0;
	if(m_pServer)
	{
		m_pServer->Close();
		delete m_pServer;
		m_pServer = NULL;
	}
}

VOID CUdpProxyTask::CloseTask()
{
	m_taskClosing = TRUE;
	m_serverReconnectPending = FALSE;
	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
		if (it->peer)
			it->peer->Close();
	if(m_pServer)
	{
		m_pServer->Close();
	}
}
