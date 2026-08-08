/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "UdpProxyTask.h"
#include "ProxyTaskMgr.h"
#include "PRCUdpPeer.h"
#include "ProxyLog.h"
#include "UdpAssociationPolicy.h"

static const DWORD UDP_ASSOCIATION_IDLE_TIMEOUT = 5 * 60 * 1000;

static UdpAssociationPolicy::Destination GetUdpDestination(PRCClient &client)
{
	UdpAssociationPolicy::Destination destination;
	destination.hasDomain = client.szDomainName[0] != '\0';
	destination.domain = client.szDomainName;
	destination.family = client.dstAddr.sa_family;
	destination.ipv4 = client.dstAddr.GetdwIP();
	ZeroMemory(destination.ipv6, sizeof(destination.ipv6));
	if (client.dstAddr.IsIPv6() && client.dstAddr.GetAddr6())
		CopyMemory(destination.ipv6, client.dstAddr.GetAddr6(), sizeof(destination.ipv6));
	destination.port = client.dstAddr.GetPort();
	return destination;
}

CUdpProxyTask::CUdpProxyTask(CProxyUDPTaskMgr *pTaskmgr)
{
	m_pTaskmgr = pTaskmgr;

	m_pServer = NULL;
	m_pendingBytes = 0;
	m_pendingReplyBytes = 0;
	m_serverReconnectPending = FALSE;
	m_serverReady = FALSE;
	m_serverDormant = FALSE;
	m_lastActivity = GetTickCount();
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
	m_serverReady = m_ProxyInfo.GetProxyType() == PROXYTYPE_NOPROXY;
	m_serverDormant = FALSE;
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
	if (m_serverReady)
	{
		m_serverReconnectDelay = 250;
		m_lastServerError = 0;
	}
	return TRUE;
}

BOOL CUdpProxyTask::AddRoute(LPPRCClient lpPRCClient)
{
	if (!lpPRCClient)
		return FALSE;
	UdpAssociationPolicy::Destination requested = GetUdpDestination(*lpPRCClient);
	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
	{
		if (UdpAssociationPolicy::IsSameDestination(
			GetUdpDestination(it->client), requested))
		{
			if (it->peer && it->peer->GetSocketHandle() != INVALID_SOCKET)
			{
				_SockAddr routeAddress = it->client.udpAddr;
				it->client = *lpPRCClient;
				it->client.udpAddr = routeAddress;
				lpPRCClient->udpAddr = routeAddress;
				PrintText(_T("UDP route reused: PID %d, socket %Iu, route %s:%d.\r\n"),
					lpPRCClient->dwPid, (ULONG_PTR)lpPRCClient->s,
					lpPRCClient->udpAddr.IsIPv6() ? _T("[::1]") : _T("127.0.0.1"),
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
	if (!peer->CreateUDPSocket(&routeAddress, &routeAddressLength, 0,
		FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE,
		lpPRCClient->dstAddr.IsIPv6() ? "::1" : "127.0.0.1", FALSE,
		lpPRCClient->dstAddr.IsIPv6() ? AF_INET6 : AF_INET))
	{
		delete peer;
		return FALSE;
	}
	lpPRCClient->udpAddr = routeAddress;

	UdpRoute route;
	route.client = *lpPRCClient;
	route.peer = peer;
	ZeroMemory(&route.applicationEndpoint, sizeof(route.applicationEndpoint));
	route.hasApplicationEndpoint = FALSE;
	m_routes.push_back(route);
	if (m_routes.size() == 1)
	{
		if (m_pServer)
			m_pServer->SetPartner(peer);
		m_LocalProxyUdpPort = routeAddress.GetPort();
	}
	PrintText(_T("UDP route created: PID %d, socket %Iu, route %s:%d.\r\n"),
		lpPRCClient->dwPid, (ULONG_PTR)lpPRCClient->s,
		routeAddress.IsIPv6() ? _T("[::1]") : _T("127.0.0.1"),
		routeAddress.GetPort());
	return TRUE;
}

BOOL CUdpProxyTask::HasRoute(const LPPRCClient lpPRCClient)
{
	if (!lpPRCClient)
		return FALSE;
	UdpAssociationPolicy::Destination requested = GetUdpDestination(*lpPRCClient);
	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
	{
		if (UdpAssociationPolicy::IsSameDestination(
			GetUdpDestination(it->client), requested))
			return TRUE;
	}
	return FALSE;
}

BOOL CUdpProxyTask::CanAcceptRoute(const LPPRCClient lpPRCClient)
{
	if (!lpPRCClient)
		return FALSE;
	UdpAssociationPolicy::Destination requested = GetUdpDestination(*lpPRCClient);
	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
	{
		if (!UdpAssociationPolicy::CanShareAssociation(
			GetUdpDestination(it->client), requested))
			return FALSE;
	}
	return TRUE;
}

BOOL CUdpProxyTask::MatchesAssociation(const LPPRCClient lpPRCClient,
	const LPProxyInfo lpProxyInfo)
{
	return lpPRCClient && lpProxyInfo &&
		m_PRCClient.dwPid == lpPRCClient->dwPid &&
		m_PRCClient.processCreateTime == lpPRCClient->processCreateTime &&
		m_PRCClient.socketGeneration == lpPRCClient->socketGeneration &&
		m_PRCClient.s == lpPRCClient->s &&
		m_ProxyInfo.GetProxyType() == lpProxyInfo->GetProxyType() &&
		m_ProxyInfo.nProxyPort == lpProxyInfo->nProxyPort &&
		_stricmp(m_ProxyInfo.strProxyHost.szbuf, lpProxyInfo->strProxyHost.szbuf) == 0;
}

VOID CUdpProxyTask::OnPeerClosed(CPRCUdpPeer *pPeer, int errorCode)
{
	if (pPeer == m_pServer)
	{
		m_serverReady = FALSE;
		if (m_taskClosing || m_serverDormant)
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

VOID CUdpProxyTask::OnServerReady(CPRCUdpPeer *pPeer)
{
	if (m_taskClosing || m_serverDormant || pPeer != m_pServer)
		return;
	m_serverReady = TRUE;
	m_serverReconnectPending = FALSE;
	m_serverReconnectDelay = 250;
	m_lastServerError = 0;
	PrintText(_T("UDP SOCKS5 association ready; local route %d.\r\n"),
		m_LocalProxyUdpPort);
	OnServerWritable();
}

VOID CUdpProxyTask::ScheduleServerReconnect(int errorCode)
{
	if (m_taskClosing)
		return;
	m_serverDormant = FALSE;
	if (!m_serverReconnectPending)
	{
		m_serverReady = FALSE;
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
	ExpirePendingDatagrams(now);
	FlushPendingReplies();

	if (m_serverReconnectPending)
	{
		if ((LONG)(now - m_nextServerReconnect) < 0)
			return;

		CPRCUdpPeer *oldServer = m_pServer;
		m_pServer = NULL;
		for (UdpRouteList::iterator it = m_routes.begin();
			it != m_routes.end(); ++it)
		{
			if (it->peer)
				it->peer->SetPartner(NULL);
		}
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

	if (!m_serverReady || !m_pServer ||
		m_pServer->GetSocketHandle() == INVALID_SOCKET)
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
				&packet.target.dstAddr, packet.target.dstAddr.Size());
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
	FlushPendingReplies();
}

VOID CUdpProxyTask::OnMaintenanceTimer()
{
	if (m_taskClosing)
		return;
	const DWORD now = GetTickCount();
	ExpirePendingDatagrams(now);
	FlushPendingReplies();

	if (m_serverDormant)
		return;

	BOOL hasPendingWork = !m_pending.empty() || !m_pendingReplies.empty();
	if (UdpAssociationPolicy::ShouldEnterDormant(now, m_lastActivity,
		UDP_ASSOCIATION_IDLE_TIMEOUT, hasPendingWork))
	{
		// This method is called only by the manager timer. Never destroy the
		// server peer from its own FD_WRITE/FD_CONNECT callback stack.
		EnterServerDormant();
		return;
	}

	OnServerWritable();
}

VOID CUdpProxyTask::ExpirePendingDatagrams(DWORD now)
{
	while (!m_pending.empty() &&
		(DWORD)(now - m_pending.front().queuedAt) > 5000)
	{
		m_pendingBytes -= (DWORD)m_pending.front().data.size();
		m_pending.pop_front();
	}
}

VOID CUdpProxyTask::EnterServerDormant()
{
	if (m_taskClosing || m_serverDormant || !m_pending.empty() ||
		!m_pendingReplies.empty())
		return;

	m_serverDormant = TRUE;
	m_serverReady = FALSE;
	m_serverReconnectPending = FALSE;
	m_serverReconnectDelay = 250;
	m_lastServerError = 0;

	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
	{
		if (it->peer)
			it->peer->SetPartner(NULL);
	}

	CPRCUdpPeer *oldServer = m_pServer;
	if (oldServer)
	{
		oldServer->AsyncSelect(0);
		oldServer->Close();
	}
	m_pServer = NULL;
	delete oldServer;

	PrintText(_T("UDP association dormant after %d seconds; local route %d remains open.\r\n"),
		UDP_ASSOCIATION_IDLE_TIMEOUT / 1000, m_LocalProxyUdpPort);
}

VOID CUdpProxyTask::WakeServerAssociation()
{
	if (m_taskClosing || !m_serverDormant)
		return;

	m_serverDormant = FALSE;
	m_serverReconnectPending = FALSE;
	m_serverReconnectDelay = 250;
	PrintText(_T("UDP association waking; local route %d was preserved.\r\n"),
		m_LocalProxyUdpPort);

	if (!CreateServerPeer())
	{
		int errorCode = WSAGetLastError();
		if (!errorCode)
			errorCode = WSAECONNREFUSED;
		ScheduleServerReconnect(errorCode);
		return;
	}

	if (m_serverReady)
		OnServerWritable();
}

VOID CUdpProxyTask::OnRouteWritable(CPRCUdpPeer *routePeer)
{
	FlushPendingReplies(routePeer);
}

BOOL CUdpProxyTask::ForwardClientDatagram(CPRCUdpPeer *routePeer,
	CPRCUdpPeer::_CSAddrInfo target, _SockAddr application,
	const char *data, int length)
{
	if (!data || length < 0)
		return FALSE;
	m_lastActivity = GetTickCount();

	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
	{
		if (it->peer == routePeer)
		{
			it->applicationEndpoint = application;
			it->hasApplicationEndpoint = TRUE;
			break;
		}
	}

	if (m_serverDormant)
	{
		BOOL queued = QueueDatagram(target, data, length);
		if (queued)
			WakeServerAssociation();
		return queued;
	}

	if (m_serverReady && !m_serverReconnectPending && m_pServer &&
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
			sent = m_pServer->SendTo(data, length, &target.dstAddr,
				target.dstAddr.Size());
		}
		if (sent != SOCKET_ERROR)
			return TRUE;
		if (WSAGetLastError() != WSAEWOULDBLOCK)
			ScheduleServerReconnect(WSAGetLastError());
	}

	return QueueDatagram(target, data, length);
}

BOOL CUdpProxyTask::ForwardServerDatagram(_SockAddr source,
	const char *data, int length)
{
	if (!data || length < 0)
		return FALSE;
	UdpRoute *selected = NULL;
	UdpRoute *domainCandidate = NULL;
	DWORD domainCandidateCount = 0;
	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
	{
		if (!it->peer || it->peer->GetSocketHandle() == INVALID_SOCKET ||
			it->client.dstAddr.GetPort() != source.GetPort())
			continue;
		if (!it->client.IsDNValid() &&
			it->client.dstAddr.SameAddress(source))
		{
			selected = &*it;
			break;
		}
		// Domain replies normally carry their resolved IPv4 address. The
		// destination port remains a stable discriminator.
		if (it->client.IsDNValid())
		{
			domainCandidate = &*it;
			++domainCandidateCount;
		}
	}
	if (!selected && domainCandidateCount == 1)
		selected = domainCandidate;
	if (!selected && domainCandidateCount == 0 && m_routes.size() == 1 &&
		m_routes.front().peer &&
		m_routes.front().peer->GetSocketHandle() != INVALID_SOCKET)
		selected = &m_routes.front();
	if (!selected)
		return FALSE;
	m_lastActivity = GetTickCount();

	_SockAddr application = selected->hasApplicationEndpoint ?
		selected->applicationEndpoint : selected->client.srcAddr;
	if (application.IsAny())
		application.SetIP(application.IsIPv6() ? "::1" : "127.0.0.1");
	int sent = selected->peer->SendTo(data, length, &application,
		application.Size());
	if (sent == length)
		return TRUE;
	return QueueReply(selected->peer, application, data, length);
}

BOOL CUdpProxyTask::QueueReply(CPRCUdpPeer *routePeer,
	_SockAddr application, const char *data, int length)
{
	if (!routePeer || !data || length < 0)
		return FALSE;
	const DWORD maxPackets = 128;
	const DWORD maxBytes = 1024 * 1024;
	while (!m_pendingReplies.empty() &&
		(m_pendingReplies.size() >= maxPackets ||
		m_pendingReplyBytes + length > maxBytes))
	{
		m_pendingReplyBytes -= (DWORD)m_pendingReplies.front().data.size();
		m_pendingReplies.pop_front();
	}
	if ((DWORD)length > maxBytes)
		return FALSE;
	PendingReply reply;
	reply.routePeer = routePeer;
	reply.application = application;
	reply.data.assign(data, data + length);
	reply.queuedAt = GetTickCount();
	m_pendingReplyBytes += (DWORD)reply.data.size();
	m_pendingReplies.push_back(reply);
	return TRUE;
}

VOID CUdpProxyTask::FlushPendingReplies(CPRCUdpPeer *routePeer)
{
	DWORD now = GetTickCount();
	for (PendingReplyList::iterator it = m_pendingReplies.begin();
		it != m_pendingReplies.end(); )
	{
		if (now - it->queuedAt > 5000 || !it->routePeer ||
			it->routePeer->GetSocketHandle() == INVALID_SOCKET)
		{
			m_pendingReplyBytes -= (DWORD)it->data.size();
			it = m_pendingReplies.erase(it);
			continue;
		}
		if (routePeer && it->routePeer != routePeer)
		{
			++it;
			continue;
		}
		const char *packetData = it->data.empty() ? "" : &it->data[0];
		int sent = it->routePeer->SendTo(packetData, (int)it->data.size(),
			&it->application, it->application.Size());
		if (sent != (int)it->data.size())
		{
			++it;
			continue;
		}
		m_pendingReplyBytes -= (DWORD)it->data.size();
		it = m_pendingReplies.erase(it);
	}
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
	m_serverReady = FALSE;
	m_serverDormant = FALSE;
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
	m_pendingReplies.clear();
	m_pendingReplyBytes = 0;
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
	m_serverReady = FALSE;
	m_serverDormant = FALSE;
	m_pendingReplies.clear();
	m_pendingReplyBytes = 0;
	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
		if (it->peer)
			it->peer->Close();
	if(m_pServer)
	{
		m_pServer->Close();
	}
}
