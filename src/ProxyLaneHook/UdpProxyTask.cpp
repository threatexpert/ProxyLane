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
	m_upstreamState = UdpAssociationPolicy::UPSTREAM_ROUTE_RESERVED;
	m_lastActivity = GetTickCount();
	m_nextServerReconnect = 0;
	m_serverReconnectDelay = 250;
	m_lastServerError = 0;

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
		if (!AddRoute(lpPRCClient))
			break;
		// A connected UDP socket may never send a datagram (Go uses such
		// sockets for RFC 6724 source-address selection).  The application-
		// facing loopback route must exist before connect returns, but the
		// remote SOCKS5 association is activated only by the first datagram.
		m_upstreamState = UdpAssociationPolicy::UPSTREAM_ROUTE_RESERVED;
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
	csai.srcAddr = m_PRCClient.GetProxyDestination();
	csai.dstAddr = m_PRCClient.srcAddr;
	server->SetAddrInfo(&csai);

	if (!server->ConnectProxy(&m_PRCClient, &m_ProxyInfo))
	{
		delete server;
		return FALSE;
	}

	m_pServer = server;
	m_upstreamState = m_ProxyInfo.GetProxyType() == PROXYTYPE_NOPROXY
		? UdpAssociationPolicy::UPSTREAM_READY
		: UdpAssociationPolicy::UPSTREAM_ASSOCIATING;
	for (UdpRouteList::iterator it = m_routes.begin(); it != m_routes.end(); ++it)
	{
		if (it->peer && it->peer->GetSocketHandle() != INVALID_SOCKET)
		{
			it->peer->SetPartner(m_pServer);
			if (m_pServer->GetSocketHandle() != INVALID_SOCKET)
				m_pServer->SetPartner(it->peer);
		}
	}
	if (m_upstreamState == UdpAssociationPolicy::UPSTREAM_READY)
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
				ATLTRACE(_T("UDP route reused: PID %d, socket %Iu, route %s:%d.\r\n"),
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
	csai.dstAddr = lpPRCClient->GetProxyDestination();
	if (!lpPRCClient->HasProxyDestination())
	{
		strncpy(csai.szDomainName, lpPRCClient->szDomainName,
			sizeof(csai.szDomainName) - 1);
	}
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
	route.firstDatagramLogged = FALSE;
	m_routes.push_back(route);
	if (m_routes.size() == 1)
	{
		if (m_pServer)
			m_pServer->SetPartner(peer);
		m_LocalProxyUdpPort = routeAddress.GetPort();
	}
	ATLTRACE(_T("UDP route reserved: PID %d, socket %Iu, route %s:%d.\r\n"),
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
		// Redirected DNS routes deliberately keep independent associations.
		// Several original private resolvers all become the same public :53
		// endpoint, so a shared association could not identify the local route
		// for a reply.
		if (it->client.HasProxyDestination() ||
			lpPRCClient->HasProxyDestination())
			return FALSE;
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
		m_ProxyInfo.reserved == lpProxyInfo->reserved &&
		strcmp(m_ProxyInfo.strTransportPsk.szbuf,
			lpProxyInfo->strTransportPsk.szbuf) == 0 &&
		_stricmp(m_ProxyInfo.strProxyHost.szbuf, lpProxyInfo->strProxyHost.szbuf) == 0;
}

VOID CUdpProxyTask::OnPeerClosed(CPRCUdpPeer *pPeer, int errorCode)
{
	if (pPeer == m_pServer)
	{
		if (m_upstreamState == UdpAssociationPolicy::UPSTREAM_CLOSING ||
			m_upstreamState == UdpAssociationPolicy::UPSTREAM_DORMANT ||
			m_upstreamState == UdpAssociationPolicy::UPSTREAM_ROUTE_RESERVED)
			return;
		// Keep every application-facing route bound.  Deletion/recreation of
		// the closed server peer is deferred to the task timer so this callback
		// never deletes the object currently executing OnClose().
		if (m_pTaskmgr->ReportUdpAssociationFailure(&m_ProxyInfo,
			errorCode))
		{
			if (m_pTaskmgr->IsUdpPermanentlyUnsupported())
				CloseTask();
			else
			{
				ScheduleServerReconnect(errorCode);
				m_nextServerReconnect = GetTickCount() + 60 * 1000;
			}
		}
		else
			ScheduleServerReconnect(errorCode);
		return;
	}

	// A local route itself failed.  It cannot safely be handed out again;
	// close the task and let the manager remove it.
	CloseTask();
}

VOID CUdpProxyTask::OnServerReady(CPRCUdpPeer *pPeer)
{
	if (m_upstreamState != UdpAssociationPolicy::UPSTREAM_ASSOCIATING ||
		pPeer != m_pServer)
		return;
	m_upstreamState = UdpAssociationPolicy::UPSTREAM_READY;
	m_pTaskmgr->ReportUdpAssociationReady(&m_ProxyInfo);
	m_serverReconnectDelay = 250;
	m_lastServerError = 0;
	PrintText(_T("UDP SOCKS5 association ready; local route %d.\r\n"),
		m_LocalProxyUdpPort);
	OnServerWritable();
}

VOID CUdpProxyTask::ScheduleServerReconnect(int errorCode)
{
	if (m_upstreamState == UdpAssociationPolicy::UPSTREAM_CLOSING)
		return;
	if (m_upstreamState != UdpAssociationPolicy::UPSTREAM_RECONNECT_WAIT)
	{
		m_upstreamState = UdpAssociationPolicy::UPSTREAM_RECONNECT_WAIT;
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
	if (m_upstreamState == UdpAssociationPolicy::UPSTREAM_CLOSING)
		return;
	const DWORD now = GetTickCount();
	ExpirePendingDatagrams(now);
	FlushPendingReplies();

	if (m_upstreamState == UdpAssociationPolicy::UPSTREAM_RECONNECT_WAIT)
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
			int errorCode = WSAGetLastError();
			if (!errorCode)
				errorCode = WSAECONNREFUSED;
			if (m_pTaskmgr->ReportUdpAssociationFailure(
				&m_ProxyInfo, errorCode))
			{
				if (m_pTaskmgr->IsUdpPermanentlyUnsupported())
					CloseTask();
				else
				{
					m_upstreamState = UdpAssociationPolicy::UPSTREAM_RECONNECT_WAIT;
					m_nextServerReconnect = now + 60 * 1000;
				}
				return;
			}
			m_upstreamState = UdpAssociationPolicy::UPSTREAM_RECONNECT_WAIT;
			m_serverReconnectDelay = min(m_serverReconnectDelay * 2, (DWORD)5000);
			m_nextServerReconnect = now + m_serverReconnectDelay;
			return;
		}

		PrintText(_T("UDP SOCKS5 association restarting; local route %d was preserved.\r\n"),
			m_LocalProxyUdpPort);
	}

	if (m_upstreamState != UdpAssociationPolicy::UPSTREAM_READY || !m_pServer ||
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
	if (m_upstreamState == UdpAssociationPolicy::UPSTREAM_CLOSING)
		return;
	const DWORD now = GetTickCount();
	ExpirePendingDatagrams(now);
	FlushPendingReplies();

	if (m_upstreamState == UdpAssociationPolicy::UPSTREAM_DORMANT ||
		m_upstreamState == UdpAssociationPolicy::UPSTREAM_ROUTE_RESERVED)
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
	if (m_upstreamState == UdpAssociationPolicy::UPSTREAM_CLOSING ||
		m_upstreamState == UdpAssociationPolicy::UPSTREAM_DORMANT ||
		m_upstreamState == UdpAssociationPolicy::UPSTREAM_ROUTE_RESERVED ||
		!m_pending.empty() ||
		!m_pendingReplies.empty())
		return;

	m_upstreamState = UdpAssociationPolicy::UPSTREAM_DORMANT;
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
	if (m_upstreamState == UdpAssociationPolicy::UPSTREAM_CLOSING ||
		!UdpAssociationPolicy::ShouldActivateUpstream(m_upstreamState))
		return;

	const BOOL firstActivation =
		m_upstreamState == UdpAssociationPolicy::UPSTREAM_ROUTE_RESERVED;
	m_upstreamState = UdpAssociationPolicy::UPSTREAM_ASSOCIATING;
	m_serverReconnectDelay = 250;
	ATLTRACE(firstActivation
		? _T("UDP upstream starting after first datagram; local route %d was ready.\r\n")
		: _T("UDP association waking; local route %d was preserved.\r\n"),
		m_LocalProxyUdpPort);

	if (!CreateServerPeer())
	{
		int errorCode = WSAGetLastError();
		if (!errorCode)
			errorCode = WSAECONNREFUSED;
		if (m_pTaskmgr->ReportUdpAssociationFailure(&m_ProxyInfo,
			errorCode))
		{
			if (m_pTaskmgr->IsUdpPermanentlyUnsupported())
				CloseTask();
			else
			{
				ScheduleServerReconnect(errorCode);
				m_nextServerReconnect = GetTickCount() + 60 * 1000;
			}
		}
		else
			ScheduleServerReconnect(errorCode);
		return;
	}

	if (m_upstreamState == UdpAssociationPolicy::UPSTREAM_READY)
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
			if (!it->firstDatagramLogged)
			{
				it->firstDatagramLogged = TRUE;
				LogUdpFirstDatagram(m_pTaskmgr->m_pPRC, &it->client,
					&m_ProxyInfo);
			}
			break;
		}
	}

	if (UdpAssociationPolicy::ShouldActivateUpstream(m_upstreamState))
	{
		BOOL queued = QueueDatagram(target, data, length);
		if (queued)
			WakeServerAssociation();
		return queued;
	}

	if (m_upstreamState == UdpAssociationPolicy::UPSTREAM_READY && m_pServer &&
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
		const _SockAddr& effectiveDestination =
			it->client.GetProxyDestination();
		if (!it->peer || it->peer->GetSocketHandle() == INVALID_SOCKET ||
			effectiveDestination.GetPort() != source.GetPort())
			continue;
		if (!it->client.IsDNValid() &&
			effectiveDestination.SameAddress(source))
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
	m_upstreamState = UdpAssociationPolicy::UPSTREAM_CLOSING;
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
	m_upstreamState = UdpAssociationPolicy::UPSTREAM_CLOSING;
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
