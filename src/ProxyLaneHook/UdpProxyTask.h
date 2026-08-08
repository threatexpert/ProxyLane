#pragma once

#include "structinfo.h"
#include "PRCUdpPeer.h"
#include <list>
#include <vector>

class CProxyUDPTaskMgr;

class CUdpProxyTask
{
	friend CProxyUDPTaskMgr;
public:
	CUdpProxyTask(CProxyUDPTaskMgr *pTaskmgr);
	~CUdpProxyTask(void);


	VOID EndTask();
	VOID CloseTask();
	BOOL IsClosed();
	BOOL SetTaskInfo(LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo);
	BOOL AddRoute(LPPRCClient lpPRCClient);
	BOOL HasRoute(const LPPRCClient lpPRCClient);
	BOOL CanAcceptRoute(const LPPRCClient lpPRCClient);
	BOOL MatchesAssociation(const LPPRCClient lpPRCClient, const LPProxyInfo lpProxyInfo);

	VOID OnPeerClosed(CPRCUdpPeer *pPeer, int errorCode);
	VOID OnServerReady(CPRCUdpPeer *pPeer);
	VOID OnMaintenanceTimer();
	VOID OnServerWritable();
	VOID OnRouteWritable(CPRCUdpPeer *routePeer);
	BOOL ForwardClientDatagram(CPRCUdpPeer *routePeer,
		CPRCUdpPeer::_CSAddrInfo target, _SockAddr application,
		const char *data, int length);
	BOOL ForwardServerDatagram(_SockAddr source,
		const char *data, int length);
	BOOL CreateServerPeer();
	VOID ScheduleServerReconnect(int errorCode);
	BOOL QueueDatagram(CPRCUdpPeer::_CSAddrInfo target,
		const char *data, int length);
	BOOL QueueReply(CPRCUdpPeer *routePeer, _SockAddr application,
		const char *data, int length);
	VOID FlushPendingReplies(CPRCUdpPeer *routePeer = NULL);

public:
	PRCClient m_PRCClient;
	ProxyInfo m_ProxyInfo;
	WORD m_LocalProxyUdpPort;

private:
	VOID EnterServerDormant();
	VOID WakeServerAssociation();
	VOID ExpirePendingDatagrams(DWORD now);

	struct UdpRoute
	{
		PRCClient client;
		CPRCUdpPeer *peer;
		_SockAddr applicationEndpoint;
		BOOL hasApplicationEndpoint;
	};
	typedef std::list<UdpRoute> UdpRouteList;
	UdpRouteList m_routes;
	struct PendingDatagram
	{
		CPRCUdpPeer::_CSAddrInfo target;
		std::vector<char> data;
		DWORD queuedAt;
	};
	typedef std::list<PendingDatagram> PendingDatagramList;
	PendingDatagramList m_pending;
	DWORD m_pendingBytes;
	struct PendingReply
	{
		CPRCUdpPeer *routePeer;
		_SockAddr application;
		std::vector<char> data;
		DWORD queuedAt;
	};
	typedef std::list<PendingReply> PendingReplyList;
	PendingReplyList m_pendingReplies;
	DWORD m_pendingReplyBytes;
	CPRCUdpPeer *m_pServer;
	BOOL m_serverReconnectPending;
	BOOL m_serverReady;
	BOOL m_serverDormant;
	DWORD m_lastActivity;
	DWORD m_nextServerReconnect;
	DWORD m_serverReconnectDelay;
	int m_lastServerError;
	BOOL m_taskClosing;

public:
	CProxyUDPTaskMgr *m_pTaskmgr;
};
