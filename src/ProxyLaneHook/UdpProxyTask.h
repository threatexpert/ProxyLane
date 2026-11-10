#pragma once

#include "structinfo.h"
#include "PRCUdpPeer.h"
#include "UdpAssociationPolicy.h"
#include <list>
#include <vector>
#include <memory>
#include "DohResolver.h"
class CProtocolTap;
class CQuicBridge;

class CProxyUDPTaskMgr;

class CUdpProxyTask : public CWndTimer
{
	friend CProxyUDPTaskMgr;
public:
	CUdpProxyTask(CProxyUDPTaskMgr *pTaskmgr);
	~CUdpProxyTask(void);


	VOID EndTask();
	VOID CloseTask(const char* reason = "UDP route closed; cause unavailable");
	BOOL IsClosed();
	BOOL SetTaskInfo(LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo);
	BOOL AddRoute(LPPRCClient lpPRCClient);
	BOOL HasRoute(const LPPRCClient lpPRCClient);
	BOOL CanAcceptRoute(const LPPRCClient lpPRCClient);
	BOOL MatchesAssociation(const LPPRCClient lpPRCClient, const LPProxyInfo lpProxyInfo);

	VOID OnPeerClosed(CPRCUdpPeer *pPeer, int errorCode);
	VOID OnServerReady(CPRCUdpPeer *pPeer);
	VOID OnMaintenanceTimer();
    void OnMessage(UINT, WPARAM, LPARAM, BOOL&) override;
	VOID OnServerWritable();
	VOID OnRouteWritable(CPRCUdpPeer *routePeer);
	BOOL ForwardClientDatagram(CPRCUdpPeer *routePeer,
		CPRCUdpPeer::_CSAddrInfo target, _SockAddr application,
		const char *data, int length);
	BOOL ForwardServerDatagram(_SockAddr source,
		const char *data, int length);
    BOOL ForwardUpstreamDatagram(CPRCUdpPeer::_CSAddrInfo target,const char *data,int length);
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
    std::shared_ptr<CDohWakeup> m_dohWake;
    bool m_dohNoticeFailed = false;
	VOID EnterServerDormant();
	VOID WakeServerAssociation();
	VOID ExpirePendingDatagrams(DWORD now);

	struct UdpRoute
	{
		PRCClient client;
		CPRCUdpPeer *peer;
		_SockAddr applicationEndpoint;
		BOOL hasApplicationEndpoint;
		BOOL firstDatagramLogged;
		std::shared_ptr<CProtocolTap> capture;
        std::shared_ptr<CQuicBridge> quic;
        bool quicRetired = false;
        CPRCUdpPeer::_CSAddrInfo quicTarget;
        std::shared_ptr<CDohQuery> doh;
        std::list<std::vector<char>> dohPending;
        size_t dohPendingBytes = 0;
        std::list<CDnsDohRequest> dnsRequests;
	};
	typedef std::list<UdpRoute> UdpRouteList;
    BOOL DeliverServerDatagram(UdpRoute&,const char*,int);
    void PumpQuic(UdpRoute&);
	UdpRouteList m_routes;
    ProxyChain m_dnsChain;
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
	UdpAssociationPolicy::UpstreamState m_upstreamState;
	DWORD m_lastActivity;
	DWORD m_nextServerReconnect;
	DWORD m_serverReconnectDelay;
	int m_lastServerError;

public:
	CProxyUDPTaskMgr *m_pTaskmgr;
};
