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
	BOOL MatchesAssociation(const LPPRCClient lpPRCClient, const LPProxyInfo lpProxyInfo);

	VOID OnPeerClosed(CPRCUdpPeer *pPeer, int errorCode);
	VOID OnServerWritable();
	BOOL ForwardClientDatagram(CPRCUdpPeer::_CSAddrInfo target,
		const char *data, int length);
	BOOL CreateServerPeer();
	VOID ScheduleServerReconnect(int errorCode);
	BOOL QueueDatagram(CPRCUdpPeer::_CSAddrInfo target,
		const char *data, int length);

public:
	PRCClient m_PRCClient;
	ProxyInfo m_ProxyInfo;
	WORD m_LocalProxyUdpPort;

private:
	struct UdpRoute
	{
		PRCClient client;
		CPRCUdpPeer *peer;
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
	CPRCUdpPeer *m_pServer;
	BOOL m_serverReconnectPending;
	DWORD m_nextServerReconnect;
	DWORD m_serverReconnectDelay;
	int m_lastServerError;
	BOOL m_taskClosing;

public:
	CProxyUDPTaskMgr *m_pTaskmgr;
};
