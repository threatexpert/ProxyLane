#pragma once

#include "structinfo.h"

class CProxyUDPTaskMgr;
class CPRCUdpPeer;

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

	VOID OnPeerClosed(CPRCUdpPeer *pPeer);

public:
	PRCClient m_PRCClient;
	ProxyInfo m_ProxyInfo;
	WORD m_LocalProxyUdpPort;

private:
	CPRCUdpPeer *m_pClient;
	CPRCUdpPeer *m_pServer;

public:
	CProxyUDPTaskMgr *m_pTaskmgr;
};
