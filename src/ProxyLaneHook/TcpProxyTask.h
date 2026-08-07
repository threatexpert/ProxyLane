#pragma once

#include "structinfo.h"

class CProxyTCPTaskMgr;
class CPRCTcpPeer;

class CTcpProxyTask
{
	friend CProxyTCPTaskMgr;
public:
	CTcpProxyTask(CProxyTCPTaskMgr *pTaskmgr);
	~CTcpProxyTask(void);


	VOID EndTask();
	BOOL SetTaskInfo(SOCKET sClient, LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo);

	VOID OnPeerClosed(CPRCTcpPeer *pPeer);
	BOOL IsDeletePending() const { return m_bDeletePending; }

public:
	PRCClient m_PRCClient;
	ProxyInfo m_ProxyInfo;

private:
	CPRCTcpPeer *m_pClient;
	CPRCTcpPeer *m_pServer;
	BOOL m_bDeletePending;

public:
	CProxyTCPTaskMgr *m_pTaskmgr;
};
