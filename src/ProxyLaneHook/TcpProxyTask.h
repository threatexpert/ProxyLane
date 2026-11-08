#pragma once

#include "ProxyModule.h"

class CProxyTCPTaskMgr;
class CPRCTcpPeer;
class CMitmBridge;
class CProtocolTap;

class CTcpProxyTask
{
	friend CProxyTCPTaskMgr;
	friend CMitmBridge;
public:
	CTcpProxyTask(CProxyTCPTaskMgr *pTaskmgr);
	~CTcpProxyTask(void);


	VOID EndTask();
	BOOL SetTaskInfo(SOCKET sClient, LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo,
	IProxyLog::ConnectionStage& stage, const ProxyChain *lpChain = NULL);

	VOID OnPeerClosed(CPRCTcpPeer *pPeer);
	BOOL IsDeletePending() const { return m_bDeletePending; }

public:
	PRCClient m_PRCClient;
	ProxyInfo m_ProxyInfo;
	CMitmBridge* m_pMitm;
	CProtocolTap* m_pProtocol;

private:
	CPRCTcpPeer *m_pClient;
	CPRCTcpPeer *m_pServer;
	BOOL m_bDeletePending;
    bool m_reconnectSelected = false, m_reconnectPending = false;

public:
	CProxyTCPTaskMgr *m_pTaskmgr;
};
