#pragma once

#include "ProxyModule.h"
#include "DohResolver.h"

class CProxyTCPTaskMgr;
class CPRCTcpPeer;
class CMitmBridge;
class CProtocolTap;

class CTcpProxyTask : public CWndTimer
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
	BOOL IsDeletePending() const { return m_bDeletePending || (m_dnsTcp && m_dnsTcp->GetSocketHandle() == INVALID_SOCKET); }
    void OnMessage(UINT, WPARAM, LPARAM, BOOL&) override;
    bool RetryDohAddress(CPRCTcpPeer*, int error);

public:
	PRCClient m_PRCClient;
	ProxyInfo m_ProxyInfo;
	CMitmBridge* m_pMitm;
	CProtocolTap* m_pProtocol;

private:
	CPRCTcpPeer *m_pClient;
	CPRCTcpPeer *m_pServer;
	BOOL m_bDeletePending;
    std::shared_ptr<CDohWakeup> m_dohWake;
    std::shared_ptr<CDohQuery> m_doh;
    std::unique_ptr<CDnsDohTcp> m_dnsTcp;
    ProxyChain m_dohChain;
    std::vector<_SockAddr> m_dohAddresses;
    size_t m_dohAddress = 0;
    bool m_dohRetry = false;
    BOOL ConnectResolved();
    bool m_reconnectSelected = false, m_reconnectPending = false;

public:
	CProxyTCPTaskMgr *m_pTaskmgr;
};
