#pragma once

#include "PRCXServer.h"
#include "asynsocket\AsyncSocketEx.h"
#include "PRCTcpPeer.h"
#include "ProxyTaskMgr.h"

class CProxyReceptionCentre;
class CGlobalProxy;

class CPRCTcpServer
	: public CPRCXServer
	, public CAsyncSocketEx
{
public:
	CPRCTcpServer(CProxyReceptionCentre *pPRC, int addressFamily = AF_INET,
		CProxyTCPTaskMgr *sharedTaskMgr = NULL);
	~CPRCTcpServer(void);

	BOOL StartupServer();

	BOOL ShutdownServer();

	void OnAccept(int nErrorCode);

	IProxyTaskMgr *GetPTMInstance();
	CProxyTCPTaskMgr *GetTCPTaskMgr();

private:
	int m_addressFamily;

	CProxyTCPTaskMgr *m_pProxyTaskMgr;
	BOOL m_ownsProxyTaskMgr;

};
