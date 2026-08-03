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
	CPRCTcpServer(CProxyReceptionCentre *pPRC);
	~CPRCTcpServer(void);

	BOOL StartupServer();

	BOOL ShutdownServer();

	void OnAccept(int nErrorCode);

	IProxyTaskMgr *GetPTMInstance();

private:

	CProxyTCPTaskMgr m_ProxyTaskMgr;

};
