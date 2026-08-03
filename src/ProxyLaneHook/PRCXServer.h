#pragma once

class CGlobalProxy;
class CProxyReceptionCentre;

class CPRCXServer
{
public:
	CPRCXServer(CProxyReceptionCentre *pPRC);
	virtual ~CPRCXServer(void);

	virtual BOOL StartupServer() = 0;
	virtual BOOL ShutdownServer() = 0;

public:
	CProxyReceptionCentre *m_pPRC;
	CGlobalProxy *m_pGlobalProxy;
};
