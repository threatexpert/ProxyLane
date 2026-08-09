#pragma once

#include "PRCXServer.h"
#include "ProxyTaskMgr.h"

class CProxyReceptionCentre;

class CPRCUdpServer
	: public CPRCXServer
{
	friend CProxyReceptionCentre;

#define WM_PRC_REG_CLIENT WM_USER+0x32
#define WM_PRC_UNREG_CLIENT WM_USER+0x34
public:
	CPRCUdpServer(CProxyReceptionCentre *pPRC);
	~CPRCUdpServer(void);

	BOOL StartupServer();

	BOOL ShutdownServer();

	VOID OnTimer(UINT_PTR nIDEvent);
	BOOL OnRegister(LPPRCClient lpPRCClient);
	INT  OnUnregister(LPPRCClient lpPRCClient);
	BOOL GetUDPPortState(UDPLocalProxyAddrInfo *pLPAI);

	IProxyTaskMgr *GetPTMInstance();

protected:

	BOOL InitWnd();
	BOOL DestroyWnd();
	static LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

	INT OnLocalThreadRegister(LPPRCClient lpPRCClient);
	BOOL OnLocalThreadUnregister(LPPRCClient lpPRCClient);

private:

	HWND m_hWnd;
	CProxyUDPTaskMgr m_ProxyTaskMgr;

};
