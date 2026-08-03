#pragma once

#include "ProxyModule.h"
#include "TSSTL.h"
#include "asynsocket\AsyncSocketEx.h"
#include "asynsocket\AsyncProxySocketLayer.h"
#include "TimerQueue.h"

class CProxyTesterMgr;

class CProxyTester
	: public IProxyTester
	, public CAsyncSocketEx
{

#define WM_DELTESTER WM_USER+1

public:
	CProxyTester(CProxyTesterMgr *pNotify);
	~CProxyTester(void);

	void Release();

	BOOL Start(IProxyTesterCallback *pCallback, const LPPRCClient lpPRCClient, const LPProxyInfo lpPI);
	void Stop();

	BOOL AddProxyLayer(LPProxyInfo lpProxyInfo);
	void RemoveAllLayers();

	void OnClose(int nErrorCode);
	void OnConnect(int nErrorCode);
	void OnReceive(int nErrorCode);
	void OnSend(int nErrorCode);

	int OnLayerCallback(const CAsyncSocketExLayer *pLayer, int nType, int nCode, WPARAM wParam, LPARAM lParam);

private:
	CAsyncProxySocketLayer *m_pProxyLayer;

	PRCClient m_client;
	ProxyInfo m_proxyinfo;

	CProxyTesterMgr *m_pNotify;
	IProxyTesterCallback *m_pCallback;
};

class CProxyTesterMgr
	: public CWndTimer
{
public:
	CProxyTesterMgr(void);
	~CProxyTesterMgr(void);


	IProxyTester* CreateTester();

	void OnDestroyTester(CProxyTester *pTester);
	void RemoveAll();

	VOID OnMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);

private:

	CTSList<CProxyTester*> m_testerlist;

};
