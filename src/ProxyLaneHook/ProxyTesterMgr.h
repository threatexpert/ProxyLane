#pragma once

#include "ProxyModule.h"
#include "TSSTL.h"
#include "asynsocket\AsyncSocketEx.h"
#include "asynsocket\AsyncProxySocketLayer.h"
#include "asynsocket\AsyncSecureSocketLayer.h"
#include "ProxyChainLayers.h"
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
	BOOL StartChain(IProxyTesterCallback *pCallback, const LPPRCClient lpPRCClient,
		const ProxyInfo *lpHops, INT nHops);
	int GetFailedHop();

	BOOL AddProxyLayer(LPProxyInfo lpProxyInfo);
	void RemoveAllLayers();

	void OnClose(int nErrorCode);
	void OnConnect(int nErrorCode);
	void OnReceive(int nErrorCode);
	void OnSend(int nErrorCode);

	int OnLayerCallback(const CAsyncSocketExLayer *pLayer, int nType, int nCode, WPARAM wParam, LPARAM lParam);
	void OnTimeout();

private:
	void Complete(int nCode, WPARAM wParam = 0, LPARAM lParam = 0);
	BOOL ConnectTcp(const LPPRCClient lpPRCClient);
	CAsyncProxySocketLayer *m_pProxyLayer;
	CAsyncSecureSocketLayer *m_pSecureLayer;
	// Allocated only for a chain test; it owns every layer of the chain, and
	// m_pProxyLayer then points at its last hop.
	CProxyChainLayers *m_pChain;
	int m_failedHop;

	PRCClient m_client;
	ProxyInfo m_proxyinfo;

	CProxyTesterMgr *m_pNotify;
	IProxyTesterCallback *m_pCallback;
	BOOL m_completed;
	WORD m_dnsTransactionId;
};

class CProxyTesterMgr
	: public CWndTimer
{
public:
	CProxyTesterMgr(void);
	~CProxyTesterMgr(void);


	IProxyTester* CreateTester();

	void OnDestroyTester(CProxyTester *pTester);
	void ArmTester(CProxyTester *pTester, UINT timeoutMilliseconds);
	void DisarmTester(CProxyTester *pTester);
	VOID OnTimer(UINT_PTR nIDEvent);
	void RemoveAll();

	VOID OnMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);

private:

	CTSList<CProxyTester*> m_testerlist;

};
