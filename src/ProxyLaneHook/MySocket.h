#pragma once

#include "asynsocket\AsyncSocketEx.h"
#include "asynsocket\AsyncProxySocketLayer.h"
#include "TimerQueue.h"

#define MYMAXSIZE 1024*3

class CMySocket
	: public CAsyncSocketEx
	, public CWndTimer
{
public:
	CMySocket(void);
	~CMySocket(void);

	void OnClose(int nErrorCode);
	void OnConnect(int nErrorCode);
	void OnReceive(int nErrorCode);
	void OnSend(int nErrorCode);

	//BOOL Connect(SOCKADDR* pSockAddr, int iSockAddrLen);

	void InitProxySupport(BOOL bEnableProxy, BOOL bBypassHook);

	int OnLayerCallback(const CAsyncSocketExLayer *pLayer, int nType, int nCode, WPARAM wParam, LPARAM lParam);
	//BOOL OnHostNameResolved(const SOCKADDR_IN * /*pSockAddr*/);

	VOID OnTimer(UINT_PTR nIDEvent);

	CAsyncProxySocketLayer *m_pProxyLayer;

	DWORD m_lastrecv, m_lastsend;


	char m_recvbuf[MYMAXSIZE+1];

};
