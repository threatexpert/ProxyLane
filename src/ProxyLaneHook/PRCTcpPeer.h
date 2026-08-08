#pragma once


#include "asynsocket\AsyncSocketEx.h"
#include "asynsocket\AsyncProxySocketLayer.h"
#include "structinfo.h"
#include "TimeoutMonitor.h"

class CTcpProxyTask;
class CProxyDataHandle;

class CPRCTcpPeer
	: public CAsyncSocketEx
{

#define MAXTCPBUFSIZE 1024*4

public:
	CPRCTcpPeer(CTcpProxyTask *pNotify);
	~CPRCTcpPeer(void);

	BOOL ConnectProxy(LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo);

	void OnReceive(int nErrorCode);
	void OnSend(int nErrorCode);
	void OnConnect(int nErrorCode);
	void OnClose(int nErrorCode);

	void OnTimer();

	int  TransferSend();
	int  GetValidDataLen();

	int  TestSocketStatus(long lEvent);

	BOOL AddProxyLayer(LPProxyInfo lpProxyInfo);
	void RemoveAllLayers();

	void SetPartner(CPRCTcpPeer *pPartner);
	//void SendSocketEvent(long lEvent, int nErrorCode);
	//void PostSocketEvent(long lEvent, int nErrorCode);

	void ClearBuffer();
	void PropagateHalfClose();
	void TryFinishConnection();

	int OnLayerCallback(const CAsyncSocketExLayer *pLayer, int nType, int nCode, WPARAM wParam, LPARAM lParam);

	DWORD GetLastError();

private:

	BOOL m_bConnShutted;
	BOOL m_bReadClosed;
	BOOL m_bWriteShutdown;
	BOOL m_bForwardingReady;
	BOOL m_bFullyClosing;
	em_TMTimeOut m_SocketStatus;
	CTimeoutMonitor m_TimeoutMonitor[TM_COUNT];

	char m_recvbuf[MAXTCPBUFSIZE+1];
	UINT64 m_DataLenRecvd;
	UINT64 m_DataLenSent;

	int m_recvbufpos;
	int m_sentpos;

	DWORD m_dwLastError;

	ProxyPacketInfo m_ppi;

	CPRCTcpPeer *m_pPartner;

	CAsyncProxySocketLayer *m_pProxyLayer;
	CTcpProxyTask *m_pNotify;
	CProxyDataHandle *m_pProxyDataHandle;

};

