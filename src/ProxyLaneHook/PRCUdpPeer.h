#pragma once

#include "asynsocket\AsyncSocketEx.h"
#include "asynsocket\AsyncProxySocketLayer.h"
#include "structinfo.h"

class CUdpProxyTask;
class CProxyDataHandle;

class CUDPRAWProxyLayer
	: public CAsyncProxySocketLayer
{

protected:

	virtual int SendTo(const void* lpBuf, int nBufLen,
		const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags = 0);
	virtual int SendTo(const void* lpBuf, int nBufLen,
		UINT nHostPort, LPCTSTR lpszHostAddress = NULL, int nFlags = 0);
	virtual int ReceiveFrom(void* lpBuf, int nBufLen,
		SOCKADDR* lpSockAddr, int* lpSockAddrLen, int nFlags = 0);

};

class CUDPClientSocketLayer
	: public CAsyncSocketExLayer
{
public:
	virtual void OnClose(int nErrorCode);
	virtual void OnReceive(int nErrorCode);
	virtual void OnSend(int nErrorCode);
};

class CPRCUdpPeer
	: public CAsyncSocketEx
{

#define MAXUDPBUFSIZE 1024*16

#define CLIENT 1
#define SERVER 2

public:
	struct _CSAddrInfo 
	{
		_SockAddr srcAddr;
		char szDomainName[50];
		_SockAddr dstAddr;
		BOOL IsDNValid(){ return szDomainName[0] != '\0';}
		void zero(){ ZeroMemory(this, sizeof(*this));}
	};

public:
	CPRCUdpPeer(CUdpProxyTask *pNotify);
	~CPRCUdpPeer(void);

	BOOL CreateUDPSocket(OUT SOCKADDR* lpSockAddr, OUT int* lpSockAddrLen, UINT nSocketPort = 0, 
		long lEvent = FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT |	FD_CONNECT | FD_CLOSE,
		LPCSTR lpszSocketAddress = NULL, BOOL bReuseAddr = FALSE);
	void OnReceive(int nErrorCode);
	void OnSend(int nErrorCode);
	void OnClose(int nErrorCode);

	virtual void Close();

	int  TransferSend();
	int  GetValidDataLen();

	int  TestSocketStatus(long lEvent);

	BOOL ConnectProxy(LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo);
	BOOL AddProxyLayer(LPProxyInfo lpProxyInfo);
	void RemoveAllLayers();
	void SetPartner(CPRCUdpPeer *pPartner);
	void SetAddrInfo(_CSAddrInfo *pInfo);

	void ClearBuffer();
	void SetIdentity(INT iId);

	int OnLayerCallback(const CAsyncSocketExLayer *pLayer, int nType, int nCode, WPARAM wParam, LPARAM lParam);

private:

	char m_recvbuf[MAXUDPBUFSIZE+1];
	int m_recvbufpos;

	int m_Identity;

	_CSAddrInfo m_CSAddrInfo; 

	ProxyPacketInfo m_ppi;

	CPRCUdpPeer *m_pPartner;
	CAsyncProxySocketLayer *m_pProxyLayer;
	CUDPClientSocketLayer *m_pClientLayer;
	CUdpProxyTask *m_pNotify;
	CProxyDataHandle *m_pProxyDataHandle;
};
