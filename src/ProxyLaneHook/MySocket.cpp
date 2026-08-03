#include "stdafx.h"
#include "MySocket.h"
#include <stdlib.h>
#include <time.h>

CMySocket::CMySocket(void)
{
	srand( (unsigned)time( NULL ) );
	m_pProxyLayer = NULL;
}

CMySocket::~CMySocket(void)
{
	delete m_pProxyLayer;
}


//BOOL CMySocket::Connect(SOCKADDR* pSockAddr, int iSockAddrLen)
//{
//	InitProxySupport();
//	return CAsyncSocketEx::Connect(pSockAddr, iSockAddrLen);
//}
// end deadlake

VOID CMySocket::OnTimer(UINT_PTR nIDEvent)
{
	switch(nIDEvent)
	{
	case 100:
		{
			if(GetTickCount() - m_lastrecv > 5000)
			{
				//return;
				TriggerEvent(FD_WRITE);
			}
		}
		break;
	}
}

void CMySocket::InitProxySupport(BOOL bEnableProxy, BOOL bBypassHook)
{
	if(bEnableProxy)
	{
		m_pProxyLayer=new CAsyncProxySocketLayer;

		m_pProxyLayer->SetProxy(PROXYTYPE_SOCKS5, "127.0.0.1", 307, "abc", "abc");

		m_pProxyLayer->BypassHook(bBypassHook);

		AddLayer(m_pProxyLayer);

	}


	//Create(0, SOCK_STREAM, FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE);
	Create(0, SOCK_DGRAM, FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE);
	AsyncSelect(FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE);
	//SetTimer(100, 1000);

}
//
//BOOL CMySocket::OnHostNameResolved(const SOCKADDR_IN * pSockAddr)
//{
//	//if(!Connect((SOCKADDR*)pSockAddr, sizeof(SOCKADDR_IN) ))
//	//{
//	//	if(WSAGetLastError() != WSAEWOULDBLOCK)
//	//		return FALSE;
//	//}
//	return TRUE;
//}

void CMySocket::OnClose(int nErrorCode)
{
	Close();
	delete this;
}


void CMySocket::OnConnect(int nErrorCode)
{
	printf("OnConnect = %d\r\n", nErrorCode);

	if(nErrorCode == 0)
		return;

	OnClose(0);
}

//
//void CMySocket::OnReceive(int nErrorCode)
//{
//	//return;
//	int ret;
//
//	m_lastrecv = GetTickCount();
//	//while(1)
//	{
//		ret = Receive(m_recvbuf, MYMAXSIZE);
//
//		if(ret <= 0)
//		{
//			if(WSAGetLastError() == WSAEWOULDBLOCK)
//				return;
//			OnClose(0);
//			return;
//		}
//
//		m_recvbuf[ret] = '\0';
//
//		//printf("%s\r\n", m_recvbuf);
//		printf("r");
//	}
//
//
//}
//
//
//void CMySocket::OnSend(int nErrorCode)
//{
//	//return;
//	int ret;
//
//	char cPack = 'A';
//	char buf[MYMAXSIZE];
//	memset(buf, 0, sizeof(buf));
//
//	buf[sizeof(buf)-3] = '\r';
//	buf[sizeof(buf)-2] = '\n';
//	buf[sizeof(buf)-1] = '\0';
//
//	//srand( (unsigned)time( NULL ) );
//
//	int status = 1;
//	int nSent = 0;
//
//	//ATLTRACE("CMySocket::OnSend() = ");
//
//	while(1)
//	{
//		char ch = 'A'+(rand()%24);
//		memset(buf, ch, sizeof(buf)-3);
//
//		ret = Send(buf, sizeof(buf), 0);
//
//		if(ret == SOCKET_ERROR)
//		{
//			if(WSAGetLastError() == WSAEWOULDBLOCK)
//			{
//				status = 1;
//				break;
//			}else
//			{
//				status = 0;
//				OnClose(0);
//				break;
//			}
//		}
//
//		nSent += ret;
//	}
//
//	ATLTRACE("CMySocket::OnSend() = %d, status = %d\r\n", nSent, status);
//}

int CMySocket::OnLayerCallback(const CAsyncSocketExLayer *pLayer, int nType, int nCode, WPARAM wParam, LPARAM lParam)
{

	return 1;
}


void CMySocket::OnReceive(int nErrorCode)
{
	//return;
	int ret;

	UINT maxudpdg = 0;
	ret = sizeof(maxudpdg);

	ret = GetSockOpt(SO_MAX_MSG_SIZE, &maxudpdg, &ret);
	_SockAddr sa;
	int addrlen = sizeof(sa);

	ret = ReceiveFrom(m_recvbuf, MYMAXSIZE, &sa, &addrlen);

	if(ret >= 0)
	{
		m_recvbuf[ret] = '\0';

		DWORD nIP = sa.GetdwIP();
		const BYTE* pucIP = (BYTE*)&nIP;

		printf("%u.%u.%u.%u:%d\r\n", pucIP[0], pucIP[1], pucIP[2], pucIP[3], sa.GetPort());
		printf("%s\r\n", m_recvbuf);
	}
}


void CMySocket::OnSend(int nErrorCode)
{
	//return;
	int ret;

	_SockAddr sa;
	int addrlen = sizeof(sa);

	char buf[1024];
	memset(buf, 0, sizeof(buf));
	buf[sizeof(buf)-3] = '\r';
	buf[sizeof(buf)-2] = '\n';
	buf[sizeof(buf)-1] = '\0';

	char ch = 'A'+(rand()%24);
	memset(buf, ch, sizeof(buf)-3);

	sa.SetIP("127.0.0.1");
	sa.SetPort(513);

	ret = SendTo(buf, sizeof(buf), &sa, addrlen);
	//ret = SendTo(buf, sizeof(buf), 513, "localhost");

}