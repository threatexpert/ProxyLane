/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/


#include "stdafx.h"
#include "PRCUdpPeer.h"
#include "ProxyTaskMgr.h"
#include "ProxyLog.h"
#include "ProxyReceptionCentre.h"
#include "ProxyDataHandle.h"

//////////////////////////////////////////////////////////////////////////

int CUDPRAWProxyLayer::SendTo(const void* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags /* = 0 */)
{
	if (GetProxyOpID())
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	//if(nFlags == 0x1308)
	//{
	//	return CAsyncProxySocketLayer::SendTo(lpBuf, nBufLen, lpSockAddr, nSockAddrLen);
	//}else
	//{
		return SendToNext(lpBuf, nBufLen, (SOCKADDR*)&m_udpsrvAddr, sizeof(SOCKADDR));
	//}
}

int CUDPRAWProxyLayer::SendTo(const void* lpBuf, int nBufLen, UINT nHostPort, LPCTSTR lpszHostAddress /* = NULL */, int nFlags /* = 0 */)
{
	if (GetProxyOpID())
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	//CStringA szIP;
	//szIP = lpszHostAddress;
	//const char* pszAsciiProxyPeerHost;
	//int iLenAsciiProxyPeerHost;
	//pszAsciiProxyPeerHost = szIP.GetBuffer();
	//iLenAsciiProxyPeerHost = strlen(pszAsciiProxyPeerHost);

	//if (inet_addr(pszAsciiProxyPeerHost) != INADDR_NONE)
	//{
	//	_SockAddr dstAddr;
	//	dstAddr.sa_family = AF_INET;
	//	dstAddr.SetIP(pszAsciiProxyPeerHost);
	//	dstAddr.SetPort(nHostPort);
	//	return SendTo(lpBuf, nBufLen, &dstAddr, sizeof(dstAddr));
	//}

	//if(nFlags == 0x1308)
	//{
	//	return CAsyncProxySocketLayer::SendTo(lpBuf, nBufLen, nHostPort, lpszHostAddress);
	//}else
	//{
		return SendToNext(lpBuf, nBufLen, (SOCKADDR*)&m_udpsrvAddr, sizeof(SOCKADDR));
	//}
}

int CUDPRAWProxyLayer::ReceiveFrom(void* lpBuf, int nBufLen, SOCKADDR* lpSockAddr, int* lpSockAddrLen, int nFlags /* = 0 */)
{
	if (GetProxyOpID())
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	return ReceiveFromNext(lpBuf, nBufLen, lpSockAddr, lpSockAddrLen, nFlags);
}


//////////////////////////////////////////////////////////////////////////

void CUDPClientSocketLayer::OnClose(int nErrorCode)
{
	TriggerEvent(FD_READ, nErrorCode, TRUE);
}

void CUDPClientSocketLayer::OnReceive(int nErrorCode)
{
	TriggerEvent(FD_READ, nErrorCode, TRUE);
}

void CUDPClientSocketLayer::OnSend(int nErrorCode)
{
	TriggerEvent(FD_WRITE, nErrorCode, TRUE);
}


//////////////////////////////////////////////////////////////////////////

CPRCUdpPeer::CPRCUdpPeer(CUdpProxyTask *pNotify)
{
	m_pProxyLayer = NULL;
	m_pClientLayer = NULL;
	m_pNotify = pNotify;
	m_pProxyDataHandle = (CProxyDataHandle*)pNotify->m_pTaskmgr->m_pPRC->GetPDHInstance();
	m_ppi.lpC = &pNotify->m_PRCClient;
	m_ppi.lpPI = &pNotify->m_ProxyInfo;

	m_Identity = 0;
	ClearBuffer();
}

CPRCUdpPeer::~CPRCUdpPeer(void)
{
}

void CPRCUdpPeer::SetPartner(CPRCUdpPeer *pPartner)
{
	m_pPartner = pPartner;
}

void CPRCUdpPeer::SetIdentity(INT iId)
{
	m_Identity = iId;
}

void CPRCUdpPeer::SetAddrInfo(_CSAddrInfo *pInfo)
{
	m_CSAddrInfo = *pInfo;
	if(m_CSAddrInfo.dstAddr.GetdwIP() == 0)
		m_CSAddrInfo.dstAddr.SetIP("127.0.0.1");
	if(m_CSAddrInfo.srcAddr.GetdwIP() == 0)
		m_CSAddrInfo.srcAddr.SetIP("127.0.0.1");
}

BOOL CPRCUdpPeer::CreateUDPSocket(OUT SOCKADDR* lpSockAddr, OUT int* lpSockAddrLen, 
								  UINT nSocketPort /* = 0 */, long lEvent /* = FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE */, 
								  LPCSTR lpszSocketAddress /* = NULL */, BOOL bReuseAddr /* = FALSE */)
{
	ATLASSERT(m_Identity == CLIENT);

	if (!AddProxyLayer(NULL))
		return FALSE;

	if (m_pClientLayer)
		m_pClientLayer->BypassHook(TRUE);

	if (!CAsyncSocketEx::Create(nSocketPort, SOCK_DGRAM, lEvent, lpszSocketAddress, bReuseAddr))
		return FALSE;

	if (!CAsyncSocketEx::GetSockName(lpSockAddr, lpSockAddrLen))
		return FALSE;

	if (!AsyncSelect(FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE))
		return FALSE;

	return TRUE;
}

BOOL CPRCUdpPeer::ConnectProxy(LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo)
{
	//设置代理
	if (!AddProxyLayer(lpProxyInfo))
		return FALSE;

	if (m_pProxyLayer)
		m_pProxyLayer->BypassHook(TRUE);

	if (!Create(0, SOCK_DGRAM, FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE))
		return FALSE;
	if (!AsyncSelect(FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE))
		return FALSE;

	if (m_pProxyLayer)
	{
		if (lpPRCClient->uaFlag)
		{
			_SockAddr sa;
			m_pProxyLayer->GetUdpLocalAddr((LPSOCKADDR_IN)&sa);
			
			if ( lpPRCClient->uaFlag & UAF_SET_ADDR )
			{
				sa.SetIPLong(lpPRCClient->udpAddr.GetdwIP());
			}
			if ( lpPRCClient->uaFlag & UAF_SET_PORT )
			{
				sa.SetPort(lpPRCClient->udpAddr.GetPort());
			}
			m_pProxyLayer->SetUdpLocalAddr((LPSOCKADDR_IN)&sa);
		}

	}


	return TRUE;
}

BOOL CPRCUdpPeer::AddProxyLayer(LPProxyInfo lpProxyInfo)
{
	int nProxyType;

	if (m_Identity == CLIENT)
	{
		CUDPClientSocketLayer *pLayer = new CUDPClientSocketLayer;
		if(pLayer == NULL)
			return FALSE;

		m_pClientLayer = pLayer;
		return AddLayer(m_pClientLayer);

	}else if (m_Identity == SERVER)
	{
		if(!lpProxyInfo)
			nProxyType = PROXYTYPE_NOPROXY;
		else 
			nProxyType = lpProxyInfo->GetProxyType();

		if(nProxyType == PROXYTYPE_NOPROXY)
			return TRUE;

		if(nProxyType != PROXYTYPE_SOCKS5)
			return FALSE;

		CUDPRAWProxyLayer *pLayer = new CUDPRAWProxyLayer;
		if(pLayer == NULL)
			return FALSE;

		pLayer->SetProxy(nProxyType, (CStringA)lpProxyInfo->strProxyHost, lpProxyInfo->nProxyPort, (CStringA)lpProxyInfo->strProxyUser, (CStringA)lpProxyInfo->strProxyPass);

		m_pProxyLayer = pLayer;
		return AddLayer(m_pProxyLayer);
	}else
	{
		ATLASSERT(0);
		return FALSE;
	}

}


void CPRCUdpPeer::RemoveAllLayers()
{
	CAsyncSocketEx::RemoveAllLayers();
	delete m_pProxyLayer;
	delete m_pClientLayer;
	m_pProxyLayer = NULL;
	m_pClientLayer = NULL;
}

int CPRCUdpPeer::TestSocketStatus(long lEvent)
{
	DWORD timepassed = 0;
	fd_set FdRead, FdWrite;
	struct timeval TimeOut;

	TimeOut.tv_sec  = 0;
	TimeOut.tv_usec = 0;

	SOCKET s = GetSocketHandle();

	FD_ZERO(&FdRead);
	FD_SET(s,&FdRead);

	FD_ZERO(&FdWrite);
	FD_SET(s,&FdWrite);

	return select(s+1,
		(lEvent&FD_READ)?&FdRead:NULL,
		(lEvent&FD_WRITE)?&FdWrite:NULL,
		NULL,
		&TimeOut);
}

int CPRCUdpPeer::GetValidDataLen()
{
	return m_recvbufpos;
}

void CPRCUdpPeer::ClearBuffer()
{
	m_recvbuf[0] = '\0';
	m_recvbufpos = 0;
}

void CPRCUdpPeer::OnReceive(int nErrorCode)
{
	if(nErrorCode != 0)
	{
		return;
	}
	int nRecvd = 0;
	BOOL bOK = TRUE;

	if(m_Identity == SERVER)
		ATLTRACE("Server::OnReceive() ");
	else
		ATLTRACE("Client::OnReceive() ");

	if(m_recvbufpos > 0)
	{
		//等待OnSend将所有数据转发出去再接收
		ATLTRACE("buffer not empty.\r\n");
		return;
	}

	do
	{
		_SockAddr addrname;
		int addrlen = sizeof(_SockAddr);

		int nRetVal = ReceiveFrom(m_recvbuf, MAXUDPBUFSIZE, &addrname, &addrlen);
		if (nRetVal == SOCKET_ERROR)
		{
			nErrorCode = WSAGetLastError();
			if (nErrorCode == WSAEMSGSIZE)
			{
				nRetVal = MAXUDPBUFSIZE;
			}
			else if (nErrorCode == WSAEWOULDBLOCK)
			{
				break;
			}else
			{
				bOK = FALSE;
				break;
			}
		}else if (nRetVal == 0)
		{
			//connection has a graceful closing
			//continue transferring if there are any available data existing.
			if(m_recvbufpos == 0)
			{
				ATLTRACE("m_recvbufpos == 0. connection closed\r\n");
				bOK = FALSE;
				break;
			}
		}

		ATLASSERT(nRetVal >= 10);

		DWORD nIP = addrname.GetdwIP();
		const BYTE* pucIP = (BYTE*)&nIP;

		ATLTRACE("ReceiveFrom: %u.%u.%u.%u:%d\r\n", pucIP[0], pucIP[1], pucIP[2], pucIP[3], addrname.GetPort());

		nRecvd += nRetVal;
		m_recvbufpos += nRetVal;
		m_recvbuf[m_recvbufpos] = '\0';

		m_ppi.errcode = 0;
		m_ppi.datafrom = m_pProxyLayer?1:0;
		m_ppi.pData = m_recvbuf;
		m_ppi.datalen = m_recvbufpos;

		//m_recvbuf[3] == ATYP
		if (m_recvbuf[3] == 0x01 && nRetVal >= 10)
		{
			m_ppi.lpC->szDomainName[0] = '\0';
			m_ppi.lpC->dstAddr.SetIPLong(*(DWORD*)&m_recvbuf[0x04]);
			m_ppi.lpC->dstAddr.SetPort(ntohs(*(WORD*)&m_recvbuf[0x08]));
		}else if (m_recvbuf[3] == 0x03 && nRetVal >= 10
			&& nRetVal >= 2+1+1+1+(BYTE)m_recvbuf[4]+2 // |RSV:2 | FRAG:1 | ATYP:1| DST.ADDR:1+[N] | DST.PORT:2 |　　DATA:N　|
			)
		{
			int nDN = m_recvbuf[4];
			strncpy(m_ppi.lpC->szDomainName, &m_recvbuf[5], nDN);
			m_ppi.lpC->dstAddr.SetIPLong(0);
			m_ppi.lpC->dstAddr.SetPort(ntohs(*(WORD*)&m_recvbuf[2+1+1+1+nDN]));
		}else
		{
			//??
			ASSERT(0);
			m_ppi.lpC->szDomainName[0] = '\0';
			m_ppi.lpC->dstAddr.SetIPLong(0);
			m_ppi.lpC->dstAddr.SetPort(0);
		}

		m_pProxyDataHandle->OnEachPacket(&m_ppi);

		int nValidLen = m_recvbufpos;
		nRetVal = TransferSend();
		if(nRetVal < 0)
		{
			//error
			ATLTRACE("TransferSend < 0.\r\n");
			bOK = FALSE;
			break;
		}else if(nRetVal < nValidLen)
		{
			//data not completely transferred, break receiving, the next OnReceive event will be triggered when OnSend event occurred on side of Partner,
			ATLTRACE("TransferSend < nValidLen. nLeft = %d\r\n", nValidLen-nRetVal);
			break;
		}
		//data have been completely transferred. continue receiving
		ATLTRACE("nValidLen = %d, TransferSend = %d\r\n", nValidLen, nRetVal);
	}
	while(FALSE);

	if(!bOK)
	{
		//???
		ClearBuffer();
		return;
	}

}

int CPRCUdpPeer::TransferSend()
{
	//将已经接收到m_recvbuf的数据都发给Partner
	int nBytesLeft = m_recvbufpos;
	int nBytesSent = 0;

	int nErrorCode = 0;
	BOOL bOK = TRUE;

	//if(nBytesLeft > 0)
	while(nBytesLeft > 0)
	{
		int nRetVal;

		//if(m_CSAddrInfo.IsDNValid())
		//{
		//	CString tszHost;
		//	tszHost = m_CSAddrInfo.szDomainName;
		//	nRetVal	= m_pPartner->SendTo(m_recvbuf+nBytesSent, nBytesLeft, m_CSAddrInfo.dstAddr.GetPort(), tszHost);
		//}
		//else
		//{
		//	nRetVal	= m_pPartner->SendTo(m_recvbuf+nBytesSent, nBytesLeft, &m_CSAddrInfo.dstAddr, sizeof(_SockAddr));
		//}

		if (m_Identity == CLIENT)
		{
			//udp报头已经在hook的时候加上了
			//直接发到代理服务器
			nRetVal	= m_pPartner->SendTo(m_recvbuf+nBytesSent, nBytesLeft, 0, 0);
		} 
		else
		{
			nRetVal	= m_pPartner->SendTo(m_recvbuf+nBytesSent, nBytesLeft, &m_CSAddrInfo.dstAddr, sizeof(_SockAddr));
		}

		if(nRetVal == SOCKET_ERROR)
		{
			nErrorCode = WSAGetLastError();
			if(nErrorCode == WSAEWOULDBLOCK)
				break;
			bOK = FALSE;
			break;
		}

		nBytesSent += nRetVal;
		nBytesLeft -= nRetVal;

		break;// always
	}

	if(nBytesLeft > 0 && nBytesSent)
	{
		memmove(m_recvbuf, m_recvbuf+nBytesSent, nBytesLeft);
	}
	m_recvbufpos = nBytesLeft;
	m_recvbuf[m_recvbufpos] = '\0';

	if(bOK == FALSE)
	{
		//???
		return -1;
	}

	return nBytesSent;
}

void CPRCUdpPeer::OnSend(int nErrorCode)
{
	if(nErrorCode != 0)
	{
		return;
	}

	if(m_Identity == SERVER)
		ATLTRACE("Server::OnSend()\r\n");
	else
		ATLTRACE("Client::OnSend()\r\n");

	//当前套接字可写， 则将Partner的m_recvbuf中的有效数据转发出去
	int nRetVal;
	int validlen = m_pPartner->GetValidDataLen();
	if(validlen > 0)
	{
		//将Partner的数据转发至本套接字
		nRetVal = m_pPartner->TransferSend();
		if(nRetVal < 0)
		{
			ClearBuffer();
			m_pPartner->ClearBuffer();

			return;
		}else if(nRetVal < validlen)
		{
			ATLTRACE("CPRCUdpPeer.OnSend(), nRetVal < validlen\r\n");
		}else
		{
			//数据全部转发出去了， 判断Partner那边的套接字的FD_READ状态，小于0为连接异常，0为正常但无数据可读，1为有数据可读
			nRetVal = m_pPartner->TestSocketStatus(FD_READ);
			if(nRetVal < 0)
			{
				ClearBuffer();
				m_pPartner->ClearBuffer();

			}else if(nRetVal > 0)
			{
				m_pPartner->TriggerEvent(FD_READ);
				ATLTRACE("CPRCUdpPeer.OnSend(), m_pPartner->TriggerEvent(FD_READ)\r\n");
			}else
			{
				ATLTRACE("CPRCUdpPeer.OnSend(), no data arrived\r\n");
			}
		}

		ATLTRACE("CPRCUdpPeer.OnSend(). validlen = %d, nSent = %d\r\n", validlen, nRetVal);
	}else
	{

	}

}

void CPRCUdpPeer::OnClose(int nErrorCode)
{
	m_ppi.errcode = nErrorCode;
	m_ppi.datafrom = m_Identity == SERVER?1:0;;
	m_ppi.pData = "";
	m_ppi.datalen = 0;
	m_pProxyDataHandle->OnClose(&m_ppi);

	AsyncSelect(0);
	Close();

	if(m_pPartner->GetSocketHandle() != INVALID_SOCKET)
	{
		m_pPartner->AsyncSelect(0);
		m_pPartner->Close();
	}
	m_pNotify->OnPeerClosed(this);
}

void CPRCUdpPeer::Close()
{
#ifdef _DEBUG
	SOCKET sClient = GetSocketHandle();
	if (m_Identity == CLIENT && sClient != INVALID_SOCKET)
	{
		_SockAddr srcAddr;
		int srcaddrlen = sizeof(_SockAddr);
		//查询该socket绑定的地址
		if(getsockname(sClient, &srcAddr, &srcaddrlen) == 0)
		{		
			in_addr *pAddr = srcAddr.GetAddr();

			ATLTRACE("Close::UDP.Socket: %d , localAddr: %u.%u.%u.%u:%d\r\n", sClient, pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, srcAddr.GetPort());
		}
	}
#endif

	CAsyncSocketEx::Close();
}

int CPRCUdpPeer::OnLayerCallback(const CAsyncSocketExLayer *pLayer, int nType, int nCode, WPARAM wParam, LPARAM lParam)
{
	m_pProxyDataHandle->OnLayerCallback(&m_ppi, nType, nCode, wParam, lParam);
	return 1;
}
