/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "PRCTcpPeer.h"
#include "ProxyTaskMgr.h"
#include "ProxyLog.h"
#include "ProxyReceptionCentre.h"
#include "ProxyDataHandle.h"


CPRCTcpPeer::CPRCTcpPeer(CTcpProxyTask *pNotify)
{
	m_pProxyLayer = NULL;
	m_pNotify = pNotify;
	m_pProxyDataHandle = (CProxyDataHandle*)pNotify->m_pTaskmgr->m_pPRC->GetPDHInstance();
	m_ppi.lpC = &pNotify->m_PRCClient;
	m_ppi.lpPI = &pNotify->m_ProxyInfo;

	m_dwLastError = 0;
	m_recvbufpos = 0;
	m_sentpos = 0;
	m_DataLenSent = 0;
	m_DataLenRecvd = 0;
	m_SocketStatus = TM_0;
	m_bConnShutted = 0;

	m_TimeoutMonitor[TM_CONN].SetTimeoutVal(15*1000);
	m_TimeoutMonitor[TM_SEND].SetTimeoutVal(30*1000);
	m_TimeoutMonitor[TM_RECV].SetTimeoutVal(30*1000);
}

CPRCTcpPeer::~CPRCTcpPeer(void)
{
	//???
}

DWORD CPRCTcpPeer::GetLastError()
{
	return m_dwLastError;
}

void CPRCTcpPeer::SetPartner(CPRCTcpPeer *pPartner)
{
	m_pPartner = pPartner;
}

BOOL CPRCTcpPeer::ConnectProxy(LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo)
{

	//设置代理
	if(!AddProxyLayer(lpProxyInfo))
		return FALSE;


	//注意
	//代理请求调用connect也会给HookWinsock拦截，
	//旧方法1
	//SetConnectionFlag 将设置一个8字节的标志， 告知HookWinsock直接调用系统的connect
	//8字节的标志放置在sockaddr_in.sin_zero的中, :)
	/*
	struct sockaddr_in {
	short   sin_family;
	u_short sin_port;
	struct  in_addr sin_addr;
	char    sin_zero[8];
	*/
	//m_pProxyLayer->SetConnectionFlag('pass', 'port');

	//方法2
	m_pProxyLayer->BypassHook(TRUE);

	BOOL bConnect = FALSE;

	CAsyncSocketEx::Create(0, SOCK_STREAM, FD_READ | FD_WRITE | FD_CONNECT | FD_CLOSE);
	CAsyncSocketEx::AsyncSelect(FD_READ | FD_WRITE | FD_CONNECT | FD_CLOSE);

	//Is domain name valid?
	if(lpPRCClient->IsDNValid())
		bConnect = CAsyncSocketEx::Connect(lpPRCClient->szDomainName, lpPRCClient->dstAddr.GetPort());
	else
		bConnect = CAsyncSocketEx::Connect(&lpPRCClient->dstAddr, sizeof(lpPRCClient->dstAddr));

	if(!bConnect)
	{
		if(WSAGetLastError() != WSAEWOULDBLOCK)
			return FALSE;
	}

	m_SocketStatus = TM_CONN;
	m_TimeoutMonitor[TM_CONN].Update();

	m_pPartner->m_TimeoutMonitor[TM_SEND].Disable();
	m_pPartner->m_TimeoutMonitor[TM_RECV].Disable();

	return TRUE;
}

BOOL CPRCTcpPeer::AddProxyLayer(LPProxyInfo lpProxyInfo)
{
	CAsyncProxySocketLayer *pNewLayer = new CAsyncProxySocketLayer;
	if(pNewLayer == NULL)
		return FALSE;

	int nProxyType;

	if(!lpProxyInfo)
		nProxyType = PROXYTYPE_NOPROXY;
	else 
		nProxyType = lpProxyInfo->GetProxyType();
	
	switch(nProxyType)
	{
	case PROXYTYPE_NOPROXY:
		pNewLayer->SetProxy(nProxyType);
		break;

	case PROXYTYPE_HTTP10:
	case PROXYTYPE_HTTP11:
	case PROXYTYPE_SOCKS5:
		pNewLayer->SetProxy(nProxyType, (CStringA)lpProxyInfo->strProxyHost, lpProxyInfo->nProxyPort, (CStringA)lpProxyInfo->strProxyUser, (CStringA)lpProxyInfo->strProxyPass);
		break;

	default:
		pNewLayer->SetProxy(nProxyType, (CStringA)lpProxyInfo->strProxyHost, lpProxyInfo->nProxyPort);
		break;
	}

	m_pProxyLayer = pNewLayer;
	return AddLayer(m_pProxyLayer);
}

void CPRCTcpPeer::RemoveAllLayers()
{
	CAsyncSocketEx::RemoveAllLayers();
	delete m_pProxyLayer;
	m_pProxyLayer = NULL;
}

//void CPRCTcpPeer::PostSocketEvent(long lEvent, int nErrorCode)
//{
//	LPARAM lParam = MAKELPARAM(lEvent, nErrorCode);
//	::PostMessage(GetHelperWindowHandle(), m_SocketData.nSocketIndex + WM_SOCKETEX_NOTIFY, m_SocketData.hSocket, lParam);
//}
//
//void CPRCTcpPeer::SendSocketEvent(long lEvent, int nErrorCode)
//{
//	LPARAM lParam = MAKELPARAM(lEvent, nErrorCode);
//	::SendMessage(GetHelperWindowHandle(), m_SocketData.nSocketIndex + WM_SOCKETEX_NOTIFY, m_SocketData.hSocket, lParam);
//}

int CPRCTcpPeer::TestSocketStatus(long lEvent)
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

int CPRCTcpPeer::GetValidDataLen()
{
	return m_recvbufpos - m_sentpos;
}

void CPRCTcpPeer::ClearBuffer()
{
	m_recvbuf[0] = '\0';
	m_recvbufpos = 0;
	m_sentpos = 0;
}

void CPRCTcpPeer::OnReceive(int nErrorCode)
{
	if(nErrorCode != 0)
	{
		return;
	}

	int nRecvd = 0;
	BOOL bOK = TRUE;

	if(m_pProxyLayer)
		ATLTRACE("%d.Server::OnReceive() ", GetSocketHandle());
	else
		ATLTRACE("%d.Client::OnReceive() ", GetSocketHandle());

	m_SocketStatus = TM_RECV;
	m_TimeoutMonitor[TM_RECV].Update();

	if(m_recvbufpos > 0)
	{
		//等待OnSend将所有数据转发出去再接收
		ATLTRACE("buffer not empty.\r\n");
		return;
	}

	while(m_recvbufpos<MAXTCPBUFSIZE)
	//do
	{
		int nRetVal = Receive(m_recvbuf+m_recvbufpos, MAXTCPBUFSIZE-m_recvbufpos);
		if(nRetVal == SOCKET_ERROR)
		{
			nErrorCode = WSAGetLastError();
			if(nErrorCode == WSAEWOULDBLOCK)
			{
				ATLTRACE("nRecvd = %d, m_recvbufpos = %d\r\n", nRecvd, m_recvbufpos);
				break;
			}
			bOK = FALSE;
			break;
		}else if(nRetVal == 0)
		{
			//connection has a graceful closing
			//continue transferring if there are any available data existing.
			if(m_recvbufpos == 0)
			{
				ATLTRACE("m_recvbufpos == 0. connection closed\r\n");
				bOK = FALSE;
				break;
			}

			ATLTRACE("%d.Receive == 0. m_recvbufpos > 0\r\n", GetSocketHandle());
			break;
		}

		nRecvd += nRetVal;
		m_recvbufpos += nRetVal;
		m_DataLenRecvd += nRetVal;
		m_recvbuf[m_recvbufpos] = '\0';

		m_ppi.errcode = 0;
		m_ppi.datafrom = m_pProxyLayer?1:0;
		m_ppi.pData = m_recvbuf;
		m_ppi.datalen = m_recvbufpos;
		m_pProxyDataHandle->OnEachPacket(&m_ppi);

		ATLASSERT(m_sentpos == 0);
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
		//data have been completely transferred. continue receiving?
		ATLTRACE("nValidLen = %d, TransferSend = %d\r\n", nValidLen, nRetVal);
		//一般一个FD_READ对应一次recv， 如果连接已经优雅的关闭，那么把系统buf中的数据全部收下来并转发
		if (m_bConnShutted)
			continue;
		else
			break;
	}
	//while(FALSE);

	if(!bOK)
	{
		//???
		ClearBuffer();
		TriggerEvent(FD_CLOSE, nErrorCode);
		return;
	}

}

//returns -1 if error occurs, otherwise, the value are total number of bytes sent
int CPRCTcpPeer::TransferSend()
{
	//将已经接收到m_recvbuf的数据都发给Partner
	int nBytesLeft = m_recvbufpos - m_sentpos;
	int nBytesSent = 0;

	ATLASSERT(nBytesLeft >= 0);

	int nErrorCode = 0;
	BOOL bOK = TRUE;

	m_pPartner->m_SocketStatus = TM_SEND;
	m_pPartner->m_TimeoutMonitor[TM_SEND].Update();

	while(nBytesLeft > 0)
	{
		int nRetVal = m_pPartner->Send(m_recvbuf+m_sentpos+nBytesSent, nBytesLeft);

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
		m_DataLenSent += nRetVal;
	}

	//if(nBytesLeft > 0 && nBytesSent)
	//{
	//	memmove(m_recvbuf, m_recvbuf+nBytesSent, nBytesLeft);
	//}
	//m_recvbufpos = nBytesLeft;
	//m_recvbuf[m_recvbufpos] = '\0';

	//如果没全部转发完则标志已经发送的下标
	if (nBytesLeft > 0)
	{
		m_sentpos += nBytesSent;
	}else
	{
		//全部转发完， 下标都清0
		m_sentpos = 0;
		m_recvbufpos = 0;
	}

	if(bOK == FALSE)
	{
		//???
		return -1;
	}

	return nBytesSent;
}

void CPRCTcpPeer::OnSend(int nErrorCode)
{
	if(nErrorCode != 0)
	{
		return;
	}

	m_SocketStatus = TM_SEND;
	m_TimeoutMonitor[TM_SEND].Update();

	if(m_pProxyLayer)
		ATLTRACE("%d.Server::OnSend()\r\n", GetSocketHandle());
	else
		ATLTRACE("%d.Client::OnSend()\r\n", GetSocketHandle());

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

			TriggerEvent(FD_CLOSE);
			return;
		}else if(nRetVal < validlen)
		{
			//Partner的m_recvbuf中的数据还没能完全转发出去, 等待下次OnSend
			ATLTRACE("CPRCTcpPeer.OnSend(), nRetVal < validlen\r\n");
		}else
		{
			//数据全部转发出去了， 判断Partner那边的套接字的FD_READ状态，小于0为连接异常，0为正常但无数据可读，1为有数据可读
			nRetVal = m_pPartner->TestSocketStatus(FD_READ);
			if(nRetVal < 0)
			{
				//Partner的连接已经异常
				ClearBuffer();
				m_pPartner->ClearBuffer();

				TriggerEvent(FD_CLOSE);
			}else if(nRetVal > 0)
			{
				m_pPartner->TriggerEvent(FD_READ);
				ATLTRACE("CPRCTcpPeer.OnSend(), m_pPartner->TriggerEvent(FD_READ)\r\n");
			}else
			{
				//no data arrived
				//do nothing
				ATLTRACE("CPRCTcpPeer.OnSend(), no data arrived\r\n");
			}
		}

		ATLTRACE("CPRCTcpPeer.OnSend(). validlen = %d, nSent = %d\r\n", validlen, nRetVal);
	}else
	{

	}




}

void CPRCTcpPeer::OnConnect(int nErrorCode)
{
	m_ppi.errcode = nErrorCode;
	m_ppi.datafrom = 1;
	m_ppi.pData = NULL;
	m_ppi.datalen = 0;
	m_pProxyDataHandle->OnConnect(&m_ppi);

	if(nErrorCode != 0)
	{
		OnClose(nErrorCode);
		return;
	}

	ATLTRACE("CPRCTcpPeer.OnConnect()\r\n");
	//代理已经建立，修改Client关注的event
	m_pPartner->AsyncSelect(FD_READ | FD_WRITE | FD_CLOSE);
	if(m_pPartner->TestSocketStatus(FD_WRITE) > 0)
		m_pPartner->TriggerEvent(FD_WRITE);
	if(m_pPartner->TestSocketStatus(FD_READ) > 0)
		m_pPartner->TriggerEvent(FD_READ);

	m_pPartner->m_TimeoutMonitor[TM_SEND].Enable();
	m_pPartner->m_TimeoutMonitor[TM_SEND].Update();
	m_pPartner->m_TimeoutMonitor[TM_RECV].Enable();
	m_pPartner->m_TimeoutMonitor[TM_RECV].Update();

}

void CPRCTcpPeer::OnClose(int nErrorCode)
{
	m_bConnShutted = TRUE;
	if( nErrorCode == 0 )
	{
		//正常关闭，但 还有数据没转发?
		//if(GetValidDataLen() > 0)
		//{
		//	return;
		//}
		//if(m_pPartner->GetValidDataLen())
		//{
		//	return;
		//}

		//DWORD nCBytes = 0, nSBytes = 0;
		//if(IOCtl(FIONREAD, &nCBytes) &&	m_pPartner->IOCtl(FIONREAD, &nSBytes))
		//{
		//	if(nCBytes > 0)
		//		TriggerEvent(FD_READ);
		//	if(nSBytes > 0)
		//		m_pPartner->TriggerEvent(FD_READ);

		//	if(nCBytes || nSBytes)
		//		return;
		//}

		if(GetValidDataLen() > 0)
		{
			ATLTRACE("%d.OnClose() -> GetValidDataLen() > 0", GetSocketHandle());
			return;
		}

		DWORD nBytes = 0;
		IOCtl(FIONREAD, &nBytes);
		if(nBytes > 0)
		{
			ATLTRACE("%d.OnClose() -> IOCtl(FIONREAD) > 0", GetSocketHandle());
			TriggerEvent(FD_READ);
			return;
		}
	}

	ATLTRACE("OnClose! All.sent: %I64d/%I64d, recvd: %I64d/%I64d \r\n", m_DataLenSent, m_pPartner->m_DataLenSent, m_DataLenRecvd, m_pPartner->m_DataLenRecvd);

	m_ppi.errcode = nErrorCode;
	m_ppi.datafrom = m_pProxyLayer?1:0;;
	m_ppi.pData = "";
	m_ppi.datalen = 0;
	m_pProxyDataHandle->OnClose(&m_ppi);

	//
	m_SocketStatus = TM_CLOSE;
	AsyncSelect(0);
	CAsyncSocketEx::Close();
	m_dwLastError = nErrorCode;

	if(m_pPartner->GetSocketHandle() != INVALID_SOCKET)
	{
		//m_pPartner->m_SocketStatus = TM_SHUT;
		//m_pPartner->m_TimeoutMonitor[TM_SHUT].Update();
		//m_pPartner->ShutDown(SD_BOTH);
		m_pPartner->AsyncSelect(0);
		m_pPartner->Close();
	}
	m_pNotify->OnPeerClosed(this);
}

void CPRCTcpPeer::OnTimer()
{

	switch(m_SocketStatus)
	{
	case TM_CONN:
		{
			if(m_TimeoutMonitor[TM_CONN].IsTimeout())
			{
				PrintText(_T("connect to the proxy is timeout.\r\n"));
				ClearBuffer();
				TriggerEvent(FD_CLOSE, WSAETIMEDOUT);
				return;
			}
		}
	    break;
	case TM_SEND:
	case TM_RECV:
		{
			if(m_TimeoutMonitor[TM_SEND].IsTimeout() && m_TimeoutMonitor[TM_RECV].IsTimeout())
			{
				//timeout
				//m_dwLastError = nErrorCode;
				//TriggerEvent(FD_CLOSE);
				return;
			}

		}
		break;
	case TM_SHUT:
		{
			if(m_TimeoutMonitor[TM_SHUT].IsTimeout())
			{
				ClearBuffer();
				TriggerEvent(FD_CLOSE, WSAETIMEDOUT);
				return;
			}

		}
		break;

	default:
		break;
	}
}

int CPRCTcpPeer::OnLayerCallback(const CAsyncSocketExLayer *pLayer, int nType, int nCode, WPARAM wParam, LPARAM lParam)
{
/*
//Error codes
PROXYERROR_NOERROR 0
PROXYERROR_NOCONN 1 //Can't connect to proxy server, use GetLastError for more information
PROXYERROR_REQUESTFAILED 2 //Request failed, can't send data
PROXYERROR_AUTHREQUIRED 3 //Authentication required
PROXYERROR_AUTHTYPEUNKNOWN 4 //Authtype unknown or not supported
PROXYERROR_AUTHFAILED 5  //Authentication failed
PROXYERROR_AUTHNOLOGON 6
PROXYERROR_CANTRESOLVEHOST 7
*/
	UNREFERENCED_PARAMETER(wParam);
	ASSERT( pLayer );
	if (nType == LAYERCALLBACK_STATECHANGE)
	{
		m_pProxyDataHandle->OnLayerCallback(&m_ppi, nType, nCode, wParam, lParam);
		return 1;
	}
	else if (nType == LAYERCALLBACK_LAYERSPECIFIC)
	{
		if (pLayer == m_pProxyLayer)
		{
			switch (nCode)
			{
			case PROXYERROR_NOCONN:
				PrintText(_T("Connect to proxy failed.\r\n"));
				break;
				/* fall through */
			case PROXYERROR_REQUESTFAILED:
				PrintText(_T("Proxy server failed to connect to the peer.\r\n"));
				break;
			case PROXYERROR_AUTHREQUIRED:
				PrintText(_T("Proxy Error: Authentication required.\r\n"));
				break;
			case PROXYERROR_AUTHTYPEUNKNOWN:
				PrintText(_T("Proxy Error: Authentication type unknown or not supported.\r\n"));
				break;
			case PROXYERROR_AUTHFAILED:
				PrintText(_T("Proxy Error: Authentication failed.\r\n"));
				break;

			default:
				break;
			}
		}
	}
	m_pProxyDataHandle->OnLayerCallback(&m_ppi, nType, nCode, wParam, lParam);
	return 1;
}
