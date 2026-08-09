#include "stdafx.h"
#include "ProxyTesterMgr.h"
#include "ProxyTransportPolicy.h"



//////////////////////////////////////////////////////////////////////////
// CProxyTester
//
//////////////////////////////////////////////////////////////////////////

CProxyTester::CProxyTester(CProxyTesterMgr *pNotify)
{
	m_pNotify = pNotify;
	m_pProxyLayer = NULL;
	m_pSecureLayer = NULL;
	m_pCallback = NULL;
	m_completed = FALSE;
	m_dnsTransactionId = 0;
}

CProxyTester::~CProxyTester(void)
{
	Close();
	delete m_pProxyLayer;
	delete m_pSecureLayer;
	m_pProxyLayer = NULL;
	m_pSecureLayer = NULL;
}

void CProxyTester::Release()
{
	Stop();
	m_pNotify->OnDestroyTester(this);
}

BOOL CProxyTester::Start(IProxyTesterCallback *pCallback, const LPPRCClient lpPRCClient, const LPProxyInfo lpPI)
{
	m_pCallback = pCallback;
	m_client = *lpPRCClient;
	m_proxyinfo = *lpPI;
	m_completed = FALSE;

	if (!AddProxyLayer(lpPI))
		return FALSE;

	if (!Create(0, lpPRCClient->sType))
	{
		return FALSE;
	}

	if (lpPRCClient->sType == SOCK_STREAM)
	{
		BOOL bConnect = FALSE;

		if(lpPRCClient->IsDNValid())
			bConnect = CAsyncSocketEx::Connect(lpPRCClient->szDomainName, lpPRCClient->dstAddr.GetPort());
		else
			bConnect = CAsyncSocketEx::Connect(&lpPRCClient->dstAddr, sizeof(lpPRCClient->dstAddr));

		if(!bConnect)
		{
			if(WSAGetLastError() != WSAEWOULDBLOCK)
				return FALSE;
		}

		return TRUE;
	}else if (lpPRCClient->sType == SOCK_DGRAM)
	{
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

	}else
	{
		return FALSE;
	}

}


BOOL CProxyTester::AddProxyLayer(LPProxyInfo lpProxyInfo)
{
	if (lpProxyInfo &&
		lpProxyInfo->reserved == PROXY_TRANSPORT_GONC_TLS_PSK &&
		(!ProxyTransportPolicy::SupportsGoncTlsPsk(
			lpProxyInfo->GetProxyType()) ||
		 !lpProxyInfo->strTransportPsk.szbuf[0]))
	{
		WSASetLastError(WSAEINVAL);
		return FALSE;
	}
	if (!m_completed)
		m_pNotify->ArmTester(this, 10000);

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
	if (!AddLayer(m_pProxyLayer))
		return FALSE;
	if (lpProxyInfo && lpProxyInfo->reserved == PROXY_TRANSPORT_GONC_TLS_PSK)
	{
		if (m_client.sType == SOCK_DGRAM)
			return m_pProxyLayer->SetSecureTransport(
				lpProxyInfo->strTransportPsk.szbuf);
		m_pSecureLayer = new CAsyncSecureSocketLayer;
		if (!m_pSecureLayer ||
			!m_pSecureLayer->Configure(lpProxyInfo->strTransportPsk.szbuf,
				lpProxyInfo->strProxyHost.szbuf) ||
			!AddLayer(m_pSecureLayer))
			return FALSE;
	}
	return TRUE;
}

void CProxyTester::RemoveAllLayers()
{
	CAsyncSocketEx::RemoveAllLayers();
}

void CProxyTester::Stop()
{
	m_pNotify->DisarmTester(this);
	Close();
}

void CProxyTester::Complete(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (m_completed || !m_pCallback)
		return;
	m_completed = TRUE;
	m_pNotify->DisarmTester(this);
	m_pCallback->OnProxyTesterCallback(this,
		MAKEWPARAM(nCode, LAYERCALLBACK_LAYERSPECIFIC), wParam, lParam);
}

void CProxyTester::OnClose(int nErrorCode)
{
	if(nErrorCode == 0)
		nErrorCode = ~0;
	Complete(m_client.sType == SOCK_DGRAM
		? (nErrorCode == WSAEOPNOTSUPP ? PROXYERROR_UDP_UNSUPPORTED :
			PROXYERROR_UDP_RELAY_FAILED)
		: nErrorCode);
}

void CProxyTester::OnConnect(int nErrorCode)
{
	if(nErrorCode)
	{
		OnClose(nErrorCode);
	}else
	{
		if (m_client.sType == SOCK_STREAM)
		{
			Complete(0);
			return;
		}

		BYTE query[] = {
			0, 0, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
			7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
			3, 'c', 'o', 'm', 0, 0, 1, 0, 1
		};
		m_dnsTransactionId = (WORD)(GetTickCount() & 0xffff);
		query[0] = (BYTE)(m_dnsTransactionId >> 8);
		query[1] = (BYTE)m_dnsTransactionId;
		int sent = SendTo(query, sizeof(query), &m_client.dstAddr,
			m_client.dstAddr.Size());
		if (sent != sizeof(query))
		{
			Complete(WSAGetLastError() == WSAEOPNOTSUPP
				? PROXYERROR_UDP_UNSUPPORTED : PROXYERROR_UDP_RELAY_FAILED);
			return;
		}
		m_pNotify->ArmTester(this, 5000);
	}

}

void CProxyTester::OnReceive(int nErrorCode)
{
	if (m_client.sType != SOCK_DGRAM || m_completed)
		return;
	if (nErrorCode)
	{
		Complete(PROXYERROR_UDP_RELAY_FAILED);
		return;
	}
	BYTE reply[2048];
	_SockAddr source;
	int sourceLength = sizeof(source);
	int received = ReceiveFrom(reply, sizeof(reply), &source, &sourceLength);
	if (received == SOCKET_ERROR)
	{
		if (WSAGetLastError() != WSAEWOULDBLOCK)
			Complete(WSAGetLastError() == WSAEOPNOTSUPP
				? PROXYERROR_UDP_UNSUPPORTED : PROXYERROR_UDP_RELAY_FAILED);
		return;
	}
	if (received >= 12 && reply[0] == (BYTE)(m_dnsTransactionId >> 8) &&
		reply[1] == (BYTE)m_dnsTransactionId && (reply[2] & 0x80))
		Complete(0);
}

void CProxyTester::OnSend(int nErrorCode)
{

}

int CProxyTester::OnLayerCallback(const CAsyncSocketExLayer *pLayer, int nType, int nCode, WPARAM wParam, LPARAM lParam)
{
	if (m_pProxyLayer != pLayer)
	{
		return 0;
	}

	//nType: LAYERCALLBACK_STATECHANGE | LAYERCALLBACK_LAYERSPECIFIC
	if (nType == LAYERCALLBACK_LAYERSPECIFIC && nCode != 0 &&
		nCode != PROXYSTATUS_LISTENSOCKETCREATED)
		Complete(m_client.sType == SOCK_DGRAM &&
			nCode == PROXYERROR_REQUESTFAILED
				? PROXYERROR_UDP_RELAY_FAILED : nCode,
			wParam, lParam);
	else if (!m_completed)
		m_pCallback->OnProxyTesterCallback(this, MAKEWPARAM(nCode, nType),
			wParam, lParam);

	return 1;
}

void CProxyTester::OnTimeout()
{
	Complete(m_client.sType == SOCK_DGRAM
		? PROXYERROR_UDP_RELAY_FAILED : PROXYERROR_NOCONN);
}

//////////////////////////////////////////////////////////////////////////
// CProxyTesterMgr
//
//////////////////////////////////////////////////////////////////////////

CProxyTesterMgr::CProxyTesterMgr(void)
{
}

CProxyTesterMgr::~CProxyTesterMgr(void)
{
	RemoveAll();
}

IProxyTester* CProxyTesterMgr::CreateTester()
{
	CProxyTester *pTester = new CProxyTester(this);
	if (pTester == NULL)
	{
		return NULL;
	}

	CTSList<CProxyTester*>::critical lc(m_testerlist);

	m_testerlist.push_back(pTester);

	return pTester;
}

void CProxyTesterMgr::OnDestroyTester(CProxyTester *pTester)
{
	DisarmTester(pTester);
	CTSList<CProxyTester*>::critical lc(m_testerlist);

	for (CTSList<CProxyTester*>::iterator it=m_testerlist.begin(); it!=m_testerlist.end(); it++)
	{
		if (*it == pTester)
		{
			m_testerlist.erase(it);

			HWND hWnd = CWndTimer::GetHwnd();

			::PostMessage(hWnd, WM_DELTESTER, (WPARAM)pTester, 0);
			return;
		}
	}
}

void CProxyTesterMgr::RemoveAll()
{
	CTSList<CProxyTester*>::critical lc(m_testerlist);

	for (CTSList<CProxyTester*>::iterator it=m_testerlist.begin(); it!=m_testerlist.end(); it++)
	{
		delete *it;
	}

	m_testerlist.clear();
}

VOID CProxyTesterMgr::OnMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	switch(uMsg)
	{
	case WM_DELTESTER:

		CProxyTester *pTester = (CProxyTester*)wParam;

		delete pTester;

		bHandled = TRUE;
		break;
	}
}

void CProxyTesterMgr::ArmTester(CProxyTester *pTester,
	UINT timeoutMilliseconds)
{
	if (!pTester)
		return;
	KillTimer((UINT_PTR)pTester);
	SetTimer((UINT_PTR)pTester, timeoutMilliseconds);
}

void CProxyTesterMgr::DisarmTester(CProxyTester *pTester)
{
	if (pTester)
		KillTimer((UINT_PTR)pTester);
}

VOID CProxyTesterMgr::OnTimer(UINT_PTR nIDEvent)
{
	KillTimer(nIDEvent);
	CProxyTester *tester = reinterpret_cast<CProxyTester *>(nIDEvent);
	{
		BOOL found = FALSE;
		CTSList<CProxyTester*>::critical lc(m_testerlist);
		for (CTSList<CProxyTester*>::iterator it = m_testerlist.begin();
			it != m_testerlist.end(); ++it)
		{
			if (*it == tester)
			{
				found = TRUE;
				break;
			}
		}
		if (!found)
			return;
	}
	tester->OnTimeout();
}
