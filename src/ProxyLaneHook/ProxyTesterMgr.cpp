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
	Close();
}

void CProxyTester::OnClose(int nErrorCode)
{
	if(nErrorCode == 0)
		nErrorCode = ~0;
	m_pCallback->OnProxyTesterCallback(this, MAKEWPARAM(nErrorCode, LAYERCALLBACK_LAYERSPECIFIC), 0, 0);
}

void CProxyTester::OnConnect(int nErrorCode)
{
	if(nErrorCode)
	{
		OnClose(nErrorCode);
	}else
	{
		//OK!
		m_pCallback->OnProxyTesterCallback(this, MAKEWPARAM(nErrorCode, LAYERCALLBACK_LAYERSPECIFIC), 0, 0);
	}

}

void CProxyTester::OnReceive(int nErrorCode)
{

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
	m_pCallback->OnProxyTesterCallback(this, MAKEWPARAM(nCode, nType), wParam, lParam);

	return 1;
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
