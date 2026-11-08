#pragma once

#include "asynsocket\AsyncSocketEx.h"
#include "asynsocket\AsyncProxySocketLayer.h"
#include "asynsocket\AsyncSecureSocketLayer.h"
#include "ProxyTransportPolicy.h"

// The layers of a strict proxy chain on one socket.
//
// CAsyncSocketEx puts the first-added layer nearest the application, so the
// hops are added from the last to the first: the socket connects to hops[0],
// and each proxy layer asks its hop to open a tunnel to the hop (or target)
// above it. A hop's gonc TLS layer sits directly under its proxy layer, as
// for a single upstream.
//
// The owner removes the layers from its socket before calling Free(); the
// destructor does not free them, because the socket may still use them.
class CProxyChainLayers
{
public:
	CProxyChainLayers() : m_count(0)
	{
		ZeroMemory(m_proxy, sizeof(m_proxy));
		ZeroMemory(m_secure, sizeof(m_secure));
	}

	BOOL Add(CAsyncSocketEx& socket, const ProxyChain& chain)
	{
		if (m_count || chain.nHops < 2 || chain.nHops > PROXY_CHAIN_MAX_HOPS)
		{
			WSASetLastError(WSAEINVAL);
			return FALSE;
		}
		m_count = chain.nHops;
		for (int i = chain.nHops - 1; i >= 0; --i)
		{
			ProxyInfo hop = chain.hops[i];
			const int type = hop.GetProxyType();
			const bool secure = ProxyTransportPolicy::UsesGoncTlsPsk(&hop);
			if ((type != PROXYTYPE_SOCKS5 && type != PROXYTYPE_HTTP10 && type != PROXYTYPE_HTTP11) ||
				!hop.strProxyHost.szbuf[0] || !hop.nProxyPort ||
				(secure && !hop.strTransportPsk.szbuf[0]))
			{
				WSASetLastError(WSAEINVAL);
				return FALSE;
			}

			m_proxy[i] = new CAsyncProxySocketLayer;
			if (!m_proxy[i])
			{
				WSASetLastError(WSAENOBUFS);
				return FALSE;
			}
			m_proxy[i]->SetProxy(type, (CStringA)hop.strProxyHost, hop.nProxyPort,
				(CStringA)hop.strProxyUser, (CStringA)hop.strProxyPass);
			if (!socket.AddLayer(m_proxy[i]))
				return FALSE;

			if (secure)
			{
				m_secure[i] = new CAsyncSecureSocketLayer;
				if (!m_secure[i])
				{
					WSASetLastError(WSAENOBUFS);
					return FALSE;
				}
				if (!m_secure[i]->Configure(hop.strTransportPsk.szbuf, hop.strProxyHost.szbuf) ||
					!socket.AddLayer(m_secure[i]))
					return FALSE;
			}
		}
		return TRUE;
	}

	void Free()
	{
		for (int i = 0; i < PROXY_CHAIN_MAX_HOPS; ++i)
		{
			delete m_proxy[i];
			delete m_secure[i];
			m_proxy[i] = NULL;
			m_secure[i] = NULL;
		}
		m_count = 0;
	}

	BOOL IsActive() const { return m_count > 0; }

	// The last hop's proxy layer: the one nearest the application.
	CAsyncProxySocketLayer* Top() const { return m_count ? m_proxy[m_count - 1] : NULL; }

	// The hop a proxy or TLS layer belongs to, or -1.
	int HopOf(const CAsyncSocketExLayer* layer) const
	{
		for (int i = 0; layer && i < m_count; ++i)
		{
			if (layer == m_proxy[i] || layer == m_secure[i])
				return i;
		}
		return -1;
	}

	// The first hop whose proxy handshake has not finished, or -1. Every
	// layer starts its connect operation at once and resets it on success, so
	// on a timeout the lowest unfinished hop is the one that stalled.
	int StalledHop() const
	{
		for (int i = 0; i < m_count; ++i)
		{
			if (m_proxy[i] && m_proxy[i]->GetProxyOpID() != 0)
				return i;
		}
		return -1;
	}

	BOOL HasPendingSecureRead() const
	{
		for (int i = 0; i < m_count; ++i)
		{
			if (m_secure[i] && m_secure[i]->HasPendingRead())
				return TRUE;
		}
		return FALSE;
	}

private:
	int m_count;
	CAsyncProxySocketLayer* m_proxy[PROXY_CHAIN_MAX_HOPS];
	CAsyncSecureSocketLayer* m_secure[PROXY_CHAIN_MAX_HOPS];
};
