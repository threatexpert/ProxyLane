#pragma once

#include "asynsocket\AsyncSocketEx.h"
#include "asynsocket\AsyncProxySocketLayer.h"
#include "asynsocket\AsyncSecureSocketLayer.h"
#include "asynsocket\AsyncSshSocketLayer.h"
#include "ProxyModule.h"
#include "ProxyTransportPolicy.h"

// The layers of a strict proxy chain on one socket. Owners allocate it only
// for a chained connection, so a single upstream pays nothing for it.
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
	BOOL Add(CAsyncSocketEx& socket, const ProxyInfo* hops, int count,
        SshSessionUse sshUse = SshSessionUse::Business, SshSession* dependent = NULL)
	{
		if (!m_hops.empty() || !hops || count < 1)
		{
			WSASetLastError(WSAEINVAL);
			return FALSE;
		}
		m_hops.assign(hops, hops + count);
		m_proxy.assign(count, NULL);
		m_secure.assign(count, NULL);
		for (int i = count - 1; i >= 0; --i)
		{
			ProxyInfo& hop = m_hops[i];
			const int type = hop.GetProxyType();
			const bool secure = ProxyTransportPolicy::UsesGoncTlsPsk(&hop);
			if ((type != PROXYTYPE_SOCKS5 && type != PROXYTYPE_HTTP10 && type != PROXYTYPE_HTTP11 && type != PROXYTYPE_SSH) ||
				!hop.strProxyHost.szbuf[0] || !hop.nProxyPort ||
				(type == PROXYTYPE_SSH && (hop.reserved != PROXY_TRANSPORT_PLAIN || !hop.strProxyUser.szbuf[0])) ||
				(secure && !hop.strTransportPsk.szbuf[0]))
			{
				WSASetLastError(WSAEINVAL);
				return FALSE;
			}

			if (type == PROXYTYPE_SSH)
			{
				m_proxy[i] = new CAsyncSshSocketLayer(ProxyChain(hops, hops + i + 1), sshUse, dependent);
				// The shared session owns all preceding hops. This socket owns
				// only its channel adapter and the hops above that adapter.
				return socket.AddLayer(m_proxy[i]);
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
		for (size_t i = 0; i < m_proxy.size(); ++i)
		{
			delete m_proxy[i];
			delete m_secure[i];
		}
		m_proxy.clear();
		m_secure.clear();
		m_hops.clear();
	}

	int Count() const { return (int)m_hops.size(); }
	const ProxyInfo& Hop(int index) const { return m_hops[index]; }

	// The last hop's proxy layer: the one nearest the application.
	CAsyncProxySocketLayer* Top() const { return m_proxy.empty() ? NULL : m_proxy.back(); }

	// The hop a proxy or TLS layer belongs to, or -1.
	int HopOf(const CAsyncSocketExLayer* layer) const
	{
		for (size_t i = 0; layer && i < m_proxy.size(); ++i)
		{
			if (layer == m_proxy[i] || layer == m_secure[i])
				return m_proxy[i] && m_proxy[i]->FailedHop() >= 0 ? m_proxy[i]->FailedHop() : (int)i;
		}
		return -1;
	}

	// The first hop whose proxy handshake has not finished, or -1. Every
	// layer starts its connect operation at once and resets it on success, so
	// on a timeout the lowest unfinished hop is the one that stalled.
	int StalledHop() const
	{
		for (size_t i = 0; i < m_proxy.size(); ++i)
		{
			if (m_proxy[i] && m_proxy[i]->GetProxyOpID() != 0)
				return (int)i;
		}
		return -1;
	}

	BOOL HasPendingSecureRead() const
	{
		for (size_t i = 0; i < m_secure.size(); ++i)
		{
			if (m_proxy[i] && m_proxy[i]->HasPendingRead()) return TRUE;
			if (m_secure[i] && m_secure[i]->HasPendingRead())
				return TRUE;
		}
		return FALSE;
	}

	BOOL HasSsh() const
	{
		for (auto hop : m_hops) if (hop.GetProxyType() == PROXYTYPE_SSH) return TRUE;
		return FALSE;
	}
private:
	ProxyChain m_hops;
	std::vector<CAsyncProxySocketLayer*> m_proxy;
	std::vector<CAsyncSecureSocketLayer*> m_secure;
};
