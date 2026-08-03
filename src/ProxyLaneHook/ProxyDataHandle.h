#pragma once

#include "ProxyModule.h"

class CProxyDataHandle
	: public IProxyDataHandle
{
public:

	CProxyDataHandle(void)
	{
	}

	~CProxyDataHandle(void)
	{
	}

	void OnConnect(LPProxyPacketInfo lpppi)
	{
		IProxyDataHandle *p = IProxyDataHandle::m_pNext;
		while(p)
		{
			p->OnConnect(lpppi);
			p = p->m_pNext;
		}
	}

	void OnEachPacket(LPProxyPacketInfo lpppi)
	{
		IProxyDataHandle *p = IProxyDataHandle::m_pNext;
		while(p)
		{
			p->OnEachPacket(lpppi);
			p = p->m_pNext;
		}
	}

	void OnClose(LPProxyPacketInfo lpppi)
	{
		IProxyDataHandle *p = IProxyDataHandle::m_pNext;
		while(p)
		{
			p->OnClose(lpppi);
			p = p->m_pNext;
		}
	}

	void OnLayerCallback(LPProxyPacketInfo lpppi, int nType, int nCode, WPARAM wParam, LPARAM lParam)
	{
		IProxyDataHandle *p = IProxyDataHandle::m_pNext;
		while(p)
		{
			p->OnLayerCallback(lpppi, nType, nCode, wParam, lParam);
			p = p->m_pNext;
		}
	}

};
