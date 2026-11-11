#pragma once

#include "ProxyModule.h"
#include "ProxyMonitor.h"

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
		CProxyMonitor::Instance().RecordPacket(lpppi, 5, lpppi->errcode ? "Connection failed" : "Connected");
		IProxyDataHandle *p = IProxyDataHandle::m_pNext;
		while(p)
		{
			p->OnConnect(lpppi);
			p = p->m_pNext;
		}
	}

	void OnEachPacket(LPProxyPacketInfo lpppi)
	{
		DispatchPacket(lpppi, true);
	}

	// A MITM session supplies classified plaintext/passthrough monitor events.
	// Other observers still receive the original network packets unchanged.
	void DispatchPacket(LPProxyPacketInfo lpppi, bool monitor)
	{
		if (monitor) CProxyMonitor::Instance().RecordPacket(lpppi, lpppi->datafrom ? 4 : 3);
		IProxyDataHandle *p = IProxyDataHandle::m_pNext;
		while(p)
		{
			p->OnEachPacket(lpppi);
			p = p->m_pNext;
		}
	}

	void OnClose(LPProxyPacketInfo lpppi)
	{
		CProxyMonitor::Instance().RecordPacket(lpppi, 5, "Closed");
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
