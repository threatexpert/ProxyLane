#include "stdafx.h"
#include "ProxySettings.h"

CProxySettings::CProxySettings(void)
{
}

CProxySettings::~CProxySettings(void)
{
}

BOOL CProxySettings::GetProxyInfo(const LPPRCClient pPRCC, LPProxyInfo lpPI)
{
	IProxySettings *p = IProxySettings::m_pNext;
	while(p)
	{
		if(p->GetProxyInfo(pPRCC, lpPI))
			return TRUE;
		p = p->m_pNext;
	}

	return FALSE;
}

INT CProxySettings::GetProxyChain(const LPPRCClient pPRCC, LPProxyInfo lpHops, INT nCapacity)
{
	IProxySettings *p = IProxySettings::m_pNext;
	while(p)
	{
		const INT hops = p->GetProxyChain(pPRCC, lpHops, nCapacity);
		if(hops)
			return hops;
		p = p->m_pNext;
	}

	return 0;
}

BOOL CProxySettings::GetProxySettings(LPProxySettingsInfo lpPSI)
{
	IProxySettings *p = IProxySettings::m_pNext;
	while(p)
	{
		if(p->GetProxySettings(lpPSI))
			return TRUE;
		p = p->m_pNext;
	}

	return FALSE;
}