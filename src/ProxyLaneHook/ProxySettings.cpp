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