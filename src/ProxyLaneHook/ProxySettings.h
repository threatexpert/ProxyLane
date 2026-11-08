#pragma once

#include "ProxyModule.h"

class CProxySettings
	: public IProxySettings
{
public:
	CProxySettings(void);
	~CProxySettings(void);


	BOOL GetProxyInfo(const LPPRCClient pPRCC, LPProxyInfo lpPI);
	BOOL GetProxySettings(LPProxySettingsInfo lpPSI);
	INT GetProxyChain(const LPPRCClient pPRCC, LPProxyInfo lpHops, INT nCapacity);

};
