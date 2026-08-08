#pragma once

#include "ProxyModule.h"

class CProxyReceptionCentre;

class CProxyLog
	: public IProxyLog
{
public:
	CProxyLog(void);
	~CProxyLog(void);

	void LogText(LPCWSTR lpText);
	void LogNewProxyTask(const LPPRCClient lpC);
	BOOL OnNewProcess(LPHookNewProcessInfo lphnpi);
	void OnChildInjectionResult(LPHookNewProcessInfo lphnpi, BOOL succeeded);
	void OnHookWsock(LPHookWSockResult res);
	void OnHookLogtext(LPHookLogtext log);

private:

};

void PrintText(const TCHAR *fmt, ...);
void LogNewProxyTask(const LPPRCClient lpC);
void LogUdpFirstDatagram(CProxyReceptionCentre *receptionCentre,
	const LPPRCClient lpC, const LPProxyInfo lpPI);
void LogDnsRedirect(const LPPRCClient lpC);
