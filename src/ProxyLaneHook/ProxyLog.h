#pragma once

#include "ProxyModule.h"

class CProxyLog
	: public IProxyLog
{
public:
	CProxyLog(void);
	~CProxyLog(void);

	void LogText(LPCWSTR lpText);
	void LogNewProxyTask(const LPPRCClient lpC);
	void OnNewProcess(LPHookNewProcessInfo lphnpi);
	void OnHookWsock(LPHookWSockResult res);
	void OnHookLogtext(LPHookLogtext log);

private:

};

void PrintText(const TCHAR *fmt, ...);
void LogNewProxyTask(const LPPRCClient lpC);
