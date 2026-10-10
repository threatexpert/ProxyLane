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
	BOOL ShouldInjectNewProcess(LPHookNewProcessInfo lphnpi);
	void OnChildInjectionResult(LPHookNewProcessInfo lphnpi, BOOL succeeded);
	void OnHookWsock(LPHookWSockResult res);
	void OnHookLogtext(LPHookLogtext log);
	void OnConnectionFailure(const LPPRCClient client, LPCWSTR processName,
		ConnectionStage stage, DWORD error);
	void OnConnectionEvent(ConnectionEvent event, const LPPRCClient client,
		LPCWSTR processName);

private:

};

void PrintText(const TCHAR *fmt, ...);
void LogNewProxyTask(const LPPRCClient lpC);
void LogConnectionFailure(const LPPRCClient client, LPCWSTR processName,
	IProxyLog::ConnectionStage stage, DWORD error);
void LogConnectionEvent(IProxyLog::ConnectionEvent event, const LPPRCClient client,
	LPCWSTR processName);
void LogUdpFirstDatagram(CProxyReceptionCentre *receptionCentre,
	const LPPRCClient lpC, const LPProxyInfo lpPI);
void LogDnsRedirect(const LPPRCClient lpC);
