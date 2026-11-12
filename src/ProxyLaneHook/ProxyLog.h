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
	BOOL GetAppLauncherHostInfo(AppLauncherHostInfo* info);
	BOOL LaunchAppFromShell(const AppLauncherRequest& request, AppLauncherResult& result);
	void OnProxyFailure(const LPPRCClient client, LPCWSTR processName,
		LPCWSTR target, BOOL connectingProxy, DWORD error, LPCWSTR detail);

private:

};

void PrintText(const TCHAR *fmt, ...);
CString GetDnsLogProcessName(CProxyReceptionCentre* receptionCentre, const PRCClient& client);
void LogDnsRelay(DWORD pid, LPCSTR name, LPCSTR type, LPCSTR result, LPCWSTR processName = NULL);
void LogDnsRelayRoute(const PRCClient* client, LPCSTR result, CProxyReceptionCentre* receptionCentre = NULL);
void LogDohTargetSelection(CProxyReceptionCentre* receptionCentre,
    const PRCClient* client, size_t attempt = 0, size_t total = 0);
void LogNewProxyTask(const LPPRCClient lpC);
void LogConnectionFailure(const LPPRCClient client, LPCWSTR processName,
	IProxyLog::ConnectionStage stage, DWORD error);
void LogConnectionEvent(IProxyLog::ConnectionEvent event, const LPPRCClient client,
	LPCWSTR processName);
void LogUdpFirstDatagram(CProxyReceptionCentre *receptionCentre,
	const LPPRCClient lpC, const LPProxyInfo lpPI);
void LogDnsRedirect(const LPPRCClient lpC, LPCWSTR processName,
    CProxyReceptionCentre* receptionCentre = NULL);
void LogProxyFailure(CProxyReceptionCentre* receptionCentre, const LPPRCClient client,
	BOOL connectingProxy, int socketError, LPCSTR detail);
