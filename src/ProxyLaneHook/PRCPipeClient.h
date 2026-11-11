#pragma once

#include "structinfo.h"

namespace BrowserQuicPolicy { struct Report; }

class CPRCPipeClient
{
public:
	CPRCPipeClient(void);
	~CPRCPipeClient(void);

	BOOL Connect(LPCTSTR lpszServerName);
	BOOL Disconnect();
	BOOL IsConnected();
	DWORD GetLastError();

	BOOL WritePipe(LPCVOID lpBuf, int size);
	BOOL ReadPipe(LPVOID lpBuf, int size);

	BOOL GetPRCStartupInfo(LPPRCINFO lpStartupInfo, bool* quicPolicy = NULL, AppLauncherHostInfo* launcher = NULL);
	BOOL PRCReportQuicStatus(const BrowserQuicPolicy::Report& report);

	BOOL PRCRegisterClient(LPPRCClient lpClientInfo);

	BOOL PRCUnregisterClient(LPPRCClient lpClientInfo);

	BOOL PRCCanProxyMe(LPPRCClientInfo lpCI);

	BOOL PRCGetProxySettingsInfo(LPProxySettingsInfo lpPSI);
	BOOL PRCGetProxyInfo(LPPRCClient lpClientInfo, LPProxyInfo lpPI);

	BOOL PRCShouldInjectNewProcess(LPHookNewProcessInfo lphnpi, bool recordOnly = false);
	BOOL PRCNotifyChildInjectionResult(LPHookNewProcessInfo lphnpi, BOOL succeeded);
	BOOL PRCNotifyChildReleased(LPHookNewProcessInfo lphnpi);
	BOOL PRCRegisterProcessIdentity(LPHookProcessIdentityInfo identity);

	BOOL PRCGetUDPClientPortState(UDPLocalProxyAddrInfo *pLPAI);

	BOOL PRCNotifyHookWSockResult(DWORD err, ULONGLONG processCreateTime);
	BOOL PRCLogtext(LPCWSTR lpsz);
	BOOL PRCLogBlockedIPv6(const HookBlockedIPv6Info& info);
	BOOL PRCLogBlockedUDP(const HookBlockedUdpInfo& info);

private:

	CString m_szFullPipename;
	HANDLE m_hPipe;
	INT    m_ConnState;

};
