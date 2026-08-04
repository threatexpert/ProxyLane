#pragma once

#include "structinfo.h"

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

	BOOL GetPRCStartupInfo(LPPRCINFO lpStartupInfo);

	BOOL PRCRegisterClient(LPPRCClient lpClientInfo);

	BOOL PRCUnregisterClient(LPPRCClient lpClientInfo);

	BOOL PRCCanProxyMe(LPPRCClientInfo lpCI);

	BOOL PRCGetProxySettingsInfo(LPProxySettingsInfo lpPSI);
	BOOL PRCGetProxyInfo(LPPRCClient lpClientInfo, LPProxyInfo lpPI);

	BOOL PRCNotifyNewProcess(LPHookNewProcessInfo lphnpi);
	BOOL PRCNotifyChildInjectionResult(LPHookNewProcessInfo lphnpi, BOOL succeeded);
	BOOL PRCRegisterProcessIdentity(LPHookProcessIdentityInfo identity);

	BOOL PRCGetUDPClientPortState(UDPLocalProxyAddrInfo *pLPAI);

	BOOL PRCNotifyHookWSockResult(DWORD err);
	BOOL PRCLogtext(LPCWSTR lpsz);

private:

	CString m_szFullPipename;
	HANDLE m_hPipe;
	INT    m_ConnState;

};
