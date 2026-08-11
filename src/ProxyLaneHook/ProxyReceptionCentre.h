#pragma once

#include "ProxyModule.h"
#include "PRCPipeServer.h"
#include "PRCTcpServer.h"
#include "PRCUdpServer.h"
#include "TimerQueue.h"
#include <map>

class CGlobalProxy;
class CProxyDataHandle;

class CProxyReceptionCentre
	: public IProxyReceptionCentre
	, public CWndTimer
{
public:
	CProxyReceptionCentre(CGlobalProxy *pGlobalProxy);
	~CProxyReceptionCentre(void);

	//重载
	BOOL GetPRCPipeName(LPSTR lpBuf, int bufsize);
	IProxyTaskMgr* GetPTMInstance(int type);
	IProxyDataHandle* GetPDHInstance();
	//
	BOOL CreatePRC();
	BOOL DestroyPRC();
	CString GetLastErrorText() const { return m_szLastError; }


	VOID OnTimer(UINT_PTR nIDEvent);

	BOOL GetStartupInfo(LPPRCINFO lpStartupInfo);

	BOOL IsFiltered(LPPRCClient lpClient);
	BOOL IsFiltered(LPPRCClientInfo lpClientInfo);

	BOOL RegisterClient(LPPRCClient lpClientInfo);
	BOOL RegisterTCPClient(LPPRCClient lpClientInfo);
	BOOL RegisterUDPClient(LPPRCClient lpClientInfo);
	BOOL GetUDPClientPortState(UDPLocalProxyAddrInfo *pLPAI);
	BOOL UnregisterClient(LPPRCClient lpClientInfo);
	BOOL GetProxySettingsInfo(LPProxySettingsInfo lpPSI);
	BOOL GetProxyInfo(LPPRCClient lpClientInfo, LPProxyInfo lpPI);

	BOOL GetClientInfo(SOCKET accepted, LPPRCClient lpClientInfo, BOOL bpop=FALSE);
	BOOL RegisterProcessIdentity(LPHookProcessIdentityInfo identity);
	BOOL RegisterReleasedChild(LPHookNewProcessInfo child);
	BOOL GetProcessIdentity(DWORD processId, LPWSTR appPath, DWORD appPathCount);


protected:

	typedef enum
	{
		threadstatus_inactive,
		threadstatus_error,
		threadstatus_running,
		threadstatus_end,
	}threadstatus;

	threadstatus m_ThreadStatus;

	HANDLE m_hTestEvent;
	HWND m_PRCWnd;
	void SetThreadStatus(threadstatus status);

	static LRESULT CALLBACK PRCWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
	//BOOL InitPRCWnd();
	//BOOL ClosePRCWnd();

	static DWORD WINAPI _PRCThreadProc(LPVOID lParam);
	DWORD WINAPI InternalPRCThreadProc();

	BOOL StartupPRCServer();
	BOOL ShutdownPRCServer();

private:
	struct SuspendedChildObservation
	{
		ULONGLONG processCreateTime;
		ULONGLONG cpuTime;
		DWORD consecutiveChecks;
	};
	void CheckSuspendedChildren();
	CString m_szLastError;

	HANDLE m_hPRCThread;
	DWORD m_dwPRCThreadId;
	CPRCTcpServer *m_pTcpServer;
	CPRCTcpServer *m_pTcpServer6;
	CPRCUdpServer *m_pUdpServer;
	CPRCPipeServer *m_pPipeServer;
	CProxyDataHandle *m_pProxyDataHandle;

	CTSList<PRCClient> m_RegisteredClient;
	std::map<DWORD, HookProcessIdentityInfo> m_ProcessIdentities;
	std::map<DWORD, ULONGLONG> m_ReleasedChildren;
	std::map<DWORD, SuspendedChildObservation> m_SuspendedChildObservations;
	std::map<DWORD, ULONGLONG> m_ProcessedSuspendedChildren;
	CRITICAL_SECTION m_ProcessIdentityLock;

public:

	CGlobalProxy *m_pGlobalProxy;

};
