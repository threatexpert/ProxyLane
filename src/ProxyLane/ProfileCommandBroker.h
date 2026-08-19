#pragma once

#include "AutomationOptions.h"

#include <vector>

#define WM_PROFILE_COMMAND_REQUEST (WM_APP + 104)

enum ProfileCommandForwardResult
{
	PROFILE_COMMAND_NOT_FOUND = 0,
	PROFILE_COMMAND_HANDLED,
	PROFILE_COMMAND_TRANSPORT_FAILED
};

class CProfileCommandRequest
{
public:
	CProfileCommandRequest();
	~CProfileCommandRequest();

	void AddRef();
	void Release();

	LONG references;
	LONG cancelled;
	HANDLE completedEvent;
	CString profileName;
	CString targetPath;
	std::vector<CString> targetArguments;
	int exitCode;
};

class CProfileCommandBroker
{
public:
	CProfileCommandBroker();
	~CProfileCommandBroker();

	ProfileCommandForwardResult Forward(
		const AutomationOptions& options,
		int& exitCode);
	BOOL AcquireLaunchGate(LPCTSTR profileName);
	void ReleaseLaunchGate();

	BOOL StartServer(LPCTSTR profileName, HWND notifyWindow);
	void StopServer();
	BOOL IsServerActive(LPCTSTR profileName = NULL) const;

private:
	static DWORD WINAPI ServerThreadProc(LPVOID context);
	DWORD ServerThread();
	BOOL ProcessClient(HANDLE pipeHandle);

	CString m_profileName;
	CString m_pipeName;
	CString m_mutexName;
	HWND m_notifyWindow;
	HANDLE m_stopEvent;
	HANDLE m_readyEvent;
	HANDLE m_serverThread;
	HANDLE m_launchGate;
	volatile LONG m_serverReady;
};
