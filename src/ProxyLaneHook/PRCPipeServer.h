#pragma once

#include "TSSTL.h"
#include "PRCXServer.h"
#include "structinfo.h"


class CPRCPipeServer
	: public CPRCXServer
{
#define MAXBUFSIZE 4096

	enum
	{
		threadstatus_ok = 0,
		threadstatus_ready,
		threadstatus_error,
		threadstatus_abort,
	};

public:
	CPRCPipeServer(CProxyReceptionCentre *pPRC);
	~CPRCPipeServer(void);

	BOOL StartupServer();
	BOOL ShutdownServer();
	CString GetPipeName();

	void  SetThreadStatus(int status);
	static DWORD WINAPI mainThread(LPVOID lParam);
	DWORD WINAPI _mainThread();

	static DWORD WINAPI InstanceThread(LPVOID lParam);
	DWORD WINAPI _InstanceThread(HANDLE hPipe, HANDLE hThread);

	BOOL WritePipe(HANDLE hPipe, LPVOID lpBuf, int size);
	BOOL ReadPipe(HANDLE hPipe, LPVOID lpBuf, int size);
	BOOL ReadPipeExactly(HANDLE hPipe, LPVOID lpBuf, int size);


private:

	HANDLE m_hNoThreadEvent;
	LONG m_dwThreadCount;
	BOOL m_bExitThread;
	INT  m_threadstatus;
	HANDLE m_hTestEvent;
	HANDLE m_hMainThread;
	HANDLE m_hPipeServer;

	CString m_szPipeName;

	CTSList<HANDLE> m_ChildThreadList;

};
