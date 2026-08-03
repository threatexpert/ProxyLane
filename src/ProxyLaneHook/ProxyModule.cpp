/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/


#include "stdafx.h"
#include "ProxyModule.h"
#include "GlobalProxy.h"
#include "HookWinsock.h"
#include <shlobj.h>
#include "InjectDll.h"

CGlobalProxy *g_pPMGlobalProxy = NULL;
CHookWinsock *g_pPMHookWs = NULL;
HMODULE g_hDllModule = NULL;

const DWORD ProxyModuleVersion = 20080129;
//////////////////////////////////////////////////////////////////////////

//#pragma comment(linker, "/EXPORT:DllRegisterServer=_DllRegisterServer@0,PRIVATE")
//#pragma comment(linker, "/EXPORT:DllUnregisterServer=_DllUnregisterServer@0,PRIVATE")



STDAPI DllRegisterServer(void)
{
	HRESULT hr = S_OK;


	return hr;
}


STDAPI DllUnregisterServer(void)
{
	HRESULT hr = S_OK;


	return hr;
}



//////////////////////////////////////////////////////////////////////////
//
BOOL APIENTRY DllMain( HANDLE hModule, 
					  DWORD  ul_reason_for_call, 
					  LPVOID lpReserved
					  )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			g_hDllModule = (HMODULE)hModule;
			//WSADATA wsaData;
			//if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
			//	return FALSE;
			//char buf[100];
			//sprintf(buf, "pid=%d", GetCurrentProcessId());
			//MessageBoxA(0, buf, "", 0);
		}


		break;

	case DLL_PROCESS_DETACH:
		{
			gp_UnhookWinsock();
			//WSACleanup();
		}

		break;
	}

	return TRUE;
}

//

IGlobalProxy* WINAPI GetGlobalProxyInstance()
{
	if(!g_pPMGlobalProxy)
		g_pPMGlobalProxy = new CGlobalProxy;

	g_pPMGlobalProxy->AddRef();
	return g_pPMGlobalProxy;
}

BOOL WINAPI ReleaseGlobalProxyInstance()
{
	if(!g_pPMGlobalProxy)
		return FALSE;

	if(g_pPMGlobalProxy->Release() == 0)
	{
		g_pPMGlobalProxy = NULL;
	}
	return TRUE;
}

////////////////////////////////////////



BOOL WINAPI gp_HookWinsock(LPCSTR lpszPRCPipeName)
{
	if (g_pPMHookWs) {
		g_pPMHookWs->SetPRCPipeName(lpszPRCPipeName);

		return FALSE;
	}

	g_pPMHookWs = new CHookWinsock;
	if(!g_pPMHookWs)
		return FALSE;

	g_pPMHookWs->SetPRCPipeName(lpszPRCPipeName);
	return g_pPMHookWs->EnableHook();
}


BOOL WINAPI gp_UnhookWinsock()
{
	if(!g_pPMHookWs)
		return FALSE;

	if(! g_pPMHookWs->DisableHook())
		return FALSE;

	delete g_pPMHookWs;
	g_pPMHookWs = NULL;

	return TRUE;
}

static UINT get_arg(LPSTR lpszIn, LPCSTR lpszOpt, LPSTR lpszBuf, int size)
{
	LPSTR pOpt = strstr(lpszIn, lpszOpt);
	if (!pOpt)
		return 0;

	pOpt += strlen(lpszOpt);

	LPSTR pW = lpszBuf;

	while ( size > 0 )
	{
		if (*pOpt == '\0' || *pOpt == ' ')
		{
			*pW = 0;
			break;
		}

		*pW = *pOpt;
		pW++;
		pOpt++;
		size--;
	}

	return (UINT)(pW - lpszBuf);
}

DWORD WINAPI AttachToI(DWORD dwPid, DWORD dwTid, LPCSTR szPipeName)
{
	DWORD dwExitCode = 0xf;
	HANDLE hProc;
	HANDLE hThread;
	char myDllPath[MAX_PATH];

	HANDLE hRemoteThread = NULL;
	PTHREAD_START_ROUTINE pfnThreadRtn = NULL;
	static unsigned char scspace[64];
	memset(scspace, 0x90, sizeof(scspace));
#ifdef _WIN64
	unsigned char sc_ret[] = { 0xC3 };
	memcpy(scspace + sizeof(scspace)-sizeof(sc_ret), sc_ret, sizeof(sc_ret));
#else
	unsigned char sc_ret[] = { 0xC2, 0x04, 0x00 };
	memcpy(scspace + sizeof(scspace)-sizeof(sc_ret), sc_ret, sizeof(sc_ret));
#endif

	GetModuleFileNameA(g_hDllModule, myDllPath, MAX_PATH);

	hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, dwPid);

	if (dwTid != 0)
	{
		hThread = OpenThread(THREAD_ALL_ACCESS, 0, dwTid);
	}
	else
	{
		pfnThreadRtn = (PTHREAD_START_ROUTINE)
			VirtualAllocEx(hProc, NULL, sizeof(scspace), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!pfnThreadRtn)
		{
			return 0;
		}

		if (!::WriteProcessMemory(hProc, pfnThreadRtn,
			(PVOID)scspace, sizeof(scspace), NULL))
		{
			return 0;
		}

		hRemoteThread = ::CreateRemoteThread(hProc, NULL, 0,
			pfnThreadRtn, NULL, CREATE_SUSPENDED, &dwTid);

		if (!hRemoteThread)
		{
			return 0;
		}

		hThread = hRemoteThread;
	}

	if (hProc && hThread)
	{
		int ret = InjectDll(hProc, hThread, myDllPath, szPipeName);
		if (ret == 1)
		{
			if (hRemoteThread)
				ResumeThread(hRemoteThread);

			dwExitCode = 0xFF01;
		}

		CloseHandle(hProc);
		CloseHandle(hThread);
	}

	return dwExitCode;
}

void CALLBACK AttachTo(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
// #ifdef _WIN64
// 	MessageBoxA(hwnd, "dbg", "", 0);
// #endif

	DWORD dwPid;
	DWORD dwTid;
	char szOpt[256];
	char szPipeName[128];

	memset(szOpt, 0, sizeof(szOpt));

	if (!get_arg(lpszCmdLine, "--pid=", szOpt, sizeof(szOpt)-1))
		return;

	dwPid = strtoul(szOpt, NULL, 10);

	if (!get_arg(lpszCmdLine, "--tid=", szOpt, sizeof(szOpt)-1))
		return;

	dwTid = strtoul(szOpt, NULL, 10);

	memset(szPipeName, 0, sizeof(szPipeName));
	if (!get_arg(lpszCmdLine, "--pipe=", szPipeName, sizeof(szPipeName)-1))
		return;

	ExitProcess(AttachToI(dwPid, dwTid, szPipeName));
}
