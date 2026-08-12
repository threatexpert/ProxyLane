/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/


#include "stdafx.h"
#include "PRCPipeClient.h"

CPRCPipeClient::CPRCPipeClient(void)
{
	m_hPipe = INVALID_HANDLE_VALUE;
	m_ConnState = 0;
}

CPRCPipeClient::~CPRCPipeClient(void)
{
	Disconnect();
}

BOOL CPRCPipeClient::IsConnected()
{
	return m_ConnState != 0;
}

BOOL CPRCPipeClient::Connect(LPCTSTR lpszServerName)
{
	BOOL bResult = FALSE;

	m_szFullPipename = lpszServerName;

	ATLTRACE(_T("CPRCPipeClient.Create = %s\r\n"), m_szFullPipename); 

	ATLASSERT(m_hPipe == INVALID_HANDLE_VALUE);

	for(;;)
	{
		//连接管道
		m_hPipe = CreateFile(
			m_szFullPipename, 
			GENERIC_READ|GENERIC_WRITE,
			FILE_SHARE_READ|FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			SECURITY_IMPERSONATION,
			NULL);
		if(m_hPipe != INVALID_HANDLE_VALUE && m_hPipe != NULL)
			break;

		if (GetLastError() == ERROR_ACCESS_DENIED ||
			!WaitNamedPipe(m_szFullPipename, 20000) )
		{
			m_hPipe = INVALID_HANDLE_VALUE;
			return FALSE;
		}
	}

	m_ConnState = 1;
	return TRUE;
}

BOOL CPRCPipeClient::Disconnect()
{
	if (m_hPipe != INVALID_HANDLE_VALUE)
	{
		ATLTRACE(_T("CPRCPipeClient.Disconnect\r\n")); 

		CloseHandle(m_hPipe);
		m_hPipe = INVALID_HANDLE_VALUE;
		m_ConnState = 0;
	}
	return TRUE;
}

DWORD CPRCPipeClient::GetLastError()
{
	return ::GetLastError();
}

BOOL CPRCPipeClient::WritePipe(LPCVOID lpBuf, int size)
{
	ATLASSERT(m_hPipe && m_hPipe != INVALID_HANDLE_VALUE && size>0);

	DWORD nWritten = 0;

	if(!WriteFile(m_hPipe, lpBuf, size, &nWritten, NULL))
		return FALSE;

	return nWritten == (DWORD)size;
}

BOOL CPRCPipeClient::ReadPipe(LPVOID lpBuf, int size)
{
	ATLASSERT(m_hPipe && m_hPipe != INVALID_HANDLE_VALUE && size>0);

	DWORD nRead = 0;
	if(!ReadFile(m_hPipe, lpBuf, size, &nRead, NULL))
		return FALSE;

	return nRead == (DWORD)size;
}


BOOL CPRCPipeClient::GetPRCStartupInfo(LPPRCINFO lpStartupInfo)
{
	PRCPipeDataHead hdr;

	hdr.action = PRCPD_GETSTARTUPINFO;
	hdr.flag = 0;
	hdr.dataSize = 0;

	if(!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(!ReadPipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(hdr.action != PRCPD_REPLY || hdr.flag != 1 || hdr.dataSize != sizeof(*lpStartupInfo))
		return FALSE;

	if(!ReadPipe(lpStartupInfo, hdr.dataSize))
		return FALSE;

	return TRUE;
}


BOOL CPRCPipeClient::PRCRegisterClient(LPPRCClient lpClientInfo)
{
	PRCPipeDataHead hdr;
	WSASetLastError(0);

	hdr.action = PRCPD_REGISTERCLIENT;
	hdr.flag = 0;
	hdr.dataSize = sizeof(*lpClientInfo);

	if(!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(!WritePipe(lpClientInfo, sizeof(*lpClientInfo)))
		return FALSE;

	if(!ReadPipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(hdr.action != PRCPD_REPLY)
	{
		WSASetLastError(WSAEPROTONOSUPPORT);
		return FALSE;
	}
	if (hdr.flag == 0)
	{
		DWORD registrationError = WSAEFAULT;
		if (hdr.dataSize != sizeof(registrationError) ||
			!ReadPipe(&registrationError, sizeof(registrationError)))
			return FALSE;
		WSASetLastError(registrationError);
		return FALSE;
	}
	if (hdr.flag != 1)
	{
		WSASetLastError(WSAEPROTONOSUPPORT);
		return FALSE;
	}

	//TCP Client 注册后无需返回其他数据
	if(lpClientInfo->sType == SOCK_STREAM && hdr.dataSize == 0)
		return TRUE;

	if(lpClientInfo->sType != SOCK_DGRAM || hdr.dataSize != sizeof(*lpClientInfo))
		return FALSE;

	if(!ReadPipe(lpClientInfo, sizeof(*lpClientInfo)))
		return FALSE;

	return TRUE;
}

BOOL CPRCPipeClient::PRCUnregisterClient(LPPRCClient lpClientInfo)
{
	PRCPipeDataHead hdr;

	hdr.action = PRCPD_UNREGISTER_CLIENT;
	hdr.flag = 0;
	hdr.dataSize = sizeof(*lpClientInfo);

	if(!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(!WritePipe(lpClientInfo, sizeof(*lpClientInfo)))
		return FALSE;

	if(!ReadPipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(hdr.action != PRCPD_REPLY || hdr.flag != 1)
		return FALSE;

	return TRUE;
}

BOOL CPRCPipeClient::PRCCanProxyMe(LPPRCClientInfo lpCI)
{
	PRCPipeDataHead hdr;

	hdr.action = PRCPD_CANPROXYME;
	hdr.flag = 0;
	hdr.dataSize = sizeof(*lpCI);

	if(!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;//NO

	if(!WritePipe(lpCI, sizeof(*lpCI)))
		return FALSE;//NO

	if(!ReadPipe(&hdr, sizeof(hdr)))
		return FALSE;//NO

	if(hdr.action != PRCPD_REPLY || !hdr.flag || hdr.dataSize != 0)
		return FALSE;//NO

	return TRUE;//YES
}

BOOL CPRCPipeClient::PRCGetProxySettingsInfo(LPProxySettingsInfo lpPSI)
{
	PRCPipeDataHead hdr;

	hdr.action = PRCPD_GET_SETTINGS_INFO;
	hdr.flag = 0;
	hdr.dataSize = sizeof(*lpPSI);

	if(!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(!ReadPipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(hdr.action != PRCPD_REPLY || hdr.flag != 1 || hdr.dataSize != sizeof(*lpPSI))
		return FALSE;

	if(!ReadPipe(lpPSI, sizeof(*lpPSI)))
		return FALSE;

	return TRUE;
}


BOOL CPRCPipeClient::PRCShouldInjectNewProcess(LPHookNewProcessInfo lphnpi)
{
	PRCPipeDataHead hdr;

	hdr.action = PRCPD_SHOULD_INJECT_NEW_PROCESS;
	hdr.flag = 0;
	hdr.dataSize = sizeof(*lphnpi);

	if(!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(!WritePipe(lphnpi, sizeof(*lphnpi)))
		return FALSE;

	if(!ReadPipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(hdr.action != PRCPD_REPLY || hdr.flag != 1 || hdr.dataSize != 0)
		return FALSE;

	return TRUE;
}

BOOL CPRCPipeClient::PRCNotifyChildInjectionResult(
	LPHookNewProcessInfo lphnpi,
	BOOL succeeded)
{
	PRCPipeDataHead hdr;

	hdr.action = PRCPD_CHILD_INJECTION_RESULT;
	hdr.flag = succeeded ? 1 : 0;
	hdr.dataSize = sizeof(*lphnpi);

	if(!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;

	return WritePipe(lphnpi, sizeof(*lphnpi));
}

BOOL CPRCPipeClient::PRCNotifyChildReleased(LPHookNewProcessInfo lphnpi)
{
	if (!lphnpi || !lphnpi->dwProcessId || !lphnpi->processCreateTime)
		return FALSE;

	PRCPipeDataHead hdr;
	hdr.action = PRCPD_CHILD_RELEASED;
	hdr.flag = 0;
	hdr.dataSize = sizeof(*lphnpi);
	if (!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;
	return WritePipe(lphnpi, sizeof(*lphnpi));
}

BOOL CPRCPipeClient::PRCRegisterProcessIdentity(
	LPHookProcessIdentityInfo identity)
{
	if (!identity || !identity->dwProcessId || !identity->szAppPath[0])
		return FALSE;

	PRCPipeDataHead hdr;
	hdr.action = PRCPD_REGISTER_PROCESS_IDENTITY;
	hdr.flag = 0;
	hdr.dataSize = sizeof(*identity);

	if (!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;

	return WritePipe(identity, sizeof(*identity));
}

BOOL CPRCPipeClient::PRCGetUDPClientPortState(UDPLocalProxyAddrInfo *pLPAI)
{
	PRCPipeDataHead hdr;

	hdr.action = PRCPD_GET_CLIENT_UDPPORT_STATE;
	hdr.flag = 0;
	hdr.dataSize = sizeof(*pLPAI);

	if(!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(!WritePipe(pLPAI, sizeof(*pLPAI)))
		return FALSE;

	if(!ReadPipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(hdr.action != PRCPD_REPLY || !hdr.flag || hdr.dataSize != 0)
		return FALSE;

	return TRUE;
}

BOOL CPRCPipeClient::PRCGetProxyInfo(LPPRCClient lpClientInfo, LPProxyInfo lpPI)
{
	PRCPipeDataHead hdr;

	hdr.action = PRCPD_GET_PROXYINFO;
	hdr.flag = 0;
	hdr.dataSize = sizeof(*lpClientInfo);

	if(!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(!WritePipe(lpClientInfo, sizeof(*lpClientInfo)))
		return FALSE;

	if(!ReadPipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(hdr.action != PRCPD_REPLY || !hdr.flag || hdr.dataSize != sizeof(*lpPI))
		return FALSE;

	if(!ReadPipe(lpPI, sizeof(*lpPI)))
		return FALSE;

	return TRUE;
}

BOOL CPRCPipeClient::PRCNotifyHookWSockResult(
	DWORD err,
	ULONGLONG processCreateTime)
{
	PRCPipeDataHead hdr;
	HookWSockResult result;

	hdr.action = PRCPD_HOOKWSOCK_RESULT;
	hdr.flag = 0;
	hdr.dataSize = sizeof(result);

	result.err = err;
	result.dwProcessId = GetCurrentProcessId();
	result.processCreateTime = processCreateTime;

	if (!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;

	if (!WritePipe(&result, sizeof(result)))
		return FALSE;

	return TRUE;
}

BOOL CPRCPipeClient::PRCLogtext(LPCWSTR lpsz)
{
	PRCPipeDataHead hdr;
	HookLogtext hdr2;

	hdr2.dwProcessId = GetCurrentProcessId();
	hdr2.len = (int)((wcslen(lpsz)+1)*sizeof(lpsz[0]));

	hdr.action = PRCPD_Logtext;
	hdr.flag = 0;
	hdr.dataSize = sizeof(hdr2) + hdr2.len;

	if (!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;

	if (!WritePipe(&hdr2, sizeof(hdr2)))
		return FALSE;

	if (!WritePipe(lpsz, hdr2.len))
		return FALSE;

	return TRUE;
}
