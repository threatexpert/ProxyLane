/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/


#include "stdafx.h"
#include "PRCPipeClient.h"
#include "BrowserQuicPolicy.h"
#include "AppContainerPipeAccess.h"
#include "ProcessCreationSnapshot.h"

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
		// GENERIC_WRITE includes FILE_CREATE_PIPE_INSTANCE. Clients only need
		// message I/O; do not request the right to create a competing server.
		m_hPipe = CreateFile(
			m_szFullPipename, 
			PROXYLANE_PIPE_CLIENT_ACCESS,
			FILE_SHARE_READ|FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
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

	if (nWritten != (DWORD)size) { ::SetLastError(ERROR_WRITE_FAULT); return FALSE; }
	return TRUE;
}

BOOL CPRCPipeClient::ReadPipe(LPVOID lpBuf, int size)
{
	ATLASSERT(m_hPipe && m_hPipe != INVALID_HANDLE_VALUE && size>0);

	DWORD nRead = 0;
	if(!ReadFile(m_hPipe, lpBuf, size, &nRead, NULL))
		return FALSE;

	if (nRead != (DWORD)size) { ::SetLastError(ERROR_INVALID_DATA); return FALSE; }
	return TRUE;
}


BOOL CPRCPipeClient::GetPRCStartupInfo(LPPRCINFO lpStartupInfo, bool* quicPolicy, AppLauncherHostInfo* launcher)
{
    PRCPipeDataHead hdr={};hdr.action=PRCPD_GETSTARTUPINFO;
    // Opt-in extension: old hosts ignore the flag and return the original size;
    // old clients receive the original layout from new hosts.
    hdr.flag=launcher?3:(quicPolicy?2:0);if(quicPolicy)*quicPolicy=false;
    if(launcher) ZeroMemory(launcher,sizeof(*launcher));
    if(!WritePipe(&hdr,sizeof(hdr))||!ReadPipe(&hdr,sizeof(hdr)))return FALSE;
    if(hdr.action!=PRCPD_REPLY||hdr.flag!=1 ||
        (hdr.dataSize!=sizeof(*lpStartupInfo)&&
        (!(quicPolicy||launcher)||hdr.dataSize!=sizeof(*lpStartupInfo)+sizeof(DWORD))&&
        (!launcher||hdr.dataSize!=sizeof(*lpStartupInfo)+sizeof(DWORD)+sizeof(*launcher)))) {
        ::SetLastError(ERROR_INVALID_DATA); return FALSE;
    }
    if(!ReadPipe(lpStartupInfo,sizeof(*lpStartupInfo)))return FALSE;
    if(hdr.dataSize>sizeof(*lpStartupInfo)) {DWORD flags=0;if(!ReadPipe(&flags,sizeof(flags)))return FALSE;if(quicPolicy)*quicPolicy=(flags&1)!=0;}
    if(launcher && hdr.dataSize==sizeof(*lpStartupInfo)+sizeof(DWORD)+sizeof(*launcher)) {
        if(!ReadPipe(launcher,sizeof(*launcher)))return FALSE;
        if(launcher->version!=1 || !launcher->processId || !launcher->creationTime ||
            !launcher->executable[0] || launcher->executable[MAX_PATH-1]) ZeroMemory(launcher,sizeof(*launcher));
    }
    return TRUE;
}
BOOL CPRCPipeClient::PRCReportQuicStatus(const BrowserQuicPolicy::Report& report)
{
    PRCPipeDataHead hdr={};hdr.action=PRCPD_QUIC_STATUS;hdr.flag=1;hdr.dataSize=sizeof(report);
    return WritePipe(&hdr,sizeof(hdr))&&WritePipe(&report,sizeof(report))&&ReadPipe(&hdr,sizeof(hdr))
        &&hdr.action==PRCPD_REPLY&&hdr.flag==1&&hdr.dataSize==0;
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
	{ ::SetLastError(ERROR_INVALID_DATA); return FALSE; }

	if(!ReadPipe(lpPSI, sizeof(*lpPSI)))
		return FALSE;

	return TRUE;
}


BOOL CPRCPipeClient::PRCShouldInjectNewProcess(LPHookNewProcessInfo lphnpi, bool recordOnly)
{
	PRCPipeDataHead hdr;
    const HookProcessCreationNotice notice = MakeProcessCreationNotice(*lphnpi);

	hdr.action = PRCPD_SHOULD_INJECT_NEW_PROCESS;
	hdr.flag = recordOnly ? 1 : 0;
	hdr.dataSize = sizeof(notice);

	if(!WritePipe(&hdr, sizeof(hdr)))
		return FALSE;

	if(!WritePipe(&notice, sizeof(notice)))
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

	if(hdr.action != PRCPD_REPLY || !hdr.flag || hdr.dataSize != PROXYINFO_PIPE_SIZE)
		return FALSE;

	ZeroMemory(lpPI, sizeof(*lpPI));
	if(!ReadPipe(lpPI, PROXYINFO_PIPE_SIZE))
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

BOOL CPRCPipeClient::PRCLogBlockedIPv6(const HookBlockedIPv6Info& info)
{
	PRCPipeDataHead header = { 0 };
	header.action = PRCPD_BLOCKED_IPV6;
	header.dataSize = sizeof(info);
	return WritePipe(&header, sizeof(header)) && WritePipe(&info, sizeof(info));
}

BOOL CPRCPipeClient::PRCLogBlockedUDP(const HookBlockedUdpInfo& info)
{
	PRCPipeDataHead header = { 0 };
	header.action = PRCPD_BLOCKED_UDP;
	header.dataSize = sizeof(info);
	return WritePipe(&header, sizeof(header)) && WritePipe(&info, sizeof(info));
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
