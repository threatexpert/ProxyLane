/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "PRCPipeServer.h"
#include "GlobalProxy.h"
#include "ProxyReceptionCentre.h"
#include "token.h"

#include <new>

//CString g_szPRCPipeServerName;
GUID g_GuidPipeName;

CPRCPipeServer::CPRCPipeServer(CProxyReceptionCentre *pPRC)
	: CPRCXServer(pPRC)
{
	m_hTestEvent = NULL;
	m_hPipeServer = NULL;
	m_hMainThread = NULL;
	m_dwThreadCount = 0;
	m_hNoThreadEvent = NULL;
}

CPRCPipeServer::~CPRCPipeServer(void)
{
	ShutdownServer();
}


BOOL CPRCPipeServer::StartupServer()
{
	CString strGuid;
	GUID guid;
	CONST INT nGUIDLen = 16;
	UCHAR szGUID[nGUIDLen+1] = {0};

	memset(&guid, 0, sizeof(GUID));

	//每次进程第一次 启动 的时候 才创建一个 guid
	if(memcmp(&g_GuidPipeName, &guid, sizeof(GUID)) == 0)
	{
		if(CoCreateGuid(&g_GuidPipeName) != S_OK)
			return FALSE;
	}

	memcpy(&guid, &g_GuidPipeName, sizeof(GUID));
	memcpy(szGUID, &guid, nGUIDLen);

	strGuid.Format(_T("{%.2X%.2X%.2X%.2X-%.2X%.2X-%.2X%.2X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X}"),
		szGUID[0],szGUID[1],szGUID[2],szGUID[3],szGUID[4],szGUID[5],szGUID[6],szGUID[7],
		szGUID[8],szGUID[9],szGUID[10],szGUID[11],szGUID[12],szGUID[13],szGUID[14],szGUID[15]);

	m_szPipeName.Format(_T("\\\\.\\pipe\\PRCPipeName%s"), strGuid);

	//m_szPipeName.Format(_T("\\\\.\\pipe\\%s"), PRC_PIPESERVER_NAME);

	ATLTRACE(_T("PRCPipeName: %s\r\n"), m_szPipeName);

	m_hTestEvent = CreateEvent(0, 0, 0, 0);
	m_hNoThreadEvent = CreateEvent(0, 0, 1, 0);//初始化信号， 表示一开始没client pipe的线程
	if(m_hTestEvent == NULL || m_hNoThreadEvent == NULL)
	{
		if (m_hTestEvent)
			CloseHandle(m_hTestEvent);
		if (m_hNoThreadEvent)
			CloseHandle(m_hNoThreadEvent);
		m_hTestEvent = NULL;
		m_hNoThreadEvent = NULL;
		return FALSE;
	}

	m_bExitThread = FALSE;
	m_threadstatus = threadstatus_ok;
	m_hMainThread = CreateThread(0, 0, mainThread, this, 0, NULL);
	if(m_hMainThread == NULL)
	{
		CloseHandle(m_hTestEvent);
		CloseHandle(m_hNoThreadEvent);
		m_hTestEvent = NULL;
		m_hNoThreadEvent = NULL;
		return FALSE;
	}

	WaitForSingleObject(m_hTestEvent, INFINITE);
	if(m_threadstatus != threadstatus_ready)
	{
		WaitForSingleObject(m_hMainThread, INFINITE);
		CloseHandle(m_hMainThread);
		m_hMainThread = NULL;
		CloseHandle(m_hTestEvent);
		m_hTestEvent = NULL;
		CloseHandle(m_hNoThreadEvent);
		m_hNoThreadEvent = NULL;
		return FALSE;
	}

	return TRUE;
}


BOOL CPRCPipeServer::ShutdownServer()
{
	if(m_hMainThread)
	{
		m_bExitThread = TRUE;
		HANDLE hPipe = CreateFile( 
			m_szPipeName,   // pipe name 
			GENERIC_READ |  // read and write access 
			GENERIC_WRITE, 
			0,              // no sharing 
			NULL,           // no security attributes
			OPEN_EXISTING,  // opens existing pipe 
			0,              // default attributes 
			NULL);          // no template file

		if(hPipe != INVALID_HANDLE_VALUE)
			CloseHandle(hPipe);

		WaitForSingleObject(m_hMainThread, INFINITE);
		CloseHandle(m_hMainThread);
		m_hMainThread = NULL;

		if (m_hNoThreadEvent)
			WaitForSingleObject(m_hNoThreadEvent, INFINITE);

		ATLASSERT(m_dwThreadCount == 0);
		ATLASSERT(m_ChildThreadList.size() == 0);

	}
	if(m_hNoThreadEvent)
	{
		CloseHandle(m_hNoThreadEvent);
		m_hNoThreadEvent = NULL;
	}

	if(m_hTestEvent)
	{
		CloseHandle(m_hTestEvent);
		m_hTestEvent = NULL;
	}
	return TRUE;
}

CString CPRCPipeServer::GetPipeName()
{
	return m_szPipeName;
}

void CPRCPipeServer::SetThreadStatus(int status)
{
	m_threadstatus = status;
	SetEvent(m_hTestEvent); 
}

DWORD WINAPI CPRCPipeServer::mainThread(LPVOID lParam)
{
	return ((CPRCPipeServer*)lParam)->_mainThread();
}

DWORD WINAPI CPRCPipeServer::_mainThread()
{
	BOOL bInit = FALSE;

	CSecurityAttributes sa;

	sa.CreateSD(_T("Everyone"), GENERIC_READ|GENERIC_WRITE, 0);
	sa.LowIntegrity();

	for(;;)
	{
		m_hPipeServer = CreateNamedPipe( 
			m_szPipeName,             // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_MESSAGE |       // message type pipe 
			PIPE_READMODE_MESSAGE |   // message-read mode 
			PIPE_WAIT,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			MAXBUFSIZE,                  // output buffer size 
			MAXBUFSIZE,                  // input buffer size 
			INFINITE,                   // client time-out 
			&sa);                    // default security attribute 

		if (m_hPipeServer == INVALID_HANDLE_VALUE) 
		{
			ATLTRACE("CreatePipe failed: %d\r\n", GetLastError());
			SetThreadStatus(threadstatus_error);
			return 0;
		}

		if(!bInit)
		{
			SetThreadStatus(threadstatus_ready);
			bInit = TRUE;
		}

		BOOL fConnected = ConnectNamedPipe(m_hPipeServer, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 

		if(m_bExitThread)
		{
			if (fConnected)
				DisconnectNamedPipe(m_hPipeServer);
			CloseHandle(m_hPipeServer);
			m_hPipeServer = NULL;
			SetThreadStatus(threadstatus_abort);
			break;
		}

		if(fConnected)
		{
			DWORD_PTR *pParam = new (std::nothrow) DWORD_PTR[3];
			if (!pParam)
			{
				DisconnectNamedPipe(m_hPipeServer);
				CloseHandle(m_hPipeServer);
				m_hPipeServer = NULL;
				continue;
			}
			pParam[0] = (DWORD_PTR)this;
			pParam[1] = (DWORD_PTR)m_hPipeServer;
			pParam[2] = 0;
			HANDLE hThread = CreateThread(0, 0, InstanceThread, pParam, CREATE_SUSPENDED, NULL);
			if (!hThread)
			{
				delete[] pParam;
				DisconnectNamedPipe(m_hPipeServer);
				CloseHandle(m_hPipeServer);
				m_hPipeServer = NULL;
				continue;
			}
			pParam[2] = (DWORD_PTR)hThread;

			//清除信号
			InterlockedIncrement(&m_dwThreadCount);
			ResetEvent(m_hNoThreadEvent);
			{
				CTSList<HANDLE>::critical lc = m_ChildThreadList;
				m_ChildThreadList.push_back(hThread);
			}
			if (ResumeThread(hThread) == (DWORD)-1)
			{
				{
					CTSList<HANDLE>::critical lc = m_ChildThreadList;
					m_ChildThreadList.remove(hThread);
				}
				if (TerminateThread(hThread, 0))
					WaitForSingleObject(hThread, INFINITE);
				CloseHandle(hThread);
				delete[] pParam;
				DisconnectNamedPipe(m_hPipeServer);
				CloseHandle(m_hPipeServer);
				m_hPipeServer = NULL;
				if (InterlockedDecrement(&m_dwThreadCount) == 0)
					SetEvent(m_hNoThreadEvent);
				continue;
			}

			// 管道和线程句柄的所有权已交给 InstanceThread。
			m_hPipeServer = NULL;

		}
		else
		{
			CloseHandle(m_hPipeServer);
			m_hPipeServer = NULL;
		}
	}

	return 0;
}

DWORD WINAPI CPRCPipeServer::InstanceThread(LPVOID lParam) 
{
	DWORD_PTR *pParam = (DWORD_PTR*)lParam;
	CPRCPipeServer *_this = (CPRCPipeServer*)pParam[0];
	HANDLE hPipe = (HANDLE)pParam[1];
	HANDLE hThread = (HANDLE)pParam[2];
	delete[] pParam;
	return _this->_InstanceThread(hPipe, hThread);
}

DWORD WINAPI CPRCPipeServer::_InstanceThread(HANDLE hPipe, HANDLE hThread)
{
	BOOL bRet;
	PRCPipeDataHead hdr;
	ULONG pipeClientPid = 0;
	typedef BOOL (WINAPI *PFN_GET_NAMED_PIPE_CLIENT_PROCESS_ID)(HANDLE, PULONG);
	HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
	PFN_GET_NAMED_PIPE_CLIENT_PROCESS_ID getClientProcessId = kernel32
		? (PFN_GET_NAMED_PIPE_CLIENT_PROCESS_ID)GetProcAddress(kernel32,
			"GetNamedPipeClientProcessId") : NULL;
	if (getClientProcessId && !getClientProcessId(hPipe, &pipeClientPid))
		goto SEC_ERROR;
	
	for(; !m_bExitThread ;)
	{

		DWORD TotalBytesAvail = 0;

		if (!PeekNamedPipe(
			hPipe,
			NULL,
			NULL,
			NULL,
			&TotalBytesAvail,
			NULL)
			)
			break;

		if (!TotalBytesAvail)
		{
			Sleep(10);
			continue;
		}

		bRet = ReadPipe(hPipe, &hdr, sizeof(hdr));
		if(! bRet)
			break;

		switch(hdr.action)
		{
		case PRCPD_GETSTARTUPINFO:
			{
				PRCINFO info;
				if (!m_pPRC->GetStartupInfo(&info))
					goto SEC_ERROR;

				//先写协议头
				hdr.action = PRCPD_REPLY;
				hdr.flag = 1;// means true
				hdr.dataSize = sizeof(info); //协议头后面的数据长度
				if (! WritePipe(hPipe, &hdr, sizeof(hdr)))
					goto SEC_ERROR;
				//写数据
				if (! WritePipe(hPipe, &info, sizeof(info)))
					goto SEC_ERROR;

			}
			break;

		case PRCPD_REGISTERCLIENT:
			{
				//接收登记信息
				PRCClient client;
				//判断数据长度是否符合
				if (hdr.dataSize != sizeof(client))
					goto SEC_ERROR;

				if (! ReadPipe(hPipe, &client, hdr.dataSize))
					goto SEC_ERROR;
				if (pipeClientPid && client.dwPid != pipeClientPid)
					goto SEC_ERROR;

				//将数据注册到PRC
				if (! m_pPRC->RegisterClient(&client))
					goto SEC_ERROR;

				//回复成功消息
				hdr.action = PRCPD_REPLY;
				hdr.flag = 1;

				//如果是登记 UDP的则 RegisterClient 会返回新的数据到client， 回复之
				if (client.sType == SOCK_DGRAM)
				{
					hdr.dataSize = sizeof(client);
					if(! WritePipe(hPipe, &hdr, sizeof(hdr)))
						goto SEC_ERROR;

					if (! WritePipe(hPipe, &client, sizeof(client)))
						goto SEC_ERROR;
				}else
				{
					hdr.dataSize = 0;
					if (! WritePipe(hPipe, &hdr, sizeof(hdr)))
						goto SEC_ERROR;
				}

			}
			break;
		
		case PRCPD_UNREGISTER_CLIENT:
			{
				PRCClient client;
				//判断数据长度是否符合
				if(hdr.dataSize != sizeof(client))
					goto SEC_ERROR;

				if (! ReadPipe(hPipe, &client, hdr.dataSize))
					goto SEC_ERROR;
				if (pipeClientPid && client.dwPid != pipeClientPid)
					goto SEC_ERROR;

				if (! m_pPRC->UnregisterClient(&client))
					goto SEC_ERROR;

				//回复成功消息
				hdr.action = PRCPD_REPLY;
				hdr.flag = 1;

				hdr.dataSize = 0;
				if (! WritePipe(hPipe, &hdr, sizeof(hdr)))
					goto SEC_ERROR;

			}
			break;

		case PRCPD_CANPROXYME:
			{
				PRCClientInfo clientinfo;
				//判断数据长度是否符合
				if (hdr.dataSize != sizeof(clientinfo))
					goto SEC_ERROR;

				if(! ReadPipe(hPipe, &clientinfo, hdr.dataSize))
					goto SEC_ERROR;
				if (pipeClientPid && clientinfo.dwPid != pipeClientPid)
					goto SEC_ERROR;

				//查询PRC
				BOOL bFiltered = m_pPRC->IsFiltered(&clientinfo);

				//回复消息
				hdr.action = PRCPD_REPLY;
				//如果给过滤了则flag为 false, means can not
				hdr.flag = (BYTE)!bFiltered;
				hdr.dataSize = 0;
				if (! WritePipe(hPipe, &hdr, sizeof(hdr)))
					goto SEC_ERROR;
			}
			break;

		case PRCPD_GET_SETTINGS_INFO:
			{
				ProxySettingsInfo psi;

				bRet = m_pPRC->GetProxySettingsInfo(&psi);

				//先写协议头
				hdr.action = PRCPD_REPLY;
				hdr.flag = bRet ? true : false;

				if(bRet)
				{
					hdr.dataSize = sizeof(psi); //协议头后面的数据长度
					if (! WritePipe(hPipe, &hdr, sizeof(hdr)))
						goto SEC_ERROR;
					//写数据
					if (! WritePipe(hPipe, &psi, sizeof(psi)))
						goto SEC_ERROR;
				}else
				{
					hdr.dataSize = 0;
					if (! WritePipe(hPipe, &hdr, sizeof(hdr)))
						goto SEC_ERROR;
				}

			}
			break;

		case PRCPD_ON_CREATEPROCESS:
			{
				HookNewProcessInfo hnpi;

				if (hdr.dataSize != sizeof(hnpi))
					goto SEC_ERROR;

				if(! ReadPipe(hPipe, &hnpi, hdr.dataSize))
					goto SEC_ERROR;

				//先写协议头
				hdr.action = PRCPD_REPLY;
				hdr.flag = false;
				hdr.dataSize = 0;

				hdr.flag = (BYTE)m_pPRC->m_pGlobalProxy->GetLogInstance()->OnNewProcess(&hnpi);

				if (! WritePipe(hPipe, &hdr, sizeof(hdr)))
					goto SEC_ERROR;


			}
			break;

		case PRCPD_CHILD_INJECTION_RESULT:
			{
				HookNewProcessInfo hnpi;

				if (hdr.dataSize != sizeof(hnpi))
					goto SEC_ERROR;

				if(! ReadPipe(hPipe, &hnpi, hdr.dataSize))
					goto SEC_ERROR;

				m_pPRC->m_pGlobalProxy->GetLogInstance()->OnChildInjectionResult(
					&hnpi,
					hdr.flag != 0);
			}
			break;

		case PRCPD_REGISTER_PROCESS_IDENTITY:
			{
				HookProcessIdentityInfo identity;
				if (hdr.dataSize != sizeof(identity))
					goto SEC_ERROR;

				if (!ReadPipe(hPipe, &identity, hdr.dataSize))
					goto SEC_ERROR;
				if (pipeClientPid && identity.dwProcessId != pipeClientPid)
					goto SEC_ERROR;

				identity.szAppPath[_countof(identity.szAppPath) - 1] = L'\0';
				m_pPRC->RegisterProcessIdentity(&identity);
			}
			break;

		case PRCPD_GET_CLIENT_UDPPORT_STATE:
			{
				UDPLocalProxyAddrInfo udpai;

				if (hdr.dataSize != sizeof(udpai))
					goto SEC_ERROR;

				if(! ReadPipe(hPipe, &udpai, hdr.dataSize))
					goto SEC_ERROR;

				//先写协议头
				hdr.action = PRCPD_REPLY;
				hdr.flag = (BYTE)m_pPRC->GetUDPClientPortState(&udpai);
				hdr.dataSize = 0;

				if (! WritePipe(hPipe, &hdr, sizeof(hdr)))
					goto SEC_ERROR;

			}
			break;

		case PRCPD_GET_PROXYINFO:
			{
				ProxyInfo pi;

				//接收PRCClient信息
				PRCClient client;
				//判断数据长度是否符合
				if (hdr.dataSize != sizeof(client))
					goto SEC_ERROR;

				if (! ReadPipe(hPipe, &client, hdr.dataSize))
					goto SEC_ERROR;
				if (pipeClientPid && client.dwPid != pipeClientPid)
					goto SEC_ERROR;

				bRet = m_pPRC->GetProxyInfo(&client, &pi);

				hdr.action = PRCPD_REPLY;
				hdr.flag = bRet ? true : false;

				if(bRet)
				{
					// Injected processes only need routing policy.  Keep the profile
					// PSK inside the PRC process even though it is stored in the INI.
					SecureZeroMemory(pi.strTransportPsk.szbuf,
						sizeof(pi.strTransportPsk.szbuf));
					hdr.dataSize = sizeof(pi);
					if (! WritePipe(hPipe, &hdr, sizeof(hdr)))
						goto SEC_ERROR;
					if (! WritePipe(hPipe, &pi, sizeof(pi)))
						goto SEC_ERROR;
				}else
				{
					hdr.dataSize = 0;
					if (! WritePipe(hPipe, &hdr, sizeof(hdr)))
						goto SEC_ERROR;
				}
			}
			break;

		case PRCPD_HOOKWSOCK_RESULT:
		{
					HookWSockResult res;

					if (hdr.dataSize != sizeof(res))
						goto SEC_ERROR;

					if (!ReadPipe(hPipe, &res, hdr.dataSize))
						goto SEC_ERROR;
					if (pipeClientPid && res.dwProcessId != pipeClientPid)
						goto SEC_ERROR;

					m_pPRC->m_pGlobalProxy->GetLogInstance()->OnHookWsock(&res);
		}
			break;

		case PRCPD_Logtext:
		{
			const DWORD fixedSize = FIELD_OFFSET(HookLogtext, str);
			const DWORD maxLogBytes = 64 * 1024;
			if (hdr.dataSize < fixedSize || hdr.dataSize > maxLogBytes ||
				hdr.dataSize > MAXDWORD - sizeof(WCHAR))
				goto SEC_ERROR;

			HookLogtext *textinfo = (HookLogtext*)malloc(hdr.dataSize + sizeof(WCHAR));
			if (!textinfo)
				goto SEC_ERROR;
			if (!ReadPipeExactly(hPipe, textinfo, hdr.dataSize))
			{
				free(textinfo);
				goto SEC_ERROR;
			}
			if (pipeClientPid && textinfo->dwProcessId != pipeClientPid)
			{
				free(textinfo);
				goto SEC_ERROR;
			}

			const DWORD payloadBytes = hdr.dataSize - fixedSize;
			if (textinfo->len < 0 || (textinfo->len & 1) != 0 ||
				(DWORD)textinfo->len > payloadBytes)
			{
				free(textinfo);
				goto SEC_ERROR;
			}
			textinfo->str[textinfo->len / sizeof(WCHAR)] = L'\0';
			textinfo->len /= sizeof(WCHAR);

			m_pPRC->m_pGlobalProxy->GetLogInstance()->OnHookLogtext(textinfo);
			free(textinfo);

		}
		break;


		default:
			goto SEC_ERROR;
		}
	}

SEC_ERROR:
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);

	CTSList<HANDLE>::critical lc = m_ChildThreadList;
	m_ChildThreadList.remove(hThread);
	CloseHandle(hThread);

	//如果当前线程退出后没线程了， 设置信号
	if (InterlockedDecrement(&m_dwThreadCount) == 0)
	{
		SetEvent(m_hNoThreadEvent);
	}

	return 0;
}

BOOL CPRCPipeServer::WritePipe(HANDLE hPipe, LPVOID lpBuf, int size)
{
	DWORD nWritten = 0;

	if(!WriteFile(hPipe, lpBuf, size, &nWritten, NULL))
		return FALSE;

	return nWritten == (DWORD)size;
}

BOOL CPRCPipeServer::ReadPipe(HANDLE hPipe, LPVOID lpBuf, int size)
{
	DWORD nRead = 0;
	if(!ReadFile(hPipe, lpBuf, size, &nRead, NULL))
		return FALSE;

	return nRead == (DWORD)size;
}


BOOL CPRCPipeServer::ReadPipeExactly(HANDLE hPipe, LPVOID lpBuf, int size)
{
	DWORD  dwTotal = 0;
	while (dwTotal < (DWORD)size)
	{
		DWORD nRead = 0;
		if (!ReadFile(hPipe, (char*)lpBuf+dwTotal, size-dwTotal, &nRead, NULL) || !nRead)
			return FALSE;

		dwTotal += nRead;
	}

	return dwTotal == (DWORD)size;
}
