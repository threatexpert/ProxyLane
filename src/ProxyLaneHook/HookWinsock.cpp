/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "HookWinsock.h"
#include <psapi.h>
#include "GlobalProxy.h"
#include "token.h"
#include "ElevatedLauncher.h"

#pragma comment(lib,"psapi.lib")
#pragma comment(lib,"ws2_32.lib")

CHookWinsock *g_pHookWinsock = NULL;

static void RegisterCurrentProcessIdentity(CPRCPipeClient& pipeClient)
{
	HookProcessIdentityInfo identity = { 0 };
	identity.dwProcessId = GetCurrentProcessId();
	const DWORD pathLength = GetModuleFileNameW(
		NULL,
		identity.szAppPath,
		_countof(identity.szAppPath));
	identity.szAppPath[_countof(identity.szAppPath) - 1] = L'\0';
	if (pathLength > 0 && identity.szAppPath[0])
		pipeClient.PRCRegisterProcessIdentity(&identity);
}


static BOOL IsWin8OrLater()
{
	OSVERSIONINFO osvi;
	BOOL bLater;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	GetVersionEx(&osvi);

	bLater =
		((osvi.dwMajorVersion > 6) ||
		((osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion >= 2)));

	return bLater;
}

CHookWinsock::CHookWinsock(void)
: m_HackedSocket(this)
{
	ZeroMemory(m_HookedInfo, sizeof(m_HookedInfo));
	ZeroMemory(&m_psi, sizeof(m_psi));
	ZeroMemory(m_mem4bakcode, sizeof(m_mem4bakcode));

	m_bHookEnabled = FALSE;
	//
	ATLASSERT(g_pHookWinsock == NULL);

	g_pHookWinsock = this;

	m_ModuleName[HOOKMODULE_WS2_32] = "Ws2_32.dll";

	if (IsWin8OrLater())
		m_ModuleName[HOOKMODULE_KERNEL32] = "KernelBase.dll";
	else
		m_ModuleName[HOOKMODULE_KERNEL32] = "Kernel32.dll";

	m_szPRCPipeName = PRC_PIPESERVER_NAME;
	m_pConnectEx = NULL;
}

CHookWinsock::~CHookWinsock(void)
{
	g_pHookWinsock = NULL;
}

CString CHookWinsock::GetLastError()
{
	return m_szLastError;
}

BOOL CHookWinsock::IsHookEnabled()
{
	return m_bHookEnabled;
}

BOOL CHookWinsock::EnableHook()
{
	CPRCPipeClient PRCPipeClient;

	if (!PRCPipeClient.Connect(m_szPRCPipeName))
		return FALSE;

	if (!PRCPipeClient.PRCGetProxySettingsInfo(&m_psi))
	{
		return FALSE;
	}

	// 在安装网络 Hook 前登记身份，避免其他线程的首个连接早于路径缓存建立。
	RegisterCurrentProcessIdentity(PRCPipeClient);

	if (IsHookEnabled()) {
		PRCPipeClient.PRCNotifyHookWSockResult(0);
		PRCPipeClient.Disconnect();
		return TRUE;
	}

	//m_psi.bHookTCP = TRUE;
	//m_psi.bHookUDP = TRUE;
	//m_psi.nDNSOption = PSI_DNSOPT_LOCAL;
	//m_psi.bHookCreateProcess = TRUE;

	//hook API

	BOOL bOK = HookWinsock();

	PRCPipeClient.PRCNotifyHookWSockResult(bOK ? 0 : 1);

	PRCPipeClient.Disconnect();

	return bOK;
}

BOOL CHookWinsock::DisableHook()
{
	UnhookWinsock();
	ZeroMemory(m_HookedInfo, sizeof(m_HookedInfo));
	ZeroMemory(&m_psi, sizeof(m_psi));
	ZeroMemory(m_mem4bakcode, sizeof(m_mem4bakcode));

	return TRUE;
}

BOOL CHookWinsock::SetPRCPipeName(LPCSTR lpszPipeName)
{
	m_szPRCPipeName = lpszPipeName;
	return TRUE;
}

CString CHookWinsock::GetPRCPipeName()
{
	return m_szPRCPipeName;
}

BOOL CHookWinsock::UnhookWinsock()
{
	m_bHookEnabled = FALSE;
	int i = 0;
	for (i = 0; i<HOOKAPI_COUNT; i++)
	{
		HookOnOff((eHOOKFUN)i, false);
	}

	return TRUE;
}

void CHookWinsock::HookOnOff(eHOOKFUN ehf, bool DOUNT)
{
	HOOKSTRUCT *hookfunc = &m_HookedInfo[ehf];
	if (!hookfunc->funcaddr)
	{
		return;
	}

	int ret;

	if (DOUNT)
	{
		ret = hook_set((unsigned char*)hookfunc->funcaddr, (unsigned char*)hookfunc->newfuncaddr, hookfunc->myfuncaddr);
	}
	else
	{
		ret = hook_remove((unsigned char*)hookfunc->newfuncaddr, hookfunc->myfuncaddr);
	}
	
}

BOOL CHookWinsock::HookAPI(eHOOKMODUDLE ehm, eHOOKFUN ehf, char *exportfunc, LPVOID myfuncaddr, LPVOID newfuncaddr)
{
	char *dllname = m_ModuleName[ehm];
	HOOKSTRUCT *hookfunc = &m_HookedInfo[ehf];
	long writtenCodeSize = 0;

	hookfunc->myfuncaddr = myfuncaddr;
	hookfunc->newfuncaddr = newfuncaddr;

	HMODULE hModule = GetModuleHandleA(dllname);
	if (hModule == NULL)
		return FALSE;

	hookfunc->funcaddr = GetProcAddress(hModule, exportfunc);
	if (hookfunc->funcaddr == NULL)
		return FALSE;

#ifdef _WIN64

	if (0 != hook_set_hp((unsigned char*)hookfunc->funcaddr, (unsigned char*)newfuncaddr, myfuncaddr, (void*)(((char*)m_mem4bakcode[ehm]) + ehf*JMPBOARD_SIZE)))
		return FALSE;

#else

	if (0 != hook_set((unsigned char*)hookfunc->funcaddr, (unsigned char*)newfuncaddr, myfuncaddr))
		return FALSE;

#endif

	return TRUE;
}

BOOL CHookWinsock::IsHostNameReserved(const char *name)
{
	if (inet_addr(name) != INADDR_NONE)
		return TRUE;

	CPRCPipeClient PRCPipeClient;

	//查询是否可以代理本进程, 连接pipe server 失败则返回值为 不保留
	if (!PRCPipeClient.Connect(m_szPRCPipeName))
		return TRUE;

	PRCClientInfo ci;
	ci.dwPid = GetCurrentProcessId();
	ci.dwTid = GetCurrentThreadId();

	BOOL bCan = PRCPipeClient.PRCCanProxyMe(&ci);

	PRCPipeClient.Disconnect();

	//能代理则不是保留的主机名
	return !bCan;
}

BOOL CHookWinsock::HackDNS(const char *name)
{
	if (m_psi.nDNSOption == PSI_DNSOPT_LOCAL)
	{
		return FALSE;
	}
	else if (m_psi.nDNSOption == PSI_DNSOPT_REMOTE)
	{
		return !IsHostNameReserved(name);
	}
	else
	{
		return FALSE;
	}
}

MyDetourProc(has_Return, hostent*, WSAAPI, gethostbyname, (const char* name))
{
	return g_pHookWinsock->inhook_gethostbyname(name);
}

hostent* WSAAPI CHookWinsock::inhook_gethostbyname(const char* name)
{

	//判断解析的域名，如果是设置的代理服务器地址的域名则直接调用系统的解析函数

	if (name && HackDNS(name))
	{
		DWORD dummyIP = m_DummyDNS.GetDummyIP(name);

		return m_DummyDNS.GetHostent(dummyIP);
	}

	return CallTrampoline(gethostbyname)(name);
}

MyDetourProc(has_Return, HANDLE, WSAAPI, WSAAsyncGetHostByName, (HWND hWnd, unsigned int wMsg, const char* name, char* buf, int buflen))
{
	return g_pHookWinsock->inhook_WSAAsyncGetHostByName(hWnd, wMsg, name, buf, buflen);
}

HANDLE WSAAPI CHookWinsock::inhook_WSAAsyncGetHostByName(HWND hWnd, unsigned int wMsg, const char* name, char* buf, int buflen)
{
	if (name && HackDNS(name))
	{
		HANDLE hDummy = m_DummyDNS.GetDummyHandle(name, buf, buflen);
		::PostMessage(hWnd, wMsg, (WPARAM)hDummy, 0);
		return hDummy;
	}

	return CallTrampoline(WSAAsyncGetHostByName)(hWnd, wMsg, name, buf, buflen);
}

MyDetourProc(has_Return, int, WSAAPI, getaddrinfo, (IN const char FAR * nodename, IN const char FAR * servname, IN const struct addrinfo FAR * hints, OUT struct addrinfo FAR * FAR * res))
{
	return g_pHookWinsock->inhook_getaddrinfo(nodename, servname, hints, res);
}

int WSAAPI CHookWinsock::inhook_getaddrinfo(IN const char FAR * nodename, IN const char FAR * servname, IN const struct addrinfo FAR * hints, OUT struct addrinfo FAR * FAR * res)
{
	int ret;

	if (!nodename)
		return CallTrampoline(getaddrinfo)(nodename, servname, hints, res);

	if (HackDNS(nodename))
	{
		ATLTRACE("inhook_getaddrinfo %s\r\n", nodename);

		DWORD dummyIP = m_DummyDNS.GetDummyIP(nodename);
		// 		CHAR szIP[64];
		// 		const BYTE* pucIP = (BYTE*)&dummyIP;
		// 
		// 		sprintf(szIP, "%u.%u.%u.%u", pucIP[0], pucIP[1], pucIP[2], pucIP[3]);
		// 
		// 		ret = pFunc(szIP, servname, hints, res);

		ret = CallTrampoline(getaddrinfo)("localhost", servname, hints, res);
		struct addrinfo FAR *resls = *res;
		while (resls)
		{
			_SockAddr *pas = (_SockAddr*)resls->ai_addr;
			if (pas)
			{
				if (resls->ai_family == AF_INET6)
				{
					resls->ai_family = AF_INET;
					resls->ai_addrlen = sizeof(sockaddr);
				}
				pas->sa_family = AF_INET;
				pas->SetIPLong(dummyIP);
			}
			resls = resls->ai_next;
		}
	}
	else
	{
		ret = CallTrampoline(getaddrinfo)(nodename, servname, hints, res);
	}

	return ret;
}

MyDetourProc(has_Return, int, WSAAPI, GetAddrInfoExW, (PCWSTR          pName,
	PCWSTR          pServiceName,
	DWORD           dwNameSpace,
	LPGUID          lpNspId,
	const ADDRINFOEXW *hints,
	PADDRINFOEXW *  ppResult,
struct timeval *timeout,
	LPOVERLAPPED    lpOverlapped,
	LPLOOKUPSERVICE_COMPLETION_ROUTINE  lpCompletionRoutine,
	LPHANDLE        lpHandle))
{
	return g_pHookWinsock->inhook_GetAddrInfoExW(pName,
		pServiceName,
		dwNameSpace,
		lpNspId,
		hints,
		ppResult,
		timeout,
		lpOverlapped,
		lpCompletionRoutine,
		lpHandle);
}

INT
WSAAPI
CHookWinsock::inhook_GetAddrInfoExW(
PCWSTR          pName,
PCWSTR          pServiceName,
DWORD           dwNameSpace,
LPGUID          lpNspId,
const ADDRINFOEXW *hints,
PADDRINFOEXW *  ppResult,
struct timeval *timeout,
	LPOVERLAPPED    lpOverlapped,
	LPLOOKUPSERVICE_COMPLETION_ROUTINE  lpCompletionRoutine,
	LPHANDLE        lpHandle
	)
{
	int ret;

	char nodename[256];
	int iLen = 0;

	if (pName)
		iLen = WideCharToMultiByte(0, 0, pName, -1, nodename, sizeof(nodename), 0, 0);

	if (iLen > 0
		&& HackDNS(nodename)
		)
	{
		ATLTRACE("inhook_GetAddrInfoEx %s\r\n", nodename);

		if (lpOverlapped)
		{
			ATLTRACE("inhook_GetAddrInfoEx Overlapped\r\n");
		}

		DWORD dummyIP = m_DummyDNS.GetDummyIP(nodename);

		ret = CallTrampoline(GetAddrInfoExW)(L"localhost", // 127.0.0.1的话不知道为什么会引起堆破坏？？
			pServiceName,
			dwNameSpace,
			lpNspId,
			hints,
			ppResult,
			timeout,
			NULL,
			NULL,
			NULL);

		if (ret == 0)
		{
			PADDRINFOEX resls = *ppResult;
			while (resls)
			{
				_SockAddr *pas = (_SockAddr*)resls->ai_addr;
				if (pas)
				{
					if (resls->ai_family == AF_INET6)
					{
						resls->ai_family = AF_INET;
						resls->ai_addrlen = sizeof(sockaddr);
					}
					pas->sa_family = AF_INET;
					pas->SetIPLong(dummyIP);
				}
				resls = resls->ai_next;
			}
		}

	}
	else
	{
		ret = CallTrampoline(GetAddrInfoExW)(pName,
			pServiceName,
			dwNameSpace,
			lpNspId,
			hints,
			ppResult,
			timeout,
			lpOverlapped,
			lpCompletionRoutine,
			lpHandle);
	}

	return ret;
}

MyDetourProc(has_Return, 
	int, WSAAPI, GetAddrInfoW,(
	PCWSTR pNodeName,
	PCWSTR pServiceName,
	const ADDRINFOW *pHints,
	PADDRINFOW *ppResult
	)
	)
{
	return g_pHookWinsock->inhook_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
}

int WSAAPI CHookWinsock::inhook_GetAddrInfoW(
	PCWSTR pNodeName,
	PCWSTR pServiceName,
	const ADDRINFOW *pHints,
	PADDRINFOW *ppResult
	)
{
	int ret;

	char nodename[256];
	int iLen = 0;

	if (pNodeName)
		iLen = WideCharToMultiByte(0, 0, pNodeName, -1, nodename, sizeof(nodename), 0, 0);

	if (iLen > 0
		&& HackDNS(nodename)
		)
	{
		ATLTRACE("inhook_GetAddrInfoW %s\r\n", nodename);

		DWORD dummyIP = m_DummyDNS.GetDummyIP(nodename);

		ret = CallTrampoline(GetAddrInfoW)(L"localhost", 
			pServiceName,
			pHints,
			ppResult);

		if (ret == 0)
		{
			PADDRINFOW resls = *ppResult;
			while (resls)
			{
				_SockAddr *pas = (_SockAddr*)resls->ai_addr;
				if (pas)
				{
					if (resls->ai_family == AF_INET6)
					{
						resls->ai_family = AF_INET;
						resls->ai_addrlen = sizeof(sockaddr);
					}
					pas->sa_family = AF_INET;
					pas->SetIPLong(dummyIP);
				}
				resls = resls->ai_next;
			}
		}

	}
	else
	{
		ret = CallTrampoline(GetAddrInfoW)(pNodeName,
			pServiceName,
			pHints,
			ppResult);
	}

	return ret;
}


MyDetourProc(has_Return, int, WSAAPI, connect, (SOCKET s, const struct sockaddr FAR * name, int namelen))
{
	return g_pHookWinsock->inhook_connect(s, name, namelen);
}

int
WSAAPI
CHookWinsock::inhook_connect(SOCKET s, const struct sockaddr FAR * name, int namelen)
{
	_SockAddr addrname;

	addrname = *name;

	HackConnect(s, addrname);

	return CallTrampoline(connect)(s, &addrname, namelen);
}

MyDetourProc(has_Return,
	int,
	WSAAPI,
	WSAConnect,(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS)
	)
{
	return g_pHookWinsock->inhook_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

int
WSAAPI
CHookWinsock::inhook_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS)
{
	_SockAddr addrname;

	addrname = *name;

	HackConnect(s, addrname);

	return CallTrampoline(WSAConnect)(s, &addrname, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

MyDetourProc(has_Return,
	BOOL, PASCAL, ConnectEx, (
	SOCKET s,
	const struct sockaddr *name,
	int namelen,
	PVOID lpSendBuffer,
	DWORD dwSendDataLength,
	LPDWORD lpdwBytesSent,
	LPOVERLAPPED lpOverlapped
	)
	)
{
	return g_pHookWinsock->inhook_ConnectEx(s,
		name,
		namelen,
		lpSendBuffer,
		dwSendDataLength,
		lpdwBytesSent,
		lpOverlapped);
}

BOOL PASCAL CHookWinsock::inhook_ConnectEx(
	SOCKET s,
	const struct sockaddr *name,
	int namelen,
	PVOID lpSendBuffer,
	DWORD dwSendDataLength,
	LPDWORD lpdwBytesSent,
	LPOVERLAPPED lpOverlapped
	)
{
	_SockAddr addrname;

	addrname = *name;

	HackConnect(s, addrname);

	if (!m_pConnectEx)
		return FALSE;

	return m_pConnectEx(s,
		&addrname,
		namelen,
		lpSendBuffer,
		dwSendDataLength,
		lpdwBytesSent,
		lpOverlapped);
}

BOOL CHookWinsock::HackConnect(SOCKET s, _SockAddr &addrname)
{
	if (!m_psi.bHookTCP)
		return FALSE;

	if (*(DWORD*)&addrname.sa_data[6] == 'pass' && *(DWORD*)&addrname.sa_data[10] == 'port')
	{
		*(DWORD*)&addrname.sa_data[6] = 0;
		*(DWORD*)&addrname.sa_data[10] = 0;
		return FALSE;
	}

	//check SO_REUSEADDR?
	int nSockType = SOCK_STREAM;
	int nTypeLen = sizeof(nSockType);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&nSockType, &nTypeLen) != 0)
		return FALSE;

	ATLTRACE("HackConnect.getsockopt:SO_TYPE = %d\r\n", nSockType);

	if (nSockType != SOCK_DGRAM && nSockType != SOCK_STREAM)
		return FALSE;

	if (addrname.GetdwIP() == 0x0100007f)
		return FALSE;

	_SockAddr srcAddr;
	int srcaddrlen = sizeof(_SockAddr);
	//查询该socket绑定的地址
	if (getsockname(s, &srcAddr, &srcaddrlen) == SOCKET_ERROR)
	{
		//未绑定则绑定之, 再重新查询
		srcAddr.sa_family = AF_INET;
		srcAddr.SetIPLong(0);
		srcAddr.SetPort(0);
		if (bind(s, &srcAddr, sizeof(_SockAddr)) == SOCKET_ERROR)
			return FALSE;

		srcaddrlen = sizeof(_SockAddr);
		if (getsockname(s, &srcAddr, &srcaddrlen) == SOCKET_ERROR)
			return FALSE;
	}


	//保存原请求地址
	PRCClient prcc;
	prcc.zero();
	prcc.sType = nSockType;
	prcc.s = s;
	prcc.dwPid = GetCurrentProcessId();
	prcc.dwTid = GetCurrentThreadId();
	prcc.srcAddr = srcAddr;
	prcc.dstAddr = addrname;

	//如果该地址是通过dummyDNS取得的话，在这里查询得到原请求域名
	if (m_DummyDNS.IsDummyIP(addrname.GetdwIP()))
	{
		if (!m_DummyDNS.GetHostByIP(addrname.GetdwIP(), prcc.szDomainName, sizeof(prcc.szDomainName)))
		{
			//?
		}

	}


	CPRCPipeClient PRCPipeClient;

	//获得PRC 的地址信息
	if (!PRCPipeClient.Connect(m_szPRCPipeName))
		return FALSE;

	PRCINFO prcinfo;
	if (!PRCPipeClient.GetPRCStartupInfo(&prcinfo))
	{
		PRCPipeClient.Disconnect();
		return FALSE;
	}

	if (!m_HackedSocket.CanHackIt(&prcc))
	{
		ATLTRACE("TCP: CHackedSocket.CanHackIt == FALSE\r\n");
		PRCPipeClient.Disconnect();
		return FALSE;
	}

	//将原请求登记到PRC
	if (!PRCPipeClient.PRCRegisterClient(&prcc))
	{
		PRCPipeClient.Disconnect();
		return FALSE;
	}

	PRCPipeClient.Disconnect();

	m_HackedSocket.push(&prcc);

	//修改请求的目的地址为PRC

	if (nSockType == SOCK_DGRAM)
	{
		addrname = prcc.udpAddr;
	}
	else
	{
		addrname = prcinfo.tcpaddr;
	}

	if (addrname.GetdwIP() == 0)
		addrname.SetIP("127.0.0.1");

#ifdef _DEBUG

	DWORD nIP = prcc.dstAddr.GetdwIP();
	const BYTE* pucIP = (BYTE*)&nIP;

	if (prcc.IsDNValid())
	{
		ATLTRACE("inhook_connect: connect to %s(%u.%u.%u.%u):%d\r\n", prcc.szDomainName, pucIP[0], pucIP[1], pucIP[2], pucIP[3], prcc.dstAddr.GetPort());
	}
	else
	{
		ATLTRACE("inhook_connect: connect to %u.%u.%u.%u:%d\r\n", pucIP[0], pucIP[1], pucIP[2], pucIP[3], prcc.dstAddr.GetPort());
	}

	nIP = addrname.GetdwIP();
	ATLTRACE("inhook_connect: redirect to %u.%u.%u.%u:%d\r\n", pucIP[0], pucIP[1], pucIP[2], pucIP[3], addrname.GetPort());
#endif

	return TRUE;
}

MyDetourProc(has_Return,
	int, WSAAPI, getpeername, (SOCKET s, struct sockaddr* name, int* namelen)
	)
{
	return g_pHookWinsock->inhook_getpeername(s, name, namelen);
}

int WSAAPI CHookWinsock::inhook_getpeername(SOCKET s, struct sockaddr* name, int* namelen)
{
	if (!m_psi.bHookTCP && !m_psi.bHookUDP)
	{
		return CallTrampoline(getpeername)(s, name, namelen);
	}
	/*
	先查询该套接字是否之前被拦截修改过，
	比如之前connect的原目的是aa.aa.aa.aa， 然后被HackConnect修改为PRC的服务地址, 为了避免getpeername得到PRC的地址，这里要做处理
	*/
	PRCClient prcc;
	if (m_HackedSocket.GetInfo(s, &prcc))
	{
		if (*namelen < sizeof(sockaddr))
		{
			WSASetLastError(WSAEFAULT);
			return SOCKET_ERROR;
		}
		*name = prcc.dstAddr;
		*namelen = sizeof(sockaddr);
		WSASetLastError(0);
		return 0;
	}
	else
	{
		return CallTrampoline(getpeername)(s, name, namelen);
	}
}

MyDetourProc(has_Return,
	int, WSAAPI, closesocket, (SOCKET s))
{
	return g_pHookWinsock->inhook_closesocket(s);
}

int WSAAPI CHookWinsock::inhook_closesocket(SOCKET s)
{
	if (!m_psi.bHookTCP && !m_psi.bHookUDP)
	{
		return CallTrampoline(closesocket)(s);
	}

	do
	{
		int nSockType = SOCK_STREAM;
		int nTypeLen = sizeof(nSockType);
		if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&nSockType, &nTypeLen) != 0)
			break;

		if (nSockType != SOCK_DGRAM && nSockType != SOCK_STREAM)
			break;

		if (m_HackedSocket.remove(s) > 0)
		{
			CPRCPipeClient PRCPipeClient;

			if (!PRCPipeClient.Connect(m_szPRCPipeName))
				break;

			PRCClient client;
			client.dwPid = GetCurrentProcessId();
			client.s = s;
			client.sType = nSockType;

			PRCPipeClient.PRCUnregisterClient(&client);

			PRCPipeClient.Disconnect();

		}

	} while (FALSE);

	return CallTrampoline(closesocket)(s);
}

MyDetourProc(has_Return,
	int, WSAAPI, sendto,(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen))
{
	return g_pHookWinsock->inhook_sendto(s, buf, len, flags, to, tolen);
}

MyDetourProc(has_Return,
	int, WSAAPI, recvfrom,(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen))
{
	return g_pHookWinsock->inhook_recvfrom(s, buf, len, flags, from, fromlen);
}

MyDetourProc(has_Return, int, WSAAPI, WSASendTo, (
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags,
	const struct sockaddr* lpTo,
	int iToLen,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	))
{
	return g_pHookWinsock->inhook_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
}

MyDetourProc(has_Return, int, WSAAPI, WSARecvFrom, (
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags,
struct sockaddr* lpFrom,
	LPINT lpFromlen,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	)
	)
{
	return g_pHookWinsock->inhook_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
}

////////////////////

int WSAAPI CHookWinsock::inhook_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
	if (m_psi.bBlockUDP)
	{
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}
	if (!m_psi.bHookUDP)
	{
		return CallTrampoline(sendto)(s, buf, len, flags, to, tolen);
	}

	WSABUF bufs;

	bufs.buf = (char FAR *)buf;
	bufs.len = len;

	DWORD dwNumberOfBytesSent = 0;
	int nRetVal = inhook_WSASendTo(s, &bufs, 1, &dwNumberOfBytesSent, flags, to, tolen, NULL, NULL);

	if (nRetVal == 0)
	{
		return (int)dwNumberOfBytesSent;
	}
	else
	{
		//SOCKET_ERROR
		return nRetVal;
	}

}

int WSAAPI CHookWinsock::inhook_WSASendTo(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags,
	const struct sockaddr* lpTo,
	int iToLen,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	)
{
	if (m_psi.bBlockUDP)
	{
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}
	if (!m_psi.bHookUDP)
	{
		return CallTrampoline(WSASendTo)(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
	}

	if (lpOverlapped != NULL)
	{
		//OutputDebugStringA("WSASendTo dwBufferCount >= max_bufs || lpOverlapped != NULL");

		CPRCPipeClient PRCPipeClient;
		if (PRCPipeClient.Connect(m_szPRCPipeName))
		{
			PRCPipeClient.PRCLogtext(L"WSASendTo with Overlapped param, drop udp pkg");
			PRCPipeClient.Disconnect();
		}

		//如果使用了lpOverlapped，比较麻烦，暂时放弃，丢弃
		WSASetLastError(ERROR_CALL_NOT_IMPLEMENTED);
		return -1;
	}

	_SockAddr addrname;
	int iLenAddrname = sizeof(addrname);
	BOOL bErr = FALSE;

	if (lpTo)
		addrname = *lpTo;
	else
	{
		if (SOCKET_ERROR == getpeername(s, (struct sockaddr FAR *)&addrname, &iLenAddrname))
		{
			bErr = TRUE;
		}
	}

	PRCClient prcc;

	if (bErr || !HackSendTo(s, addrname, &prcc))
	{
		return CallTrampoline(WSASendTo)(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
	}


	DWORD nBufLenAdded = 0;
	char hdr[0xff + 8];
	memset(hdr, 0, sizeof(hdr));
	WSABUF wsabuf[32];
	DWORD bufidx = 0;

	if (prcc.IsDNValid())
	{
		const char* pszAsciiProxyPeerHost = prcc.szDomainName;
		int iLenAsciiProxyPeerHost = strlen(pszAsciiProxyPeerHost);

		//ATYP
		hdr[3] = 0x03;
		//DST.ADDR
		int nHdrLen = 4;
		hdr[nHdrLen++] = (char)iLenAsciiProxyPeerHost;
		memcpy(&hdr[nHdrLen], pszAsciiProxyPeerHost, iLenAsciiProxyPeerHost);
		nHdrLen += iLenAsciiProxyPeerHost;
		//DST.PORT
		*(WORD*)&hdr[nHdrLen] = (WORD)htons((u_short)prcc.dstAddr.GetPort());
		nHdrLen += 2;

		wsabuf[bufidx].buf = hdr;
		wsabuf[bufidx].len = nHdrLen;
		bufidx++;

		nBufLenAdded = nHdrLen;

		//
		for (DWORD i = 0; bufidx<32 && i<dwBufferCount; bufidx++, i++)
		{
			wsabuf[bufidx].buf = lpBuffers[i].buf;
			wsabuf[bufidx].len = lpBuffers[i].len;
		}

	}
	else
	{
		//ATYP
		hdr[3] = 0x01;
		//DST.ADDR
		int nHdrLen = 4;
		*(DWORD*)&hdr[nHdrLen] = prcc.dstAddr.GetdwIP();
		nHdrLen += 4;
		//DST.PORT
		*(WORD*)&hdr[nHdrLen] = (WORD)htons((u_short)prcc.dstAddr.GetPort());
		nHdrLen += 2;

		wsabuf[bufidx].buf = hdr;
		wsabuf[bufidx].len = nHdrLen;
		bufidx++;

		nBufLenAdded = nHdrLen;

		//
		for (DWORD i = 0; bufidx<32 && i<dwBufferCount; bufidx++, i++)
		{
			wsabuf[bufidx].buf = lpBuffers[i].buf;
			wsabuf[bufidx].len = lpBuffers[i].len;
		}
	}

	int nRetVal = CallTrampoline(WSASendTo)(s, wsabuf, bufidx, lpNumberOfBytesSent, dwFlags, &addrname, iLenAddrname, lpOverlapped, lpCompletionRoutine);

	if (nRetVal == 0 && nBufLenAdded > 0 && *lpNumberOfBytesSent > nBufLenAdded)
	{
		*lpNumberOfBytesSent -= nBufLenAdded;
	}

	return nRetVal;
}

int WSAAPI CHookWinsock::inhook_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
	if (m_psi.bBlockUDP)
	{
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}
	if (!m_psi.bHookUDP)
	{
		return CallTrampoline(recvfrom)(s, buf, len, flags, from, fromlen);
	}

	WSABUF bufs;

	bufs.buf = (char FAR *)buf;
	bufs.len = len;

	int nRetVal;
	DWORD dwNumberOfBytesRecvd = 0;

	nRetVal = inhook_WSARecvFrom(s, &bufs, 1, &dwNumberOfBytesRecvd, (LPDWORD)&flags, from, fromlen, NULL, NULL);

	if (nRetVal == 0)
	{
		return (int)dwNumberOfBytesRecvd;
	}

	return nRetVal;

	//
	//	int ret = pFunc(s, buf, len, flags, from, fromlen);
	//
	//	if(ret > 0)
	//	{
	//#ifdef _DEBUG
	//		in_addr *pAddr = ((_SockAddr*)from)->GetAddr();
	//		ATLTRACE("recvfrom1: %u.%u.%u.%u:%d\r\n", pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, ((_SockAddr*)from)->GetPort());
	//#endif
	//
	//		if (m_HackedSocket.ReplaceAddr(s, (_SockAddr *)from))
	//		{
	//#ifdef _DEBUG
	//			pAddr = ((_SockAddr*)from)->GetAddr();
	//			ATLTRACE("recvfrom2: %u.%u.%u.%u:%d\r\n", pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, ((_SockAddr*)from)->GetPort());
	//#endif
	//		}
	//	}
	//
	//	return ret;
}


int WSAAPI CHookWinsock::inhook_WSARecvFrom(
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesRecvd,
	LPDWORD lpFlags,
struct sockaddr* lpFrom,
	LPINT lpFromlen,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	)
{
	if (m_psi.bBlockUDP)
	{
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}
	if (!m_psi.bHookUDP)
	{
		return CallTrampoline(WSARecvFrom)(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
	}

	enum {
		max_bufs = 32,
	};

	WSABUF wsabuf[max_bufs]; //如果使用了lpOverlapped，这里不能用栈空间,并且需要GetOverlappedResult返回结果后替换返回数据
	DWORD bufidx = 0;
	DWORD i;

	if (dwBufferCount >= max_bufs || lpOverlapped != NULL)
	{
		//OutputDebugStringA("WSARecvFrom dwBufferCount >= max_bufs || lpOverlapped != NULL");
		CPRCPipeClient PRCPipeClient;
		if (PRCPipeClient.Connect(m_szPRCPipeName))
		{
			if (dwBufferCount >= max_bufs)
				PRCPipeClient.PRCLogtext(L"WSARecvFrom with dwBufferCount >= max_bufs, drop udp pkg");
			else
				PRCPipeClient.PRCLogtext(L"WSARecvFrom with Overlapped param, drop udp pkg");
			PRCPipeClient.Disconnect();
		}

		//如果使用了lpOverlapped，比较麻烦，暂时放弃，丢弃
		WSASetLastError(ERROR_CALL_NOT_IMPLEMENTED);
		return -1;
	}

	char hdr[10];
	memset(hdr, 0, 10);
	//
	wsabuf[0].buf = hdr;
	wsabuf[0].len = 10;

	bufidx++;

	for (i = 0; bufidx<32 && i<dwBufferCount; bufidx++, i++)
	{
		wsabuf[bufidx].buf = lpBuffers[i].buf;
		wsabuf[bufidx].len = lpBuffers[i].len;
	}

	int nRetVal = CallTrampoline(WSARecvFrom)(s, wsabuf, bufidx, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);

	if (nRetVal == 0)
	{
		if (*lpNumberOfBytesRecvd > 10)
		{
			*lpNumberOfBytesRecvd -= 10;

			bufidx = 1;
			for (i = 0; bufidx<32 && i<dwBufferCount; bufidx++, i++)
			{
				lpBuffers[i].buf = wsabuf[bufidx].buf;
				lpBuffers[i].len = wsabuf[bufidx].len;
			}


#ifdef _DEBUG
			in_addr *pAddr = ((_SockAddr*)lpFrom)->GetAddr();
			ATLTRACE("inhook_WSARecvFrom1: %u.%u.%u.%u:%d\r\n", pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, ((_SockAddr*)lpFrom)->GetPort());
#endif

			if (!m_HackedSocket.ReplaceAddr(s, (_SockAddr *)lpFrom, *(DWORD*)&hdr[4], *(WORD*)&hdr[8]))
			{
				//可能包的来源不是PRC
				//丢掉算了
				ATLTRACE("m_HackedSocket.ReplaceAddr(%d, ...) == FALSE\r\n", s);
				WSASetLastError(WSAEWOULDBLOCK);
				return SOCKET_ERROR;
			}
#ifdef _DEBUG
			pAddr = ((_SockAddr*)lpFrom)->GetAddr();
			ATLTRACE("inhook_WSARecvFrom2: %u.%u.%u.%u:%d\r\n", pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, ((_SockAddr*)lpFrom)->GetPort());
#endif

		}
		else
		{
			//丢
			WSASetLastError(WSAEWOULDBLOCK);
			return SOCKET_ERROR;
		}
	}

	return nRetVal;


	//	int ret = pFunc(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
	//
	//	if(ret == 0)
	//	{
	//#ifdef _DEBUG
	//		in_addr *pAddr = ((_SockAddr*)lpFrom)->GetAddr();
	//		ATLTRACE("recvfrom1: %u.%u.%u.%u:%d\r\n", pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, ((_SockAddr*)lpFrom)->GetPort());
	//#endif
	//
	//		if (m_HackedSocket.ReplaceAddr(s, (_SockAddr *)lpFrom))
	//		{
	//#ifdef _DEBUG
	//			pAddr = ((_SockAddr*)lpFrom)->GetAddr();
	//			ATLTRACE("recvfrom2: %u.%u.%u.%u:%d\r\n", pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, ((_SockAddr*)lpFrom)->GetPort());
	//#endif
	//		}
	//	}


	//return ret;
}


BOOL CHookWinsock::HackSendTo(SOCKET s, _SockAddr &addrname, LPPRCClient lpC)
{
	if (!m_psi.bHookUDP)
		return FALSE;

	if (*(DWORD*)&addrname.sa_data[6] == 'pass' && *(DWORD*)&addrname.sa_data[10] == 'port')
	{
		*(DWORD*)&addrname.sa_data[6] = 0;
		*(DWORD*)&addrname.sa_data[10] = 0;
		return FALSE;
	}

	int nSockType;
	int nTypeLen = sizeof(nSockType);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&nSockType, &nTypeLen) != 0)
		return FALSE;

	if (nSockType != SOCK_DGRAM)
		return FALSE;

	_SockAddr srcAddr;
	int srcaddrlen = sizeof(_SockAddr);
	//查询该socket绑定的地址
	if (getsockname(s, &srcAddr, &srcaddrlen) == SOCKET_ERROR)
	{
		return FALSE;
	}

	PRCClient prcc;
	prcc.zero();
	prcc.sType = SOCK_DGRAM;
	prcc.s = s;
	prcc.dwPid = GetCurrentProcessId();
	prcc.dwTid = GetCurrentThreadId();
	prcc.srcAddr = srcAddr;
	prcc.dstAddr = addrname;

	//如果该地址是通过dummyDNS取得的话，在这里查询得到原请求域名
	if (m_DummyDNS.IsDummyIP(addrname.GetdwIP()))
	{
		if (!m_DummyDNS.GetHostByIP(addrname.GetdwIP(), prcc.szDomainName, sizeof(prcc.szDomainName)))
		{
			//?
		}

	}

	//如果已经hacked 则函数会设置prcc.udpAddr， 即处理转发udp的服务地址
	if (m_HackedSocket.IsUDPReqHacked(&prcc))
	{
		addrname = prcc.udpAddr;
		if (addrname.GetdwIP() == 0)
			addrname.SetIP("127.0.0.1");

		*lpC = prcc;

#ifdef _DEBUG
		in_addr *pAddr = addrname.GetAddr();
		if (prcc.IsDNValid())
		{
			ATLTRACE("sendto1: socket:%d: %s(%u.%u.%u.%u):%d\r\n", s, prcc.szDomainName, pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, addrname.GetPort());
		}
		else
		{
			ATLTRACE("sendto1: socket:%d: %u.%u.%u.%u:%d\r\n", s, pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, addrname.GetPort());
		}
#endif

		return TRUE;
	}

	if (!m_HackedSocket.CanHackIt(&prcc))
	{
		ATLTRACE("UDP: CHackedSocket.CanHackIt == FALSE\r\n");
		return FALSE;
	}

	CPRCPipeClient PRCPipeClient;

	//获得PRC 的地址信息
	if (!PRCPipeClient.Connect(m_szPRCPipeName))
		return FALSE;

	if (!PRCPipeClient.PRCRegisterClient(&prcc))
	{
		return FALSE;
	}

	PRCPipeClient.Disconnect();

#ifdef _DEBUG
	in_addr *pAddr = addrname.GetAddr();
	if (prcc.IsDNValid())
	{
		ATLTRACE("sendto1: socket:%d: %s(%u.%u.%u.%u):%d\r\n", s, prcc.szDomainName, pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, addrname.GetPort());
	}
	else
	{
		ATLTRACE("sendto1: socket:%d: %u.%u.%u.%u:%d\r\n", s, pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, addrname.GetPort());
	}
#endif

	addrname = prcc.udpAddr;


	m_HackedSocket.push(&prcc);

	if (addrname.GetdwIP() == 0)
		addrname.SetIP("127.0.0.1");

	*lpC = prcc;

#ifdef _DEBUG
	pAddr = addrname.GetAddr();
	ATLTRACE("sendto2: socket:%d: %u.%u.%u.%u:%d\r\n", s, pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, addrname.GetPort());
#endif

	return TRUE;
}


static BOOL ResolveChildAppPath(HANDLE hChildProc, LPCWSTR lpApplicationName, LPCWSTR lpCommandLine, LPWSTR szOut, DWORD cchOut)
{
	if (!szOut || cchOut == 0)
		return FALSE;

	szOut[0] = L'\0';

	// 1) 优先用真实磁盘路径：QueryFullProcessImageNameW（Vista+，动态加载兼容更老系统）
	if (hChildProc)
	{
		typedef BOOL (WINAPI *PFN_QFIN)(HANDLE, DWORD, LPWSTR, PDWORD);
		static PFN_QFIN s_pQFIN = (PFN_QFIN)-1;
		if (s_pQFIN == (PFN_QFIN)-1)
		{
			HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
			s_pQFIN = hK32 ? (PFN_QFIN)GetProcAddress(hK32, "QueryFullProcessImageNameW") : NULL;
		}
		if (s_pQFIN)
		{
			DWORD cch = cchOut;
			if (s_pQFIN(hChildProc, 0, szOut, &cch) && szOut[0])
				return TRUE;
			szOut[0] = L'\0';
		}

		// 2) 回退：XP 支持的 PSAPI。hModule 为 NULL 时直接查询主程序路径。
		if (GetModuleFileNameExW(hChildProc, NULL, szOut, cchOut) > 0)
		{
			szOut[cchOut - 1] = L'\0';
			if (szOut[0])
				return TRUE;
		}
		szOut[0] = L'\0';
	}

	// 3) 再回退：调用方传入的 lpApplicationName
	if (lpApplicationName && lpApplicationName[0])
	{
		wcsncpy(szOut, lpApplicationName, cchOut - 1);
		szOut[cchOut - 1] = L'\0';
		return TRUE;
	}

	// 4) 最后回退：从 lpCommandLine 解析出第一段（可能带引号）
	if (lpCommandLine && lpCommandLine[0])
	{
		LPCWSTR p = lpCommandLine;
		while (*p == L' ' || *p == L'\t') p++;

		DWORD i = 0;
		if (*p == L'"')
		{
			p++;
			while (*p && *p != L'"' && i < cchOut - 1)
				szOut[i++] = *p++;
		}
		else
		{
			while (*p && *p != L' ' && *p != L'\t' && i < cchOut - 1)
				szOut[i++] = *p++;
		}
		szOut[i] = L'\0';
		return i > 0;
	}

	return FALSE;
}

MyDetourProc(has_Return, BOOL, WINAPI, CreateProcessInternalW, (HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken))
{
	return g_pHookWinsock->inhook_CreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
}

static BOOL WINAPI CreateProcessWithoutProxyLaneHook(
	LPCWSTR applicationName,
	LPWSTR commandLine,
	LPSECURITY_ATTRIBUTES processAttributes,
	LPSECURITY_ATTRIBUTES threadAttributes,
	BOOL inheritHandles,
	DWORD creationFlags,
	LPVOID environment,
	LPCWSTR currentDirectory,
	LPSTARTUPINFOW startupInfo,
	LPPROCESS_INFORMATION processInformation)
{
	return CallTrampoline(CreateProcessInternalW)(
		NULL,
		applicationName,
		commandLine,
		processAttributes,
		threadAttributes,
		inheritHandles,
		creationFlags,
		environment,
		currentDirectory,
		startupInfo,
		processInformation,
		NULL);
}

BOOL WINAPI CHookWinsock::inhook_CreateProcessInternalW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken)
{
	if (!m_psi.bHookCreateProcess)
	{
		return CallTrampoline(CreateProcessInternalW)(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
	}

	//如果没标志挂起主线程， 则修改之
	BOOL bSuspend;
	if ((dwCreationFlags & CREATE_SUSPENDED) == 0)
	{
		dwCreationFlags |= CREATE_SUSPENDED;
		bSuspend = TRUE;
	}
	else
	{
		bSuspend = FALSE;
	}

	BOOL bRetVal = CallTrampoline(CreateProcessInternalW)(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);

	if (bRetVal)
	{
		do
		{
			CPRCPipeClient PRCPipeClient;
			if (!PRCPipeClient.Connect(m_szPRCPipeName))
				break;

			HookNewProcessInfo hnpi = {0};

			ResolveChildAppPath(lpProcessInformation->hProcess, lpApplicationName, lpCommandLine, hnpi.szAppPath, MAX_PATH);

			if (lpCommandLine)
			{
				wcsncpy(hnpi.szCommandLine, lpCommandLine, MAX_PATH - 1);
				hnpi.szCommandLine[MAX_PATH - 1] = L'\0';
			}
			hnpi.dwProcessId = lpProcessInformation->dwProcessId;
			hnpi.dwThreadId = lpProcessInformation->dwThreadId;
			if (!PRCPipeClient.PRCNotifyNewProcess(&hnpi))
			{
				break;
			}

			CStringA pipeName(m_szPRCPipeName);
			const BOOL injectionSucceeded = ProxyLaneInjectSuspendedProcess(
				lpProcessInformation->hProcess,
				lpProcessInformation->hThread,
				lpProcessInformation->dwProcessId,
				lpProcessInformation->dwThreadId,
				pipeName,
				CreateProcessWithoutProxyLaneHook);
			PRCPipeClient.PRCNotifyChildInjectionResult(&hnpi, injectionSucceeded);
			PRCPipeClient.Disconnect();

		} while (FALSE);

		//如果是被我修改的则在通知PRC后回复
		if (bSuspend)
		{
			ResumeThread(lpProcessInformation->hThread);
		}
	}


	return bRetVal;
}

MyDetourProc(has_Return, int, WSAAPI, WSAIoctl, (
	SOCKET s,
	DWORD dwIoControlCode,
	LPVOID lpvInBuffer,
	DWORD cbInBuffer,
	LPVOID lpvOutBuffer,
	DWORD cbOutBuffer,
	LPDWORD lpcbBytesReturned,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	))
{
	return g_pHookWinsock->inhook_WSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
}

int WSAAPI CHookWinsock::inhook_WSAIoctl(
	SOCKET s,
	DWORD dwIoControlCode,
	LPVOID lpvInBuffer,
	DWORD cbInBuffer,
	LPVOID lpvOutBuffer,
	DWORD cbOutBuffer,
	LPDWORD lpcbBytesReturned,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	)
{
	int ret = CallTrampoline(WSAIoctl)(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);

	if (ret == 0)
	{
#ifndef WSAID_CONNECTEX
#define WSAID_CONNECTEX \
		{ 0x25a207b9, 0xddf3, 0x4660, { 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e } }
#endif
		static GUID guid_WSAID_CONNECTEX = WSAID_CONNECTEX;
		if (cbInBuffer == 16
			&& memcmp(&guid_WSAID_CONNECTEX, lpvInBuffer, 16) == 0
			&& cbInBuffer >= sizeof(void*)
			)
		{
			*(void**)&m_pConnectEx = *(void**)lpvOutBuffer;
			*(void**)lpvOutBuffer = hook_ConnectEx;
		}
	}
	return ret;
}

MyDetourProc(has_Return,
BOOL, WINAPI, AddAccessAllowedAce,(
	PACL pAcl,
	DWORD dwAceRevision,
	DWORD AccessMask,
	PSID pSid
	)
	)
{
	return CallTrampoline(AddAccessAllowedAce)(pAcl, dwAceRevision, AccessMask, pSid);
}


/////////////

void *myAlloc4Bakcode(HMODULE hAfterDll, SIZE_T size)
{
	//return VirtualAlloc(0, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	PIMAGE_DOS_HEADER        pDosHeader = (PIMAGE_DOS_HEADER)hAfterDll;
	PIMAGE_FILE_HEADER        pFileHeader = (PIMAGE_FILE_HEADER)(((PBYTE)hAfterDll) + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER    pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(pFileHeader + 1);
	DWORD dwOffset = pOptionalHeader->SizeOfImage;
	while (dwOffset + size < 0x7fffffff)
	{
		void *p = VirtualAlloc((char*)hAfterDll + dwOffset, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (p != NULL)
			return p;

		dwOffset += 4096;
	}

	dwOffset = 0;
	while (pOptionalHeader->SizeOfImage + dwOffset + size < 0x7fffffff)
	{
		void *p = VirtualAlloc((char*)hAfterDll - dwOffset, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (p != NULL)
			return p;

		dwOffset += 4096;
	}

	return NULL;
}

BOOL CHookWinsock::HookWinsock()
{
	int i;
	for (i = 0; i < HOOKMODULE_COUNT; i++)
	{
		if (!LoadLibraryA(m_ModuleName[i]))
		{
			m_szLastError = _T("Failed to initialize HookWinsock: LoadLibrary");
			return FALSE;
		}
	}

#ifdef _WIN64
	for (i = 0; i < HOOKMODULE_COUNT; i++)
	{
		m_mem4bakcode[i] = myAlloc4Bakcode(GetModuleHandleA(m_ModuleName[i]), HOOKAPI_COUNT * JMPBOARD_SIZE);
		if (!m_mem4bakcode[i])
		{
			m_szLastError = _T("Failed to initialize HookWinsock: myAlloc4Bakcode");
			return FALSE;
		}
	}
#endif


#define _EHF(method) HOOKAPI_##method
#define _HOOKFUNC(method) hook_##method
#define _TRAMPFUNC(method) Trampoline_##method

	do
	{
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(connect), "connect", _HOOKFUNC(connect), _TRAMPFUNC(connect)))
			break;
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(WSAConnect), "WSAConnect", _HOOKFUNC(WSAConnect), _TRAMPFUNC(WSAConnect)))
			break;
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(gethostbyname), "gethostbyname", _HOOKFUNC(gethostbyname), _TRAMPFUNC(gethostbyname)))
			break;
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(WSAAsyncGetHostByName), "WSAAsyncGetHostByName", _HOOKFUNC(WSAAsyncGetHostByName), _TRAMPFUNC(WSAAsyncGetHostByName)))
			break;
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(getaddrinfo), "getaddrinfo", _HOOKFUNC(getaddrinfo), _TRAMPFUNC(getaddrinfo)))
			break;
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(getpeername), "getpeername", _HOOKFUNC(getpeername), _TRAMPFUNC(getpeername)))
			break;
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(closesocket), "closesocket", _HOOKFUNC(closesocket), _TRAMPFUNC(closesocket)))
			break;
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(sendto), "sendto", _HOOKFUNC(sendto), _TRAMPFUNC(sendto)))
			break;
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(WSASendTo), "WSASendTo", _HOOKFUNC(WSASendTo), _TRAMPFUNC(WSASendTo)))
			break;
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(recvfrom), "recvfrom", _HOOKFUNC(recvfrom), _TRAMPFUNC(recvfrom)))
			break;
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(WSARecvFrom), "WSARecvFrom", _HOOKFUNC(WSARecvFrom), _TRAMPFUNC(WSARecvFrom)))
			break;
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(WSAIoctl), "WSAIoctl", _HOOKFUNC(WSAIoctl), _TRAMPFUNC(WSAIoctl)))
			break;

		if (IsVistaOrLater())
		{
			if (!HookAPI(HOOKMODULE_WS2_32, _EHF(GetAddrInfoW), "GetAddrInfoW", _HOOKFUNC(GetAddrInfoW), _TRAMPFUNC(GetAddrInfoW)))
				break;
			if (!HookAPI(HOOKMODULE_WS2_32, _EHF(GetAddrInfoExW), "GetAddrInfoExW", _HOOKFUNC(GetAddrInfoExW), _TRAMPFUNC(GetAddrInfoExW)))
				break;
		}

		//
		if (m_psi.bHookCreateProcess)
		{
			//if(!CloneModule("Kernel32.dll", &m_CloneModule[HOOKMODULE_KERNEL32]))
			//	break;

			//ATLTRACE("Kernel32.dll : 0x%.8x | 0x%.8x", m_CloneModule[HOOKMODULE_KERNEL32].pOldBaseAddr, m_CloneModule[HOOKMODULE_KERNEL32].pNewBaseAddr);

			if (!HookAPI(HOOKMODULE_KERNEL32, _EHF(CreateProcessInternalW), "CreateProcessInternalW", _HOOKFUNC(CreateProcessInternalW), _TRAMPFUNC(CreateProcessInternalW)))
				break;
		}

// 		if (!HookAPI(HOOKMODULE_KERNEL32, _EHF(AddAccessAllowedAce), "SHRegDeleteUSValueW", _HOOKFUNC(AddAccessAllowedAce), _TRAMPFUNC(AddAccessAllowedAce)))
// 			break;
// 
// 		AddAccessAllowedAce(0, 0, 0, 0);

		m_bHookEnabled = TRUE;
		return TRUE;
	} while (FALSE);

	//!!!!

	m_szLastError = _T("Failed to initialize HookWinsock: HookAPI");

	return FALSE;
}
