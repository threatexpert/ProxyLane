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
#include "UdpPayloadPolicy.h"

#pragma comment(lib,"psapi.lib")
#pragma comment(lib,"ws2_32.lib")

CHookWinsock *g_pHookWinsock = NULL;

static BOOL IsWSABufferPayloadAllowed(LPWSABUF buffers, DWORD bufferCount,
	size_t maxPayload)
{
	if (!buffers && bufferCount)
		return TRUE; // Let Winsock report the invalid pointer.
	size_t total = 0;
	for (DWORD i = 0; i < bufferCount; ++i)
	{
		if (buffers[i].len > maxPayload - min(total, maxPayload))
			return FALSE;
		total += buffers[i].len;
	}
	return total <= maxPayload;
}

static DWORD GetWSABufferPayloadLength(LPWSABUF buffers, DWORD bufferCount)
{
	DWORD total = 0;
	for (DWORD i = 0; i < bufferCount; ++i)
		total += buffers[i].len;
	return total;
}

static BOOL NormalizeSocketAddress(const SOCKADDR *address, int addressLength,
	_SockAddr *normalized)
{
	if (!address || !normalized)
		return FALSE;
	ZeroMemory(normalized, sizeof(*normalized));
	if (address->sa_family == AF_INET &&
		addressLength >= (int)sizeof(SOCKADDR_IN))
	{
		*normalized = *address;
		return TRUE;
	}
	if (address->sa_family != AF_INET6 ||
		addressLength < (int)sizeof(SOCKADDR_IN6))
		return FALSE;
	const SOCKADDR_IN6 *address6 = reinterpret_cast<const SOCKADDR_IN6 *>(address);
	if (!IN6_IS_ADDR_V4MAPPED(&address6->sin6_addr))
		return normalized->Set(address, addressLength);
	normalized->sa_family = AF_INET;
	DWORD ipv4 = 0;
	memcpy(&ipv4, &address6->sin6_addr.u.Byte[12], sizeof(ipv4));
	normalized->SetIPLong(ipv4);
	normalized->SetPort(ntohs(address6->sin6_port));
	return TRUE;
}

static BOOL GetSocketEndpoint(SOCKET socketHandle, int destinationFamily,
	_SockAddr *endpoint)
{
	if (!endpoint)
		return FALSE;
	SOCKADDR_STORAGE storage;
	ZeroMemory(&storage, sizeof(storage));
	int storageLength = sizeof(storage);
	if (getsockname(socketHandle, reinterpret_cast<SOCKADDR *>(&storage),
		&storageLength) == SOCKET_ERROR)
		return FALSE;
	if (storage.ss_family == AF_INET)
		return NormalizeSocketAddress(reinterpret_cast<SOCKADDR *>(&storage),
			storageLength, endpoint);
	if (storage.ss_family != AF_INET6)
		return FALSE;
	const SOCKADDR_IN6 *endpoint6 = reinterpret_cast<const SOCKADDR_IN6 *>(&storage);
	if (destinationFamily == AF_INET6 &&
		!IN6_IS_ADDR_V4MAPPED(&endpoint6->sin6_addr))
		return endpoint->Set(reinterpret_cast<const SOCKADDR *>(&storage),
			storageLength);
	if (!IN6_IS_ADDR_UNSPECIFIED(&endpoint6->sin6_addr) &&
		!IN6_IS_ADDR_V4MAPPED(&endpoint6->sin6_addr))
		return FALSE;
	ZeroMemory(endpoint, sizeof(*endpoint));
	endpoint->sa_family = AF_INET;
	if (IN6_IS_ADDR_V4MAPPED(&endpoint6->sin6_addr))
	{
		DWORD ipv4 = 0;
		memcpy(&ipv4, &endpoint6->sin6_addr.u.Byte[12], sizeof(ipv4));
		endpoint->SetIPLong(ipv4);
	}
	endpoint->SetPort(ntohs(endpoint6->sin6_port));
	return TRUE;
}

static BOOL EnsureSocketBound(SOCKET socketHandle, const SOCKADDR *address)
{
	SOCKADDR_STORAGE storage;
	int storageLength = sizeof(storage);
	if (getsockname(socketHandle, reinterpret_cast<SOCKADDR *>(&storage),
		&storageLength) == 0)
		return TRUE;
	if (WSAGetLastError() != WSAEINVAL || !address)
		return FALSE;
	ZeroMemory(&storage, sizeof(storage));
	if (address->sa_family == AF_INET6)
	{
		SOCKADDR_IN6 *local6 = reinterpret_cast<SOCKADDR_IN6 *>(&storage);
		local6->sin6_family = AF_INET6;
		return bind(socketHandle, reinterpret_cast<SOCKADDR *>(local6),
			sizeof(*local6)) == 0;
	}
	SOCKADDR_IN *local4 = reinterpret_cast<SOCKADDR_IN *>(&storage);
	local4->sin_family = AF_INET;
	return bind(socketHandle, reinterpret_cast<SOCKADDR *>(local4),
		sizeof(*local4)) == 0;
}

static const SOCKADDR *MakeSocketAddress(const SOCKADDR *original,
	_SockAddr &redirectedAddress, SOCKADDR_STORAGE *storage, int *addressLength)
{
	if (!original || original->sa_family == redirectedAddress.sa_family)
	{
		*addressLength = redirectedAddress.Size();
		return &redirectedAddress;
	}
	if (original->sa_family != AF_INET6 || !redirectedAddress.IsIPv4())
		return NULL;
	ZeroMemory(storage, sizeof(*storage));
	SOCKADDR_IN6 *mapped = reinterpret_cast<SOCKADDR_IN6 *>(storage);
	mapped->sin6_family = AF_INET6;
	mapped->sin6_port = htons(redirectedAddress.GetPort());
	mapped->sin6_addr.u.Byte[10] = 0xff;
	mapped->sin6_addr.u.Byte[11] = 0xff;
	DWORD address = redirectedAddress.GetdwIP();
	memcpy(&mapped->sin6_addr.u.Byte[12], &address, sizeof(address));
	*addressLength = sizeof(*mapped);
	return reinterpret_cast<SOCKADDR *>(mapped);
}

static void SetLoopbackAddress(_SockAddr *address, int family)
{
	if (!address)
		return;
	address->Clear();
	address->sa_family = (ADDRESS_FAMILY)family;
	if (family == AF_INET6)
		reinterpret_cast<SOCKADDR_IN6 *>(address)->sin6_addr = in6addr_loopback;
	else
		address->SetIP("127.0.0.1");
}

static ULONGLONG GetCurrentProcessCreateTimeValue()
{
	static ULONGLONG value = 0;
	if (!value)
	{
		FILETIME created, exited, kernel, user;
		if (GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
			value = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
	}
	return value;
}

class CScopedCriticalSection
{
public:
	explicit CScopedCriticalSection(CRITICAL_SECTION *lock) : m_lock(lock)
	{
		EnterCriticalSection(m_lock);
	}
	~CScopedCriticalSection() { LeaveCriticalSection(m_lock); }
private:
	CRITICAL_SECTION *m_lock;
};

static void RegisterCurrentProcessIdentity(CPRCPipeClient& pipeClient)
{
	HookProcessIdentityInfo identity = { 0 };
	identity.dwProcessId = GetCurrentProcessId();
	identity.processCreateTime = GetCurrentProcessCreateTimeValue();
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
	InitializeCriticalSection(&m_RequestPipeLock);
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
	m_pWSASendMsg = NULL;
}

CHookWinsock::~CHookWinsock(void)
{
	m_RequestPipe.Disconnect();
	DeleteCriticalSection(&m_RequestPipeLock);
	g_pHookWinsock = NULL;
}

BOOL CHookWinsock::EnsureRequestPipe()
{
	if (m_RequestPipe.IsConnected())
		return TRUE;
	return m_RequestPipe.Connect(m_szPRCPipeName);
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
	IN_ADDR address4;
	IN6_ADDR address6;
	if (name && (InetPtonA(AF_INET, name, &address4) == 1 ||
		InetPtonA(AF_INET6, name, &address6) == 1))
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
		IN6_ADDR dummyIPv6 = m_DummyDNS.GetDummyIPv6(nodename);
		// 		CHAR szIP[64];
		// 		const BYTE* pucIP = (BYTE*)&dummyIP;
		// 
		// 		sprintf(szIP, "%u.%u.%u.%u", pucIP[0], pucIP[1], pucIP[2], pucIP[3]);
		// 
		// 		ret = pFunc(szIP, servname, hints, res);

		ret = CallTrampoline(getaddrinfo)("localhost", servname, hints, res);
		struct addrinfo FAR *resls = (ret == 0 && res) ? *res : NULL;
		while (resls)
		{
			if (resls->ai_addr && resls->ai_family == AF_INET6 &&
				resls->ai_addrlen >= sizeof(SOCKADDR_IN6))
			{
				reinterpret_cast<SOCKADDR_IN6 *>(resls->ai_addr)->sin6_addr = dummyIPv6;
			}
			else if (resls->ai_addr && resls->ai_family == AF_INET &&
				resls->ai_addrlen >= sizeof(SOCKADDR_IN))
			{
				reinterpret_cast<SOCKADDR_IN *>(resls->ai_addr)->sin_addr.s_addr = dummyIP;
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
			ATLTRACE("inhook_GetAddrInfoEx Overlapped completed synchronously\r\n");

		DWORD dummyIP = m_DummyDNS.GetDummyIP(nodename);
		IN6_ADDR dummyIPv6 = m_DummyDNS.GetDummyIPv6(nodename);

		// GetAddrInfoExW may complete synchronously even when the caller supplies
		// an OVERLAPPED. Returning 0 with ppResult populated is the documented
		// completion path; the caller must not wait for a callback in that case.
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

		if (ret == 0 && ppResult && *ppResult)
		{
			PADDRINFOEX resls = *ppResult;
			while (resls)
			{
				if (resls->ai_addr && resls->ai_family == AF_INET6 &&
					resls->ai_addrlen >= sizeof(SOCKADDR_IN6))
				{
					reinterpret_cast<SOCKADDR_IN6 *>(resls->ai_addr)->sin6_addr = dummyIPv6;
				}
				else if (resls->ai_addr && resls->ai_family == AF_INET &&
					resls->ai_addrlen >= sizeof(SOCKADDR_IN))
				{
					reinterpret_cast<SOCKADDR_IN *>(resls->ai_addr)->sin_addr.s_addr = dummyIP;
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
		IN6_ADDR dummyIPv6 = m_DummyDNS.GetDummyIPv6(nodename);

		ret = CallTrampoline(GetAddrInfoW)(L"localhost", 
			pServiceName,
			pHints,
			ppResult);

		if (ret == 0 && ppResult && *ppResult)
		{
			PADDRINFOW resls = *ppResult;
			while (resls)
			{
				if (resls->ai_addr && resls->ai_family == AF_INET6 &&
					resls->ai_addrlen >= sizeof(SOCKADDR_IN6))
				{
					reinterpret_cast<SOCKADDR_IN6 *>(resls->ai_addr)->sin6_addr = dummyIPv6;
				}
				else if (resls->ai_addr && resls->ai_family == AF_INET &&
					resls->ai_addrlen >= sizeof(SOCKADDR_IN))
				{
					reinterpret_cast<SOCKADDR_IN *>(resls->ai_addr)->sin_addr.s_addr = dummyIP;
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
	if (!NormalizeSocketAddress(name, namelen, &addrname))
		return CallTrampoline(connect)(s, name, namelen);
	if (!EnsureSocketBound(s, name))
		return SOCKET_ERROR;

	int socketType = 0;
	int socketTypeLength = sizeof(socketType);
	if (m_psi.bBlockUDP &&
		getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&socketType, &socketTypeLength) == 0 &&
		socketType == SOCK_DGRAM)
	{
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}
	HookDecision decision = HackConnect(s, addrname);
	if (decision == HOOK_FAILED)
	{
		if (WSAGetLastError() == 0)
			WSASetLastError(WSAENETDOWN);
		return SOCKET_ERROR;
	}

	if (decision != HOOK_REDIRECTED)
		return CallTrampoline(connect)(s, name, namelen);
	SOCKADDR_STORAGE redirectedStorage;
	int redirectedLength = 0;
	const SOCKADDR *redirected = MakeSocketAddress(name, addrname,
		&redirectedStorage, &redirectedLength);
	if (!redirected)
	{
		WSASetLastError(WSAEAFNOSUPPORT);
		return SOCKET_ERROR;
	}
	return CallTrampoline(connect)(s, redirected, redirectedLength);
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
	if (!NormalizeSocketAddress(name, namelen, &addrname))
		return CallTrampoline(WSAConnect)(s, name, namelen, lpCallerData,
			lpCalleeData, lpSQOS, lpGQOS);
	if (!EnsureSocketBound(s, name))
		return SOCKET_ERROR;

	int socketType = 0;
	int socketTypeLength = sizeof(socketType);
	if (m_psi.bBlockUDP &&
		getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&socketType, &socketTypeLength) == 0 &&
		socketType == SOCK_DGRAM)
	{
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}
	HookDecision decision = HackConnect(s, addrname);
	if (decision == HOOK_FAILED)
	{
		if (WSAGetLastError() == 0)
			WSASetLastError(WSAENETDOWN);
		return SOCKET_ERROR;
	}

	if (decision != HOOK_REDIRECTED)
		return CallTrampoline(WSAConnect)(s, name, namelen, lpCallerData,
			lpCalleeData, lpSQOS, lpGQOS);
	SOCKADDR_STORAGE redirectedStorage;
	int redirectedLength = 0;
	const SOCKADDR *redirected = MakeSocketAddress(name, addrname,
		&redirectedStorage, &redirectedLength);
	if (!redirected)
	{
		WSASetLastError(WSAEAFNOSUPPORT);
		return SOCKET_ERROR;
	}
	return CallTrampoline(WSAConnect)(s, redirected, redirectedLength,
		lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
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
	if (!m_pConnectEx)
	{
		WSASetLastError(WSAEOPNOTSUPP);
		return FALSE;
	}
	if (!name || (name->sa_family != AF_INET && name->sa_family != AF_INET6))
		return m_pConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength,
			lpdwBytesSent, lpOverlapped);

	_SockAddr addrname;
	if (!NormalizeSocketAddress(name, namelen, &addrname))
	{
		WSASetLastError(WSAEFAULT);
		return FALSE;
	}

	HookDecision decision = HackConnect(s, addrname);
	if (decision == HOOK_FAILED)
	{
		if (WSAGetLastError() == 0)
			WSASetLastError(WSAENETDOWN);
		return FALSE;
	}

	SOCKADDR_STORAGE redirectedStorage;
	int redirectedLength = namelen;
	const SOCKADDR *redirected = name;
	if (decision == HOOK_REDIRECTED)
	{
		redirected = MakeSocketAddress(name, addrname, &redirectedStorage,
			&redirectedLength);
		if (!redirected)
		{
			WSASetLastError(WSAEAFNOSUPPORT);
			return FALSE;
		}
	}
	return m_pConnectEx(s,
		redirected,
		redirectedLength,
		lpSendBuffer,
		dwSendDataLength,
		lpdwBytesSent,
		lpOverlapped);
}

INT PASCAL hook_WSASendMsg(SOCKET s, LPWSAMSG lpMsg, DWORD dwFlags,
	LPDWORD lpNumberOfBytesSent, LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	return g_pHookWinsock->inhook_WSASendMsg(s, lpMsg, dwFlags,
		lpNumberOfBytesSent, lpOverlapped, lpCompletionRoutine);
}

INT PASCAL CHookWinsock::inhook_WSASendMsg(SOCKET s, LPWSAMSG lpMsg,
	DWORD dwFlags, LPDWORD lpNumberOfBytesSent, LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	if (!m_pWSASendMsg)
	{
		WSASetLastError(WSAEOPNOTSUPP);
		return SOCKET_ERROR;
	}
	if (m_psi.bBlockUDP)
	{
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}
	if (!m_psi.bHookUDP || !lpMsg)
		return m_pWSASendMsg(s, lpMsg, dwFlags, lpNumberOfBytesSent,
			lpOverlapped, lpCompletionRoutine);
	if (!lpMsg->name)
	{
		size_t connectedMaxPayload = 0;
		if (m_HackedSocket.GetConnectedUDPMaxPayload(s,
			&connectedMaxPayload) &&
			!IsWSABufferPayloadAllowed(lpMsg->lpBuffers,
				lpMsg->dwBufferCount, connectedMaxPayload))
		{
			WSASetLastError(WSAEMSGSIZE);
			return SOCKET_ERROR;
		}
		return m_pWSASendMsg(s, lpMsg, dwFlags, lpNumberOfBytesSent,
			lpOverlapped, lpCompletionRoutine);
	}
	_SockAddr destination;
	if (!NormalizeSocketAddress(lpMsg->name, lpMsg->namelen, &destination))
		return m_pWSASendMsg(s, lpMsg, dwFlags, lpNumberOfBytesSent,
			lpOverlapped, lpCompletionRoutine);
	if (!EnsureSocketBound(s, lpMsg->name))
		return SOCKET_ERROR;
	PRCClient client;
	size_t maxPayload = UdpPayloadPolicy::MAX_IPV4_UDP_PAYLOAD;
	HookDecision decision = HackSendTo(s, destination, &client, &maxPayload);
	if (decision == HOOK_FAILED)
	{
		if (WSAGetLastError() == 0)
			WSASetLastError(WSAENETDOWN);
		return SOCKET_ERROR;
	}
	if (decision == HOOK_BYPASS)
		return m_pWSASendMsg(s, lpMsg, dwFlags, lpNumberOfBytesSent,
			lpOverlapped, lpCompletionRoutine);
	if (!IsWSABufferPayloadAllowed(lpMsg->lpBuffers, lpMsg->dwBufferCount,
		maxPayload))
	{
		WSASetLastError(WSAEMSGSIZE);
		return SOCKET_ERROR;
	}

	SOCKADDR_STORAGE redirectedStorage;
	int redirectedLength = 0;
	const SOCKADDR *redirected = MakeSocketAddress(lpMsg->name, destination,
		&redirectedStorage, &redirectedLength);
	if (!redirected)
	{
		WSASetLastError(WSAEAFNOSUPPORT);
		return SOCKET_ERROR;
	}
	// Ancillary data describes the original egress interface / ECN state and
	// is not meaningful for the local PRC route. WSASendTo also avoids keeping
	// a stack-local WSAMSG alive across an overlapped operation.
	__WSASendTo realWSASendTo = reinterpret_cast<__WSASendTo>(
		m_HookedInfo[HOOKAPI_WSASendTo].newfuncaddr);
	INT result = realWSASendTo(s, lpMsg->lpBuffers,
		lpMsg->dwBufferCount, lpNumberOfBytesSent, dwFlags, redirected,
		redirectedLength, lpOverlapped, lpCompletionRoutine);
	// On sockets using FILE_SKIP_COMPLETION_PORT_ON_SUCCESS (notably Go's
	// UDP poller), a synchronously completed WSASendTo may leave the byte
	// count untouched. WSASendMsg callers still require the accepted datagram
	// length in that case; UDP success is all-or-nothing.
	if (result == 0 && lpNumberOfBytesSent)
		*lpNumberOfBytesSent = GetWSABufferPayloadLength(lpMsg->lpBuffers,
			lpMsg->dwBufferCount);
	return result;
}

HookDecision CHookWinsock::HackConnect(SOCKET s, _SockAddr &addrname)
{
	if (addrname.IsIPv4() && *(DWORD*)&addrname.sa_data[6] == 'pass' &&
		*(DWORD*)&addrname.sa_data[10] == 'port')
	{
		*(DWORD*)&addrname.sa_data[6] = 0;
		*(DWORD*)&addrname.sa_data[10] = 0;
		return HOOK_BYPASS;
	}

	//check SO_REUSEADDR?
	int nSockType = SOCK_STREAM;
	int nTypeLen = sizeof(nSockType);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&nSockType, &nTypeLen) != 0)
		return HOOK_FAILED;

	ATLTRACE("HackConnect.getsockopt:SO_TYPE = %d\r\n", nSockType);

	if (nSockType != SOCK_DGRAM && nSockType != SOCK_STREAM)
		return HOOK_BYPASS;
	if (nSockType == SOCK_DGRAM && !m_psi.bHookUDP)
		return HOOK_BYPASS;
	if (nSockType == SOCK_STREAM && !m_psi.bHookTCP)
		return HOOK_BYPASS;

	// 127.255.0.0/16 is ProxyLane's IPv4 dummy-DNS range.  It is part of
	// 127.0.0.0/8, but it must reach the PRC so the original hostname can be
	// recovered.  Only genuine loopback destinations bypass interception.
	const BOOL isDummyDestination =
		(addrname.IsIPv4() && m_DummyDNS.IsDummyIP(addrname.GetdwIP())) ||
		(addrname.IsIPv6() &&
			m_DummyDNS.IsDummyIPv6(addrname.GetAddr6()));
	if (addrname.IsLoopback() && !isDummyDestination)
		return HOOK_BYPASS;

	_SockAddr srcAddr;
	// Match the application socket family so the corresponding PRC loopback
	// listener can identify the registered source endpoint.
	if (!GetSocketEndpoint(s, addrname.sa_family, &srcAddr))
	{
		srcAddr.Clear();
		srcAddr.sa_family = addrname.sa_family;
		srcAddr.SetPort(0);
		if (bind(s, &srcAddr, srcAddr.Size()) == SOCKET_ERROR)
			return HOOK_FAILED;
		if (!GetSocketEndpoint(s, addrname.sa_family, &srcAddr))
			return HOOK_FAILED;
	}


	//保存原请求地址
	PRCClient prcc;
	prcc.zero();
	prcc.sType = nSockType;
	prcc.s = s;
	prcc.dwPid = GetCurrentProcessId();
	prcc.dwTid = GetCurrentThreadId();
	prcc.processCreateTime = GetCurrentProcessCreateTimeValue();
	prcc.socketGeneration = m_HackedSocket.GetSocketGeneration(s, nSockType);
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
	else if (addrname.IsIPv6() &&
		m_DummyDNS.IsDummyIPv6(addrname.GetAddr6()))
	{
		m_DummyDNS.GetHostByIPv6(addrname.GetAddr6(), prcc.szDomainName,
			sizeof(prcc.szDomainName));
	}


	CScopedCriticalSection pipeLock(&m_RequestPipeLock);
	if (!EnsureRequestPipe())
		return HOOK_FAILED;

	PRCINFO prcinfo;
	if (!m_RequestPipe.GetPRCStartupInfo(&prcinfo))
	{
		m_RequestPipe.Disconnect();
		return HOOK_FAILED;
	}

	ProxyInfo proxyInfo;
	HookDecision decision = m_HackedSocket.CanHackIt(&prcc, m_RequestPipe,
		&proxyInfo);
	if (decision != HOOK_REDIRECTED)
	{
		ATLTRACE("Hook: CHackedSocket.CanHackIt == %d\r\n", decision);
		return decision;
	}

	//将原请求登记到PRC
	if (!m_RequestPipe.PRCRegisterClient(&prcc))
	{
		m_RequestPipe.Disconnect();
		return HOOK_FAILED;
	}

	m_HackedSocket.push(&prcc);
	if (nSockType == SOCK_DGRAM)
	{
		size_t maxPayload = UdpPayloadPolicy::MaxPayload(
			proxyInfo.GetProxyType() == PROXYTYPE_SOCKS5,
			prcc.IsDNValid() ? prcc.szDomainName : NULL,
			prcc.dstAddr.IsIPv6());
		m_HackedSocket.SetUDPMaxPayload(&prcc, maxPayload, TRUE);
	}

	//修改请求的目的地址为PRC

	if (nSockType == SOCK_DGRAM)
	{
		addrname = prcc.udpAddr;
	}
	else
	{
		addrname = prcc.dstAddr.IsIPv6() ? prcinfo.tcpaddr6 : prcinfo.tcpaddr;
	}

	if (addrname.IsAny())
		SetLoopbackAddress(&addrname, prcc.dstAddr.sa_family);

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

	return HOOK_REDIRECTED;
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
	if (m_HackedSocket.GetInfo(s, &prcc) && prcc.sType == SOCK_STREAM)
	{
		const int requiredLength = prcc.dstAddr.Size();
		if (!name || !namelen || *namelen < requiredLength)
		{
			WSASetLastError(WSAEFAULT);
			return SOCKET_ERROR;
		}
		CopyMemory(name, &prcc.dstAddr, requiredLength);
		*namelen = requiredLength;
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

		PRCClient client;
		client.zero();
		if (m_HackedSocket.remove(s, &client) > 0)
		{
			CPRCPipeClient PRCPipeClient;

			if (!PRCPipeClient.Connect(m_szPRCPipeName))
				break;

			PRCPipeClient.PRCUnregisterClient(&client);

			PRCPipeClient.Disconnect();

		}

	} while (FALSE);

	return CallTrampoline(closesocket)(s);
}

MyDetourProc(has_Return,
	int, WSAAPI, send, (SOCKET s, const char* buf, int len, int flags))
{
	return g_pHookWinsock->inhook_send(s, buf, len, flags);
}

MyDetourProc(has_Return, int, WSAAPI, WSASend, (
	SOCKET s,
	LPWSABUF lpBuffers,
	DWORD dwBufferCount,
	LPDWORD lpNumberOfBytesSent,
	DWORD dwFlags,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	))
{
	return g_pHookWinsock->inhook_WSASend(s, lpBuffers, dwBufferCount,
		lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
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

int WSAAPI CHookWinsock::inhook_send(SOCKET s, const char* buf, int len,
	int flags)
{
	WSABUF buffer;
	buffer.buf = const_cast<char *>(buf);
	buffer.len = len >= 0 ? static_cast<ULONG>(len) : 0;
	DWORD sent = 0;
	if (len >= 0)
	{
		int result = inhook_WSASend(s, &buffer, 1, &sent, flags, NULL, NULL);
		return result == 0 ? static_cast<int>(sent) : SOCKET_ERROR;
	}
	return CallTrampoline(send)(s, buf, len, flags);
}

int WSAAPI CHookWinsock::inhook_WSASend(SOCKET s, LPWSABUF lpBuffers,
	DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	if (m_psi.bBlockUDP)
	{
		int socketType = 0;
		int socketTypeLength = sizeof(socketType);
		if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&socketType,
			&socketTypeLength) == 0 && socketType == SOCK_DGRAM)
		{
			WSASetLastError(WSAEACCES);
			return SOCKET_ERROR;
		}
	}
	if (!m_psi.bHookUDP)
		return CallTrampoline(WSASend)(s, lpBuffers, dwBufferCount,
			lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
	size_t maxPayload = 0;
	if (m_HackedSocket.GetConnectedUDPMaxPayload(s, &maxPayload) &&
		!IsWSABufferPayloadAllowed(lpBuffers, dwBufferCount, maxPayload))
	{
		WSASetLastError(WSAEMSGSIZE);
		return SOCKET_ERROR;
	}
	return CallTrampoline(WSASend)(s, lpBuffers, dwBufferCount,
		lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

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
	if (len < 0)
		return CallTrampoline(sendto)(s, buf, len, flags, to, tolen);

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

	_SockAddr addrname;
	if (!lpTo)
	{
		size_t connectedMaxPayload = 0;
		if (m_HackedSocket.GetConnectedUDPMaxPayload(s,
			&connectedMaxPayload) &&
			!IsWSABufferPayloadAllowed(lpBuffers, dwBufferCount,
				connectedMaxPayload))
		{
			WSASetLastError(WSAEMSGSIZE);
			return SOCKET_ERROR;
		}
		// Buffers and completion state remain owned by Winsock.
		return CallTrampoline(WSASendTo)(s, lpBuffers, dwBufferCount,
			lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped,
			lpCompletionRoutine);
	}
	if (!NormalizeSocketAddress(lpTo, iToLen, &addrname))
		return CallTrampoline(WSASendTo)(s, lpBuffers, dwBufferCount,
			lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped,
			lpCompletionRoutine);
	if (!EnsureSocketBound(s, lpTo))
		return SOCKET_ERROR;

	PRCClient prcc;

	size_t maxPayload = UdpPayloadPolicy::MAX_IPV4_UDP_PAYLOAD;
	HookDecision decision = HackSendTo(s, addrname, &prcc, &maxPayload);
	if (decision == HOOK_FAILED)
	{
		if (WSAGetLastError() == 0)
			WSASetLastError(WSAENETDOWN);
		return SOCKET_ERROR;
	}
	if (decision == HOOK_BYPASS)
	{
		return CallTrampoline(WSASendTo)(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
	}
	if (!IsWSABufferPayloadAllowed(lpBuffers, dwBufferCount, maxPayload))
	{
		WSASetLastError(WSAEMSGSIZE);
		return SOCKET_ERROR;
	}


	// Only the destination is replaced. Application buffers and completion
	// state remain owned by Winsock, so Overlapped/IOCP works naturally.
	SOCKADDR_STORAGE redirectedStorage;
	int redirectedLength = 0;
	const SOCKADDR *redirected = MakeSocketAddress(lpTo, addrname,
		&redirectedStorage, &redirectedLength);
	if (!redirected)
	{
		WSASetLastError(WSAEAFNOSUPPORT);
		return SOCKET_ERROR;
	}
	return CallTrampoline(WSASendTo)(s, lpBuffers, dwBufferCount,
		lpNumberOfBytesSent, dwFlags, redirected, redirectedLength,
		lpOverlapped, lpCompletionRoutine);
}

int WSAAPI CHookWinsock::inhook_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
	if (m_psi.bBlockUDP)
	{
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}
	return CallTrampoline(recvfrom)(s, buf, len, flags, from, fromlen);

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
	return CallTrampoline(WSARecvFrom)(s, lpBuffers, dwBufferCount,
		lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped,
		lpCompletionRoutine);


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


HookDecision CHookWinsock::HackSendTo(SOCKET s, _SockAddr &addrname,
	LPPRCClient lpC, size_t *maxPayload)
{
	if (!m_psi.bHookUDP)
		return HOOK_BYPASS;

	if (addrname.IsIPv4() && *(DWORD*)&addrname.sa_data[6] == 'pass' &&
		*(DWORD*)&addrname.sa_data[10] == 'port')
	{
		*(DWORD*)&addrname.sa_data[6] = 0;
		*(DWORD*)&addrname.sa_data[10] = 0;
		return HOOK_BYPASS;
	}

	int nSockType;
	int nTypeLen = sizeof(nSockType);
	if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&nSockType, &nTypeLen) != 0)
		return HOOK_FAILED;

	if (nSockType != SOCK_DGRAM)
		return HOOK_BYPASS;

	// getpeername on a connected proxied UDP socket intentionally exposes
	// the real PRC route. Some clients feed that address back into sendto.
	// It is already the transport endpoint of an existing route and must not
	// be registered as a new original destination.
	if (m_HackedSocket.IsUDPRouteAddress(s, &addrname))
		return HOOK_BYPASS;

	_SockAddr srcAddr;
	if (!GetSocketEndpoint(s, addrname.sa_family, &srcAddr))
	{
		if (WSAGetLastError() != WSAEINVAL)
			return HOOK_FAILED;
		srcAddr.Clear();
		srcAddr.sa_family = addrname.sa_family;
		srcAddr.SetPort(0);
		if (bind(s, &srcAddr, srcAddr.Size()) == SOCKET_ERROR)
			return HOOK_FAILED;
		if (!GetSocketEndpoint(s, addrname.sa_family, &srcAddr))
			return HOOK_FAILED;
	}

	PRCClient prcc;
	prcc.zero();
	prcc.sType = SOCK_DGRAM;
	prcc.s = s;
	prcc.dwPid = GetCurrentProcessId();
	prcc.dwTid = GetCurrentThreadId();
	prcc.processCreateTime = GetCurrentProcessCreateTimeValue();
	prcc.socketGeneration = m_HackedSocket.GetSocketGeneration(s, nSockType);
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
	else if (addrname.IsIPv6() &&
		m_DummyDNS.IsDummyIPv6(addrname.GetAddr6()))
	{
		m_DummyDNS.GetHostByIPv6(addrname.GetAddr6(), prcc.szDomainName,
			sizeof(prcc.szDomainName));
	}

	//如果已经hacked 则函数会设置prcc.udpAddr， 即处理转发udp的服务地址
	if (m_HackedSocket.IsUDPReqHacked(&prcc))
	{
		addrname = prcc.udpAddr;
		if (addrname.IsAny())
			SetLoopbackAddress(&addrname, prcc.dstAddr.sa_family);

		*lpC = prcc;
		if (maxPayload)
			m_HackedSocket.GetUDPMaxPayload(&prcc, maxPayload);

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

		return HOOK_REDIRECTED;
	}

	CScopedCriticalSection pipeLock(&m_RequestPipeLock);
	// Another thread may have completed the same first-send registration
	// while this thread was preparing its request.
	if (m_HackedSocket.IsUDPReqHacked(&prcc))
	{
		addrname = prcc.udpAddr;
		if (addrname.IsAny())
			SetLoopbackAddress(&addrname, prcc.dstAddr.sa_family);
		*lpC = prcc;
		if (maxPayload)
			m_HackedSocket.GetUDPMaxPayload(&prcc, maxPayload);
		return HOOK_REDIRECTED;
	}
	if (!EnsureRequestPipe())
		return HOOK_FAILED;

	ProxyInfo proxyInfo;
	HookDecision decision = m_HackedSocket.CanHackIt(&prcc, m_RequestPipe,
		&proxyInfo);
	if (decision != HOOK_REDIRECTED)
	{
		ATLTRACE("UDP: CHackedSocket.CanHackIt == %d\r\n", decision);
		return decision;
	}

	if (!m_RequestPipe.PRCRegisterClient(&prcc))
	{
		m_RequestPipe.Disconnect();
		return HOOK_FAILED;
	}

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
	size_t routeMaxPayload = UdpPayloadPolicy::MaxPayload(
		proxyInfo.GetProxyType() == PROXYTYPE_SOCKS5,
		prcc.IsDNValid() ? prcc.szDomainName : NULL,
		prcc.dstAddr.IsIPv6());
	m_HackedSocket.SetUDPMaxPayload(&prcc, routeMaxPayload, FALSE);
	if (maxPayload)
		*maxPayload = routeMaxPayload;

	if (addrname.IsAny())
		SetLoopbackAddress(&addrname, prcc.dstAddr.sa_family);

	*lpC = prcc;

#ifdef _DEBUG
	pAddr = addrname.GetAddr();
	ATLTRACE("sendto2: socket:%d: %u.%u.%u.%u:%d\r\n", s, pAddr->s_net, pAddr->s_host, pAddr->s_lh, pAddr->s_impno, addrname.GetPort());
#endif

	return HOOK_REDIRECTED;
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
		if (lpvInBuffer && lpvOutBuffer
			&& cbInBuffer == sizeof(GUID)
			&& memcmp(&guid_WSAID_CONNECTEX, lpvInBuffer, 16) == 0
			&& cbOutBuffer >= sizeof(void*)
			)
		{
			*(void**)&m_pConnectEx = *(void**)lpvOutBuffer;
			*(void**)lpvOutBuffer = hook_ConnectEx;
		}
#ifndef WSAID_WSASENDMSG
#define WSAID_WSASENDMSG \
	{0xa441e712,0x754f,0x43ca,{0x84,0xa7,0x0d,0xee,0x44,0xcf,0x60,0x6d}}
#endif
		static GUID guid_WSAID_WSASENDMSG = WSAID_WSASENDMSG;
		if (lpvInBuffer && lpvOutBuffer && cbInBuffer == sizeof(GUID) &&
			cbOutBuffer >= sizeof(void*) &&
			memcmp(&guid_WSAID_WSASENDMSG, lpvInBuffer, sizeof(GUID)) == 0)
		{
			*(void**)&m_pWSASendMsg = *(void**)lpvOutBuffer;
			*(void**)lpvOutBuffer = hook_WSASendMsg;
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
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(send), "send", _HOOKFUNC(send), _TRAMPFUNC(send)))
			break;
		if (!HookAPI(HOOKMODULE_WS2_32, _EHF(WSASend), "WSASend", _HOOKFUNC(WSASend), _TRAMPFUNC(WSASend)))
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
