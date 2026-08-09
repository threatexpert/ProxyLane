#pragma once


#include "structinfo.h"
#include "TSSTL.h"
#include "PRCPipeClient.h"
#include "DnsRedirectPolicy.h"
#include "inlinehook.h"

using namespace std;

typedef enum
{
	HOOKMODULE_WS2_32 = 0,
	HOOKMODULE_KERNEL32,
	HOOKMODULE_COUNT
}eHOOKMODUDLE;

//getaddrinfo
typedef enum
{
	HOOKAPI_connect = 0,
	HOOKAPI_WSAConnect,
	HOOKAPI_gethostbyname,
	HOOKAPI_WSAAsyncGetHostByName,
	HOOKAPI_getaddrinfo,
	HOOKAPI_getpeername,
	HOOKAPI_closesocket,
	HOOKAPI_sendto,
	HOOKAPI_WSASendTo,
	HOOKAPI_WSAIoctl,
	HOOKAPI_GetAddrInfoExW,
	HOOKAPI_GetAddrInfoW,

	//kernel32
	HOOKAPI_CreateProcessInternalW,
	//HOOKAPI_AddAccessAllowedAce,

	HOOKAPI_COUNT
}eHOOKFUN; 

enum HookDecision
{
	HOOK_BYPASS = 0,
	HOOK_REDIRECTED,
	HOOK_FAILED
};


class CGlobalProxy;

class CAsyncSocketExLayer;

class CHookWinsock
{
	friend CAsyncSocketExLayer;

	

	//hook info struct
	typedef struct
	{
		void* funcaddr;
		void* myfuncaddr;
		void* newfuncaddr;
	}HOOKSTRUCT;

	//

	typedef struct  
	{
		char name[MAX_PATH];

		operator char*() 
		{ 
			return &name[0];
		}

		char * operator =(char *lpsz)
		{
			int i=0;

			while(i<sizeof(name)-1 && lpsz[i])
			{
				name[i] = lpsz[i];
				i++;
			}
			name[i] = '\0';
			return name;
		}
	}MODULENAME;


	//CDummyDNS start

	//将进程的dns请求拦截下来， 记下请求解析的域名，然后返回一个特制的ip，
	//如果这个特制的ip出现在之后的connect动作， 则在之后的代理会用原请求解析的域名去解析并连接
	class CDummyDNS
	{
	public:
		typedef struct
		{
			DWORD dummyIP;
			IN6_ADDR dummyIPv6;
			char szHost[256];
		}INFO;

		CDummyDNS()
		{
			//127.255.0.0
			m_DummyIP = 0x7fff0000;
			m_DummyHandle = 0x520307;
		}

		~CDummyDNS()
		{

		}

		BOOL IsDummyIP(DWORD dwip)
		{
			return (ntohl(dwip) >> 16) == 0x7fff;//127.255.x.x
		}

		BOOL IsDummyIPv6(const IN6_ADDR *address)
		{
			return address && address->u.Byte[0] == 0xfd &&
				address->u.Byte[1] == 0xff;
		}

		HANDLE GetDummyHandle(const char* name, char* buf, int buflen)
		{
			if(m_DummyHandle > 0xffff0000)
				m_DummyHandle = 0x520307;

			DWORD dummyip = GetDummyIP(name);
			buflen = min(sizeof(hostent), buflen);
			memcpy(buf, GetHostent(dummyip), buflen);

			return (HANDLE)m_DummyHandle++;
		}

		DWORD GetDummyIP(const char *lpHost)
		{
			INFO *pNode = GetNode(lpHost);
			if(pNode)
				return pNode->dummyIP;

			CTSList<INFO>::critical lc = m_ls;
			m_DummyIP++;
			if(m_DummyIP > 0x7ffffffe)
				m_DummyIP = 0x7fff0000;

			INFO info;
			ZeroMemory(&info, sizeof(info));

			info.dummyIP = htonl(m_DummyIP);
			info.dummyIPv6.u.Byte[0] = 0xfd;
			info.dummyIPv6.u.Byte[1] = 0xff;
			CopyMemory(&info.dummyIPv6.u.Byte[12], &info.dummyIP,
				sizeof(info.dummyIP));
			strncpy(info.szHost, lpHost, sizeof(info.szHost)-1);

			m_ls.push_front(info);

			return htonl(m_DummyIP);
		}

		IN6_ADDR GetDummyIPv6(const char *lpHost)
		{
			INFO *node = GetNode(lpHost);
			if (!node)
			{
				GetDummyIP(lpHost);
				node = GetNode(lpHost);
			}
			IN6_ADDR empty = IN6ADDR_ANY_INIT;
			return node ? node->dummyIPv6 : empty;
		}

		BOOL GetHostByIP(DWORD dummyip, char *lpbuf, int bufsize)
		{
			CTSList<INFO>::critical lc = m_ls;
			for(list<INFO>::iterator it=m_ls.begin(); it!=m_ls.end(); it++)
			{
				if((*it).dummyIP == dummyip)
				{
					strncpy(lpbuf, (*it).szHost, bufsize);
					return TRUE;
				}
			}
			return FALSE;
		};

		BOOL GetHostByIPv6(const IN6_ADDR *address, char *lpbuf, int bufsize)
		{
			if (!address || !lpbuf || bufsize <= 0)
				return FALSE;
			CTSList<INFO>::critical lc = m_ls;
			for(list<INFO>::iterator it=m_ls.begin(); it!=m_ls.end(); it++)
			{
				if (IN6_ARE_ADDR_EQUAL(&it->dummyIPv6, address))
				{
					strncpy(lpbuf, it->szHost, bufsize - 1);
					lpbuf[bufsize - 1] = '\0';
					return TRUE;
				}
			}
			return FALSE;
		}

		hostent *GetHostent(DWORD nIP)
		{
			hostent *p = gethostbyname("127.0.0.1");
			//????
			if (p)
			{
				*(DWORD*)p->h_addr_list[0] = nIP;
			}
			return p;
			//m_ht = *p;
			//*(DWORD*)(m_ht.h_addr_list[0]) = nIP;
			//return &m_ht;
		};

		INFO *GetNode(const char *name)
		{
			CTSList<INFO>::critical lc = m_ls;
			for(list<INFO>::iterator it=m_ls.begin(); it!=m_ls.end(); it++)
			{
				if(_stricmp(name, it->szHost) == 0)
					return &*it;
			}
			return NULL;
		}

		//BOOL RemoveNode();

	private:

		char hoststruct[MAXGETHOSTSTRUCT];
		hostent m_ht;
		DWORD m_DummyIP;
		DWORD m_DummyHandle;
		CTSList<INFO> m_ls;
	};//CDummyDNS end

	class CHackedSocket
	{
	public:
		CHackedSocket(CHookWinsock *pHW)
		{
			m_pHW = pHW;
			m_nextSocketGeneration = 0;
		}
		~CHackedSocket()
		{

		}

		typedef PRCClient CONNINFO;
		struct SOCKETGEN
		{
			SOCKET s;
			int sType;
			ULONGLONG generation;
		};
		struct UDP_PAYLOAD_LIMIT
		{
			SOCKET s;
			ULONGLONG generation;
			_SockAddr destination;
			WORD destinationPort;
			char domain[256];
			size_t maxPayload;
			BOOL connected;
		};

		ULONGLONG GetSocketGeneration(SOCKET s, int sType)
		{
			CTSList<SOCKETGEN>::critical lc = m_socketGenerations;
			for (CTSList<SOCKETGEN>::iterator it = m_socketGenerations.begin();
				it != m_socketGenerations.end(); ++it)
			{
				if (it->s == s && it->sType == sType)
					return it->generation;
			}
			SOCKETGEN item;
			item.s = s;
			item.sType = sType;
			item.generation = ++m_nextSocketGeneration;
			if (!item.generation)
				item.generation = ++m_nextSocketGeneration;
			m_socketGenerations.push_back(item);
			return item.generation;
		}

		void push(CONNINFO *pCI)
		{
			CTSList<CONNINFO>::critical lc = m_ls;
			for (CTSList<CONNINFO>::iterator it = m_ls.begin(); it != m_ls.end(); ++it)
			{
				if (it->s == pCI->s && it->sType == pCI->sType &&
					it->srcAddr.GetPort() == pCI->srcAddr.GetPort() &&
					it->dstAddr == pCI->dstAddr &&
					_stricmp(it->szDomainName, pCI->szDomainName) == 0)
				{
					*it = *pCI;
					return;
				}
			}
			m_ls.push_front(*pCI);
		}

		int remove(SOCKET s, CONNINFO *removedInfo = NULL)
		{
			int nCount = 0;
			{
				CTSList<CONNINFO>::critical lc = m_ls;
				for(CTSList<CONNINFO>::iterator it=m_ls.begin(); it!=m_ls.end();)
				{
					if(it->s == s)
					{
						if (!nCount && removedInfo)
							*removedInfo = *it;
						m_ls.erase(it++);
						nCount++;
					}else
					{
						it++;
					}
				}
			}
			{
				CTSList<SOCKETGEN>::critical lc = m_socketGenerations;
				for (CTSList<SOCKETGEN>::iterator it = m_socketGenerations.begin();
					it != m_socketGenerations.end(); )
				{
					if (it->s == s)
						m_socketGenerations.erase(it++);
					else
						++it;
				}
			}
			{
				CTSList<UDP_PAYLOAD_LIMIT>::critical lc = m_udpPayloadLimits;
				for (CTSList<UDP_PAYLOAD_LIMIT>::iterator it = m_udpPayloadLimits.begin();
					it != m_udpPayloadLimits.end(); )
				{
					if (it->s == s)
						m_udpPayloadLimits.erase(it++);
					else
						++it;
				}
			}
			return nCount;
		}

		void SetUDPMaxPayload(CONNINFO *pCI, size_t maxPayload,
			BOOL connected)
		{
			if (!pCI || pCI->sType != SOCK_DGRAM)
				return;
			CTSList<UDP_PAYLOAD_LIMIT>::critical lc = m_udpPayloadLimits;
			for (CTSList<UDP_PAYLOAD_LIMIT>::iterator it = m_udpPayloadLimits.begin();
				it != m_udpPayloadLimits.end(); ++it)
			{
				if (it->s == pCI->s && it->generation == pCI->socketGeneration &&
					it->destination == pCI->dstAddr &&
					_stricmp(it->domain, pCI->szDomainName) == 0)
				{
					it->maxPayload = maxPayload;
					it->connected = connected;
					return;
				}
			}
			UDP_PAYLOAD_LIMIT item;
			ZeroMemory(&item, sizeof(item));
			item.s = (SOCKET)pCI->s;
			item.generation = pCI->socketGeneration;
			item.destination = pCI->dstAddr;
			item.destinationPort = pCI->dstAddr.GetPort();
			strncpy(item.domain, pCI->szDomainName, sizeof(item.domain) - 1);
			item.maxPayload = maxPayload;
			item.connected = connected;
			m_udpPayloadLimits.push_front(item);
		}

		BOOL GetUDPMaxPayload(CONNINFO *pCI, size_t *maxPayload)
		{
			if (!pCI || !maxPayload)
				return FALSE;
			CTSList<UDP_PAYLOAD_LIMIT>::critical lc = m_udpPayloadLimits;
			for (CTSList<UDP_PAYLOAD_LIMIT>::iterator it = m_udpPayloadLimits.begin();
				it != m_udpPayloadLimits.end(); ++it)
			{
				if (it->s == pCI->s && it->generation == pCI->socketGeneration &&
					it->destination == pCI->dstAddr &&
					_stricmp(it->domain, pCI->szDomainName) == 0)
				{
					*maxPayload = it->maxPayload;
					return TRUE;
				}
			}
			return FALSE;
		}

		BOOL GetConnectedUDPMaxPayload(SOCKET s, size_t *maxPayload)
		{
			if (!maxPayload)
				return FALSE;
			CTSList<UDP_PAYLOAD_LIMIT>::critical lc = m_udpPayloadLimits;
			for (CTSList<UDP_PAYLOAD_LIMIT>::iterator it = m_udpPayloadLimits.begin();
				it != m_udpPayloadLimits.end(); ++it)
			{
				if (it->s == s && it->connected)
				{
					*maxPayload = it->maxPayload;
					return TRUE;
				}
			}
			return FALSE;
		}

		BOOL GetInfo(SOCKET s, CONNINFO *pCI)
		{
			CTSList<CONNINFO>::critical lc = m_ls;

			for(CTSList<CONNINFO>::iterator it=m_ls.begin(); it!=m_ls.end(); it++)
			{
				if(it->s == s)
				{
					*pCI = *it;
					return TRUE;
				}
			}
			return FALSE;
		}

		HookDecision CanHackIt(const LPPRCClient pCI, CPRCPipeClient& pipeClient,
			LPProxyInfo proxyInfo = NULL)
		{
			ProxyInfo pi;
			if (!pipeClient.PRCGetProxyInfo((LPPRCClient)pCI, &pi))
				return HOOK_FAILED;
			if (proxyInfo)
				*proxyInfo = pi;

			// Remote-DNS mode intentionally overrides the general LAN bypass for
			// private :53 endpoints.  PRC keeps the original address for identity
			// and substitutes only the upstream destination.
			if (DnsRedirectPolicy::ShouldRedirect(*pCI, m_pHW->m_psi, pi))
				return HOOK_REDIRECTED;

			if (pCI->IsDNValid())
				return HOOK_REDIRECTED;
			if (pCI->dstAddr.IsIPv6())
				return HOOK_REDIRECTED;

			//如果程序要访问本地局域网络，但是代理服务器是公网的，则不劫持这个socket
			in_addr dstaddr;
			in_addr proxyaddr;

			dstaddr.s_addr = pCI->dstAddr.GetdwIP();
			proxyaddr.s_addr = inet_addr(pi.strProxyHost);

			if (!dstaddr.s_addr || dstaddr.s_addr == INADDR_NONE)
				return HOOK_BYPASS;
			if (!proxyaddr.s_addr || proxyaddr.s_addr == INADDR_NONE)
				return HOOK_REDIRECTED;

			if (m_pHW->m_psi.bHookLanIP)
				return HOOK_REDIRECTED;

			if (dstaddr.s_net == 127)
			{
				if (proxyaddr.s_net != 127)
				{
					return HOOK_BYPASS;
				}
			}else if (dstaddr.s_net == 192 && dstaddr.s_host == 168)
			{
				if (proxyaddr.s_net != dstaddr.s_net || proxyaddr.s_host != dstaddr.s_host || proxyaddr.s_lh != dstaddr.s_lh)
				{
					return HOOK_BYPASS;
				}
			}else if (dstaddr.s_net == 172 && dstaddr.s_host >= 16 && dstaddr.s_host <= 131)
			{
				if (proxyaddr.s_net != dstaddr.s_net || proxyaddr.s_host != dstaddr.s_host || proxyaddr.s_lh != dstaddr.s_lh)
				{
					return HOOK_BYPASS;
				}
			}else if (dstaddr.s_net == 10)
			{
				if (proxyaddr.s_net != dstaddr.s_net || proxyaddr.s_host != dstaddr.s_host || proxyaddr.s_lh != dstaddr.s_lh)
				{
					return HOOK_BYPASS;
				}
			}

			return HOOK_REDIRECTED;
		}

		BOOL IsUDPReqHacked(const CONNINFO *pCI)
		{
			CTSList<CONNINFO>::critical lc = m_ls;

			//链中记录着所有劫持过的udp包的客户端信息
			for (CTSList<CONNINFO>::iterator it=m_ls.begin(); it!=m_ls.end(); it++)
			{
				if(it->s == pCI->s && it->sType == SOCK_DGRAM)
				{
					//判断原地址是否一致
					if ( it->srcAddr.GetPort() != ((LPPRCClient)pCI)->srcAddr.GetPort()
						|| (!it->srcAddr.IsAny() && !it->srcAddr.SameAddress(((LPPRCClient)pCI)->srcAddr))
						)
						continue;//当前节点信息不一致， 但不能确定没劫持过这个socket， 继续查找其他节点

					// Each destination has a stable local PRC route. This lets the
					// application send raw payloads while the PRC still knows which
					// SOCKS5 destination header to add.
					if (((LPPRCClient)pCI)->IsDNValid())
					{
						if (!it->IsDNValid())
							continue;
						if (_stricmp(it->szDomainName, ((LPPRCClient)pCI)->szDomainName) != 0 ||
							it->dstAddr.GetPort() != ((LPPRCClient)pCI)->dstAddr.GetPort())
							continue;
					}
					else
					{
						if (it->IsDNValid() ||
							!(it->dstAddr == ((LPPRCClient)pCI)->dstAddr))
							continue;
					}

					((LPPRCClient)pCI)->udpAddr = it->udpAddr;

					return TRUE;
				}
			}
			return FALSE;
		}

		BOOL IsUDPRouteAddress(SOCKET s, _SockAddr *destination)
		{
			if (!destination ||
				(destination->sa_family != AF_INET && destination->sa_family != AF_INET6))
				return FALSE;

			CTSList<CONNINFO>::critical lc = m_ls;
			for (CTSList<CONNINFO>::iterator it = m_ls.begin();
				it != m_ls.end(); ++it)
			{
				if (it->s != s || it->sType != SOCK_DGRAM ||
					it->udpAddr.GetPort() != destination->GetPort())
					continue;

				if (it->udpAddr.SameAddress(*destination) ||
					(it->udpAddr.IsAny() && destination->IsLoopback()))
					return TRUE;
			}
			return FALSE;
		}

		//在接收后 代替 源地址
		//dwIP、Port是udp包头中的地址信息
		//如果来自PRC的包， 则要把源地址代替为dwIP、Port
		BOOL ReplaceAddr(SOCKET s, _SockAddr* from, DWORD dwIP, WORD Port)
		{
			_SockAddr srcAddr;
			int srcaddrlen = sizeof(_SockAddr);
			//查询该socket绑定的地址
			if(getsockname(s, &srcAddr, &srcaddrlen) == SOCKET_ERROR)
			{
				return FALSE;
			}

			CTSList<CONNINFO>::critical lc = m_ls;

			for (CTSList<CONNINFO>::iterator it=m_ls.begin(); it!=m_ls.end(); it++)
			{
				if(it->s == s)
				{
					if (it->srcAddr.GetPort() != srcAddr.GetPort()
						|| (!it->srcAddr.IsAny() && !it->srcAddr.SameAddress(srcAddr))
						)
						continue;

					//确定包是来自PRC的（udpAddr是本地udp代理的地址）
					if (from->GetPort() != it->udpAddr.GetPort()
						|| (!it->udpAddr.IsAny() && !it->udpAddr.SameAddress(*from))
						)
					{
						continue;
					}

					//判断客户端发包时的目的地址是域名还是IP
					if (it->IsDNValid())
					{
						//域名
						//把地址代替为 dummyIP!
						from->SetIPLong(it->dstAddr.GetdwIP());
						from->SetPort(ntohs(Port));
						return TRUE;
					}else
					{
						//IP
						//将udp包头的IP信息代替进去
						from->SetIPLong(dwIP);
						from->SetPort(ntohs(Port));
						return TRUE;
					}

				}
			}

			//包不是来自PRC？？

			return FALSE;
		}



	private:
		CTSList<CONNINFO> m_ls;
		CTSList<SOCKETGEN> m_socketGenerations;
		CTSList<UDP_PAYLOAD_LIMIT> m_udpPayloadLimits;
		ULONGLONG m_nextSocketGeneration;
		CHookWinsock *m_pHW;

	};



public:
	CHookWinsock(void);
	~CHookWinsock(void);

	CString GetLastError();

	BOOL IsHookEnabled();
	BOOL EnableHook();
	BOOL DisableHook();

	BOOL SetPRCPipeName(LPCSTR lpszPipeName);
	CString GetPRCPipeName();




	BOOL HookWinsock();
	BOOL UnhookWinsock();

	void HookOnOff(eHOOKFUN ehf, bool DOUNT);
	BOOL HookAPI(eHOOKMODUDLE ehm, eHOOKFUN ehf, char *exportfunc, LPVOID myfuncaddr, LPVOID newfuncaddr);

	BOOL IsHostNameReserved(const char *name);

	//负责dns的几个API
	hostent* WSAAPI inhook_gethostbyname(const char* name);

	HANDLE WSAAPI inhook_WSAAsyncGetHostByName(HWND hWnd, unsigned int wMsg, const char* name, char* buf, int buflen);

	int WSAAPI inhook_getaddrinfo(IN const char FAR * nodename, IN const char FAR * servname, IN const struct addrinfo FAR * hints, OUT struct addrinfo FAR * FAR * res);

	//负责建立连接的API
	int WSAAPI inhook_connect(SOCKET s, const struct sockaddr FAR * name, int namelen);

	int WSAAPI inhook_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);

	//处理拦截下来的连接
	HookDecision HackConnect(SOCKET s, _SockAddr &addrname);

	//
	BOOL HackDNS(const char *name);

	int WSAAPI inhook_getpeername(SOCKET s, struct sockaddr* name, int* namelen);

	int WSAAPI inhook_closesocket(SOCKET s);

	int WSAAPI inhook_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);

	int WSAAPI inhook_WSASendTo(
		SOCKET s,
		LPWSABUF lpBuffers,
		DWORD dwBufferCount,
		LPDWORD lpNumberOfBytesSent,
		DWORD dwFlags,
		const struct sockaddr* lpTo,
		int iToLen,
		LPWSAOVERLAPPED lpOverlapped,
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
		);

	HookDecision HackSendTo(SOCKET s, _SockAddr &addrname, LPPRCClient lpC,
		size_t *maxPayload = NULL);

	int
		WSAAPI
		inhook_WSAIoctl(
		SOCKET s,
		DWORD dwIoControlCode,
		LPVOID lpvInBuffer,
		DWORD cbInBuffer,
		LPVOID lpvOutBuffer,
		DWORD cbOutBuffer,
		LPDWORD lpcbBytesReturned,
		LPWSAOVERLAPPED lpOverlapped,
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
		);

	BOOL PASCAL inhook_ConnectEx(
		SOCKET s,
		const struct sockaddr *name,
		int namelen,
		PVOID lpSendBuffer,
		DWORD dwSendDataLength,
		LPDWORD lpdwBytesSent,
		LPOVERLAPPED lpOverlapped
		);
	INT PASCAL inhook_WSASendMsg(SOCKET s, LPWSAMSG lpMsg, DWORD dwFlags,
		LPDWORD lpNumberOfBytesSent, LPWSAOVERLAPPED lpOverlapped,
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

		INT
			WSAAPI
			inhook_GetAddrInfoExW(
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
			);

		int WSAAPI inhook_GetAddrInfoW(
			_In_opt_  PCWSTR pNodeName,
			_In_opt_  PCWSTR pServiceName,
			_In_opt_  const ADDRINFOW *pHints,
			_Out_     PADDRINFOW *ppResult
			);
	//////////////////////////////////////////////////////////////////////////

	BOOL WINAPI inhook_CreateProcessInternalW(  HANDLE hToken,
		LPCWSTR lpApplicationName,
		LPWSTR lpCommandLine,
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL bInheritHandles,
		DWORD dwCreationFlags,
		LPVOID lpEnvironment,
		LPCWSTR lpCurrentDirectory,
		LPSTARTUPINFOW lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation,
		PHANDLE hNewToken);


private:

	ProxySettingsInfo m_psi;

	BOOL m_bHookEnabled;

	CDummyDNS m_DummyDNS;
	CHackedSocket m_HackedSocket;

	MODULENAME   m_ModuleName[HOOKMODULE_COUNT];
	HOOKSTRUCT m_HookedInfo[HOOKAPI_COUNT];

	void *m_mem4bakcode[HOOKMODULE_COUNT];

	__CONNECTEX m_pConnectEx;
	__WSASENDMSG m_pWSASendMsg;

	CString m_szLastError;
	CString m_szPRCPipeName;
	CPRCPipeClient m_RequestPipe;
	CRITICAL_SECTION m_RequestPipeLock;
	BOOL EnsureRequestPipe();

};
