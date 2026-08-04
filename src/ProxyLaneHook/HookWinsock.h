#pragma once


#include "structinfo.h"
#include "TSSTL.h"
#include "PRCPipeClient.h"
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
	HOOKAPI_recvfrom,
	HOOKAPI_WSARecvFrom,
	HOOKAPI_WSAIoctl,
	HOOKAPI_GetAddrInfoExW,
	HOOKAPI_GetAddrInfoW,

	//kernel32
	HOOKAPI_CreateProcessInternalW,
	//HOOKAPI_AddAccessAllowedAce,

	HOOKAPI_COUNT
}eHOOKFUN; 


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
			strncpy(info.szHost, lpHost, sizeof(info.szHost)-1);

			m_ls.push_front(info);

			return htonl(m_DummyIP);
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
		}
		~CHackedSocket()
		{

		}

		typedef PRCClient CONNINFO;

		void push(CONNINFO *pCI)
		{
			CTSList<CONNINFO>::critical lc = m_ls;

			m_ls.push_front(*pCI);
		}

		int remove(SOCKET s)
		{
			int nCount = 0;
			CTSList<CONNINFO>::critical lc = m_ls;

			for(CTSList<CONNINFO>::iterator it=m_ls.begin(); it!=m_ls.end();)
			{
				if(it->s == s)
				{
					m_ls.erase(it++);
					nCount++;
				}else
				{
					it++;
				}
			}
			
			return nCount;
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

		BOOL CanHackIt(const LPPRCClient pCI)
		{
			CTSList<CONNINFO>::critical lc = m_ls;

			if (!m_PRCPipeClient.IsConnected())
			{
				ATLTRACE("CHackedSocket.m_PRCPipeClient is connecting.\r\n");
				if (!m_PRCPipeClient.Connect(m_pHW->GetPRCPipeName()))
				{
					ATLTRACE("CHackedSocket.m_PRCPipeClient Failed to connect to PRCPipeServer.\r\n");
					return FALSE;
				}
			}

			ProxyInfo pi;
			if (!m_PRCPipeClient.PRCGetProxyInfo((LPPRCClient)pCI, &pi))
			{
				return FALSE;
			}

			if (m_PRCPipeClient.GetLastError() != 0)
			{
				ATLTRACE("CHackedSocket.m_PRCPipeClient GetLastError == %d\r\n", m_PRCPipeClient.GetLastError());
				m_PRCPipeClient.Disconnect();
				return FALSE;
			}

			if (pCI->IsDNValid())
			{
				return TRUE;
			}

			//如果程序要访问本地局域网络，但是代理服务器是公网的，则不劫持这个socket
			in_addr dstaddr;
			in_addr proxyaddr;

			dstaddr.s_addr = pCI->dstAddr.GetdwIP();
			proxyaddr.s_addr = inet_addr(pi.strProxyHost);

			if (!dstaddr.s_addr || dstaddr.s_addr == INADDR_NONE || !proxyaddr.s_addr|| dstaddr.s_addr == INADDR_NONE )
			{
				return FALSE;
			}

			if (m_pHW->m_psi.bHookLanIP)
				return TRUE;

			if (dstaddr.s_net == 127)
			{
				if (proxyaddr.s_net != 127)
				{
					return FALSE;
				}
			}else if (dstaddr.s_net == 192 && dstaddr.s_host == 168)
			{
				if (proxyaddr.s_net != dstaddr.s_net || proxyaddr.s_host != dstaddr.s_host || proxyaddr.s_lh != dstaddr.s_lh)
				{
					return FALSE;
				}
			}else if (dstaddr.s_net == 172 && dstaddr.s_host >= 16 && dstaddr.s_host <= 131)
			{
				if (proxyaddr.s_net != dstaddr.s_net || proxyaddr.s_host != dstaddr.s_host || proxyaddr.s_lh != dstaddr.s_lh)
				{
					return FALSE;
				}
			}else if (dstaddr.s_net == 10)
			{
				if (proxyaddr.s_net != dstaddr.s_net || proxyaddr.s_host != dstaddr.s_host || proxyaddr.s_lh != dstaddr.s_lh)
				{
					return FALSE;
				}
			}

			return TRUE;
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
						|| (it->srcAddr.GetdwIP() != 0 && it->srcAddr.GetdwIP() != ((LPPRCClient)pCI)->srcAddr.GetdwIP())
						)
						continue;//当前节点信息不一致， 但不能确定没劫持过这个socket， 继续查找其他节点

					//UDP可以在本地一个地址对外多个地址发包， 所以可以不用判断目的IP来确认该udp的socket是否劫持过
					//但如果目的地址是域名的话， 为了能在收包的时候代替地址为dummyIP， 所以域名不一致的情况要单独开个本地代理udp端口
					//都一致则表示该udp socket已经hijacked
					if (((LPPRCClient)pCI)->IsDNValid())
					{
						//if (it->dstAddr.GetPort() != ((LPPRCClient)pCI)->dstAddr.GetPort()
						//	|| _stricmp(it->szDomainName, ((LPPRCClient)pCI)->szDomainName))
						//	continue;
						if (!it->IsDNValid())
							continue;

						if (_stricmp(it->szDomainName, ((LPPRCClient)pCI)->szDomainName) != 0)
							continue;

					}

					if (!m_PRCPipeClient.IsConnected())
					{
						ATLTRACE("CHackedSocket.m_PRCPipeClient is connecting.\r\n");
						if (!m_PRCPipeClient.Connect(m_pHW->GetPRCPipeName()))
						{
							ATLTRACE("CHackedSocket.m_PRCPipeClient Failed to connect to PRCPipeServer.\r\n");
							return FALSE;
						}
					}

					UDPLocalProxyAddrInfo udpai;
					udpai.clientip = it->srcAddr.GetdwIP();
					udpai.clientport = it->srcAddr.GetPort();
					udpai.proxyport = it->udpAddr.GetPort();

					BOOL bState = m_PRCPipeClient.PRCGetUDPClientPortState(&udpai);

					if (m_PRCPipeClient.GetLastError() != 0)
					{
						ATLTRACE("CHackedSocket.m_PRCPipeClient GetLastError == %d. state: %d\r\n", m_PRCPipeClient.GetLastError(), bState);
						m_PRCPipeClient.Disconnect();
						return FALSE;
					}

					if (!bState)
					{
						ATLTRACE("CHackedSocket.m_PRCPipeClient.PRCGetUDPClientPortState == FALSE\r\n");
						m_ls.erase(it);
						return FALSE;
					}

					((LPPRCClient)pCI)->udpAddr = it->udpAddr;

					return TRUE;
				}
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
						|| (it->srcAddr.GetdwIP() != 0 && it->srcAddr.GetdwIP() != srcAddr.GetdwIP())
						)
						continue;

					//确定包是来自PRC的（udpAddr是本地udp代理的地址）
					if (from->GetPort() != it->udpAddr.GetPort()
						|| (it->udpAddr.GetdwIP() != 0 && it->udpAddr.GetdwIP() != from->GetdwIP())
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
		CPRCPipeClient m_PRCPipeClient;
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
	BOOL HackConnect(SOCKET s, _SockAddr &addrname);

	//
	BOOL HackDNS(const char *name);

	int WSAAPI inhook_getpeername(SOCKET s, struct sockaddr* name, int* namelen);

	int WSAAPI inhook_closesocket(SOCKET s);

	int WSAAPI inhook_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);

	int WSAAPI inhook_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);

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

	int WSAAPI inhook_WSARecvFrom(
		SOCKET s,
		LPWSABUF lpBuffers,
		DWORD dwBufferCount,
		LPDWORD lpNumberOfBytesRecvd,
		LPDWORD lpFlags,
		struct sockaddr* lpFrom,
		LPINT lpFromlen,
		LPWSAOVERLAPPED lpOverlapped,
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
		);

	BOOL HackSendTo(SOCKET s, _SockAddr &addrname, LPPRCClient lpC);

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

	CString m_szLastError;
	CString m_szPRCPipeName;

};
