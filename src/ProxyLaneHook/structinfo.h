#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma pack(push, 1)

class _SockAddr
	: public sockaddr
{
public:
	// sockaddr is 16 bytes while sockaddr_in6 is 28 bytes. Keep the first
	// 16 bytes ABI-compatible with sockaddr and reserve the remaining bytes so
	// PRC/pipe records can carry either address family without pointers.
	BYTE ipv6Tail[sizeof(SOCKADDR_IN6) - sizeof(sockaddr)];

	void Clear()
	{
		ZeroMemory(this, sizeof(*this));
	}

	BOOL Set(const SOCKADDR *address, int addressLength)
	{
		if (!address)
			return FALSE;
		int required = address->sa_family == AF_INET6
			? (int)sizeof(SOCKADDR_IN6) : (int)sizeof(SOCKADDR_IN);
		if ((address->sa_family != AF_INET && address->sa_family != AF_INET6) ||
			addressLength < required)
			return FALSE;
		Clear();
		CopyMemory(this, address, required);
		return TRUE;
	}

	INT Size() const
	{
		return sa_family == AF_INET6 ? sizeof(SOCKADDR_IN6) : sizeof(SOCKADDR_IN);
	}

	BOOL IsIPv4() const { return sa_family == AF_INET; }
	BOOL IsIPv6() const { return sa_family == AF_INET6; }

	BOOL IsIPv4Mapped() const
	{
		return IsIPv6() && IN6_IS_ADDR_V4MAPPED(
			&reinterpret_cast<const SOCKADDR_IN6 *>(this)->sin6_addr);
	}

	BOOL IsAny() const
	{
		if (IsIPv6())
			return IN6_IS_ADDR_UNSPECIFIED(
				&reinterpret_cast<const SOCKADDR_IN6 *>(this)->sin6_addr);
		return IsIPv4() && reinterpret_cast<const SOCKADDR_IN *>(this)->sin_addr.s_addr == INADDR_ANY;
	}

	BOOL IsLoopback() const
	{
		if (IsIPv6())
			return IN6_IS_ADDR_LOOPBACK(
				&reinterpret_cast<const SOCKADDR_IN6 *>(this)->sin6_addr);
		return IsIPv4() &&
			(ntohl(reinterpret_cast<const SOCKADDR_IN *>(this)->sin_addr.s_addr) >> 24) == 127;
	}

	DWORD GetdwIP() const
	{
		if (IsIPv4())
			return reinterpret_cast<const SOCKADDR_IN *>(this)->sin_addr.s_addr;
		if (IsIPv4Mapped())
		{
			DWORD address = 0;
			CopyMemory(&address,
				&reinterpret_cast<const SOCKADDR_IN6 *>(this)->sin6_addr.u.Byte[12], 4);
			return address;
		}
		return 0;
	}

	in_addr* GetAddr()
	{
		return &((LPSOCKADDR_IN)this)->sin_addr;
	}

	const IN6_ADDR *GetAddr6() const
	{
		return IsIPv6()
			? &reinterpret_cast<const SOCKADDR_IN6 *>(this)->sin6_addr : NULL;
	}

	void SetIPLong(LONG nIP)
	{
		if (!IsIPv4())
		{
			Clear();
			sa_family = AF_INET;
		}
		SOCKADDR_IN *p = (SOCKADDR_IN*)this;
		p->sin_addr.s_addr = nIP;
	}

	BOOL SetIP(LPCSTR lpszIP)
	{
		if (!lpszIP)
			return FALSE;
		IN_ADDR address4;
		if (InetPtonA(AF_INET, lpszIP, &address4) == 1)
		{
			WORD port = (IsIPv4() || IsIPv6()) ? (WORD)GetPort() : 0;
			Clear();
			sa_family = AF_INET;
			reinterpret_cast<SOCKADDR_IN *>(this)->sin_addr = address4;
			SetPort(port);
			return TRUE;
		}
		IN6_ADDR address6;
		if (InetPtonA(AF_INET6, lpszIP, &address6) == 1)
		{
			WORD port = (IsIPv4() || IsIPv6()) ? (WORD)GetPort() : 0;
			Clear();
			sa_family = AF_INET6;
			reinterpret_cast<SOCKADDR_IN6 *>(this)->sin6_addr = address6;
			SetPort(port);
			return TRUE;
		}
		return FALSE;
	}

	INT GetPort() const
	{
		return IsIPv6()
			? (INT)ntohs(reinterpret_cast<const SOCKADDR_IN6 *>(this)->sin6_port)
			: (INT)ntohs(reinterpret_cast<const SOCKADDR_IN *>(this)->sin_port);
	}

	void SetPort(WORD Port)
	{
		if (IsIPv6())
			reinterpret_cast<SOCKADDR_IN6 *>(this)->sin6_port = htons(Port);
		else
			reinterpret_cast<SOCKADDR_IN *>(this)->sin_port = htons(Port);
	}

	//
	BYTE GetByte_sin_zero(int nPos)
	{
		SOCKADDR_IN *psa = (SOCKADDR_IN*)this;
		return psa->sin_zero[nPos];
	}

	WORD GetWord_sin_zero(int nPos)
	{
		SOCKADDR_IN *psa = (SOCKADDR_IN*)this;
		return *((WORD*)&psa->sin_zero[0]+nPos);
	}

	DWORD GetDword_sin_zero(int nPos)
	{
		SOCKADDR_IN *psa = (SOCKADDR_IN*)this;
		return *((DWORD*)&psa->sin_zero[0]+nPos);
	}

	BOOL SameAddress(const _SockAddr &_dst) const
	{
		if (sa_family != _dst.sa_family)
			return FALSE;
		if (IsIPv6())
			return IN6_ARE_ADDR_EQUAL(GetAddr6(), _dst.GetAddr6());
		return IsIPv4() && GetdwIP() == _dst.GetdwIP();
	}

	BOOL operator == (const _SockAddr &_dst) const
	{
		return SameAddress(_dst) && GetPort() == _dst.GetPort();
	}

	_SockAddr &operator = (const _SockAddr &_dst)
	{
		memcpy(this, &_dst, sizeof(_SockAddr));
		return *this;
	}
	_SockAddr &operator = (const sockaddr &_dst)
	{
		Set(&_dst, _dst.sa_family == AF_INET6
			? sizeof(SOCKADDR_IN6) : sizeof(SOCKADDR_IN));
		return *this;
	}
	_SockAddr &operator = (const SOCKADDR_IN &_dst)
	{
		Set(reinterpret_cast<const SOCKADDR *>(&_dst), sizeof(_dst));
		return *this;
	}
	_SockAddr &operator = (const SOCKADDR_IN6 &_dst)
	{
		Set(reinterpret_cast<const SOCKADDR *>(&_dst), sizeof(_dst));
		return *this;
	}
};


typedef struct _tagProxyInfo
{
	template <INT N>
	struct string
	{
		char szbuf[N];
		string(){ szbuf[0] = '\0'; }

		operator char*(){ return &szbuf[0]; }

		char * operator =(const TCHAR *lpsz)
		{
			int i=0;

			while(i<sizeof(szbuf)-1 && lpsz[i])
			{
				szbuf[i] = lpsz[i];
				i++;
			}
			szbuf[i] = '\0';
			return szbuf;
		}
	};


/////////////////////结构成员变量
	string<128> szItemName;
	string<32> strProxyType;
	string<128> strProxyHost;
	INT    nProxyPort;
	string<128> strProxyUser;
	string<128> strProxyPass;
	DWORD  reserved; // PROXY_TRANSPORT_*
	string<256> strTransportPsk;
/////////////////////

#define PROXY_TRANSPORT_PLAIN             0
#define PROXY_TRANSPORT_GONC_TLS_PSK      1

#define PROXYTYPE_NOPROXY	0
#define PROXYTYPE_SOCKS4	1
#define PROXYTYPE_SOCKS4A	2
#define PROXYTYPE_SOCKS5	3
#define PROXYTYPE_HTTP10	4
#define PROXYTYPE_HTTP11	5
	INT GetProxyType()
	{
		if(!_stricmp(strProxyType, "SOCKS4"))
			return PROXYTYPE_SOCKS4;
		else if(!_stricmp(strProxyType, "SOCKS4A"))
			return PROXYTYPE_SOCKS4A;
		else if(!_stricmp(strProxyType, "SOCKS5"))
			return PROXYTYPE_SOCKS5;
		else if(!_stricmp(strProxyType, "HTTP10"))
			return PROXYTYPE_HTTP10;
		else if(!_stricmp(strProxyType, "HTTP11"))
			return PROXYTYPE_HTTP11;
		else
			return PROXYTYPE_NOPROXY;
	}
//////////////////

}ProxyInfo, *LPProxyInfo;


#define PRC_PIPESERVER_NAME _T("{1237C887-49E0-4a29-8FFA-2B4220B5BC99}")


typedef struct  _tagProxySettingsInfo
{
	BOOL bHookTCP;
	BOOL bHookUDP;
	INT  nDNSOption;
	BOOL bHookCreateProcess;
	BOOL bHookLanIP;
	BOOL bDisableLLMNR;
	BOOL bBlockUDP;            // 禁止 UDP；优先于 bHookUDP，命中则 sendto/recvfrom 系列直接失败
	BOOL bRedirectPrivateDNS;  // 服务器解析时将内网 :53 替换为公共 DNS
	_SockAddr redirectDNSAddr;
}ProxySettingsInfo, *LPProxySettingsInfo;

#define PSI_DNSOPT_LOCAL 0
#define PSI_DNSOPT_REMOTE 1


typedef struct _tagPRCINFO
{
	//local address info
	_SockAddr tcpaddr;
	_SockAddr tcpaddr6;
	_SockAddr udpaddr;
}PRCINFO, *LPPRCINFO;

#define PRC_CLIENT_FLAG_DNS_REDIRECT 0x00000001

typedef struct _tagPRCClient
{
	//
	DWORD dwPid;
	DWORD dwTid;
	ULONGLONG processCreateTime;
	ULONGLONG socketGeneration;
	int sType;//SOCK_DGRAM SOCK_STREAM
	unsigned __int64 s;
	unsigned __int64 sAccept;
	char szDomainName[256];
	_SockAddr srcAddr;
	_SockAddr dstAddr;
	// dstAddr is always the application's original destination.  When a
	// transport policy changes only the upstream endpoint, proxyDstAddr keeps
	// that effective destination without corrupting logs or route identity.
	_SockAddr proxyDstAddr;
	DWORD routingFlags;

	DWORD uaFlag; //UDP Address Flag, 默认0
	//根据标志位在请求代理服务器UDP地址的时候，本地socket的地址将在udpAddr中取得
	_SockAddr udpAddr;

	DWORD reserved;
	BOOL IsDNValid(){ return szDomainName[0] != '\0';}
	BOOL HasProxyDestination() const
	{
		return (routingFlags & PRC_CLIENT_FLAG_DNS_REDIRECT) != 0;
	}
	const _SockAddr& GetProxyDestination() const
	{
		return HasProxyDestination() ? proxyDstAddr : dstAddr;
	}
	void zero(){ ZeroMemory(this, sizeof(*this));}
}PRCClient, *LPPRCClient;

/////PRCClient.uaFlag
#define UAF_SET_ADDR 0x1
#define UAF_SET_PORT 0x2
/////

struct UDPLocalProxyAddrInfo 
{
	u_long  clientip;
	u_short clientport;

	u_short proxyport;
};

typedef struct _tagPRCClientInfo
{
	enum
	{
		PROTOCOL_ALL = 0,
		PROTOCOL_HTTP,
		PROTOCOL_FTP,
	};
	DWORD dwPid;
	DWORD dwTid;
	int   protype;
}PRCClientInfo, *LPPRCClientInfo;


typedef struct _ProxyPacketInfo
{
	int errcode;
	int datafrom;//0: from client, 1: from server
	const char *pData;
	int datalen;
	LPPRCClient lpC;
	LPProxyInfo lpPI;
}ProxyPacketInfo, *LPProxyPacketInfo;

typedef struct _HookNewProcessInfo
{
	WCHAR szAppPath[MAX_PATH];
	WCHAR szCommandLine[MAX_PATH];

	DWORD dwProcessId;
	DWORD dwThreadId;
}HookNewProcessInfo, *LPHookNewProcessInfo;

typedef struct _HookProcessIdentityInfo
{
	DWORD dwProcessId;
	ULONGLONG processCreateTime;
	WCHAR szAppPath[MAX_PATH];
}HookProcessIdentityInfo, *LPHookProcessIdentityInfo;

//PRC Pipe Protocol Data Head
typedef struct _tagPRCPDHead
{
	BYTE action;
	BYTE flag;
	DWORD dataSize;
}PRCPipeDataHead, *LPPRCPipeDataHead;

typedef struct _tagHookWSockResult
{
	DWORD dwProcessId;
	DWORD err;
}HookWSockResult, *LPHookWSockResult;

typedef struct _tagHookLogtext
{
	DWORD dwProcessId;
	int len;
	WCHAR str[];
}HookLogtext, *LPHookLogtext;

//action
#define PRCPD_REPLY 0
#define PRCPD_GETSTARTUPINFO 1
#define PRCPD_REGISTERCLIENT 2
#define PRCPD_CANPROXYME 3
#define PRCPD_UNREGISTER_CLIENT 4
#define PRCPD_GET_SETTINGS_INFO 5
#define PRCPD_ON_CREATEPROCESS  6
#define PRCPD_GET_CLIENT_UDPPORT_STATE  7
#define PRCPD_GET_PROXYINFO  8
#define PRCPD_HOOKWSOCK_RESULT  9
#define PRCPD_Logtext    10
#define PRCPD_CHILD_INJECTION_RESULT 11
#define PRCPD_REGISTER_PROCESS_IDENTITY 12

#pragma pack(pop)

/////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////

typedef hostent* (WSAAPI *__gethostbyname)(
	const char* name
	);

typedef HANDLE (WSAAPI *__WSAAsyncGetHostByName)(
	HWND hWnd,
	unsigned int wMsg,
	const char* name,
	char* buf,
	int buflen
	);

typedef int (WSAAPI *__connect)(
								SOCKET s,
								const struct sockaddr* name,
								int namelen
								);

typedef int (WSAAPI *__WSAConnect)(
			   SOCKET s,
			   const struct sockaddr* name,
			   int namelen,
			   LPWSABUF lpCallerData,
			   LPWSABUF lpCalleeData,
			   LPQOS lpSQOS,
			   LPQOS lpGQOS
			   );

typedef 
int
(WSAAPI *__getaddrinfo)(
			IN const char FAR * nodename,
			IN const char FAR * servname,
			IN const struct addrinfo FAR * hints,
			OUT struct addrinfo FAR * FAR * res
			);

typedef
int (WSAAPI *__getpeername)(
							SOCKET s,
							struct sockaddr* name,
							int* namelen
							);

typedef 
int (WSAAPI *__closesocket)(
	SOCKET s
	);

typedef
int (WSAAPI *__sendto)(
		   SOCKET s,
		   const char* buf,
		   int len,
		   int flags,
		   const struct sockaddr* to,
		   int tolen
		   );

typedef
int (WSAAPI *__send)(
		   SOCKET s,
		   const char* buf,
		   int len,
		   int flags
		   );

typedef
int (WSAAPI *__recvfrom)(
			 SOCKET s,
			 char* buf,
			 int len,
			 int flags,
struct sockaddr* from,
	int* fromlen
	);


typedef
int (WSAAPI *__WSASendTo)(
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

typedef
int (WSAAPI *__WSASend)(
			  SOCKET s,
			  LPWSABUF lpBuffers,
			  DWORD dwBufferCount,
			  LPDWORD lpNumberOfBytesSent,
			  DWORD dwFlags,
			  LPWSAOVERLAPPED lpOverlapped,
			  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
			  );

typedef
int (WSAAPI *__WSARecvFrom)(
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

typedef
BOOL
  (WINAPI *__CreateProcessInternalW)(
  HANDLE hToken,
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
  PHANDLE hNewToken
);

typedef
int
(WSAAPI*
__WSAIoctl)(
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

typedef
BOOL
(PASCAL FAR * __CONNECTEX) (
							   IN SOCKET s,
							   IN const struct sockaddr FAR *name,
							   IN int namelen,
							   IN PVOID lpSendBuffer OPTIONAL,
							   IN DWORD dwSendDataLength,
							   OUT LPDWORD lpdwBytesSent,
							   IN LPOVERLAPPED lpOverlapped
							   );

typedef INT (PASCAL FAR * __WSASENDMSG)(
	SOCKET s,
	LPWSAMSG lpMsg,
	DWORD dwFlags,
	LPDWORD lpNumberOfBytesSent,
	LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

typedef
INT
(WSAAPI*
__GetAddrInfoExW)(
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
