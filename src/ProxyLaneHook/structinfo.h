#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma pack(push, 1)

class _SockAddr
	: public sockaddr
{
public:

	DWORD GetdwIP()
	{
		SOCKADDR_IN *p = (SOCKADDR_IN*)this;
		return p->sin_addr.s_addr;
	}

	in_addr* GetAddr()
	{
		return &((LPSOCKADDR_IN)this)->sin_addr;
	}

	void SetIPLong(LONG nIP)
	{
		SOCKADDR_IN *p = (SOCKADDR_IN*)this;
		p->sin_addr.s_addr = nIP;
	}

	BOOL SetIP(LPCSTR lpszIP)
	{
		SOCKADDR_IN *p = (SOCKADDR_IN*)this;
		p->sin_addr.s_addr = inet_addr(lpszIP);
		return p->sin_addr.s_addr != INADDR_NONE;
	}

	INT GetPort()
	{
		SOCKADDR_IN *p = (SOCKADDR_IN*)this;
		return (INT)ntohs(p->sin_port);
	}

	void SetPort(WORD Port)
	{
		SOCKADDR_IN *p = (SOCKADDR_IN*)this;
		p->sin_port = htons(Port);
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

	BOOL operator == (_SockAddr &_dst)
	{
		SOCKADDR_IN *X = (SOCKADDR_IN*)this;
		SOCKADDR_IN *Y = (SOCKADDR_IN*)&_dst;

		return /*(X->sin_family == Y->sin_family) &&*/ (X->sin_addr.s_addr == Y->sin_addr.s_addr) && (X->sin_port == Y->sin_port);
	}

	void operator = (_SockAddr &_dst)
	{
		memcpy(this, &_dst, sizeof(_SockAddr));
	}
	void operator = (const sockaddr &_dst)
	{
		memcpy(this, &_dst, sizeof(_SockAddr));
	}
	void operator = (SOCKADDR_IN &_dst)
	{
		memcpy(this, &_dst, sizeof(_SockAddr));
	}
};


typedef struct _tagProxyInfo
{
	template <INT N>
	struct string
	{
		char szbuf[N];

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
	DWORD  reserved;
/////////////////////

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
}ProxySettingsInfo, *LPProxySettingsInfo;

#define PSI_DNSOPT_LOCAL 0
#define PSI_DNSOPT_REMOTE 1


typedef struct _tagPRCINFO
{
	//local address info
	_SockAddr tcpaddr;
	_SockAddr udpaddr;
}PRCINFO, *LPPRCINFO;

typedef struct _tagPRCClient
{
	//
	DWORD dwPid;
	DWORD dwTid;
	int sType;//SOCK_DGRAM SOCK_STREAM
	unsigned __int64 s;
	unsigned __int64 sAccept;
	char szDomainName[256];
	_SockAddr srcAddr;
	_SockAddr dstAddr;

	DWORD uaFlag; //UDP Address Flag, 默认0
	//根据标志位在请求代理服务器UDP地址的时候，本地socket的地址将在udpAddr中取得
	_SockAddr udpAddr;

	DWORD reserved;
	BOOL IsDNValid(){ return szDomainName[0] != '\0';}
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
