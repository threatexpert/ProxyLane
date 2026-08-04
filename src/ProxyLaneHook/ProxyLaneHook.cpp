// ProxyLaneHook.cpp : Defines the entry point for the DLL application.
//
// 测试用的cpp
// 
// 转到ProxyModule.cpp 开始看吧

#include "stdafx.h"
#include <CONIO.H>
#include <IO.H>
#include <time.h>
#include "MySocket.h"
#include "ProxyModule.h"


//CGlobalProxy *g_proxy;


SOCKET ConnectHost(DWORD dwIP, WORD wPort)//连接指定IP和端口
{
	SOCKET sockid;

	if ((sockid = socket(PF_INET, SOCK_STREAM,IPPROTO_TCP)) == INVALID_SOCKET)
		return 0;
	struct sockaddr_in srv_addr;
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr.S_un.S_addr = dwIP;
	srv_addr.sin_port = htons(wPort);
	if (connect(sockid,(struct sockaddr*)&srv_addr,sizeof(struct sockaddr_in)) == SOCKET_ERROR)
		goto error;
	return sockid;
error:

	closesocket(sockid);
	return 0;
}

char *DNS(char *HostName)
{
	HOSTENT *hostent = NULL;
	IN_ADDR iaddr;
	hostent = gethostbyname(HostName);
	if (hostent == NULL)
	{
		return NULL;
	}
	iaddr = *((LPIN_ADDR)*hostent->h_addr_list);
	return inet_ntoa(iaddr);
}

SOCKET ConnectHost(char *szIP, WORD wPort)
{
	if (inet_addr(szIP) != INADDR_NONE)
		return ConnectHost(inet_addr(szIP), wPort);
	else
	{
		if (DNS(szIP) != NULL)
			return ConnectHost(inet_addr(DNS(szIP)), wPort);
		else
			return 0;
	}
}

int _SetTimeOut(SOCKET s, bool read, bool write, int timeout_sec)
{   
	int ret;
	DWORD timepassed = 0;
	fd_set FdRead, FdWrite;
	struct timeval TimeOut;


	TimeOut.tv_sec  = timeout_sec;
	TimeOut.tv_usec = 0;


	if(read)
	{
		FD_ZERO(&FdRead);
		FD_SET(s,&FdRead);
	}
	if(write)
	{
		FD_ZERO(&FdWrite);
		FD_SET(s,&FdWrite);
	}
	ret = select(s+1,
		read?&FdRead:NULL,
		write?&FdWrite:NULL,
		NULL,
		timeout_sec==-1?NULL:&TimeOut);


	//	DWORD err = WSAGetLastError();
	return ret;
}


// DWORD WINAPI socketProc(SOCKET s)
// {
// 
// 	char cPack = 'A';
// 	char buf[1024*4];
// 	memset(buf, 0, sizeof(buf));
// 
// 	buf[sizeof(buf)-3] = '\r';
// 	buf[sizeof(buf)-2] = '\n';
// 	buf[sizeof(buf)-1] = '\0';
// 
// 	srand( (unsigned)time( NULL ) );
// 	while (1)
// 	{
// 		int ret;
// 
// 		ret = _SetTimeOut(s, 0, 1, 0);
// 
// 		if(ret < 0)
// 			break;
// 
// 		if(ret > 0)
// 		{
// 			char ch = 'A'+(rand()%24);
// 
// 			memset(buf, ch, sizeof(buf)-3);
// 
// 			ret = send(s, buf, sizeof(buf), 0);
// 			if(ret <= 0)
// 				break;
// 		}
// 
//  
//   
//   		ret = _SetTimeOut(s, 1, 0, 0);
//   		if(ret < 0)
//  			break;
//  
//   		if(ret > 0)
//   		{
//   			ret = recv(s, buf, sizeof(buf)-3, 0);
//   			if(ret <= 0)
//   				break;
//   
//   			buf[ret] = '\r';
//   			buf[ret+1] = '\n';
//   			buf[ret+2] = '\0';
//   
//   			//printf("%s\r\n", buf);
//   			printf("r");
//   
//   		}else
//  		{
//  			if(kbhit())
//  			{
//  				int len = 0;
//  				char SendBuf[256] = "\0";
//  				while(!strstr(SendBuf, "\n"))
//  				{
//  					gets(SendBuf+len);
//  					strcat(SendBuf, "\r\n");
//  					len = strlen(SendBuf);
//  				}
// 				if(_strnicmp(SendBuf, "exit", 4) == 0)
// 					return 0;
//  				send(s, SendBuf, len,0);
//  
//  			}
//  		}
// 
// 
// 		Sleep(5);
// 	}
// 
// 
// 	printf("connection error.\r\n");
// 	return 0;
// }
//
//DWORD WINAPI mainThread(LPVOID lParam)
//{
//	if((BOOL)lParam)
//	{
//		g_proxy->DisableProxy();
//		delete g_proxy;
//		g_proxy = NULL;
//		WSACleanup();
//		return 0;
//	}
//	WSADATA wsaData;
//	WORD wVersionRequested = MAKEWORD(2, 2);
//	int nResult = WSAStartup(wVersionRequested, &wsaData);
//
//	ProxyInfo pi;
//
//	pi.szItemName = "myproxy";
//	pi.strProxyType = "SOCKS5";
//	pi.strProxyHost = "127.0.0.1";
//	pi.nProxyPort = 307;
//	pi.strProxyUser = "abc";
//	pi.strProxyPass = "abc";
//	g_proxy = new CGlobalProxy;
//	//nResult = g_proxy->AddProxy(&pi);
//	nResult = g_proxy->EnableProxy();
//
//	return 0;
//}

//
//BOOL APIENTRY DllMain( HANDLE hModule, 
//                       DWORD  ul_reason_for_call, 
//                       LPVOID lpReserved
//					 )
//{
//	switch (ul_reason_for_call)
//	{
//	case DLL_PROCESS_ATTACH:
//		{
//			HANDLE hThread = CreateThread(0, 0, mainThread, 0, 0, 0);
//			
//		}
//
//
//		break;
//
//	case DLL_PROCESS_DETACH:
//		{
//			HANDLE hThread = CreateThread(0, 0, mainThread, (LPVOID)1, 0, 0);
//
//		}
//
//		break;
//	}
//
//	return TRUE;
//}


//INT __stdcall WinMain (
//		 __in HINSTANCE hInstance,
//		 __in_opt HINSTANCE hPrevInstance,
//		 __in_opt LPSTR lpCmdLine,
//		 __in int nShowCmd
//		 )
//
//int main(int argc, char **argv)
//{
//	WSADATA wsaData;
//	WORD wVersionRequested = MAKEWORD(2, 2);
//	int nResult = WSAStartup(wVersionRequested, &wsaData);
//
//	ProxyInfo pi;
//
//	pi.szItemName = "myproxy";
//	pi.strProxyType = "SOCKS5";
//	pi.strProxyHost = "127.0.0.1";
//	pi.nProxyPort = 307;
//	pi.strProxyUser = "abc";
//	pi.strProxyPass = "abc";
//	g_proxy = new CGlobalProxy;
//	nResult = g_proxy->AddProxy(&pi);
//	nResult = g_proxy->SelectProxy("myproxy");
//
//	nResult = g_proxy->EnableProxy();
//	//nResult = g_proxy->DisableProxy();
//
//	CHookWinsock *pHookWs = new CHookWinsock;
//
//	nResult = pHookWs->EnableHook();
//
//	int t = 0;
//	//while(t++ < 1)
//	//{
//	//	//测试类
//	//	CMySocket *mysocket = new CMySocket;
//
//	//	SOCKADDR_IN sockAddr = {0};
//	//	sockAddr.sin_family = AF_INET;
//	//	sockAddr.sin_port = htons(88);
//	//	sockAddr.sin_addr.S_un.S_addr = inet_addr("127.7.7.7");
//
//	//	mysocket->InitProxySupport(0, 0);
//	//	//INT ret = mysocket.Connect((SOCKADDR*)&sockAddr,  sizeof sockAddr);
//	//	INT ret = mysocket->Connect("127.0.0.1", 88);
//
//	//}
//
//
//	SOCKET s = ConnectHost("127.0.0.1", 88);
//	socketProc(s);
//
//	pHookWs->DisableHook();
//	delete pHookWs;
//
//	g_proxy->DisableProxy();
//
//	//MSG msg;
//	//while(GetMessage(&msg, NULL, 0, 0))
//	//{
//	//	TranslateMessage(&msg);
//	//	DispatchMessage(&msg);
//	//}
//
//	return 0;
//}


// settings demo
class CMyProxySettings
	: public IProxySettings
{
public:
	CMyProxySettings()
	{

	}

	~CMyProxySettings()
	{

	}

	BOOL GetProxySettings(LPProxySettingsInfo lpPSI)
	{
		return FALSE;
	}

	BOOL GetProxyInfo(const LPPRCClient pPRCC, LPProxyInfo lpPI)
	{
		//可评估代理的客户端的信息, 再决定是否返回或返回哪个代理服务器的信息
		//pPRCC->dwPid
		//pPRCC->szDomainName
		//pPRCC->dstAddr.GetdwIP()
		//pPRCC->dstAddr.GetPort()

		*lpPI = m_pi;
		return TRUE;
	}

	void Save(LPProxyInfo lpPI)
	{
		m_pi = *lpPI;
	}
private:

	ProxyInfo m_pi;


};
extern BOOL WINAPI gp_HookWinsock(LPCSTR lpszPRCPipeName);
extern BOOL WINAPI gp_UnhookWinsock();

int main(int argc, char **argv)
{
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	int nResult = WSAStartup(wVersionRequested, &wsaData);

	INT ret;

	//ret = gp_HookWinsock("");
	//ret = gp_UnhookWinsock();

	CMyProxySettings settings;
	//
	ProxyInfo pi;
	pi.szItemName = _T("myproxy");
	pi.strProxyType = _T("SOCKS5");
	pi.strProxyHost = _T("127.0.0.1");
	pi.nProxyPort = 307;
	pi.strProxyUser = _T("abc");
	pi.strProxyPass = _T("abc");
	settings.Save(&pi);

	IGlobalProxy *pGlobalProxy = GetGlobalProxyInstance();
	IProxySettings *pPS = pGlobalProxy->GetSettingsInstance();

	pPS->AddInstance(&settings);

	pGlobalProxy->EnableProxy();
	IProxyReceptionCentre *pPRC =  pGlobalProxy->GetPRCInstance();
	//
	char szPipeName[MAX_PATH] = {0};
	ret = pPRC->GetPRCPipeName(szPipeName, sizeof(szPipeName));

	//ret = gp_HookWinsock(szPipeName);

	//
	CMySocket *mysocket = new CMySocket;


	mysocket->InitProxySupport(1, 0);
	//INT ret = mysocket.Connect((SOCKADDR*)&sockAddr,  sizeof sockAddr);
	//INT ret = mysocket->Connect("127.0.0.1", 88);

	MSG msg;
	while(GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	ret = gp_UnhookWinsock();
	return 0;
}