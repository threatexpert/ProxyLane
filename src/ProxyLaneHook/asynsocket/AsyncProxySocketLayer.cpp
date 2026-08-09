/*CAsyncProxySocketLayer by Tim Kosse (Tim.Kosse@gmx.de)
                 Version 1.6 (2003-03-26)
--------------------------------------------------------

	socks5 proxy UDP method supported.
--------------------------------------------------------

Introduction:
-------------

This class is layer class for CAsyncSocketEx. With this class you
can connect through SOCKS4/5 and HTTP 1.1 proxies. This class works
as semi-transparent layer between CAsyncSocketEx and the actual socket.
This class is used in FileZilla, a powerful open-source FTP client.
It can be found under http://sourceforge.net/projects/filezilla
For more information about SOCKS4/5 goto
http://www.socks.nec.com/socksprot.html
For more information about HTTP 1.1 goto http://www.rfc-editor.org
and search for RFC2616

How to use?
-----------

You don't have to change much in you already existing code to use
CAsyncProxySocketLayer.
To use it, create an instance of CAsyncProxySocketLayer, call SetProxy
and attach it to a CAsyncSocketEx instance.
You have to process OnLayerCallback in you CAsyncSocketEx instance as it will
receive all layer nofications.
The following notifications are sent:

//Error codes
PROXYERROR_NOERROR 0
PROXYERROR_NOCONN 1 //Can't connect to proxy server, use GetLastError for more information
PROXYERROR_REQUESTFAILED 2 //Request failed, can't send data
PROXYERROR_AUTHREQUIRED 3 //Authentication required
PROXYERROR_AUTHTYPEUNKNOWN 4 //Authtype unknown or not supported
PROXYERROR_AUTHFAILED 5  //Authentication failed
PROXYERROR_AUTHNOLOGON 6
PROXYERROR_CANTRESOLVEHOST 7

//Status messages
PROXYSTATUS_LISTENSOCKETCREATED 8 //Called when a listen socket was created successfully. Unlike the normal listen function,
								//a socksified socket has to connect to the proxy to negotiate the details with the server
								//on which the listen socket will be created
								//The two parameters will contain the ip and port of the listen socket on the server.

If you want to use CAsyncProxySocketLayer to create a listen socket, you
have to use this overloaded function:
BOOL PrepareListen(unsigned long serverIp);
serverIP is the IP of the server you are already connected
through the SOCKS proxy. You can't use listen sockets over a
SOCKS proxy without a primary connection. Listen sockets are only
supported by SOCKS proxies, this won't work with HTTP proxies.
When the listen socket is created successfully, the PROXYSTATUS_LISTENSOCKETCREATED
notification is sent. The parameters  will tell you the ip and the port of the listen socket.
After it you have to handle the OnAccept message and accept the
connection.
Be carful when calling Accept: rConnected socket will NOT be filled! Instead use the instance which created the
listen socket, it will handle the data connection.
If you want to accept more than one connection, you have to create a listing socket for each of them!

Description of important functions and their parameters:
--------------------------------------------------------

void SetProxy(int nProxyType);
void SetProxy(int nProxyType, const char * pProxyHost, int nProxyPort);
void SetProxy(int nProxyType, const char * pProxyHost, int nProxyPort, const char *pProxyUser, const char * pProxyPass);

Call one of this functions to set the proxy type.
Parametes:
- nProxyType specifies the Proxy Type.
- ProxyHost and nProxyPort specify the address of the proxy
- ProxyUser and ProxyPass are only available for SOCKS5 proxies.

supported proxy types:
PROXYTYPE_NOPROXY
PROXYTYPE_SOCKS4
PROXYTYPE_SOCKS4A
PROXYTYPE_SOCKS5
PROXYTYPE_HTTP11

There are also some other functions:

GetProxyPeerName
Like GetPeerName of CAsyncSocket, but returns the address of the
server connected through the proxy.	If using proxies, GetPeerName
only returns the address of the proxy.

int GetProxyType();
Returns the used proxy

const int GetLastProxyError() const;
Returns the last proxy error

License
-------

Feel free to use this class, as long as you don't claim that you wrote it
and this copyright notice stays intact in the source files.
If you use this class in commercial applications, please send a short message
to tim.kosse@gmx.de

Version history
---------------

- 1.6 got rid of MFC
- 1.5 released CAsyncSocketExLayer version
- 1.4 added Unicode support
- 1.3 added basic HTTP1.1 authentication
      fixed memory leak in SOCKS5 code
	  OnSocksOperationFailed will be called after Socket has been closed
      fixed some minor bugs
- 1.2 renamed into CAsyncProxySocketLayer
      added HTTP1.1 proxy support
- 1.1 fixes all known bugs, mostly with SOCKS5 authentication
- 1.0 initial release
*/

#include "stdafx.h"
#include "..\Socks5UdpCodec.h"
#include "types.h"
#include "AsyncProxySocketLayer.h"
#include "AsyncSecureSocketLayer.h"
//#include "atlconv.h" //Unicode<->Ascii conversion macros declared here
#include "CBase64coding.hpp"
//
//#ifdef _DEBUG
//#define new DEBUG_NEW
//#undef THIS_FILE
//static char THIS_FILE[] = __FILE__;
//#endif

CStringA ipstrA(uint32 nIP)
{
	const BYTE* pucIP = (BYTE*)&nIP;
	CStringA strIP;
	strIP.ReleaseBuffer(sprintf(strIP.GetBuffer(3+1+3+1+3+1+3), "%u.%u.%u.%u", pucIP[0], pucIP[1], pucIP[2], pucIP[3]));
	return strIP;
}

void ipstrA(CHAR* pszAddress, int iMaxAddress, uint32 nIP)
{
	const BYTE* pucIP = (BYTE*)&nIP;
	_snprintf(pszAddress, iMaxAddress, "%u.%u.%u.%u", pucIP[0], pucIP[1], pucIP[2], pucIP[3]);
}


//////////////////////////////////////////////////////////////////////
// Konstruktion/Destruktion
//////////////////////////////////////////////////////////////////////

CAsyncProxySocketLayer::CAsyncProxySocketLayer()
{
	m_nProxyOpID = 0;
	m_nProxyOpState = 0;
	m_pRecvBuffer = 0;
	m_nRecvBufferPos = 0;
	m_nProxyPeerIP = 0;
	m_proxyPeerAddress.Clear();
	m_nProxyPeerPort = 0;
	m_pProxyPeerHost = NULL;
	m_pStrBuffer = NULL;
	m_iStrBuffSize = 0;
	m_pSendBuffer = NULL;
	m_nSendBufferLen = 0;
	m_nSendBufferPos = 0;
	m_pAppRecvBuffer = NULL;
	m_nAppRecvBufferLen = 0;
	m_nAppRecvBufferPos = 0;
	m_ProxyData.nProxyType = PROXYTYPE_NOPROXY;
	m_pS5UC = NULL;
	m_pSecureLayer = NULL;
}

CAsyncProxySocketLayer::~CAsyncProxySocketLayer()
{
	delete[] m_pProxyPeerHost;
	delete m_pS5UC;
	delete m_pSecureLayer;
	if (!m_securePsk.IsEmpty())
	{
		LPSTR psk = m_securePsk.GetBuffer();
		SecureZeroMemory(psk, m_securePsk.GetLength());
		m_securePsk.ReleaseBuffer();
	}
	ClearBuffer();
	ClearSendBuffer();
	delete[] m_pAppRecvBuffer;
}

/////////////////////////////////////////////////////////////////////////////
// Member-Funktion CAsyncProxySocketLayer

void CAsyncProxySocketLayer::SetProxy(int nProxyType)
{
	//Validate the parameters
	ASSERT( nProxyType == PROXYTYPE_NOPROXY);

	m_ProxyData.nProxyType = nProxyType;
}

void CAsyncProxySocketLayer::SetProxy(int nProxyType, const CStringA& strProxyHost, int ProxyPort)
{
	//Validate the parameters
	ASSERT( nProxyType == PROXYTYPE_SOCKS4  ||
		    nProxyType == PROXYTYPE_SOCKS4A ||
		    nProxyType == PROXYTYPE_SOCKS5  ||
			nProxyType == PROXYTYPE_HTTP10	||
		    nProxyType == PROXYTYPE_HTTP11 );
	ASSERT( !m_nProxyOpID );
	ASSERT( !strProxyHost.IsEmpty() );
	ASSERT( ProxyPort > 0);
	ASSERT( ProxyPort <= 65535 );

	m_ProxyData.nProxyType = nProxyType;
	m_ProxyData.strProxyHost = strProxyHost;
	m_ProxyData.nProxyPort = ProxyPort;
	m_ProxyData.bUseLogon = FALSE;
}

void CAsyncProxySocketLayer::SetProxy(int nProxyType, const CStringA& strProxyHost, int ProxyPort, 
									  const CStringA& strProxyUser, const CStringA& strProxyPass)
{
	//Validate the parameters
	ASSERT( nProxyType == PROXYTYPE_SOCKS5 || nProxyType == PROXYTYPE_HTTP10 || nProxyType == PROXYTYPE_HTTP11 );
	ASSERT( !m_nProxyOpID );
	ASSERT( !strProxyHost.IsEmpty() );
	ASSERT( ProxyPort > 0 );
	ASSERT( ProxyPort <= 65535 );

	m_ProxyData.nProxyType = nProxyType;
	m_ProxyData.strProxyHost = strProxyHost;
	m_ProxyData.nProxyPort = ProxyPort;
	m_ProxyData.bUseLogon = TRUE;
	m_ProxyData.strProxyUser = strProxyUser;
	m_ProxyData.strProxyPass = strProxyPass;
}

CStringA GetSocks4Error(UINT ver, UINT cd)
{
	if (ver != 0) {
		CStringA strError;
		strError.Format("Unknown protocol version: %u", ver);
		return strError;
	}

	switch (cd)
	{
		case 90: return "";
		case 91: return "Request rejected or failed";
		case 92: return "Failed to connect to 'identd'";
		case 93: return "'identd' user-id error";
		default:{
			CStringA strError;
			strError.Format("Unknown command: %u", cd);
			return strError;
		}
	}
}

CStringA GetSocks5Error(UINT rep)
{
	switch (rep)
	{
		case 0x00: return "";
		case 0x01: return "General SOCKS server failure";
		case 0x02: return "Connection not allowed by ruleset";
		case 0x03: return "Network unreachable";
		case 0x04: return "Host unreachable";
		case 0x05: return "Connection refused";
		case 0x06: return "TTL expired";
		case 0x07: return "Command not supported";
		case 0x08: return "Address type not supported";
		default:{
			CStringA strError;
			strError.Format("Unknown reply: %u", rep);
			return strError;
		}
	}
}

void CAsyncProxySocketLayer::OnClose(int nErrorCode)
{
	// We must route that event with the same functionality (PostMessage) which is used by
	// the 'OnReceive' and 'OnConnect' event handlers. Otherwise the socket event queue of
	// the underlying 'CAsyncSocketEx' may get out of sync.
	TriggerEvent(FD_CLOSE, nErrorCode, TRUE);
}

void CAsyncProxySocketLayer::OnAccept(int nErrorCode)
{
	// We must route that event with the same functionality (PostMessage) which is used by
	// the 'OnReceive' and 'OnConnect' event handlers. Otherwise the socket event queue of
	// the underlying 'CAsyncSocketEx' may get out of sync.
	TriggerEvent(FD_ACCEPT, nErrorCode, TRUE);
}

void CAsyncProxySocketLayer::OnSend(int nErrorCode)
{
	if (m_pSendBuffer)
	{
		if (nErrorCode || !FlushProxyRequest())
		{
			int errorCode = nErrorCode ? nErrorCode : WSAGetLastError();
			DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC,
				PROXYERROR_REQUESTFAILED, errorCode);
			TriggerEvent(m_nProxyOpID == PROXYOP_CONNECT ||
				m_nProxyOpID == PROXYOP_UDPASSOCIATE ? FD_CONNECT : FD_ACCEPT,
				errorCode ? errorCode : WSAECONNABORTED, TRUE);
			Reset();
			ClearBuffer();
		}
		return;
	}
	if (m_nProxyOpID)
		return;
	// We must route that event with the same functionality (PostMessage) which is used by
	// the 'OnReceive' and 'OnConnect' event handlers. Otherwise the socket event queue of
	// the underlying 'CAsyncSocketEx' may get out of sync.
	TriggerEvent(FD_WRITE, nErrorCode, TRUE);
}

void CAsyncProxySocketLayer::OnReceive(int nErrorCode)
{
	if (m_nProxyOpID == 0) {
		TriggerEvent(FD_READ, nErrorCode, TRUE);
		return;
	}

	if (nErrorCode)
		TriggerEvent(FD_READ, nErrorCode, TRUE);

	if (m_nProxyOpState == 0) //We should not receive a response yet!
		return;

	if (m_ProxyData.nProxyType == PROXYTYPE_SOCKS4 || m_ProxyData.nProxyType == PROXYTYPE_SOCKS4A)
	{
		if (   m_nProxyOpState == 1 // Response to initial connect or bind request
			|| m_nProxyOpState == 2)// Response (2nd) to bind request
		{
			if (!m_pRecvBuffer)
				m_pRecvBuffer = new char[8];
			int numread = ReceiveNext(m_pRecvBuffer + m_nRecvBufferPos, 8 - m_nRecvBufferPos);
			if (numread == SOCKET_ERROR) {
				int nErrorCode = WSAGetLastError();
				if (nErrorCode != WSAEWOULDBLOCK) {
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, nErrorCode);
					if (m_nProxyOpID == PROXYOP_CONNECT)
						TriggerEvent(FD_CONNECT, nErrorCode, TRUE);
					else
						TriggerEvent(FD_ACCEPT, nErrorCode, TRUE);
					Reset();
					ClearBuffer();
				}
				return;
			}
			m_nRecvBufferPos += numread;

			//                +----+----+----+----+----+----+----+----+
			//                | VN | CD | DSTPORT |      DSTIP        |
			//                +----+----+----+----+----+----+----+----+
			// # of bytes:       1    1      2              4
			//
			// VN is the version of the reply code and should be 0. CD is the result
			// code with one of the following values:
			//
			//        90: request granted
			//        91: request rejected or failed
			//        92: request rejected becasue SOCKS server cannot connect to
			//            identd on the client
			//        93: request rejected because the client program and identd
			//            report different user-ids

			if (m_nRecvBufferPos == 8)
			{
				TRACE("SOCKS4 response: VN=%u  CD=%u  DSTPORT=%u  DSTIP=%s\n", (BYTE)m_pRecvBuffer[0], (BYTE)m_pRecvBuffer[1], ntohs(*(u_short*)&m_pRecvBuffer[2]), ipstrA(*(u_long*)&m_pRecvBuffer[4]));
				if (m_pRecvBuffer[0] != 0 || m_pRecvBuffer[1] != 90) {
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, 0, (LPARAM)(LPCSTR)GetSocks4Error(m_pRecvBuffer[0], m_pRecvBuffer[1]));
					if (m_nProxyOpID == PROXYOP_CONNECT)
						TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
					else
						TriggerEvent(FD_ACCEPT, WSAECONNABORTED, TRUE);
					Reset();
					ClearBuffer();
					return;
				}
				// Proxy SHOULD answer with DSTPORT and DSTIP. Most proxies do, but some answer with 0.0.0.0:0
				//ASSERT( m_nProxyPeerPort == *(u_short*)&m_pRecvBuffer[2] );
				//ASSERT( m_nProxyPeerIP == 0 || m_nProxyPeerIP == *(u_long*)&m_pRecvBuffer[4] );

				if ( (m_nProxyOpID == PROXYOP_CONNECT && m_nProxyOpState == 1) ||
					 (m_nProxyOpID == PROXYOP_BIND  && m_nProxyOpState == 2) )
				{
					int nOpIDEvent = m_nProxyOpID == PROXYOP_CONNECT ? FD_CONNECT : FD_ACCEPT;
					ClearBuffer();
					Reset();
					TriggerEvent(nOpIDEvent, 0, TRUE);
					TriggerEvent(FD_READ, 0, TRUE);
					TriggerEvent(FD_WRITE, 0, TRUE);
					return;
				}
				else if (m_nProxyOpID == PROXYOP_BIND && m_nProxyOpState == 1)
				{
					// Listen socket created
					m_nProxyOpState = 2;
					u_long ip = *(u_long*)&m_pRecvBuffer[4];
					if (ip == 0)
					{
						// No IP returned, use the IP of the proxy server
						SOCKADDR SockAddr = {0};
						int SockAddrLen = sizeof(SockAddr);
						if (GetPeerName(&SockAddr, &SockAddrLen)) {
							ip = ((LPSOCKADDR_IN)&SockAddr)->sin_addr.S_un.S_addr;
						}
						else {
							DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, 0);
							if (m_nProxyOpID == PROXYOP_CONNECT)
								TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
							else
								TriggerEvent(FD_ACCEPT, WSAECONNABORTED, TRUE);
							Reset();
							ClearBuffer();
							return;
						}
					}
					t_ListenSocketCreatedStruct data;
					data.ip = ip;
					data.nPort = *(u_short*)&m_pRecvBuffer[2];
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYSTATUS_LISTENSOCKETCREATED, 0, (LPARAM)&data);
					// Wait for 2nd response to bind request
				}
				ClearBuffer();
			}
		}
	}
	else if (m_ProxyData.nProxyType == PROXYTYPE_SOCKS5)
	{
		if (   m_nProxyOpState == 1 // Response to initialization request
			|| m_nProxyOpState == 2)// Response to authentication request
		{
			if (!m_pRecvBuffer)
				m_pRecvBuffer = new char[2];
			int numread = ReceiveNext(m_pRecvBuffer + m_nRecvBufferPos, 2 - m_nRecvBufferPos);
			if (numread == SOCKET_ERROR) {
				int nErrorCode = WSAGetLastError();
				if (nErrorCode != WSAEWOULDBLOCK) {
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, nErrorCode);
					if (m_nProxyOpID == PROXYOP_CONNECT)
						TriggerEvent(FD_CONNECT, nErrorCode, TRUE);
					else
						TriggerEvent(FD_ACCEPT, nErrorCode, TRUE);
					Reset();
				}
				return;
			}
			m_nRecvBufferPos += numread;

			if (m_nRecvBufferPos == 2)
			{
				TRACE("SOCKS5 response: VER=%u  METHOD=%u\n", (BYTE)m_pRecvBuffer[0], (BYTE)m_pRecvBuffer[1]);
				bool bIniReqFailed = m_nProxyOpState == 1 && m_pRecvBuffer[0] != 5;  // Response to initialization request
				bool bAuthReqFailed = m_nProxyOpState == 2 && m_pRecvBuffer[1] != 0; // Response to authentication request
				if (bIniReqFailed || bAuthReqFailed) {
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, bAuthReqFailed ? PROXYERROR_AUTHFAILED : PROXYERROR_REQUESTFAILED, 0);
					if (m_nProxyOpID == PROXYOP_CONNECT)
						TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
					else
						TriggerEvent(FD_ACCEPT, WSAECONNABORTED, TRUE);
					Reset();
					ClearBuffer();
					return;
				}

				if (m_nProxyOpState == 1 && m_pRecvBuffer[1] != 0) // Authentication needed
				{
					if (m_pRecvBuffer[1] != 2) { // Unknown authentication type
						DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_AUTHTYPEUNKNOWN, 0);
						if (m_nProxyOpID == PROXYOP_CONNECT)
							TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
						else
							TriggerEvent(FD_ACCEPT, WSAECONNABORTED, TRUE);
						Reset();
						ClearBuffer();
						return;
					}

					if (!m_ProxyData.bUseLogon) {
						DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_AUTHNOLOGON, 0);
						if (m_nProxyOpID == PROXYOP_CONNECT)
							TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
						else
							TriggerEvent(FD_ACCEPT, WSAECONNABORTED, TRUE);
						Reset();
						ClearBuffer();
						return;
					}

					// Send authentication
					//
					// RFC 1929 - Username/Password Authentication for SOCKS V5
					//
					// +----+------+----------+------+----------+
					// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
					// +----+------+----------+------+----------+
					// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
					// +----+------+----------+------+----------+
					//
					// The VER field contains the current version of the subnegotiation,
					// which is X'01'. The ULEN field contains the length of the UNAME field
					// that follows. The UNAME field contains the username as known to the
					// source operating system. The PLEN field contains the length of the
					// PASSWD field that follows. The PASSWD field contains the password
					// association with the given UNAME.

					char cBuff[1 + 1 + 255 + 1 + 255];
					int iLen = _snprintf(cBuff, _countof(cBuff), "\x01%c%s%c%s", 
						m_ProxyData.strProxyUser.GetLength(),
						(LPCSTR)m_ProxyData.strProxyUser,
						m_ProxyData.strProxyPass.GetLength(),
						(LPCSTR)m_ProxyData.strProxyPass);

					int res = QueueProxyRequest(cBuff, iLen) ? iLen : SOCKET_ERROR;
					if (res == SOCKET_ERROR || res < iLen)
					{
						int nErrorCode = WSAGetLastError();
						if (nErrorCode != WSAEWOULDBLOCK || res < iLen) {
							DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, nErrorCode);
							if (m_nProxyOpID == PROXYOP_CONNECT)
								TriggerEvent(FD_CONNECT, nErrorCode, TRUE);
							else
								TriggerEvent(FD_ACCEPT, nErrorCode, TRUE);
							Reset();
							return;
						}
					}
					ClearBuffer();
					m_nProxyOpState = 2;
					return;
				}

				// Send connection request
				const char* pszAsciiProxyPeerHost;
				int iLenAsciiProxyPeerHost;
				if (!m_proxyPeerAddress.IsIPv6() && m_nProxyPeerIP == 0 &&
					m_nProxyOpID != PROXYOP_UDPASSOCIATE) {
					pszAsciiProxyPeerHost = m_pProxyPeerHost;
					if (!pszAsciiProxyPeerHost)
					{
						DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC,
							PROXYERROR_REQUESTFAILED, WSAEINVAL);
						TriggerEvent(FD_CONNECT, WSAEINVAL, TRUE);
						Reset();
						return;
					}
					iLenAsciiProxyPeerHost = (int)strlen(pszAsciiProxyPeerHost);
				}
				else {
					pszAsciiProxyPeerHost = 0;
					iLenAsciiProxyPeerHost = 0;
				}
				char* pcReq = (char*)_alloca(22 + 1 + iLenAsciiProxyPeerHost);
				pcReq[0] = 5;
				//pcReq[1] = (m_nProxyOpID == PROXYOP_CONNECT) ? 1 : 2;
				pcReq[1] = (char)m_nProxyOpID;//PROXYOP_CONNECT PROXYOP_BIND PROXYOP_UDPASSOCIATE
				pcReq[2] = 0;
				int iReqLen = 3;
				if(m_nProxyOpID == PROXYOP_UDPASSOCIATE)
				{
					pcReq[iReqLen++] = 1;
					*(u_long*)&pcReq[iReqLen] = m_udpcltAddr.sin_addr.s_addr;
					iReqLen += 4;
					*(u_short*)&pcReq[iReqLen] = m_udpcltAddr.sin_port;
					iReqLen += 2;
				}else
				{
					if (m_proxyPeerAddress.IsIPv6()) {
						pcReq[iReqLen++] = 4;
						memcpy(&pcReq[iReqLen], m_proxyPeerAddress.GetAddr6(), 16);
						iReqLen += 16;
					}
					else if (m_nProxyPeerIP) {
						pcReq[iReqLen++] = 1;
						*(u_long*)&pcReq[iReqLen] = m_nProxyPeerIP;
						iReqLen += 4;
					}
					else {
						pcReq[iReqLen++] = 3;
						pcReq[iReqLen++] = (char)iLenAsciiProxyPeerHost;
						memcpy(&pcReq[iReqLen], pszAsciiProxyPeerHost, iLenAsciiProxyPeerHost);
						iReqLen += iLenAsciiProxyPeerHost;
					}
					*(u_short*)&pcReq[iReqLen] = m_nProxyPeerPort;
					iReqLen += 2;
				}


				int res = QueueProxyRequest(pcReq, iReqLen) ? iReqLen : SOCKET_ERROR;
				if (res == SOCKET_ERROR || res < iReqLen)
				{
					int nErrorCode = WSAGetLastError();
					if (nErrorCode != WSAEWOULDBLOCK || res < iReqLen) {
						DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, nErrorCode);
						if (m_nProxyOpID == PROXYOP_CONNECT)
							TriggerEvent(FD_CONNECT, nErrorCode, TRUE);
						else
							TriggerEvent(FD_ACCEPT, nErrorCode, TRUE);
						Reset();
						return;
					}
				}
				m_nProxyOpState = 3;
				ClearBuffer();
			}
		}
		else if (  m_nProxyOpState == 3  // Response to connection or bind request
			    || m_nProxyOpState == 4) // Response (2nd) to bind request
		{
			if (!m_pRecvBuffer)
				m_pRecvBuffer = new char[CSocks5UdpCodec::MAX_HEADER_SIZE];

			int responseLength = 4;
			if (m_nRecvBufferPos >= 4)
			{
				if ((BYTE)m_pRecvBuffer[3] == 1)
					responseLength = 10;
				else if ((BYTE)m_pRecvBuffer[3] == 3)
					responseLength = m_nRecvBufferPos < 5 ? 5 : 7 + (BYTE)m_pRecvBuffer[4];
				else if ((BYTE)m_pRecvBuffer[3] == 4)
					responseLength = 22;
			}
			int numread = ReceiveNext(m_pRecvBuffer + m_nRecvBufferPos,
				responseLength - m_nRecvBufferPos);
			if (numread == SOCKET_ERROR) {
				int nErrorCode = WSAGetLastError();
				if (nErrorCode != WSAEWOULDBLOCK) {
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, nErrorCode);
					if (m_nProxyOpID == PROXYOP_CONNECT)
						TriggerEvent(FD_CONNECT, nErrorCode, TRUE);
					else
						TriggerEvent(FD_ACCEPT, nErrorCode, TRUE);
					Reset();
				}
				return;
			}
			m_nRecvBufferPos += numread;

			// responseLength above is the amount that was safe to request with
			// the bytes available before ReceiveNext. Recalculate it after the
			// read before deciding that the SOCKS5 reply is complete. Otherwise
			// the first four bytes of a UDP ASSOCIATE reply are mistaken for the
			// entire reply and the relay address is read from uninitialized data.
			if (m_nRecvBufferPos >= 4)
			{
				if (m_nRecvBufferPos < 4)
					responseLength = 4;
				else if ((BYTE)m_pRecvBuffer[3] == 1)
					responseLength = 10;
				else if ((BYTE)m_pRecvBuffer[3] == 3)
					responseLength = m_nRecvBufferPos < 5
						? 5 : 7 + (BYTE)m_pRecvBuffer[4];
				else if ((BYTE)m_pRecvBuffer[3] == 4)
					responseLength = 22;
				else
				{
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC,
						PROXYERROR_REQUESTFAILED, WSAEAFNOSUPPORT,
						(LPARAM)"Unexpected ATYP received");
					TriggerEvent(m_nProxyOpID == PROXYOP_CONNECT ||
						m_nProxyOpID == PROXYOP_UDPASSOCIATE ? FD_CONNECT : FD_ACCEPT,
						WSAEAFNOSUPPORT, TRUE);
					Reset();
					ClearBuffer();
					return;
				}
			}

			if (m_nRecvBufferPos == responseLength && responseLength >= 4)
			{
				if (m_pRecvBuffer[0] != 5 || m_pRecvBuffer[1] != 0) {
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, 0, (LPARAM)(LPCSTR)GetSocks5Error(m_pRecvBuffer[1]));
					if (m_nProxyOpID == PROXYOP_CONNECT)
						TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
					else
						TriggerEvent(FD_ACCEPT, WSAECONNABORTED, TRUE);
					Reset();
					ClearBuffer();
					return;
				}

				if ( (m_nProxyOpID == PROXYOP_CONNECT && m_nProxyOpState == 3) ||
					 (m_nProxyOpID == PROXYOP_BIND  && m_nProxyOpState == 4) )
				{
					int nOpIDEvent = m_nProxyOpID == PROXYOP_CONNECT ? FD_CONNECT : FD_ACCEPT;
					Reset();
					ClearBuffer();
					TriggerEvent(nOpIDEvent, 0, TRUE);
					TriggerEvent(FD_READ, 0, TRUE);
					TriggerEvent(FD_WRITE, 0, TRUE);
					return;
				}
				else if (m_nProxyOpID == PROXYOP_BIND && m_nProxyOpState == 3)
				{
					// Listen socket created
					if (m_pRecvBuffer[3] != 1) { // Check which kind of address the response contains
						DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, 0, (LPARAM)"Unexpected ATYP received");
						if (m_nProxyOpID == PROXYOP_CONNECT)
							TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
						else
							TriggerEvent(FD_ACCEPT, WSAECONNABORTED, TRUE);
						Reset();
						ClearBuffer();
						return;
					}

					m_nProxyOpState = 4;
					t_ListenSocketCreatedStruct data;
					data.ip = *(u_long*)&m_pRecvBuffer[4];
					data.nPort = *(u_short*)&m_pRecvBuffer[8];
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYSTATUS_LISTENSOCKETCREATED, 0, (LPARAM)&data);
					// Wait for 2nd response to bind request
				}
				else if(m_nProxyOpID == PROXYOP_UDPASSOCIATE && m_nProxyOpState == 3)
				{
					if (m_pRecvBuffer[3] != 1 && m_pRecvBuffer[3] != 3)
					{
						DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC,
							PROXYERROR_REQUESTFAILED, WSAEAFNOSUPPORT,
							(LPARAM)"UDP ASSOCIATE returned a non-IPv4 relay");
						TriggerEvent(FD_CONNECT, WSAEAFNOSUPPORT, TRUE);
						Reset();
						ClearBuffer();
						return;
					}
					memset(&m_udpsrvAddr, 0, sizeof(m_udpsrvAddr));
					m_udpsrvAddr.sin_family = AF_INET;
					if (m_pRecvBuffer[3] == 1)
					{
						m_udpsrvAddr.sin_port = *(u_short*)&m_pRecvBuffer[8];
						m_udpsrvAddr.sin_addr.s_addr = *(u_long*)&m_pRecvBuffer[4];
					}
					else
					{
						const int domainLength = (BYTE)m_pRecvBuffer[4];
						char relayHost[256];
						memcpy(relayHost, m_pRecvBuffer + 5, domainLength);
						relayHost[domainLength] = '\0';
						m_udpsrvAddr.sin_port = *(u_short*)&m_pRecvBuffer[5 + domainLength];
						hostent *relay = gethostbyname(relayHost);
						if (!relay || relay->h_addrtype != AF_INET || relay->h_length != 4)
						{
							TriggerEvent(FD_CONNECT, WSAHOST_NOT_FOUND, TRUE);
							Reset();
							ClearBuffer();
							return;
						}
						memcpy(&m_udpsrvAddr.sin_addr.s_addr, relay->h_addr, 4);
					}
					// RFC 1928 servers commonly return 0.0.0.0 to mean the same
					// address as the TCP control connection.
					if (m_udpsrvAddr.sin_addr.s_addr == INADDR_ANY)
					{
						SOCKADDR_IN proxyPeer;
						int proxyPeerLength = sizeof(proxyPeer);
						if (GetPeerNameNext((SOCKADDR*)&proxyPeer, &proxyPeerLength))
							m_udpsrvAddr.sin_addr = proxyPeer.sin_addr;
					}
					Reset();
					ClearBuffer();
					//����FD_CONNECT ֪ͨUDPASSOCIATE �����Ѿ�׼���� 
					TriggerEvent(FD_CONNECT, 0, TRUE);
				}
				ClearBuffer();
			}
		}
	}
	else if (m_ProxyData.nProxyType == PROXYTYPE_HTTP10 || m_ProxyData.nProxyType == PROXYTYPE_HTTP11)
	{
		ASSERT( m_nProxyOpID == PROXYOP_CONNECT );

		// Read everything which is currently available at the socket
		//
		bool bFoundEOH = false;
		int iHeaderEnd = 0;
		while (!bFoundEOH)
		{
			char cBuff[4096];
			int iRead = ReceiveNext(cBuff, sizeof cBuff);
			if (iRead == SOCKET_ERROR) {
				int nErrorCode = WSAGetLastError();
				if (nErrorCode != WSAEWOULDBLOCK) {
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, nErrorCode);
					Reset();
					ClearBuffer();
					TriggerEvent(FD_CONNECT, nErrorCode, TRUE);
				}
				return;
			}
			else if (iRead == 0)
				return;

			// Safety check: Don't allow buffer to grow too large
			if (    m_iStrBuffSize + iRead > 4096
				|| (m_pStrBuffer = (char*)realloc(m_pStrBuffer, m_iStrBuffSize + iRead)) == NULL) {
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, 0, (LPARAM)"Invalid HTTP response - Header size exceeds limit");
				Reset();
				ClearBuffer();
				TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
				return;
			}

			// Append read chunk to buffer
			memcpy(m_pStrBuffer + m_iStrBuffSize, cBuff, iRead);
			m_iStrBuffSize += iRead;

			// Search for EOH (CRLFCRLF)
			const char* pc = m_pStrBuffer;
			int iMaxOff = m_iStrBuffSize - sizeof(DWORD);
			for (int i = 0; i <= iMaxOff; i++) {
				if (*(DWORD*)(pc++) == 0x0A0D0A0D) { // VC-BUG?: '\r\n\r\n' results in 0x0A0D0A0D too, although it should not!
					bFoundEOH = true;
					iHeaderEnd = i + sizeof(DWORD);
					break;
				}
			}
		}
		ASSERT( bFoundEOH );

		// Evaluate HTTP status
		//
		// We already know that we have a (CR)NL-character which can be safely used
		// as a NUL-character in the context of 'sscanf'.
		//
		UINT uHttpStatus;
		if (sscanf(m_pStrBuffer, "HTTP/%*u.%*u %u", &uHttpStatus) != 1 || uHttpStatus != 200)
		{
			if (*(DWORD*)m_pStrBuffer == 'PTTH')
			{
				TRACE("%hs\n", CStringA(m_pStrBuffer, m_iStrBuffSize).TrimRight("\r\n"));
				char* pcNl = (char*)memchr(m_pStrBuffer, '\n', m_iStrBuffSize);
				if (pcNl) {
					*pcNl = '\0';
					if (pcNl[-1] == '\r')
						pcNl[-1] = '\0';
				}
				if (uHttpStatus == 407)
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_AUTHREQUIRED, 0);
				else
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, 0, (LPARAM)m_pStrBuffer);
			}
			else {
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, 0, (LPARAM)"Invalid HTTP response");
			}
			Reset();
			ClearBuffer();
			TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
			return;
		}

		TRACE("%hs\n", CStringA(m_pStrBuffer, m_iStrBuffSize).TrimRight("\r\n"));
		const int surplusLength = m_iStrBuffSize - iHeaderEnd;
		if (surplusLength > 0)
		{
			delete[] m_pAppRecvBuffer;
			m_pAppRecvBuffer = new char[surplusLength];
			memcpy(m_pAppRecvBuffer, m_pStrBuffer + iHeaderEnd, surplusLength);
			m_nAppRecvBufferLen = surplusLength;
			m_nAppRecvBufferPos = 0;
		}
		Reset();
		ClearBuffer();
		TriggerEvent(FD_CONNECT, 0, TRUE);
		TriggerEvent(FD_READ, 0, TRUE);
		TriggerEvent(FD_WRITE, 0, TRUE);
	}
}

BOOL CAsyncProxySocketLayer::Connect(LPCSTR lpszHostAddress, UINT nHostPort)
{
	ASSERT( lpszHostAddress != NULL );

	if (!m_ProxyData.nProxyType)
		//Connect normally because there is no proxy
		return ConnectNext(lpszHostAddress, nHostPort);

	//Translate the host address
	SOCKADDR_IN sockAddr = {0};
	sockAddr.sin_addr.s_addr = inet_addr(lpszHostAddress);
	if (sockAddr.sin_addr.s_addr == INADDR_NONE)
	{
		// Can't resolve hostname
		if (m_ProxyData.nProxyType == PROXYTYPE_SOCKS4A ||
			m_ProxyData.nProxyType == PROXYTYPE_SOCKS5  ||
			m_ProxyData.nProxyType == PROXYTYPE_HTTP10  ||
			m_ProxyData.nProxyType == PROXYTYPE_HTTP11)
		{	//Can send domain names to proxy

			//Connect to proxy server
			BOOL res = ConnectNext(m_ProxyData.strProxyHost, m_ProxyData.nProxyPort);
			if (!res) {
				int nErrorCode = WSAGetLastError();
				if (nErrorCode != WSAEWOULDBLOCK) {
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_NOCONN, nErrorCode);
					return FALSE;
				}
			}
			m_nProxyPeerPort = htons((u_short)nHostPort);
			m_nProxyPeerIP = 0;
			m_proxyPeerAddress.Clear();
			delete[] m_pProxyPeerHost;
			m_pProxyPeerHost = NULL; // 'new' may throw an exception
			m_pProxyPeerHost = new CHAR[strlen(lpszHostAddress) + 1];
			strcpy(m_pProxyPeerHost, lpszHostAddress);
			m_nProxyOpID = PROXYOP_CONNECT;
			return TRUE;
		}
		else {

			LPHOSTENT lphost = m_pReal_gethostbyname(lpszHostAddress);
			if (lphost != NULL)
			{
				sockAddr.sin_addr.s_addr = ((LPIN_ADDR)lphost->h_addr)->s_addr;
			}else
			{
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_CANTRESOLVEHOST, 0);
				WSASetLastError(WSAEINVAL);
				return FALSE;
			}
		}

	}
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port = htons((u_short)nHostPort);

	BOOL res = CAsyncProxySocketLayer::Connect((SOCKADDR*)&sockAddr, sizeof(sockAddr));
	if (res || WSAGetLastError() == WSAEWOULDBLOCK)
	{
		delete[] m_pProxyPeerHost;
		m_pProxyPeerHost = NULL; // 'new' may throw an exception
		m_pProxyPeerHost = new CHAR[strlen(lpszHostAddress) + 1];
		strcpy(m_pProxyPeerHost, lpszHostAddress);
	}
	return res;
}

BOOL CAsyncProxySocketLayer::Connect(const SOCKADDR* lpSockAddr, int nSockAddrLen)
{
	if (!m_ProxyData.nProxyType)
		//Connect normally because there is no proxy
		return ConnectNext(lpSockAddr, nSockAddrLen);

	if (!lpSockAddr ||
		(lpSockAddr->sa_family != AF_INET && lpSockAddr->sa_family != AF_INET6) ||
		nSockAddrLen < (lpSockAddr->sa_family == AF_INET6
			? (int)sizeof(SOCKADDR_IN6) : (int)sizeof(SOCKADDR_IN)))
	{
		WSASetLastError(WSAEAFNOSUPPORT);
		return FALSE;
	}

	//Save server details
	m_proxyPeerAddress.Set(lpSockAddr, nSockAddrLen);
	m_nProxyPeerIP = m_proxyPeerAddress.GetdwIP();
	m_nProxyPeerPort = lpSockAddr->sa_family == AF_INET6
		? reinterpret_cast<const SOCKADDR_IN6 *>(lpSockAddr)->sin6_port
		: reinterpret_cast<const SOCKADDR_IN *>(lpSockAddr)->sin_port;

	if (m_proxyPeerAddress.IsAny())
		return FALSE;

	delete[] m_pProxyPeerHost;
	m_pProxyPeerHost = NULL;

	m_nProxyOpID = PROXYOP_CONNECT;

	BOOL res = ConnectNext(m_ProxyData.strProxyHost, m_ProxyData.nProxyPort);
	if (!res) {
		int nErrorCode = WSAGetLastError();
		if (nErrorCode != WSAEWOULDBLOCK) {
			DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_NOCONN, nErrorCode);
			return FALSE;
		}
	}

	return res;
}

void CAsyncProxySocketLayer::OnConnect(int nErrorCode)
{
	if (m_ProxyData.nProxyType == PROXYTYPE_NOPROXY) {
		TriggerEvent(FD_CONNECT, nErrorCode, TRUE);
		return;
	}

	if (m_nProxyOpID == 0) {
		ASSERT(0);
		return;
	}

	if (nErrorCode) {
		// Can't connect to proxy
		DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_NOCONN, nErrorCode);
		//udp������ʱ����Ҫtcp����, ����PROXYOP_UDPASSOCIATEʧ��ʱ����һ��FD_CONNECT
		if (m_nProxyOpID == PROXYOP_CONNECT || m_nProxyOpID == PROXYOP_UDPASSOCIATE)
			TriggerEvent(FD_CONNECT, nErrorCode, TRUE);
		else
			TriggerEvent(FD_ACCEPT, nErrorCode, TRUE);
		Reset();
		ClearBuffer();
		return;
	}

	if (m_nProxyOpID == PROXYOP_CONNECT || m_nProxyOpID == PROXYOP_BIND || m_nProxyOpID == PROXYOP_UDPASSOCIATE)
	{
		if (m_nProxyOpState)
			return; // Somehow OnConnect has been called more than once

		ASSERT( m_ProxyData.nProxyType != PROXYTYPE_NOPROXY );
		ClearBuffer();

		if (m_ProxyData.nProxyType == PROXYTYPE_SOCKS4 || m_ProxyData.nProxyType == PROXYTYPE_SOCKS4A)
		{
			if (m_proxyPeerAddress.IsIPv6())
			{
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC,
					PROXYERROR_REQUESTFAILED, WSAEAFNOSUPPORT);
				TriggerEvent(FD_CONNECT, WSAEAFNOSUPPORT, TRUE);
				Reset();
				return;
			}
			const char* pszAsciiProxyPeerHost;
			int iSizeAsciiProxyPeerHost;
			if (m_nProxyPeerIP == 0) {
				pszAsciiProxyPeerHost = m_pProxyPeerHost;
				iSizeAsciiProxyPeerHost = (int)strlen(pszAsciiProxyPeerHost) + 1;
			}
			else {
				pszAsciiProxyPeerHost = 0;
				iSizeAsciiProxyPeerHost = 0;
			}

			// SOCKS 4
			// ---------------------------------------------------------------------------
			//            +----+----+----+----+----+----+----+----+----+----+....+----+
			//            | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
			//            +----+----+----+----+----+----+----+----+----+----+....+----+
			//# of bytes:   1    1      2              4           variable       1

			char* pcReq = (char*)_alloca(9 + iSizeAsciiProxyPeerHost);
			pcReq[0] = 4;											// VN: 4
			pcReq[1] = (m_nProxyOpID == PROXYOP_CONNECT) ? 1 : 2;	// CD: 1=CONNECT, 2=BIND
			*(u_short*)&pcReq[2] = m_nProxyPeerPort;				// DSTPORT

			int iReqLen = 4 + 4 + 1;
			if (m_nProxyPeerIP == 0)
			{
				ASSERT( m_ProxyData.nProxyType == PROXYTYPE_SOCKS4A );
				ASSERT( strcmp(pszAsciiProxyPeerHost, "") != 0 );
				ASSERT( iSizeAsciiProxyPeerHost > 0 );

				// For version 4A, if the client cannot resolve the destination host's
				// domain name to find its IP address, it should set the first three bytes
				// of DSTIP to NULL and the last byte to a non-zero value. (This corresponds
				// to IP address 0.0.0.x, with x nonzero.)

				// DSTIP: Set the IP to 0.0.0.x (x is nonzero)
				pcReq[4] = 0;
				pcReq[5] = 0;
				pcReq[6] = 0;
				pcReq[7] = 1;

				pcReq[8] = 0;	// Terminating NUL-byte for USERID

				// Following the NULL byte terminating USERID, the client must send the 
				// destination domain name and termiantes it with another NULL byte. 

				// Add hostname (including terminating NUL-byte)
				memcpy(&pcReq[9], pszAsciiProxyPeerHost, iSizeAsciiProxyPeerHost);
				iReqLen += iSizeAsciiProxyPeerHost;
			}
			else {
				*(u_long*)&pcReq[4] = m_nProxyPeerIP;	// DSTIP
				pcReq[8] = 0;							// Terminating NUL-byte for USERID
			}

			int res = QueueProxyRequest(pcReq, iReqLen) ? iReqLen : SOCKET_ERROR;
			if (res == SOCKET_ERROR) {
				int nErrorCode = WSAGetLastError();
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, nErrorCode);
				if (m_nProxyOpID == PROXYOP_CONNECT)
					TriggerEvent(FD_CONNECT, (nErrorCode == WSAEWOULDBLOCK) ? WSAECONNABORTED : nErrorCode, TRUE);
				else
					TriggerEvent(FD_ACCEPT, nErrorCode, TRUE);
				Reset();
				ClearBuffer();
				return;
			}
			else if (res < iReqLen) {
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, 0);
				if (m_nProxyOpID == PROXYOP_CONNECT)
					TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
				else
					TriggerEvent(FD_ACCEPT, WSAECONNABORTED, TRUE);
				Reset();
				ClearBuffer();
				return;
			}
		}
		else if (m_ProxyData.nProxyType == PROXYTYPE_SOCKS5)
		{
			// SOCKS 5
			// -------------------------------------------------------------------------------------------
			// The client connects to the server, and sends a version identifier/method selection message:
			//                +----+----------+----------+
			//                |VER | NMETHODS | METHODS  |
			//                +----+----------+----------+
			//                | 1  |    1     | 1 to 255 |
			//                +----+----------+----------+
			//
			// The values currently defined for METHOD are:
			//
			//       o  X'00' NO AUTHENTICATION REQUIRED
			//       o  X'01' GSSAPI
			//       o  X'02' USERNAME/PASSWORD
			//       o  X'03' to X'7F' IANA ASSIGNED
			//       o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
			//       o  X'FF' NO ACCEPTABLE METHODS

			int iReqLen;
			char acReq[4];
			acReq[0] = 5;		// VER: 5
			if (m_ProxyData.bUseLogon) {
				acReq[1] = 2;	// NMETHODS: 2
				acReq[2] = 2;	// METHOD #1: 2 (USERNAME/PASSWORD)
				acReq[3] = 0;	// METHOD #2: 0 (NO AUTHENTICATION)
				iReqLen = 4;
			}
			else {
				acReq[1] = 1;	// NMETHODS: 1
				acReq[2] = 0;	// METHOD #1: 0 (NO AUTHENTICATION)
				iReqLen = 3;
			}

			int res = QueueProxyRequest(acReq, iReqLen) ? iReqLen : SOCKET_ERROR;
			if (res == SOCKET_ERROR) {
				int nErrorCode = WSAGetLastError();
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, nErrorCode);
				if (m_nProxyOpID == PROXYOP_CONNECT)
					TriggerEvent(FD_CONNECT, (nErrorCode == WSAEWOULDBLOCK) ? WSAECONNABORTED : nErrorCode, TRUE);
				else
					TriggerEvent(FD_ACCEPT, nErrorCode, TRUE);
				Reset();
				ClearBuffer();
				return;
			}
			else if (res < iReqLen) {
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, 0);
				if (m_nProxyOpID == PROXYOP_CONNECT)
					TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
				else
					TriggerEvent(FD_ACCEPT, WSAECONNABORTED, TRUE);
				Reset();
				ClearBuffer();
				return;
			}
		}
		else if (m_ProxyData.nProxyType == PROXYTYPE_HTTP10 || m_ProxyData.nProxyType == PROXYTYPE_HTTP11)
		{
			const char* pszHost;
			char ipv6Host[INET6_ADDRSTRLEN] = { 0 };
			if (m_pProxyPeerHost && m_pProxyPeerHost[0] != '\0')
				pszHost = m_pProxyPeerHost;
			else if (m_proxyPeerAddress.IsIPv6())
			{
				pszHost = InetNtopA(AF_INET6, (PVOID)m_proxyPeerAddress.GetAddr6(),
					ipv6Host, _countof(ipv6Host));
			}
			else
				pszHost = inet_ntoa(*(in_addr*)&m_nProxyPeerIP);
			if (!pszHost)
			{
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC,
					PROXYERROR_REQUESTFAILED, WSAEINVAL);
				TriggerEvent(m_nProxyOpID == PROXYOP_CONNECT ? FD_CONNECT : FD_ACCEPT,
					WSAEINVAL, TRUE);
				Reset();
				ClearBuffer();
				return;
			}

			UINT nProxyPeerPort = ntohs((u_short)m_nProxyPeerPort);
			char szHttpReq[4096];
			int iHttpReqLen;
			if (!m_ProxyData.bUseLogon)
			{
				if (m_ProxyData.nProxyType == PROXYTYPE_HTTP10) {
					// The reason why we offer HTTP/1.0 support is just because it 
					// allows us to *not *send the "Host" field, thus saving overhead.
					iHttpReqLen = _snprintf(szHttpReq, _countof(szHttpReq),
						"CONNECT %s%s%s:%u HTTP/1.0\r\n"
						"\r\n",
						m_proxyPeerAddress.IsIPv6() ? "[" : "", pszHost,
						m_proxyPeerAddress.IsIPv6() ? "]" : "", nProxyPeerPort);
				}
				else {
					// "Host" field is a MUST for HTTP/1.1 according RFC 2161
					iHttpReqLen = _snprintf(szHttpReq, _countof(szHttpReq),
						"CONNECT %s%s%s:%u HTTP/1.1\r\n"
						"Host: %s%s%s:%u\r\n"
						"Proxy-Connection: Keep-Alive\r\n"
						"\r\n",
						m_proxyPeerAddress.IsIPv6() ? "[" : "", pszHost,
						m_proxyPeerAddress.IsIPv6() ? "]" : "", nProxyPeerPort,
						m_proxyPeerAddress.IsIPv6() ? "[" : "", pszHost,
						m_proxyPeerAddress.IsIPv6() ? "]" : "", nProxyPeerPort);
				}
			}
			else
			{
				char szUserPass[512];
				int iUserPassLen = _snprintf(szUserPass, _countof(szUserPass),
					"%s:%s", (LPCSTR)m_ProxyData.strProxyUser,
					(LPCSTR)m_ProxyData.strProxyPass);

				char szUserPassBase64[2048];
				CBase64Coding base64coding;
				if (!base64coding.Encode(szUserPass, iUserPassLen, szUserPassBase64)) {
					DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, 0);
					if (m_nProxyOpID == PROXYOP_CONNECT)
						TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
					else
						TriggerEvent(FD_ACCEPT, WSAECONNABORTED, TRUE);
					Reset();
					ClearBuffer();
					return;
				}

				if (m_ProxyData.nProxyType == PROXYTYPE_HTTP10) {
					// The reason why we offer HTTP/1.0 support is just because it 
					// allows us to *not *send the "Host" field, thus saving overhead.
					iHttpReqLen = _snprintf(szHttpReq, _countof(szHttpReq), 
						"CONNECT %s%s%s:%u HTTP/1.0\r\n"
						"Authorization: Basic %s\r\n"
						"Proxy-Authorization: Basic %s\r\n"
						"Proxy-Connection: Keep-Alive\r\n"
						"\r\n",
						m_proxyPeerAddress.IsIPv6() ? "[" : "", pszHost,
						m_proxyPeerAddress.IsIPv6() ? "]" : "", nProxyPeerPort,
						szUserPassBase64, szUserPassBase64);
				}
				else {
					// "Host" field is a MUST for HTTP/1.1 according RFC 2161
					iHttpReqLen = _snprintf(szHttpReq, _countof(szHttpReq), 
						"CONNECT %s%s%s:%u HTTP/1.1\r\n"
						"Host: %s%s%s:%u\r\n"
						"Authorization: Basic %s\r\n"
						"Proxy-Authorization: Basic %s\r\n"
						"Proxy-Connection: Keep-Alive\r\n"
						"\r\n",
						m_proxyPeerAddress.IsIPv6() ? "[" : "", pszHost,
						m_proxyPeerAddress.IsIPv6() ? "]" : "", nProxyPeerPort,
						m_proxyPeerAddress.IsIPv6() ? "[" : "", pszHost,
						m_proxyPeerAddress.IsIPv6() ? "]" : "", nProxyPeerPort,
						szUserPassBase64, szUserPassBase64);
				}
			}
			if (iHttpReqLen <= 0 ||
				iHttpReqLen >= (int)_countof(szHttpReq))
			{
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC,
					PROXYERROR_REQUESTFAILED, WSAEINVAL);
				TriggerEvent(m_nProxyOpID == PROXYOP_CONNECT ? FD_CONNECT : FD_ACCEPT,
					WSAEINVAL, TRUE);
				Reset();
				ClearBuffer();
				return;
			}

			int iSent = QueueProxyRequest(szHttpReq, iHttpReqLen) ? iHttpReqLen : SOCKET_ERROR;
			if (iSent == SOCKET_ERROR) {
				int nErrorCode = WSAGetLastError();
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, nErrorCode);
				if (m_nProxyOpID == PROXYOP_CONNECT)
					TriggerEvent(FD_CONNECT, (nErrorCode == WSAEWOULDBLOCK) ? WSAECONNABORTED : nErrorCode, TRUE);
				else
					TriggerEvent(FD_ACCEPT, nErrorCode, TRUE);
				Reset();
				ClearBuffer();
				return;
			}
			else if (iSent < iHttpReqLen) {
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, 0);
				if (m_nProxyOpID == PROXYOP_CONNECT)
					TriggerEvent(FD_CONNECT, WSAECONNABORTED, TRUE);
				else
					TriggerEvent(FD_ACCEPT, WSAECONNABORTED, TRUE);
				Reset();
				ClearBuffer();
				return;
			}
			m_nProxyOpState++;
			return;
		}
		else
			ASSERT(0);

		//Now we'll wait for the response, handled in OnReceive
		m_nProxyOpState++;
	}
}

void CAsyncProxySocketLayer::ClearBuffer()
{
	free(m_pStrBuffer);
	m_pStrBuffer = NULL;
	m_iStrBuffSize = 0;
	delete[] m_pRecvBuffer;
	m_pRecvBuffer = 0;
	m_nRecvBufferPos = 0;
}

BOOL CAsyncProxySocketLayer::Listen(int nConnectionBacklog)
{
	if (GetProxyType() == PROXYTYPE_NOPROXY)
		return ListenNext(nConnectionBacklog);

	//Connect to proxy server
	BOOL res = ConnectNext(m_ProxyData.strProxyHost, m_ProxyData.nProxyPort);
	if (!res) {
		int nErrorCode = WSAGetLastError();
		if (nErrorCode != WSAEWOULDBLOCK) {
			DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_NOCONN, nErrorCode);
			return FALSE;
		}
	}
	m_nProxyPeerPort = 0;
	m_nProxyPeerIP = (unsigned int)nConnectionBacklog; // ???????????????????
	m_nProxyOpID = PROXYOP_BIND;
	return TRUE;
}

#ifdef _AFX
BOOL CAsyncProxySocketLayer::GetPeerName(CString &rPeerAddress, UINT &rPeerPort)
{
	if (m_ProxyData.nProxyType == PROXYTYPE_NOPROXY)
		return GetPeerNameNext(rPeerAddress, rPeerPort);

	if (GetLayerState() == notsock)
	{
		WSASetLastError(WSAENOTSOCK);
		return FALSE;
	}
	else if (GetLayerState() != connected)
	{
		WSASetLastError(WSAENOTCONN);
		return FALSE;
	}
	else if ((!m_proxyPeerAddress.IsIPv4() && !m_proxyPeerAddress.IsIPv6()) ||
		!m_nProxyPeerPort)
	{
		WSASetLastError(WSAENOTCONN);
		return FALSE;
	}

	ASSERT( m_ProxyData.nProxyType );
	BOOL res = GetPeerNameNext(rPeerAddress, rPeerPort);
	if (res)
	{
		rPeerPort = ntohs((u_short)m_nProxyPeerPort);
		if (m_proxyPeerAddress.IsIPv6())
		{
			TCHAR address[INET6_ADDRSTRLEN] = { 0 };
#ifdef _UNICODE
			InetNtopW(AF_INET6, (PVOID)m_proxyPeerAddress.GetAddr6(), address,
				_countof(address));
#else
			InetNtopA(AF_INET6, (PVOID)m_proxyPeerAddress.GetAddr6(), address,
				_countof(address));
#endif
			rPeerAddress = address;
		}
		else
			rPeerAddress.Format(_T("%u.%u.%u.%u"), m_nProxyPeerIP&0xff, (m_nProxyPeerIP>>8)&0xff, (m_nProxyPeerIP>>16)&0xff, m_nProxyPeerIP>>24);
	}
	return res;
}
#endif

BOOL CAsyncProxySocketLayer::GetPeerName(SOCKADDR* lpSockAddr, int* lpSockAddrLen)
{
	if (m_ProxyData.nProxyType == PROXYTYPE_NOPROXY)
		return GetPeerNameNext(lpSockAddr, lpSockAddrLen);

	if (GetLayerState() == notsock)
	{
		WSASetLastError(WSAENOTSOCK);
		return FALSE;
	}
	else if (GetLayerState() != connected)
	{
		WSASetLastError(WSAENOTCONN);
		return FALSE;
	}
	else if ((!m_proxyPeerAddress.IsIPv4() && !m_proxyPeerAddress.IsIPv6()) ||
		!m_nProxyPeerPort)
	{
		WSASetLastError(WSAENOTCONN);
		return FALSE;
	}

	ASSERT( m_ProxyData.nProxyType );
	const int requiredLength = m_proxyPeerAddress.Size();
	if (!lpSockAddr || !lpSockAddrLen || *lpSockAddrLen < requiredLength)
	{
		WSASetLastError(WSAEFAULT);
		return FALSE;
	}
	CopyMemory(lpSockAddr, &m_proxyPeerAddress, requiredLength);
	*lpSockAddrLen = requiredLength;
	return TRUE;
}

BOOL CAsyncProxySocketLayer::SetSecureTransport(const CStringA& psk)
{
	if (psk.IsEmpty() || m_ProxyData.nProxyType != PROXYTYPE_SOCKS5)
	{
		WSASetLastError(WSAEINVAL);
		return FALSE;
	}
	m_securePsk = psk;
	return TRUE;
}

int CAsyncProxySocketLayer::GetProxyType() const
{
	return m_ProxyData.nProxyType;
}

int CAsyncProxySocketLayer::GetProxyOpID() const
{
	return m_nProxyOpID;
}

void CAsyncProxySocketLayer::Close()
{
	m_ProxyData.strProxyHost.Empty();
	m_ProxyData.strProxyUser.Empty();
	m_ProxyData.strProxyPass.Empty();
	delete[] m_pProxyPeerHost;
	m_pProxyPeerHost = NULL;
	ClearBuffer();
	ClearSendBuffer();
	delete[] m_pAppRecvBuffer;
	m_pAppRecvBuffer = NULL;
	m_nAppRecvBufferLen = m_nAppRecvBufferPos = 0;
	Reset();
	CloseNext();
}

void CAsyncProxySocketLayer::Reset()
{
	m_nProxyOpState = 0;
	m_nProxyOpID = 0;
}

int CAsyncProxySocketLayer::Send(const void* lpBuf, int nBufLen, int nFlags)
{
	if (m_nProxyOpID)
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	return SendNext(lpBuf, nBufLen, nFlags);
}

int CAsyncProxySocketLayer::Receive(void* lpBuf, int nBufLen, int nFlags)
{
	if (nBufLen < 0 || (nBufLen > 0 && !lpBuf))
	{
		WSASetLastError(WSAEFAULT);
		return SOCKET_ERROR;
	}
	if (nBufLen == 0)
		return 0;
	if (m_nProxyOpID)
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	if (m_pAppRecvBuffer && m_nAppRecvBufferPos < m_nAppRecvBufferLen)
	{
		int available = m_nAppRecvBufferLen - m_nAppRecvBufferPos;
		int copied = min(nBufLen, available);
		memcpy(lpBuf, m_pAppRecvBuffer + m_nAppRecvBufferPos, copied);
		m_nAppRecvBufferPos += copied;
		if (m_nAppRecvBufferPos == m_nAppRecvBufferLen)
		{
			delete[] m_pAppRecvBuffer;
			m_pAppRecvBuffer = NULL;
			m_nAppRecvBufferLen = m_nAppRecvBufferPos = 0;
		}
		return copied;
	}

	return ReceiveNext(lpBuf, nBufLen, nFlags);
}

void CAsyncProxySocketLayer::ClearSendBuffer()
{
	delete[] m_pSendBuffer;
	m_pSendBuffer = NULL;
	m_nSendBufferLen = m_nSendBufferPos = 0;
}

BOOL CAsyncProxySocketLayer::QueueProxyRequest(const void *data, int length)
{
	if (!data || length <= 0 || m_pSendBuffer)
	{
		WSASetLastError(WSAEINVAL);
		return FALSE;
	}
	m_pSendBuffer = new(std::nothrow) char[length];
	if (!m_pSendBuffer)
	{
		WSASetLastError(WSAENOBUFS);
		return FALSE;
	}
	memcpy(m_pSendBuffer, data, length);
	m_nSendBufferLen = length;
	m_nSendBufferPos = 0;
	return FlushProxyRequest();
}

BOOL CAsyncProxySocketLayer::FlushProxyRequest()
{
	while (m_pSendBuffer && m_nSendBufferPos < m_nSendBufferLen)
	{
		int sent = SendNext(m_pSendBuffer + m_nSendBufferPos,
			m_nSendBufferLen - m_nSendBufferPos);
		if (sent == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAEWOULDBLOCK)
				return TRUE;
			ClearSendBuffer();
			return FALSE;
		}
		if (sent <= 0)
		{
			WSASetLastError(WSAECONNRESET);
			ClearSendBuffer();
			return FALSE;
		}
		m_nSendBufferPos += sent;
	}
	if (m_pSendBuffer && m_nSendBufferPos == m_nSendBufferLen)
		ClearSendBuffer();
	return TRUE;
}

BOOL CAsyncProxySocketLayer::PrepareListen(unsigned long ip)
{
	if (GetLayerState()!=notsock && GetLayerState()!=unconnected)
		return FALSE;
	m_nProxyPeerIP = ip;
	return TRUE;
}

BOOL CAsyncProxySocketLayer::Accept( CAsyncSocketEx& rConnectedSocket, SOCKADDR* lpSockAddr /*=NULL*/, int* lpSockAddrLen /*=NULL*/ )
{
	if (!m_ProxyData.nProxyType)
		return AcceptNext(rConnectedSocket, lpSockAddr, lpSockAddrLen);

	GetPeerName(lpSockAddr, lpSockAddrLen);
	return TRUE;
}
//
//CString GetProxyError(UINT nError)
//{
//	if (nError == PROXYERROR_NOERROR)
//		return _T("No proxy error");
//	else if (nError == PROXYERROR_NOCONN)
//		return _T("Proxy connection failed");
//	else if (nError == PROXYERROR_REQUESTFAILED)
//		return _T("Proxy request failed");
//	else if (nError == PROXYERROR_AUTHREQUIRED)
//		return _T("Proxy authentication required");
//	else if (nError == PROXYERROR_AUTHTYPEUNKNOWN)
//		return _T("Proxy authentication not supported");
//	else if (nError == PROXYERROR_AUTHFAILED)
//		return _T("Proxy authentication failed");
//	else if (nError == PROXYERROR_AUTHNOLOGON)
//		return _T("Proxy authentication required");
//	else if (nError == PROXYERROR_CANTRESOLVEHOST)
//		return _T("Proxy hostname not resolved");
//	else if (nError == PROXYSTATUS_LISTENSOCKETCREATED)
//		return _T("Proxy listen socket created");
//	else{
//		CString strError;
//		strError.Format(_T("Proxy-Error: %u"), nError);
//		return strError;
//	}
//}

BOOL CAsyncProxySocketLayer::Bind(const SOCKADDR* lpSockAddr, int nSockAddrLen)
{
	if(!BindNext(lpSockAddr, nSockAddrLen))
		return FALSE;

	INT sockType = SOCK_STREAM;
	INT optlen = sizeof(sockType);
	m_pOwnerSocket->GetSockOpt(SO_TYPE, &sockType, &optlen);

	if(sockType != SOCK_DGRAM)
		return TRUE;

	if(m_ProxyData.nProxyType != PROXYTYPE_SOCKS5)
		return TRUE;

	int addrlen = sizeof(m_udpcltAddr);
	if(getsockname(m_pOwnerSocket->GetSocketHandle(), (struct sockaddr FAR *)&m_udpcltAddr, &addrlen))
		return FALSE;

	if(!GetUdpProxyAddr())
		return FALSE;

	return TRUE;
}

void CAsyncProxySocketLayer::SetUdpLocalAddr(const SOCKADDR_IN *pName)
{
	m_udpcltAddr = *pName;
}

void CAsyncProxySocketLayer::GetUdpLocalAddr(SOCKADDR_IN *pName)
{
	*pName = m_udpcltAddr;
}

BOOL CAsyncProxySocketLayer::GetUdpProxyAddr()
{
	if (m_ProxyData.nProxyType == PROXYTYPE_SOCKS5)
	{
		ASSERT(m_pS5UC == NULL);
		m_pS5UC = new CSocks5UdpConn(m_pOwnerSocket, this);
		if (!m_pS5UC)
			return FALSE;
		if (!m_pS5UC->AddLayer(this))
		{
			delete m_pS5UC;
			return FALSE;
		}
		if (!m_securePsk.IsEmpty())
		{
			m_pSecureLayer = new CAsyncSecureSocketLayer;
			if (!m_pSecureLayer ||
				!m_pSecureLayer->Configure(m_securePsk, m_ProxyData.strProxyHost) ||
				!m_pS5UC->AddLayer(m_pSecureLayer))
			{
				delete m_pSecureLayer;
				m_pSecureLayer = NULL;
				delete m_pS5UC;
				m_pS5UC = NULL;
				return FALSE;
			}
		}
		if (!m_pS5UC->Create())
		{
			delete m_pS5UC;
			return FALSE;
		}

		m_nProxyOpID = PROXYOP_UDPASSOCIATE;

		//Connect to proxy server
		BOOL res = ConnectNext(m_ProxyData.strProxyHost, m_ProxyData.nProxyPort);
		if (!res) {
			int nErrorCode = WSAGetLastError();
			if (nErrorCode != WSAEWOULDBLOCK) {
				DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_NOCONN, nErrorCode);
				return FALSE;
			}
		}

		m_nProxyOpID = PROXYOP_UDPASSOCIATE;
		return TRUE;
	}
	else {
		DoLayerCallback(LAYERCALLBACK_LAYERSPECIFIC, PROXYERROR_REQUESTFAILED, 0);
		WSASetLastError(WSAEINVAL);
		return FALSE;
	}
}


/*

����+----+------+------+----------+----------+----------+
����|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |����DATA��|
����+----+------+------+----------+----------+----------+
����|��2 |�� 1��| ��1��| Variable | ��2������| Variable |
����+----+------+------+----------+----------+----------+

	o RSV Reserved X'0000'
	o FRAG Current fragment number
	o ATYP address type of following addresses:
����	o IP V4 address: X'01'
����	o DOMAINNAME: X'03'
����	o IP V6 address: X'04'
	o DST.ADDR desired destination address
	o DST.PORT desired destination port
	o DATA user data
*/
int CAsyncProxySocketLayer::SendTo(const void* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags /* = 0 */)
{
	if (m_nProxyOpID)
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	if (!lpSockAddr ||
		(lpSockAddr->sa_family != AF_INET && lpSockAddr->sa_family != AF_INET6) ||
		nSockAddrLen < (lpSockAddr->sa_family == AF_INET6
			? (int)sizeof(SOCKADDR_IN6) : (int)sizeof(SOCKADDR_IN)))
	{
		WSASetLastError(WSAEAFNOSUPPORT);
		return SOCKET_ERROR;
	}
	const int headerLength = lpSockAddr->sa_family == AF_INET6 ? 22 : 10;
	if (nBufLen < 0 || nBufLen > 65507 - headerLength)
	{
		WSASetLastError(WSAEMSGSIZE);
		return SOCKET_ERROR;
	}

	if(!m_udpBuffer.checkBufferSize(nBufLen+CSocks5UdpCodec::MAX_HEADER_SIZE, false))
	{
		WSASetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return SOCKET_ERROR;
	}

	int packetLength = lpSockAddr->sa_family == AF_INET6
		? CSocks5UdpCodec::EncodeIPv6(m_udpBuffer,
			nBufLen + CSocks5UdpCodec::MAX_HEADER_SIZE,
			reinterpret_cast<const SOCKADDR_IN6 *>(lpSockAddr), lpBuf, nBufLen)
		: CSocks5UdpCodec::EncodeIPv4(m_udpBuffer,
			nBufLen + CSocks5UdpCodec::MAX_HEADER_SIZE,
			reinterpret_cast<const SOCKADDR_IN *>(lpSockAddr), lpBuf, nBufLen);
	if (packetLength == SOCKET_ERROR)
	{
		WSASetLastError(WSAEINVAL);
		return SOCKET_ERROR;
	}

	const BYTE* wirePacket = (LPBYTE)m_udpBuffer;
	int wireLength = packetLength;
	if (m_pSecureLayer)
	{
		if (!m_pSecureLayer->HasUdpKey() ||
			!m_secureUdpBuffer.checkBufferSize(packetLength + 16, false) ||
			m_pSecureLayer->EncryptUdp((LPBYTE)m_udpBuffer, packetLength,
				m_secureUdpBuffer, packetLength + 16, &wireLength) == SOCKET_ERROR)
		{
			WSASetLastError(WSAEPROTONOSUPPORT);
			return SOCKET_ERROR;
		}
		wirePacket = m_secureUdpBuffer;
	}
	int nBytesSent = m_pReal_sendto(m_pOwnerSocket->GetSocketHandle(),
		(const char*)wirePacket, wireLength, nFlags,
		(SOCKADDR*)&m_udpsrvAddr, sizeof(SOCKADDR));
	if(nBytesSent == wireLength)
	{
		nBytesSent = nBufLen;
	}
	return nBytesSent;
}

int CAsyncProxySocketLayer::SendTo(const void* lpBuf, int nBufLen, UINT nHostPort, LPCTSTR lpszHostAddress /* = NULL */, int nFlags /* = 0 */)
{
	if (m_nProxyOpID)
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	CStringA szIP;
	szIP = lpszHostAddress;
	const char* pszAsciiProxyPeerHost;
	int iLenAsciiProxyPeerHost;
	pszAsciiProxyPeerHost = szIP.GetBuffer();
	iLenAsciiProxyPeerHost = (int)strlen(pszAsciiProxyPeerHost);

	if (inet_addr(pszAsciiProxyPeerHost) != INADDR_NONE)
	{
		_SockAddr dstAddr;
		dstAddr.sa_family = AF_INET;
		dstAddr.SetIP(pszAsciiProxyPeerHost);
		dstAddr.SetPort(nHostPort);
		return SendTo(lpBuf, nBufLen, &dstAddr, sizeof(dstAddr));
	}
	if (iLenAsciiProxyPeerHost <= 0 || iLenAsciiProxyPeerHost > 255 ||
		nBufLen < 0 || nBufLen > 65507 - (7 + iLenAsciiProxyPeerHost))
	{
		WSASetLastError(WSAEMSGSIZE);
		return SOCKET_ERROR;
	}

	if(!m_udpBuffer.checkBufferSize(nBufLen+CSocks5UdpCodec::MAX_HEADER_SIZE, false))
	{
		WSASetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return SOCKET_ERROR;
	}


	int packetLength = CSocks5UdpCodec::EncodeDomain(m_udpBuffer,
		nBufLen + CSocks5UdpCodec::MAX_HEADER_SIZE,
		pszAsciiProxyPeerHost, (USHORT)nHostPort, lpBuf, nBufLen);
	if (packetLength == SOCKET_ERROR)
	{
		WSASetLastError(WSAEINVAL);
		return SOCKET_ERROR;
	}
	const BYTE* wirePacket = (LPBYTE)m_udpBuffer;
	int wireLength = packetLength;
	if (m_pSecureLayer)
	{
		if (!m_pSecureLayer->HasUdpKey() ||
			!m_secureUdpBuffer.checkBufferSize(packetLength + 16, false) ||
			m_pSecureLayer->EncryptUdp((LPBYTE)m_udpBuffer, packetLength,
				m_secureUdpBuffer, packetLength + 16, &wireLength) == SOCKET_ERROR)
		{
			WSASetLastError(WSAEPROTONOSUPPORT);
			return SOCKET_ERROR;
		}
		wirePacket = m_secureUdpBuffer;
	}
	int nBytesSent = m_pReal_sendto(m_pOwnerSocket->GetSocketHandle(),
		(const char*)wirePacket, wireLength, nFlags,
		(SOCKADDR*)&m_udpsrvAddr, sizeof(SOCKADDR));
	if(nBytesSent == wireLength)
	{
		nBytesSent = nBufLen;
	}
	return nBytesSent;
}

int CAsyncProxySocketLayer::ReceiveFrom(void* lpBuf, int nBufLen, SOCKADDR* lpSockAddr, int* lpSockAddrLen, int nFlags /* = 0 */)
{
	if (m_nProxyOpID)
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	const int plainCapacity = nBufLen + CSocks5UdpCodec::MAX_HEADER_SIZE;
	const int wireCapacity = plainCapacity + (m_pSecureLayer ? 16 : 0);
	if(!m_udpBuffer.checkBufferSize(plainCapacity, false) ||
		(m_pSecureLayer && !m_secureUdpBuffer.checkBufferSize(wireCapacity, false)))
	{
		WSASetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return SOCKET_ERROR;
	}

	SOCKADDR_IN relayAddress;
	int relayAddressLength = sizeof(relayAddress);
	BYTE* wirePacket = m_pSecureLayer ? (LPBYTE)m_secureUdpBuffer : (LPBYTE)m_udpBuffer;
	int ret = m_pReal_recvfrom(m_pOwnerSocket->GetSocketHandle(),
		(char*)wirePacket, wireCapacity, nFlags,
		(SOCKADDR*)&relayAddress, &relayAddressLength);
	if (ret == SOCKET_ERROR)
		return ret;
	if (relayAddress.sin_family != AF_INET ||
		relayAddress.sin_addr.s_addr != m_udpsrvAddr.sin_addr.s_addr ||
		relayAddress.sin_port != m_udpsrvAddr.sin_port)
	{
		WSASetLastError(WSAEACCES);
		return SOCKET_ERROR;
	}
	if (m_pSecureLayer)
	{
		int plainLength = 0;
		if (!m_pSecureLayer->HasUdpKey() ||
			m_pSecureLayer->DecryptUdp(wirePacket, ret, m_udpBuffer,
				plainCapacity, &plainLength) == SOCKET_ERROR)
		{
			WSASetLastError(WSAEPROTONOSUPPORT);
			return SOCKET_ERROR;
		}
		ret = plainLength;
	}

	CSocks5UdpCodec::DecodedPacket decoded;
	if (!CSocks5UdpCodec::Decode(m_udpBuffer, ret, &decoded))
	{
		WSASetLastError(WSAEPROTONOSUPPORT);
		return SOCKET_ERROR;
	}
	if (decoded.payloadLength > nBufLen)
	{
		WSASetLastError(WSAEMSGSIZE);
		return SOCKET_ERROR;
	}
	if (decoded.payloadLength)
		memcpy(lpBuf, decoded.payload, decoded.payloadLength);
	if (lpSockAddr && lpSockAddrLen)
	{
		if (*lpSockAddrLen < decoded.sourceLength)
		{
			WSASetLastError(WSAEFAULT);
			return SOCKET_ERROR;
		}
		if (decoded.sourceLength == sizeof(decoded.source6))
			memcpy(lpSockAddr, &decoded.source6, decoded.sourceLength);
		else
			memcpy(lpSockAddr, &decoded.source, decoded.sourceLength);
		*lpSockAddrLen = decoded.sourceLength;
	}
	return decoded.payloadLength;
}

//////////////////////////////////////////////////////////////////////////

int CAsyncProxySocketLayer::WSASendTo(
					  LPWSABUF lpBuffers,
					  DWORD dwBufferCount,
					  LPDWORD lpNumberOfBytesSent,
					  const SOCKADDR* lpTo,
					  int iToLen,
					  LPWSAOVERLAPPED lpOverlapped /*= 0*/,
					  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine /*= 0*/,
					  DWORD dwFlag /*= 0*/
					  )
{
	if (m_nProxyOpID)
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	DWORD nBufLenAdded = 0;
	char hdr[10];
	memset(hdr, 0, 10);

	//ATYP
	hdr[3] = 0x01;
	//DST.ADDR
	*(DWORD*)&hdr[4] = ((LPSOCKADDR_IN)lpTo)->sin_addr.S_un.S_addr;
	//DST.PORT
	*(WORD*)&hdr[8] = ((LPSOCKADDR_IN)lpTo)->sin_port;

	WSABUF wsabuf[32];
	DWORD bufidx = 0;

	wsabuf[bufidx].buf = hdr;
	wsabuf[bufidx].len = 10;
	nBufLenAdded += 10;
	bufidx++;

	//
	for(DWORD i=0 ; bufidx<32 && i<dwBufferCount; bufidx++, i++)
	{
		wsabuf[bufidx].buf = lpBuffers[i].buf;
		wsabuf[bufidx].len = lpBuffers[i].len;
	}

	int nRet = WSASendToNext(wsabuf, bufidx, lpNumberOfBytesSent, (SOCKADDR*)&m_udpsrvAddr, sizeof(SOCKADDR), lpOverlapped, lpCompletionRoutine, dwFlag);
	if(nRet == 0)
	{
		if(*lpNumberOfBytesSent >= nBufLenAdded)
			*lpNumberOfBytesSent -= nBufLenAdded;
	}
	return nRet;
}

int CAsyncProxySocketLayer::WSASendTo(
					  LPWSABUF lpBuffers,
					  DWORD dwBufferCount,
					  LPDWORD lpNumberOfBytesSent,
					  UINT nHostPort,
					  LPCTSTR lpszHostAddress /*= NULL*/,
					  LPWSAOVERLAPPED lpOverlapped /*= 0*/,
					  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine /*= 0*/,
					  DWORD dwFlag /*= 0*/
					  )
{
	if (m_nProxyOpID)
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	CStringA szIP;
	szIP = lpszHostAddress;
	const char* pszAsciiProxyPeerHost;
	int iLenAsciiProxyPeerHost;
	pszAsciiProxyPeerHost = szIP.GetBuffer();
	iLenAsciiProxyPeerHost = (int)strlen(pszAsciiProxyPeerHost);

	if (inet_addr(pszAsciiProxyPeerHost) != INADDR_NONE)
	{
		_SockAddr dstAddr;
		dstAddr.sa_family = AF_INET;
		dstAddr.SetIP(pszAsciiProxyPeerHost);
		dstAddr.SetPort(nHostPort);
		return WSASendTo(lpBuffers, dwBufferCount, lpNumberOfBytesSent, (SOCKADDR*)&dstAddr, sizeof(dstAddr), lpOverlapped, lpCompletionRoutine, dwFlag);
	}


	DWORD nBufLenAdded = 0;
	char hdr[0xff+4];
	memset(hdr, 0, 10);

	//ATYP
	hdr[3] = 0x03;
	//DST.ADDR
	int nHdrLen = 4;
	hdr[nHdrLen++] = (char)iLenAsciiProxyPeerHost;
	memcpy(&hdr[nHdrLen], pszAsciiProxyPeerHost, iLenAsciiProxyPeerHost);
	nHdrLen += iLenAsciiProxyPeerHost;
	//DST.PORT
	*(WORD*)&hdr[nHdrLen] = (WORD)htons((u_short)nHostPort);
	nHdrLen += 2;

	WSABUF wsabuf[32];
	DWORD bufidx = 0;

	wsabuf[bufidx].buf = hdr;
	wsabuf[bufidx].len = nHdrLen;
	nBufLenAdded += nHdrLen;
	bufidx++;

	//
	for(DWORD i=0 ; bufidx<32 && i<dwBufferCount; bufidx++, i++)
	{
		wsabuf[bufidx].buf = lpBuffers[i].buf;
		wsabuf[bufidx].len = lpBuffers[i].len;
	}

	int nRet = WSASendToNext(wsabuf, bufidx, lpNumberOfBytesSent, (SOCKADDR*)&m_udpsrvAddr, sizeof(SOCKADDR), lpOverlapped, lpCompletionRoutine, dwFlag);
	if(nRet == 0)
	{
		if(*lpNumberOfBytesSent >= nBufLenAdded)
			*lpNumberOfBytesSent -= nBufLenAdded;
	}
	return nRet;

}

int CAsyncProxySocketLayer::WSARecvFrom(
						LPWSABUF lpBuffers,
						DWORD dwBufferCount,
						LPDWORD lpNumberOfBytesRecvd,
						struct sockaddr* lpFrom,
						LPINT lpFromlen,
						LPWSAOVERLAPPED lpOverlapped /*= 0*/,
						LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine /*= 0*/,
						LPDWORD lpFlags /*= 0*/
						)
{
	if (m_nProxyOpID)
	{
		WSASetLastError(WSAEWOULDBLOCK);
		return SOCKET_ERROR;
	}

	char hdr[10];
	memset(hdr, 0, 10);

	WSABUF wsabuf[32];

	wsabuf[0].buf = hdr;
	wsabuf[0].len = 10;

	int bufidx = 1;
	for(DWORD i=0; bufidx<32 && i<dwBufferCount; i++,bufidx++)
	{
		wsabuf[bufidx].buf = lpBuffers[i].buf;
		wsabuf[bufidx].len = lpBuffers[i].len;
	}

	int nRet = WSARecvFromNext(wsabuf, bufidx, lpNumberOfBytesRecvd, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine,lpFlags);
	if(nRet == 0)
	{
		if(*lpNumberOfBytesRecvd >= 10)
		{
			*lpNumberOfBytesRecvd -= 10;

			memset(lpFrom, 0, sizeof(SOCKADDR));
			((LPSOCKADDR_IN)lpFrom)->sin_family = AF_INET;
			((LPSOCKADDR_IN)lpFrom)->sin_addr.s_addr = *(DWORD*)(hdr+4);
			((LPSOCKADDR_IN)lpFrom)->sin_port = *(WORD*)(hdr+8);

			*lpFromlen = sizeof(SOCKADDR);

			for(DWORD i=0; i<32-1 && i<dwBufferCount; i++)
			{
				lpBuffers[i].buf = wsabuf[i+1].buf;
				lpBuffers[i].len = wsabuf[i+1].len;
			}
		}
	}

	return nRet;
}

int CAsyncProxySocketLayer::OnUDPConnCallback(int nType, int nCode, WPARAM wParam /* = 0 */, LPARAM lParam /* = 0 */)
{
	return DoLayerCallback(nType, nCode, wParam, lParam);
}
