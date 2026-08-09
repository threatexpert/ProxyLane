/*CAsyncSocketEx by Tim Kosse (Tim.Kosse@gmx.de)
            Version 1.2 (2003-03-28)
--------------------------------------------------------

Introduction:
-------------

CAsyncSocketEx is a replacement for the MFC class CAsyncSocket.
This class was written because CAsyncSocket is not the fastest WinSock
wrapper and it's very hard to add new functionality to CAsyncSocket
derived classes. This class offers the same functionality as CAsyncSocket.
Also, CAsyncSocketEx offers some enhancements which were not possible with
CAsyncSocket without some tricks.

How do I use it?
----------------
Basically exactly like CAsyncSocket.
To use CAsyncSocketEx, just replace all occurrences of CAsyncSocket in your
code with CAsyncSocketEx, if you did not enhance CAsyncSocket yourself in
any way, you won't have to change anything else in your code.

Why is CAsyncSocketEx faster?
-----------------------------

CAsyncSocketEx is slightly faster when dispatching notification event messages.
First have a look at the way CAsyncSocket works. For each thread that uses
CAsyncSocket, a window is created. CAsyncSocket calls WSAAsyncSelect with
the handle of that window. Until here, CAsyncSocketEx works the same way.
But CAsyncSocket uses only one window message (WM_SOCKET_NOTIFY) for all
sockets within one thread. When the window receive WM_SOCKET_NOTIFY, wParam
contains the socket handle and the window looks up an CAsyncSocket instance
using a map. CAsyncSocketEx works differently. It's helper window uses a
wide range of different window messages (WM_USER through 0xBFFF) and passes
a different message to WSAAsyncSelect for each socket. When a message in
the specified range is received, CAsyncSocketEx looks up the pointer to a
CAsyncSocketEx instance in an Array using the index of message - WM_USER.
As you can see, CAsyncSocketEx uses the helper window in a more efficient
way, as it don't have to use the slow maps to lookup it's own instance.
Still, speed increase is not very much, but it may be noticeable when using
a lot of sockets at the same time.
Please note that the changes do not affect the raw data throughput rate,
CAsyncSocketEx only dispatches the notification messages faster.

What else does CAsyncSocketEx offer?
------------------------------------

CAsyncSocketEx offers a flexible layer system. One example is the proxy layer.
Just create an instance of the proxy layer, configure it and add it to the layer
chain of your CAsyncSocketEx instance. After that, you can connect through
proxies.
Benefit: You don't have to change much to use the layer system.
Another layer that is currently in development is the SSL layer to establish
SSL encrypted connections.

License
-------

Feel free to use this class, as long as you don't claim that you wrote it
and this copyright notice stays intact in the source files.
If you use this class in commercial applications, please send a short message
to tim.kosse@gmx.de
*/

#include "stdafx.h"
#include "DebugHelpers.h"
#include "AsyncSocketEx.h"
#include "wtypes.h"
#include "oleauto.h"
#include "atlconv.h"

#ifndef NOLAYERS
#include "AsyncSocketExLayer.h"
#endif //NOLAYERS

//#ifdef _DEBUG
//#define new DEBUG_NEW
//#undef THIS_FILE
//static char THIS_FILE[] = __FILE__;
//#endif

#ifndef CCRITICALSECTIONWRAPPERINCLUDED
class CCriticalSectionWrapper
{
public:
	CCriticalSectionWrapper()
	{
		InitializeCriticalSection(&m_criticalSection);
	}

	~CCriticalSectionWrapper()
	{
		DeleteCriticalSection(&m_criticalSection);
	}

	void Lock()
	{
		EnterCriticalSection(&m_criticalSection);
	}
	void Unlock()
	{
		LeaveCriticalSection(&m_criticalSection);
	}
protected:
	CRITICAL_SECTION m_criticalSection;
};
#define CCRITICALSECTIONWRAPPERINCLUDED
#endif

CCriticalSectionWrapper CAsyncSocketEx::m_sGlobalCriticalSection;
CAsyncSocketEx::t_AsyncSocketExThreadDataList *CAsyncSocketEx::m_spAsyncSocketExThreadDataList = 0;

#ifndef _AFX
#ifndef VERIFY
#define VERIFY(x) (void(x))
#endif //VERIFY
#ifndef ASSERT
#define ASSERT(x)
#endif //ASSERT
#endif //_AFX

/////////////////////////////
//Helper Window class

class CAsyncSocketExHelperWindow
{
public:
	CAsyncSocketExHelperWindow()
	{
		//Initialize data
		m_pAsyncSocketExWindowData = new t_AsyncSocketExWindowData[512]; //Reserve space for 512 active sockets
		memset(m_pAsyncSocketExWindowData, 0, 512*sizeof(t_AsyncSocketExWindowData));
		m_nWindowDataSize = 512;
		m_nSocketCount = 0;
		m_nWindowDataPos = 0;

		//Create window
		WNDCLASSEX wndclass;
		wndclass.cbSize = sizeof wndclass;
		wndclass.style = 0;
		wndclass.lpfnWndProc = WindowProc;
		wndclass.cbClsExtra = 0;
		wndclass.cbWndExtra = 0;
		wndclass.hInstance = GetModuleHandle(0);
		wndclass.hIcon = 0;
		wndclass.hCursor = 0;
		wndclass.hbrBackground = 0;
		wndclass.lpszMenuName = 0;
		wndclass.lpszClassName = _T("CAsyncSocket Helper Window");
		wndclass.hIconSm = 0;
		RegisterClassEx(&wndclass);

		m_hWnd = CreateWindow(_T("CAsyncSocket Helper Window"), _T("CAsyncSocket Helper Window"), 0, 0, 0, 0, 0, 0, 0, 0, GetModuleHandle(0));
		ASSERT( m_hWnd );
		SetWindowLongPtr(m_hWnd, GWLP_USERDATA, (LONG_PTR)this);
	};

	virtual ~CAsyncSocketExHelperWindow()
	{
		//Clean up socket storage
		delete[] m_pAsyncSocketExWindowData;
		m_pAsyncSocketExWindowData = 0;
		m_nWindowDataSize = 0;
		m_nSocketCount = 0;

		//Destroy window
		if (m_hWnd)
		{
			DestroyWindow(m_hWnd);
			m_hWnd = 0;
		}
	}

	//Adds a socket to the list of attached sockets
	BOOL AddSocket(CAsyncSocketEx *pSocket, int &nSocketIndex)
	{
		ASSERT( pSocket );
		if (!m_nWindowDataSize)
		{
			ASSERT( !m_nSocketCount );
			m_nWindowDataSize = 512;
			m_pAsyncSocketExWindowData = new t_AsyncSocketExWindowData[512]; //Reserve space for 512 active sockets
			memset(m_pAsyncSocketExWindowData, 0, 512 * sizeof(t_AsyncSocketExWindowData));
		}

		if (nSocketIndex != -1)
		{
			ASSERT( m_pAsyncSocketExWindowData );
			ASSERT( m_nWindowDataSize>nSocketIndex );
			ASSERT( m_pAsyncSocketExWindowData[nSocketIndex].m_pSocket == pSocket );
			ASSERT( m_nSocketCount );
			return TRUE;
		}

		//Increase socket storage if too small
		if (m_nSocketCount >= m_nWindowDataSize - 10)
		{
			int nOldWindowDataSize = m_nWindowDataSize;
			ASSERT( m_nWindowDataSize < MAX_SOCKETS );
			m_nWindowDataSize += 512;
			if (m_nWindowDataSize > MAX_SOCKETS)
				m_nWindowDataSize = MAX_SOCKETS;

			t_AsyncSocketExWindowData* tmp = m_pAsyncSocketExWindowData;
			m_pAsyncSocketExWindowData = new t_AsyncSocketExWindowData[m_nWindowDataSize];
			memcpy(m_pAsyncSocketExWindowData, tmp, nOldWindowDataSize * sizeof(t_AsyncSocketExWindowData));
			memset(m_pAsyncSocketExWindowData + nOldWindowDataSize, 0, (m_nWindowDataSize - nOldWindowDataSize) * sizeof(t_AsyncSocketExWindowData));
			delete[] tmp;
		}

		//Search for free slot
		for (int i = m_nWindowDataPos; i < m_nWindowDataSize + m_nWindowDataPos; i++)
		{
			if (m_pAsyncSocketExWindowData[i % m_nWindowDataSize].m_pSocket == NULL)
			{
				m_pAsyncSocketExWindowData[i % m_nWindowDataSize].m_pSocket = pSocket;
				nSocketIndex = i % m_nWindowDataSize;
				m_nWindowDataPos = (i + 1) % m_nWindowDataSize;
				m_nSocketCount++;
				return TRUE;
			}
		}

		//No slot found, maybe there are too much sockets!
		return FALSE;
	}

	//Removes a socket from the socket storage
	BOOL RemoveSocket(CAsyncSocketEx *pSocket, int &nSocketIndex)
	{
		UNREFERENCED_PARAMETER(pSocket);
		ASSERT( pSocket );

		if (nSocketIndex == -1)
			return TRUE;

		ASSERT( m_pAsyncSocketExWindowData );
		ASSERT( m_nWindowDataSize > 0 );
		ASSERT( m_nSocketCount > 0 );
		ASSERT( m_pAsyncSocketExWindowData[nSocketIndex].m_pSocket == pSocket );
		m_pAsyncSocketExWindowData[nSocketIndex].m_pSocket = 0;
		nSocketIndex = -1;
		m_nSocketCount--;

		return TRUE;
	}

	BOOL IsSocketValid(int Index, CAsyncSocketEx *pSocket)
	{
		return m_pAsyncSocketExWindowData[Index % m_nWindowDataSize].m_pSocket == pSocket;
	}

	int GetSocketIndex(CAsyncSocketEx *pSocket)
	{
		if(!pSocket)
			return -1;
		int nSocketIndex;
		for (int i = m_nWindowDataPos; i < m_nWindowDataSize + m_nWindowDataPos; i++)
		{
			if (m_pAsyncSocketExWindowData[i % m_nWindowDataSize].m_pSocket == pSocket)
			{
				nSocketIndex = i % m_nWindowDataSize;
				return nSocketIndex;
			}
		}
		return -1;
	}

	//Processes event notifications sent by the sockets or the layers
	static LRESULT CALLBACK WindowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
	{
#if !NO_USE_CLIENT_TCP_CATCH_ALL_HANDLER
		try
		{
#endif//!NO_USE_CLIENT_TCP_CATCH_ALL_HANDLER
			if (message >= WM_SOCKETEX_NOTIFY)
			{
				//Verify parameters
				ASSERT( hWnd );
				CAsyncSocketExHelperWindow *pWnd = (CAsyncSocketExHelperWindow *)GetWindowLongPtr(hWnd, GWLP_USERDATA);
				ASSERT( pWnd );

				if (message < (UINT)(WM_SOCKETEX_NOTIFY + pWnd->m_nWindowDataSize)) //Index is within socket storage
				{
					//Lookup socket and verify if it's valid
					CAsyncSocketEx *pSocket = pWnd->m_pAsyncSocketExWindowData[message - WM_SOCKETEX_NOTIFY].m_pSocket;
					SOCKET hSocket = wParam;
					if (!pSocket)
						return 0;
					if (hSocket == INVALID_SOCKET)
						return 0;
					if (pSocket->m_SocketData.hSocket != hSocket)
						return 0;

					int nEvent = lParam & 0xFFFF;
					int nErrorCode = (int)(lParam >> 16);

					//Dispatch notification
	#ifndef NOLAYERS
					if (!pSocket->m_pFirstLayer)
					{
	#endif //NOLAYERS
						//Dispatch to CAsyncSocketEx instance
						switch (nEvent)
						{
							case FD_READ:
							{
								//DWORD nBytes;
								//if (!pSocket->IOCtl(FIONREAD, &nBytes))
								//	nErrorCode = WSAGetLastError();
								//if (nBytes != 0 || nErrorCode != 0)
									pSocket->OnReceive(nErrorCode);
								break;
							}
							case FD_FORCEREAD: //Forceread does not check if there's data waiting
								pSocket->OnReceive(nErrorCode);
								break;
							case FD_WRITE:
								pSocket->OnSend(nErrorCode);
								break;
							case FD_CONNECT:
								pSocket->OnConnect(nErrorCode);
								break;
							case FD_ACCEPT:
								pSocket->OnAccept(nErrorCode);
								break;
							case FD_CLOSE:
								pSocket->OnClose(nErrorCode);
								break;
						}
					}
	#ifndef NOLAYERS
					else //Dispatch notification to the lowest layer
					{
						if (nEvent == FD_READ)
						{
							//DWORD nBytes;
							//if (!pSocket->IOCtl(FIONREAD, &nBytes))
							//	nErrorCode = WSAGetLastError();
							//if (nBytes != 0 || nErrorCode != 0)
								pSocket->m_pLastLayer->CallEvent(nEvent, nErrorCode);
						}
						else
							pSocket->m_pLastLayer->CallEvent(nEvent, nErrorCode);
					}
				}
	#endif //NOLAYERS
				return 0;
			}
	#ifndef NOLAYERS
			else if (message == WM_SOCKETEX_TRIGGER) //Notification event sent by a layer
			{
				//Verify parameters, lookup socket and notification message
				ASSERT( hWnd );
				CAsyncSocketExHelperWindow *pWnd = (CAsyncSocketExHelperWindow *)GetWindowLongPtr(hWnd, GWLP_USERDATA);
				ASSERT( pWnd );
				CAsyncSocketEx *pSocket = (CAsyncSocketEx *)wParam;
				CAsyncSocketExLayer::t_LayerNotifyMsg *pMsg = (CAsyncSocketExLayer::t_LayerNotifyMsg *)lParam;

				//int nSocketIndex = pWnd->GetSocketIndex(pSocket);

				//if(nSocketIndex == -1)
				//{
				//	delete pMsg;
				//	return 0;
				//}

				if(!pWnd->IsSocketValid(pMsg->nSocketIndex, pSocket))
				{
					delete pMsg;
					return 0;
				}

				if (pSocket->m_SocketData.hSocket == INVALID_SOCKET) {
					delete pMsg;
					return 0;
				}

				int nEvent = pMsg->lEvent & 0xFFFF;
				int nErrorCode = pMsg->lEvent >> 16;

				//Dispatch to layer
				if (pMsg->pLayer)
					pMsg->pLayer->CallEvent(nEvent, nErrorCode);
				else
				{
					//Dispatch to socket class
					switch (nEvent)
					{
						case FD_READ:
							if (pSocket->m_lEvent & FD_READ)
								pSocket->OnReceive(nErrorCode);
							break;
						case FD_FORCEREAD:
							if (pSocket->m_lEvent & FD_FORCEREAD)
								pSocket->OnReceive(nErrorCode);
							break;
						case FD_WRITE:
							if (pSocket->m_lEvent & FD_WRITE)
								pSocket->OnSend(nErrorCode);
							break;
						case FD_CONNECT:
							if (pSocket->m_lEvent & FD_CONNECT)
								pSocket->OnConnect(nErrorCode);
							break;
						case FD_ACCEPT:
							if (pSocket->m_lEvent & FD_ACCEPT)
								pSocket->OnAccept(nErrorCode);
							break;
						case FD_CLOSE:
							if (pSocket->m_lEvent & FD_CLOSE)
								pSocket->OnClose(nErrorCode);
							break;
					}
				}
				delete pMsg;
				return 0;
			}
	#endif //NOLAYERS
			else if (message == WM_SOCKETEX_GETHOST)
			{
				//WSAAsyncGetHostByName reply

				//Verify parameters
				ASSERT( hWnd );
				CAsyncSocketExHelperWindow *pWnd = (CAsyncSocketExHelperWindow *)GetWindowLongPtr(hWnd, GWLP_USERDATA);
				ASSERT( pWnd );

				CAsyncSocketEx *pSocket = NULL;
				int i;
				for (i = 0; i < pWnd->m_nWindowDataSize; i++)
				{
					pSocket = pWnd->m_pAsyncSocketExWindowData[i].m_pSocket;
					if (pSocket && pSocket->m_hAsyncGetHostByNameHandle &&
						pSocket->m_hAsyncGetHostByNameHandle == (HANDLE)wParam)
						break;
				}
				if (i == pWnd->m_nWindowDataSize)
					return 0;

				int nErrorCode = (int)(lParam >> 16);
				if (nErrorCode) {
					pSocket->OnConnect(nErrorCode);
					// Do *NOT* access 'pSocket', it may already have been deleted (CServerConnect)
					//delete[] pSocket->m_pAsyncGetHostByNameBuffer;
					//pSocket->m_pAsyncGetHostByNameBuffer = 0;
					//pSocket->m_hAsyncGetHostByNameHandle = 0;
					return 0;
				}

				SOCKADDR_IN sockAddr = {0};
				sockAddr.sin_family = AF_INET;
				sockAddr.sin_addr.s_addr = ((LPIN_ADDR)((LPHOSTENT)pSocket->m_pAsyncGetHostByNameBuffer)->h_addr)->s_addr;
				sockAddr.sin_port = htons((u_short)pSocket->m_nAsyncGetHostByNamePort);

				if (!pSocket->OnHostNameResolved(&sockAddr)) {
					// Do *NOT* access 'pSocket', it may already have been deleted (CServerConnect)
					//delete[] pSocket->m_pAsyncGetHostByNameBuffer;
					//pSocket->m_pAsyncGetHostByNameBuffer = 0;
					//pSocket->m_hAsyncGetHostByNameHandle = 0;
					return 0;
				}

				BOOL res = pSocket->ConnectRaw((SOCKADDR*)&sockAddr, sizeof(sockAddr));
				delete[] pSocket->m_pAsyncGetHostByNameBuffer;
				pSocket->m_pAsyncGetHostByNameBuffer = 0;
				pSocket->m_hAsyncGetHostByNameHandle = 0;

				if (!res && GetLastError() != WSAEWOULDBLOCK)
					pSocket->OnConnect(GetLastError());

				return 0;
			}
			return DefWindowProc(hWnd, message, wParam, lParam);
#if !NO_USE_CLIENT_TCP_CATCH_ALL_HANDLER
		}
		catch(CException* e){
			TCHAR szError[1024];
			e->GetErrorMessage(szError, _countof(szError));
			const CRuntimeClass* pRuntimeClass = e->GetRuntimeClass();
			LPCSTR pszClassName = (pRuntimeClass) ? pRuntimeClass->m_lpszClassName : NULL;
			if (!pszClassName)
				pszClassName = "CException";
			TRACE(_T("*** Unknown %hs exception in CAsyncSocketExHelperWindow::WindowProc - %s\n"), pszClassName, szError);
			e->Delete();
		}
		catch (...) {
			// TODO: This exception handler should definitively *not* be here. Though we seem to need it to
			// catch some very strange crashs which deal with socket deletion problems in the client's TCP socket.
			TRACE("*** Unknown exception in CAsyncSocketExHelperWindow::WindowProc\n");
			ASSERT(0);
		}
		return 0;
#endif//!NO_USE_CLIENT_TCP_CATCH_ALL_HANDLER
	}

	HWND CAsyncSocketExHelperWindow::GetHwnd()
	{
		return m_hWnd;
	}

private:
	HWND m_hWnd;
	struct t_AsyncSocketExWindowData
	{
		CAsyncSocketEx *m_pSocket;
	} *m_pAsyncSocketExWindowData;
	int m_nWindowDataSize;
	int m_nWindowDataPos;
	int m_nSocketCount;
};

//////////////////////////////////////////////////////////////////////
// Konstruktion/Destruktion
//////////////////////////////////////////////////////////////////////

CAsyncSocketEx::CAsyncSocketEx()
{
	m_SocketData.hSocket = INVALID_SOCKET;
	m_SocketData.nSocketIndex = -1;
	m_pLocalAsyncSocketExThreadData = 0;
#ifndef NOLAYERS
	m_pFirstLayer = 0;
	m_pLastLayer = 0;
#endif //NOLAYERS
	m_pAsyncGetHostByNameBuffer = NULL;
	m_hAsyncGetHostByNameHandle = NULL;
}

CAsyncSocketEx::~CAsyncSocketEx()
{
	Close();
	FreeAsyncSocketExInstance();
}

BOOL CAsyncSocketEx::Create(UINT nSocketPort /*=0*/, int nSocketType /*=SOCK_STREAM*/, 
							long lEvent /*=FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE*/, 
							LPCSTR lpszSocketAddress /*=NULL*/, BOOL bReuseAddr /*=FALSE*/,
							int nAddressFamily /*=AF_INET*/ )
{
	//Close the socket, although this should not happen
	if (GetSocketHandle() != INVALID_SOCKET) {
		ASSERT(0);
		WSASetLastError(WSAEALREADY);
		return FALSE;
	}

	if (!InitAsyncSocketExInstance()) {
		ASSERT(0);
		WSASetLastError(WSANOTINITIALISED);
		return FALSE;
	}

#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->Create(nSocketPort, nSocketType, lEvent,
			lpszSocketAddress, nAddressFamily);
	else
#endif //NOLAYERS
	{
		SOCKET hSocket = socket(nAddressFamily, nSocketType, 0);
		if (hSocket == INVALID_SOCKET)
			return FALSE;
		m_SocketData.hSocket = hSocket;

		AttachHandle(hSocket);
		if (!AsyncSelect(lEvent)) {
			Close();
			return FALSE;
		}
#ifndef NOLAYERS
		if (m_pFirstLayer)
		{
			if (WSAAsyncSelect(m_SocketData.hSocket, GetHelperWindowHandle(), m_SocketData.nSocketIndex + WM_SOCKETEX_NOTIFY, FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE)) {
				Close();
				return FALSE;
			}
		}
#endif //NOLAYERS

		if (bReuseAddr)
		{
			// Has to be done right before binding the socket!
			int iOptVal = 1;
			VERIFY( SetSockOpt(SO_REUSEADDR, &iOptVal, sizeof iOptVal) );
		}

		if (nAddressFamily == AF_INET6)
		{
			SOCKADDR_IN6 local6 = { 0 };
			local6.sin6_family = AF_INET6;
			local6.sin6_port = htons((u_short)nSocketPort);
			if (lpszSocketAddress &&
				InetPtonA(AF_INET6, lpszSocketAddress, &local6.sin6_addr) != 1)
			{
				Close();
				WSASetLastError(WSAEINVAL);
				return FALSE;
			}
			if (!Bind(reinterpret_cast<SOCKADDR *>(&local6), sizeof(local6)))
			{
				Close();
				return FALSE;
			}
		}
		else if (!Bind(nSocketPort, lpszSocketAddress)) {
			Close();
			return FALSE;
		}
	}
	return TRUE;
}

void CAsyncSocketEx::OnReceive(int /*nErrorCode*/)
{
}

void CAsyncSocketEx::OnSend(int /*nErrorCode*/)
{
}

void CAsyncSocketEx::OnConnect(int /*nErrorCode*/)
{
}

void CAsyncSocketEx::OnAccept(int /*nErrorCode*/)
{
}

void CAsyncSocketEx::OnClose(int /*nErrorCode*/)
{
}

BOOL CAsyncSocketEx::OnHostNameResolved(const SOCKADDR_IN * /*pSockAddr*/)
{
	return TRUE;
}

BOOL CAsyncSocketEx::Bind(UINT nSocketPort, LPCSTR lpszSocketAddress)
{
	SOCKADDR_IN sockAddr = {0};
	if (lpszSocketAddress == NULL)
		sockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	else
	{
		sockAddr.sin_addr.s_addr = inet_addr(lpszSocketAddress);
		if (sockAddr.sin_addr.s_addr == INADDR_NONE) {
			WSASetLastError(WSAEINVAL);
			return FALSE;
		}
	}
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port = htons((u_short)nSocketPort);
	return Bind((SOCKADDR*)&sockAddr, sizeof(sockAddr));
}

BOOL CAsyncSocketEx::Bind(const SOCKADDR* lpSockAddr, int nSockAddrLen)
{
	if (!bind(m_SocketData.hSocket, lpSockAddr, nSockAddrLen))
		return TRUE;
	else
		return FALSE;
}

void CAsyncSocketEx::AttachHandle(SOCKET /*hSocket*/)
{
	ASSERT( m_pLocalAsyncSocketExThreadData );
	VERIFY( m_pLocalAsyncSocketExThreadData->m_pHelperWindow->AddSocket(this, m_SocketData.nSocketIndex) );
}

void CAsyncSocketEx::DetachHandle(SOCKET /*hSocket*/)
{
	ASSERT( m_pLocalAsyncSocketExThreadData );
	if (!m_pLocalAsyncSocketExThreadData)
		return;
	
	ASSERT( m_pLocalAsyncSocketExThreadData->m_pHelperWindow );
	if (!m_pLocalAsyncSocketExThreadData->m_pHelperWindow)
		return;
	
	VERIFY( m_pLocalAsyncSocketExThreadData->m_pHelperWindow->RemoveSocket(this, m_SocketData.nSocketIndex) );
}

void CAsyncSocketEx::Close()
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
		m_pFirstLayer->Close();
#endif //NOLAYERS
	if (m_SocketData.hSocket != INVALID_SOCKET)
	{
		VERIFY( closesocket(m_SocketData.hSocket) != SOCKET_ERROR );
		DetachHandle(m_SocketData.hSocket);
		m_SocketData.hSocket = INVALID_SOCKET;
	}
#ifndef NOLAYERS
	RemoveAllLayers();
#endif //NOLAYERS
	delete[] m_pAsyncGetHostByNameBuffer;
	m_pAsyncGetHostByNameBuffer = NULL;
	if (m_hAsyncGetHostByNameHandle) {
		WSACancelAsyncRequest(m_hAsyncGetHostByNameHandle);
		m_hAsyncGetHostByNameHandle = NULL;
	}
}

BOOL CAsyncSocketEx::InitAsyncSocketExInstance()
{
	//Check if already initialized
	if (m_pLocalAsyncSocketExThreadData)
		return TRUE;

	DWORD id = GetCurrentThreadId();
	BOOL bResult = TRUE;
	m_sGlobalCriticalSection.Lock();

	try{
	    //Get thread specific data
	    if (m_spAsyncSocketExThreadDataList)
	    {
		    t_AsyncSocketExThreadDataList *pList = m_spAsyncSocketExThreadDataList;
		    while (pList)
		    {
			    ASSERT( pList->pThreadData );
			    ASSERT( pList->pThreadData->nInstanceCount > 0 );
    
			    if (pList->pThreadData->nThreadId == id)
			    {
				    m_pLocalAsyncSocketExThreadData = pList->pThreadData;
				    m_pLocalAsyncSocketExThreadData->nInstanceCount++;
				    break;
			    }
			    pList = pList->pNext;
		    }
		    //Current thread yet has no sockets
		    if (!pList)
		    {
			    //Initialize data for current thread
			    pList = new t_AsyncSocketExThreadDataList;
			    pList->pNext = m_spAsyncSocketExThreadDataList;
			    m_spAsyncSocketExThreadDataList = pList;
			    m_pLocalAsyncSocketExThreadData = new t_AsyncSocketExThreadData;
			    m_pLocalAsyncSocketExThreadData->nInstanceCount = 1;
			    m_pLocalAsyncSocketExThreadData->nThreadId = id;
			    m_pLocalAsyncSocketExThreadData->m_pHelperWindow = new CAsyncSocketExHelperWindow;
			    m_spAsyncSocketExThreadDataList->pThreadData = m_pLocalAsyncSocketExThreadData;
		    }
	    }
	    else
	    {	//No thread has instances of CAsyncSocketEx; Initialize data
		    m_spAsyncSocketExThreadDataList = new t_AsyncSocketExThreadDataList;
		    m_spAsyncSocketExThreadDataList->pNext = 0;
		    m_pLocalAsyncSocketExThreadData = new t_AsyncSocketExThreadData;
		    m_pLocalAsyncSocketExThreadData->nInstanceCount = 1;
		    m_pLocalAsyncSocketExThreadData->nThreadId = id;
		    m_pLocalAsyncSocketExThreadData->m_pHelperWindow = new CAsyncSocketExHelperWindow;
		    m_spAsyncSocketExThreadDataList->pThreadData = m_pLocalAsyncSocketExThreadData;
	    }
	}
	catch(...){
		TRACE("Unknown exception in CAsyncSocketEx::InitAsyncSocketExInstance()\n");
		ASSERT(0);
		bResult = FALSE;
	}

	m_sGlobalCriticalSection.Unlock();

	return bResult;
}

void CAsyncSocketEx::FreeAsyncSocketExInstance()
{
	//Check if already freed
	if (!m_pLocalAsyncSocketExThreadData)
		return;

	DWORD id = m_pLocalAsyncSocketExThreadData->nThreadId;
	m_sGlobalCriticalSection.Lock();

	try{
	    ASSERT( m_spAsyncSocketExThreadDataList );
	    t_AsyncSocketExThreadDataList *pList = m_spAsyncSocketExThreadDataList;
	    t_AsyncSocketExThreadDataList *pPrev = 0;
    
	    //Search for data for current thread and decrease instance count
	    while (pList)
	    {
		    ASSERT( pList->pThreadData );
		    ASSERT( pList->pThreadData->nInstanceCount > 0 );

    	    if (pList->pThreadData->nThreadId == id)
		    {
			    ASSERT( m_pLocalAsyncSocketExThreadData == pList->pThreadData );
			    m_pLocalAsyncSocketExThreadData->nInstanceCount--;
    
			    //Freeing last instance?
			    //If so, destroy helper window
			    if (!m_pLocalAsyncSocketExThreadData->nInstanceCount)
			    {
				    delete m_pLocalAsyncSocketExThreadData->m_pHelperWindow;
				    delete m_pLocalAsyncSocketExThreadData;
				    if (pPrev)
					    pPrev->pNext = pList->pNext;
				    else
					    m_spAsyncSocketExThreadDataList = pList->pNext;
				    delete pList;
				    break;
			    }
   			    break;
		    }
		    pPrev = pList;
		    pList = pList->pNext;
		    ASSERT( pList );
	    }
	}
	catch(...){
		TRACE("Unknown exception in CAsyncSocketEx::FreeAsyncSocketExInstance()\n");
		ASSERT(0);
	}

	m_sGlobalCriticalSection.Unlock();
}

int CAsyncSocketEx::Receive(void* lpBuf, int nBufLen, int nFlags /*=0*/)
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->Receive(lpBuf, nBufLen, nFlags);
	else
#endif //NOLAYERS
		return recv(m_SocketData.hSocket, (LPSTR)lpBuf, nBufLen, nFlags);
}

int CAsyncSocketEx::Send(const void* lpBuf, int nBufLen, int nFlags /*=0*/)
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->Send(lpBuf, nBufLen, nFlags);
	else
#endif //NOLAYERS
		return send(m_SocketData.hSocket, (LPSTR)lpBuf, nBufLen, nFlags);
}

BOOL CAsyncSocketEx::ConnectRaw(const SOCKADDR* lpSockAddr, int nSockAddrLen)
{
	return connect(m_SocketData.hSocket, (SOCKADDR*)lpSockAddr, nSockAddrLen) != SOCKET_ERROR;
}

BOOL CAsyncSocketEx::ConnectRawByName(LPCSTR lpszHostAddress, UINT nHostPort)
{
	SOCKADDR_IN sockAddr = { 0 };
	sockAddr.sin_addr.s_addr = inet_addr(lpszHostAddress);
	if (sockAddr.sin_addr.s_addr == INADDR_NONE)
	{
		m_pAsyncGetHostByNameBuffer = new char[MAXGETHOSTSTRUCT];
		m_nAsyncGetHostByNamePort = nHostPort;
		m_hAsyncGetHostByNameHandle = WSAAsyncGetHostByName(GetHelperWindowHandle(), WM_SOCKETEX_GETHOST, lpszHostAddress, m_pAsyncGetHostByNameBuffer, MAXGETHOSTSTRUCT);
		if (!m_hAsyncGetHostByNameHandle)
			return FALSE;
		WSASetLastError(WSAEWOULDBLOCK);
		return TRUE;
	}
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port = htons((u_short)nHostPort);
	return ConnectRaw((SOCKADDR*)&sockAddr, sizeof(sockAddr));
}

BOOL CAsyncSocketEx::Connect(LPCSTR lpszHostAddress, UINT nHostPort)
{
	ASSERT( lpszHostAddress != NULL );

#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->Connect(lpszHostAddress, nHostPort);
	else
#endif //NOLAYERS
	{
		return ConnectRawByName(lpszHostAddress, nHostPort);
	}
}

BOOL CAsyncSocketEx::Connect(const SOCKADDR* lpSockAddr, int nSockAddrLen)
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->Connect(lpSockAddr, nSockAddrLen);
	else
#endif //NOLAYERS
		return connect(m_SocketData.hSocket, lpSockAddr, nSockAddrLen) != SOCKET_ERROR;
}

#ifdef _AFX
BOOL CAsyncSocketEx::GetPeerName(CString& rPeerAddress, UINT& rPeerPort)
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->GetPeerName(rPeerAddress, rPeerPort);
#endif NOLAYERS

	SOCKADDR_IN sockAddr = {0};
	int nSockAddrLen = sizeof(sockAddr);
	BOOL bResult = GetPeerName((SOCKADDR*)&sockAddr, &nSockAddrLen);
	if (bResult)
	{
		rPeerPort = ntohs(sockAddr.sin_port);
		rPeerAddress = inet_ntoa(sockAddr.sin_addr);
	}
	return bResult;
}
#endif //AFX

BOOL CAsyncSocketEx::GetPeerName(SOCKADDR* lpSockAddr, int* lpSockAddrLen)
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->GetPeerName(lpSockAddr, lpSockAddrLen);
#endif //NOLAYERS

	if (!getpeername(m_SocketData.hSocket, lpSockAddr, lpSockAddrLen))
		return TRUE;
	else
		return FALSE;
}

#ifdef _AFX
BOOL CAsyncSocketEx::GetSockName(CString& rSocketAddress, UINT& rSocketPort)
{
	SOCKADDR_IN sockAddr = {0};
	int nSockAddrLen = sizeof(sockAddr);
	BOOL bResult = GetSockName((SOCKADDR*)&sockAddr, &nSockAddrLen);
	if (bResult)
	{
		rSocketPort = ntohs(sockAddr.sin_port);
		rSocketAddress = inet_ntoa(sockAddr.sin_addr);
	}
	return bResult;
}
#endif

BOOL CAsyncSocketEx::GetSockName(SOCKADDR* lpSockAddr, int* lpSockAddrLen)
{
	if (!getsockname(m_SocketData.hSocket, lpSockAddr, lpSockAddrLen))
		return TRUE;
	else
		return FALSE;
}

BOOL CAsyncSocketEx::ShutDown(int nHow /*=sends*/)
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
	{
		return m_pFirstLayer->ShutDown();
	}
	else
#endif
	{
		if (!shutdown(m_SocketData.hSocket, nHow))
			return TRUE;
		else
			return FALSE;
	}
}

SOCKET CAsyncSocketEx::Detach()
{
	SOCKET socket = m_SocketData.hSocket;
	DetachHandle(socket);
	m_SocketData.hSocket = INVALID_SOCKET;
	return socket;
}

BOOL CAsyncSocketEx::Attach(SOCKET hSocket, long lEvent /*= FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE*/)
{
	if (hSocket == INVALID_SOCKET || !hSocket)
		return FALSE;
	VERIFY( InitAsyncSocketExInstance() );
	m_SocketData.hSocket = hSocket;
	AttachHandle(hSocket);
	return AsyncSelect(lEvent);
}

BOOL CAsyncSocketEx::AsyncSelect(long lEvent /*= FD_READ | FD_WRITE | FD_OOB | FD_ACCEPT | FD_CONNECT | FD_CLOSE*/)
{
	ASSERT( m_pLocalAsyncSocketExThreadData );
	m_lEvent = lEvent;
#ifndef NOLAYERS
	if (!m_pFirstLayer)
#endif //NOLAYERS
	{
		if (!WSAAsyncSelect(m_SocketData.hSocket, GetHelperWindowHandle(), m_SocketData.nSocketIndex + WM_SOCKETEX_NOTIFY, lEvent))
			return TRUE;
		else
			return FALSE;
	}
	return TRUE;
}

BOOL CAsyncSocketEx::Listen(int nConnectionBacklog /*=5*/)
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->Listen(nConnectionBacklog);
#endif //NOLAYERS

	if (!listen(m_SocketData.hSocket, nConnectionBacklog))
		return TRUE;
	else
		return FALSE;
}

BOOL CAsyncSocketEx::Accept(CAsyncSocketEx& rConnectedSocket, SOCKADDR* lpSockAddr /*=NULL*/, int* lpSockAddrLen /*=NULL*/)
{
	ASSERT( rConnectedSocket.m_SocketData.hSocket == INVALID_SOCKET );
#ifndef NOLAYERS
	if (m_pFirstLayer)
	{
		return m_pFirstLayer->Accept(rConnectedSocket, lpSockAddr, lpSockAddrLen);
	}
	else
#endif //NOLAYERS
	{
		SOCKET hTemp = accept(m_SocketData.hSocket, lpSockAddr, lpSockAddrLen);
		if (hTemp == INVALID_SOCKET)
			return FALSE;
		VERIFY(rConnectedSocket.InitAsyncSocketExInstance());
		rConnectedSocket.m_SocketData.hSocket = hTemp;
		rConnectedSocket.AttachHandle(hTemp);
	}
	return TRUE;
}

BOOL CAsyncSocketEx::IOCtl(long lCommand, DWORD* lpArgument)
{
	return ioctlsocket(m_SocketData.hSocket, lCommand, lpArgument) != SOCKET_ERROR;
}

int CAsyncSocketEx::GetLastError()
{
	return WSAGetLastError();
}

BOOL CAsyncSocketEx::TriggerEvent(long lEvent, int nErrorCode/* =0 */)
{
	if (m_SocketData.hSocket == INVALID_SOCKET)
		return FALSE;

	ASSERT( m_pLocalAsyncSocketExThreadData );
	ASSERT( m_pLocalAsyncSocketExThreadData->m_pHelperWindow );
	ASSERT( m_SocketData.nSocketIndex != -1 );

#ifndef NOLAYERS
	if (m_pFirstLayer)
	{
		CAsyncSocketExLayer::t_LayerNotifyMsg *pMsg = new CAsyncSocketExLayer::t_LayerNotifyMsg;
		pMsg->nSocketIndex = m_SocketData.nSocketIndex;
		pMsg->lEvent = MAKELONG(lEvent, nErrorCode);
		pMsg->pLayer = 0;
		BOOL res = PostMessage(GetHelperWindowHandle(), WM_SOCKETEX_TRIGGER, (WPARAM)this, (LPARAM)pMsg);
		if (!res)
			delete pMsg;
		return res;
	}
	else
#endif //NOLAYERS
		return PostMessage(GetHelperWindowHandle(), m_SocketData.nSocketIndex + WM_SOCKETEX_NOTIFY, m_SocketData.hSocket, lEvent & 0xFFFF);
}

SOCKET CAsyncSocketEx::GetSocketHandle()
{
	return m_SocketData.hSocket;
}

HWND CAsyncSocketEx::GetHelperWindowHandle()
{
	if (!m_pLocalAsyncSocketExThreadData)
		return 0;
	if (!m_pLocalAsyncSocketExThreadData->m_pHelperWindow)
		return 0;
	return m_pLocalAsyncSocketExThreadData->m_pHelperWindow->GetHwnd();
}

#ifndef NOLAYERS
BOOL CAsyncSocketEx::AddLayer(CAsyncSocketExLayer *pLayer)
{
	ASSERT( pLayer );
	if (m_SocketData.hSocket != INVALID_SOCKET)
		return FALSE;
	if (m_pFirstLayer)
	{
		ASSERT( m_pLastLayer );
		m_pLastLayer = m_pLastLayer->AddLayer(pLayer, this);
		return m_pLastLayer ? TRUE : FALSE;
	}
	else
	{
		ASSERT( !m_pLastLayer );
		pLayer->Init(0, this);
		m_pFirstLayer = pLayer;
		m_pLastLayer = m_pFirstLayer;
	}
	return TRUE;
}

void CAsyncSocketEx::RemoveAllLayers()
{
	m_pFirstLayer = 0;
	m_pLastLayer = 0;
}

int CAsyncSocketEx::OnLayerCallback(const CAsyncSocketExLayer *pLayer, int /*nType*/, int /*nCode*/, WPARAM /*wParam*/, LPARAM /*lParam*/)
{
	UNREFERENCED_PARAMETER(pLayer);
	ASSERT(pLayer);
	return 1;
}
#endif //NOLAYERS

BOOL CAsyncSocketEx::GetSockOpt(int nOptionName, void* lpOptionValue, int* lpOptionLen, int nLevel /*=SOL_SOCKET*/)
{
	return getsockopt(m_SocketData.hSocket, nLevel, nOptionName, (LPSTR)lpOptionValue, lpOptionLen) != SOCKET_ERROR;
}

BOOL CAsyncSocketEx::SetSockOpt(int nOptionName, const void* lpOptionValue, int nOptionLen, int nLevel /*=SOL_SOCKET*/)
{
	return setsockopt(m_SocketData.hSocket, nLevel, nOptionName, (LPSTR)lpOptionValue, nOptionLen) != SOCKET_ERROR;
}
//
//#ifdef _DEBUG
//void CAsyncSocketEx::AssertValid() const
//{
//	//CObject::AssertValid();
//
//	(void)m_SocketData;
//	(void)m_lEvent;
//	(void)m_pAsyncGetHostByNameBuffer;
//	(void)m_hAsyncGetHostByNameHandle;
//	(void)m_nAsyncGetHostByNamePort;
//
//	//Pointer to the data of the local thread
////	struct t_AsyncSocketExThreadData
////	{
////		CAsyncSocketExHelperWindow *m_pHelperWindow;
////		int nInstanceCount;
////		DWORD nThreadId;
////	} *m_pLocalAsyncSocketExThreadData;
//
//	//List of the data structures for all threads
////	static struct t_AsyncSocketExThreadDataList
////	{
////		t_AsyncSocketExThreadDataList *pNext;
////		t_AsyncSocketExThreadData *pThreadData;
////	} *m_spAsyncSocketExThreadDataList;
//
//#ifndef NOLAYERS
//	CHECK_PTR(m_pFirstLayer);
//	CHECK_PTR(m_pLastLayer);
//#endif //NOLAYERS
//}
//#endif
//
//#ifdef _DEBUG
//void CAsyncSocketEx::Dump(CDumpContext& dc) const
//{
//	CObject::Dump(dc);
//}
//#endif

int CAsyncSocketEx::SendTo(const void* lpBuf, int nBufLen, const SOCKADDR* lpSockAddr, int nSockAddrLen, int nFlags /* = 0 */)
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->SendTo(lpBuf, nBufLen, lpSockAddr, nSockAddrLen, nFlags);
	else
#endif //NOLAYERS
		return sendto(m_SocketData.hSocket, (LPSTR)lpBuf, nBufLen, nFlags, lpSockAddr, nSockAddrLen);
}

int CAsyncSocketEx::SendTo(const void* lpBuf, int nBufLen, UINT nHostPort, LPCTSTR lpszHostAddress /* = NULL */, int nFlags /* = 0 */)
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->SendTo(lpBuf, nBufLen, nHostPort, lpszHostAddress, nFlags);
	else
#endif //NOLAYERS
	{
		SOCKADDR_IN sockAddr;

		memset(&sockAddr,0,sizeof(sockAddr));

		CStringA szAscii;
		LPSTR lpszAscii;
		if (lpszHostAddress != NULL)
		{
			szAscii = lpszHostAddress;
			lpszAscii = szAscii.GetBuffer();
			if (lpszAscii == NULL)
			{
				// OUT OF MEMORY
				WSASetLastError(ERROR_NOT_ENOUGH_MEMORY);
				return FALSE;
			}	
		}
		else
		{
			lpszAscii = NULL;
		}

		sockAddr.sin_family = AF_INET;

		if (lpszAscii == NULL)
			sockAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
		else
		{
			sockAddr.sin_addr.s_addr = inet_addr(lpszAscii);
			if (sockAddr.sin_addr.s_addr == INADDR_NONE)
			{
				LPHOSTENT lphost;
				lphost = gethostbyname(lpszAscii);
				if (lphost != NULL)
					sockAddr.sin_addr.s_addr = ((LPIN_ADDR)lphost->h_addr)->s_addr;
				else
				{
					WSASetLastError(WSAEINVAL);
					return SOCKET_ERROR;
				}
			}
		}

		sockAddr.sin_port = htons((u_short)nHostPort);

		return SendTo(lpBuf, nBufLen, (SOCKADDR*)&sockAddr, sizeof(sockAddr), nFlags);
	}
}

int CAsyncSocketEx::ReceiveFrom(void* lpBuf, int nBufLen, SOCKADDR* lpSockAddr, int* lpSockAddrLen, int nFlags /* = 0 */)
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->ReceiveFrom(lpBuf, nBufLen, lpSockAddr, lpSockAddrLen, nFlags);
	else
#endif //NOLAYERS
		return recvfrom(m_SocketData.hSocket, (LPSTR)lpBuf, nBufLen, nFlags, lpSockAddr, lpSockAddrLen);
}

int CAsyncSocketEx::WSASendTo(LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, const struct sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped /* = 0 */, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine /* = 0 */, DWORD dwFlag /* = 0  */)
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->WSASendTo(lpBuffers, dwBufferCount, lpNumberOfBytesSent, lpTo, iToLen, lpOverlapped, lpCompletionRoutine, dwFlag);
	else
#endif //NOLAYERS
		return ::WSASendTo(m_SocketData.hSocket, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlag, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
}

int CAsyncSocketEx::WSARecvFrom(LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped /* = 0 */, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine /* = 0 */, LPDWORD lpFlags /* = 0  */)
{
#ifndef NOLAYERS
	if (m_pFirstLayer)
		return m_pFirstLayer->WSARecvFrom(lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine, lpFlags);
	else
#endif //NOLAYERS
		return ::WSARecvFrom(m_SocketData.hSocket, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);

}
