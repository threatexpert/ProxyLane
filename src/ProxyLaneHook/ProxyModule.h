/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/


#pragma once

#include "structinfo.h"

#define CLSID_PROXYMODULE L"{FAB59DC1-C950-4699-9647-085143BCD67C}"

#pragma pack(push, 1)

class IProxyReceptionCentre;
class IProxySettings;
class IProxyLog;
class IProxyTaskMgr;
class IProxyDataHandle;
class IProxyTester;

class IGlobalProxy
{
public:
	virtual ~IGlobalProxy(void){}

	virtual LPCSTR  GetLastErrorA() = 0;
	virtual LPCWSTR GetLastErrorW() = 0;

	virtual IProxyReceptionCentre* GetPRCInstance() = 0;
	virtual IProxySettings* GetSettingsInstance() = 0;
	virtual IProxyLog* GetLogInstance() = 0;

	virtual IProxyTester* CreateTester() = 0;

	virtual BOOL IsProxyEnabled() = 0;
	virtual BOOL EnableProxy() = 0;
	virtual BOOL DisableProxy() = 0;

	virtual INT AddRef() = 0;
	virtual INT Release() = 0;
};

class IProxyReceptionCentre
{
public:
	virtual ~IProxyReceptionCentre(void){}

	//查询PRC通讯的管道名
	virtual BOOL GetPRCPipeName(LPSTR lpBuf, int bufsize) = 0;
	//查询IProxyTaskMgr 实例的指针
	virtual IProxyTaskMgr* GetPTMInstance(int type) = 0;
	//查询IProxyDataHandle 实例的指针
	virtual IProxyDataHandle* GetPDHInstance() = 0;
};

template<typename T>
class IInstanceList
{
public:
	IInstanceList(void)
	{
		m_pNext = NULL;
		m_pPrev = NULL;
	}
	virtual ~IInstanceList(void)
	{
		Detach();
	}

	virtual void AddInstance(T *pInstance)
	{
		if ( m_pNext && (m_pNext != pInstance) )
			m_pNext->AddInstance(pInstance);
		else
		{
			pInstance->m_pPrev = (T*)this;
			m_pNext = pInstance;
		}
	}

	virtual void Detach()
	{
		if (m_pNext)
			m_pNext->m_pPrev = m_pPrev;
		if (m_pPrev)
			m_pPrev->m_pNext = m_pNext;

		m_pPrev = m_pNext = NULL;
	}

	T *m_pPrev;
	T *m_pNext;
};


//////////////////////////////////////////////////////////////////////////
// IProxySettings
// 请继承并重载该类， 假设GetGlobalProxyInstance得到的实例指针为pIGlobalProxy，
// 然后将你的类指针yourPoint 传入 pIGlobalProxy->GetSettingsInstance->AddInstance(yourPoint)
// 
// 之后内部每次需要代理一个网络请求都会触发你的类的GetProxyInfo函数， 这时候你的函数可以根据pPRCC信息有选择的设置一个代理服务器的信息到lpPI
// 
//////////////////////////////////////////////////////////////////////////

class IProxySettings
	: public IInstanceList<IProxySettings>
{
public:
	virtual ~IProxySettings(void){}

	virtual BOOL GetProxySettings(LPProxySettingsInfo lpPSI) = 0;
	virtual BOOL GetProxyInfo(const LPPRCClient pPRCC, LPProxyInfo lpPI) = 0;

};



//////////////////////////////////////////////////////////////////////////
// IProxyLog
//
//////////////////////////////////////////////////////////////////////////

class IProxyLog
	: public IInstanceList<IProxyLog>
{
public:
	virtual ~IProxyLog(void){}

	virtual void LogText(LPCWSTR lpText) = 0;
	virtual void LogNewProxyTask(const LPPRCClient lpC) = 0;
	virtual BOOL OnNewProcess(LPHookNewProcessInfo lphnpi) = 0;
	virtual void OnHookWsock(LPHookWSockResult res) = 0;
	virtual void OnHookLogtext(LPHookLogtext log) = 0;
	// 新增回调放在接口末尾，避免改变既有虚函数在 vtable 中的位置。
	virtual void OnChildInjectionResult(LPHookNewProcessInfo lphnpi, BOOL succeeded) = 0;
};


//////////////////////////////////////////////////////////////////////////
// IProxyTaskMgr
//
//////////////////////////////////////////////////////////////////////////

class IProxyTaskMgr
	: public IInstanceList<IProxyTaskMgr>
{
public:
	virtual ~IProxyTaskMgr(void){}

	virtual void OnAddTask(const LPPRCClient lpC, const LPProxyInfo lpPI) = 0;
	virtual void OnDelTask(const LPPRCClient lpC) = 0;
	virtual void EnumTask(IProxyTaskMgr *pCallBack) = 0;
	virtual void OnEachTask(const LPPRCClient lpC, const LPProxyInfo lpPI) = 0;
	virtual BOOL GetTaskCount(DWORD *pCount) = 0;
};


//////////////////////////////////////////////////////////////////////////
// IProxyDataHandle
//
//////////////////////////////////////////////////////////////////////////

class IProxyDataHandle
	: public IInstanceList<IProxyDataHandle>
{
public:
	virtual ~IProxyDataHandle(void){}

	virtual void OnConnect(LPProxyPacketInfo lpppi) = 0;
	virtual void OnEachPacket(LPProxyPacketInfo lpppi) = 0;
	virtual void OnClose(LPProxyPacketInfo lpppi) = 0;
	virtual void OnLayerCallback(LPProxyPacketInfo lpppi, int nType, int nCode, WPARAM wParam, LPARAM lParam) = 0;
};


//////////////////////////////////////////////////////////////////////////
// IProxyTesterCallback, IProxyTester
//
// pIGlobalProxyForTesting = GetGlobalProxyInstance();
//
// pTester = pIGlobalProxyForTesting->CreateTester; //
//
// pTester->Start(......);
//
// //取消测试或者在你的OnProxyTesterCallback被触发时 释放对象
// pTester->Release();
//
// //每个GetGlobalProxyInstance的调用 对应一个 ReleaseGlobalProxyInstance
// ReleaseGlobalProxyInstance();
//////////////////////////////////////////////////////////////////////////

class IProxyTesterCallback
{
protected:

//HIWORD(nErrorCode);
#define LAYERCALLBACK_STATECHANGE 0
#define LAYERCALLBACK_LAYERSPECIFIC 1

	enum LayerState
	{
		notsock,
		unconnected,
		connecting,
		listening,
		connected,
		closed,
		aborted
	};

#define PROXYERROR_NOERROR			0
#define PROXYERROR_NOCONN			1 //Can't connect to proxy server, use GetLastError for more information
#define PROXYERROR_REQUESTFAILED	2 //Request failed, can't send data
#define PROXYERROR_AUTHREQUIRED		3 //Authentication required
#define PROXYERROR_AUTHTYPEUNKNOWN	4 //Authtype unknown or not supported
#define PROXYERROR_AUTHFAILED		5 //Authentication failed
#define PROXYERROR_AUTHNOLOGON		6
#define PROXYERROR_CANTRESOLVEHOST	7

public:
	virtual ~IProxyTesterCallback(void){}

	//nErrorCode = MAKEWPARAM(nCode, nType)
	virtual void OnProxyTesterCallback(IProxyTester *pTester, int nErrorCode, WPARAM wParam, LPARAM lParam) = 0;
};


class IProxyTester
{
public:
	virtual ~IProxyTester(void){}

	virtual void Release() = 0;
	virtual BOOL Start(IProxyTesterCallback *pCallback, const LPPRCClient lpPRCClient, const LPProxyInfo lpPI) = 0;
	virtual void Stop() = 0;

};


////////////////////////////////////////
// 获得一个IGlobalProxy对象指针。
// 
// 注意：一次GetGlobalProxyInstance的调用对应一次ReleaseGlobalProxyInstance, 内部根据计数来决定是否释放
//
///////////////////////////////////////

IGlobalProxy* WINAPI GetGlobalProxyInstance();
BOOL WINAPI ReleaseGlobalProxyInstance();


////////////////////////////////////////
// 在需要代理的进程调用以下API
//
///////////////////////////////////////


BOOL WINAPI gp_HookWinsock(LPCSTR lpszPRCPipeName);
BOOL WINAPI gp_UnhookWinsock();
DWORD WINAPI AttachToHandles(HANDLE hProcess, HANDLE hThread, LPCSTR szPipeName);
DWORD WINAPI AttachToI(DWORD dwPid, DWORD dwTid, LPCSTR szPipeName);


#pragma pack(pop)
