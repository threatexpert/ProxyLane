/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/


#pragma once
#include "ProxyTestProgress.h"

#include "structinfo.h"
#include <vector>

// A strict chain of upstream proxies, first hop first: [0] is the server the
// socket connects to and the ProxyInfo every other component still sees. The
// host and this DLL link separate C runtimes, so each keeps its own copy and
// the interfaces pass plain ProxyInfo arrays. No hop limit.
typedef std::vector<ProxyInfo> ProxyChain;

#define CLSID_PROXYMODULE L"{FAB59DC1-C950-4699-9647-085143BCD67C}"

#pragma pack(push, 1)

class IProxyReceptionCentre;
class IProxySettings;
class IProxyLog;
class IProxyTaskMgr;
class IProxyDataHandle;
class IProxyTester;
class IProxyTlsControl;
class IProxyMonitor;

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

	// Append only: preserve existing virtual slots. Borrowed services live for
	// the loaded module lifetime, including proxy stop/start and async CA jobs.
	// Do not delete/release them. New callers need the matching Hook DLL.
	virtual IProxyTlsControl* GetTlsControl() = 0;
	virtual IProxyMonitor* GetMonitorInstance() = 0;
	virtual IProxyProcessRegistry* GetProcessRegistry() = 0;
};

class IProxyTlsControl
{
public:
	enum CaAction { QueryCA, InitializeCA, TrustCA, RemoveCATrust, PrepareCA };
	// UTF-8 output; negative on failure, otherwise flags: 1 initialized, 2 trusted.
	// PrepareCA checks trust and prepares the local CRL listener.
	virtual int ManageCA(CaAction action, char* output, size_t capacity) = 0;
	virtual BOOL SetEnabled(BOOL enabled, char* error, size_t capacity) = 0;
	virtual BOOL IsEnabled() = 0;
	// Protocol reconstruction/cache, gated by monitor_start/monitor_stop. UTF-8
	// JSON request/reply. Consumer thread only: may wait for analysis/disk work.
	// Returns required capacity INCLUDING NUL (undersized buffer untouched),
	// or -1 with error text. Non-destructive polls use a sequence cursor.
	virtual int QueryProtocol(const char* request, char* output, size_t capacity) = 0;
protected:
	virtual ~IProxyTlsControl() {}
};

struct ProxyMonitorEvent
{
	ULONGLONG connection;
	PRCClient client;
	DWORD kind; // 0 TLS error (UTF-8), 1/2 plaintext request/response, 3/4 non-decrypted data, 5 connection status
	DWORD length;
	BYTE data[8192];
};

class IProxyMonitor
{
public:
	// One consumer per host; producers belong to the forwarding core.
	// Disabling clears pending events; Poll copies into caller-owned storage.
	virtual void SetEnabled(BOOL enabled) = 0;
	virtual BOOL Poll(ProxyMonitorEvent* event) = 0;
	virtual DWORD TakeDroppedCount() = 0;
	virtual void Clear() = 0;
protected:
	virtual ~IProxyMonitor() {}
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
	// Query the final Winsock Hook result for one exact process lifetime.
	virtual BOOL GetProcessHookState(
		DWORD processId,
		ULONGLONG processCreateTime,
		DWORD *hookState,
		DWORD *hookError) = 0;
	// Must succeed before injection; ordinary processes need no extra grant.
	virtual BOOL AuthorizeProcessPipeAccess(HANDLE targetProcess) = 0;
	// Successfully forwarded application payload, excluding direct routes and
	// proxy/TLS framing. Appended to preserve existing virtual method slots.
	virtual void GetTrafficTotals(ULONGLONG& upload, ULONGLONG& download) = 0;
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

	// Append only. The number of hops when this connection goes through a chain
	// of two or more proxies, 0 for a single upstream. The hops are copied to
	// lpHops only when nCapacity holds them all; otherwise call again with room
	// for the returned count. hops[0] matches GetProxyInfo.
	virtual INT GetProxyChain(const LPPRCClient pPRCC, LPProxyInfo lpHops, INT nCapacity)
	{
		UNREFERENCED_PARAMETER(pPRCC);
		UNREFERENCED_PARAMETER(lpHops);
		UNREFERENCED_PARAMETER(nCapacity);
		return 0;
	}
};



//////////////////////////////////////////////////////////////////////////
// IProxyLog
//
//////////////////////////////////////////////////////////////////////////

class IProxyLog
	: public IInstanceList<IProxyLog>
{
public:
	enum ConnectionEvent
	{
		ROUTE_PROXY,
		ROUTE_DIRECT,
		ROUTE_BLOCKED,
		TASK_FAILED,
		SETTINGS_FAILED,
		IPV6_BLOCKED,
		UDP_BLOCKED
	};
	enum ConnectionStage
	{
		STAGE_ALLOCATE,
		STAGE_TRANSPORT,
		STAGE_SOCKET,
		STAGE_CONNECT,
		STAGE_ATTACH,
		STAGE_IPV6_ROUTE
	};
	virtual ~IProxyLog(void){}

	virtual void LogText(LPCWSTR lpText) = 0;
	virtual void LogNewProxyTask(const LPPRCClient lpC) = 0;
	virtual BOOL ShouldInjectNewProcess(LPHookNewProcessInfo lphnpi) = 0;
	virtual void OnHookWsock(LPHookWSockResult res) = 0;
	virtual void OnHookLogtext(LPHookLogtext log) = 0;
	// 新增回调放在接口末尾，避免改变既有虚函数在 vtable 中的位置。
	virtual void OnChildInjectionResult(LPHookNewProcessInfo lphnpi, BOOL succeeded) = 0;
	// Routing decisions are distinct from successful connection handshakes.
	// The receiver must copy borrowed strings/client data before returning.
	virtual void OnConnectionEvent(ConnectionEvent event, const LPPRCClient client,
		LPCWSTR processName) {}
	virtual void OnConnectionFailure(const LPPRCClient client, LPCWSTR processName,
		ConnectionStage stage, DWORD error)
	{
		OnConnectionEvent(TASK_FAILED, client, processName);
	}
	// Optional GUI host capabilities; non-GUI/older hosts do not advertise them.
	virtual BOOL GetAppLauncherHostInfo(AppLauncherHostInfo*) { return FALSE; }
	virtual BOOL LaunchAppFromShell(const AppLauncherRequest&, AppLauncherResult&) { return FALSE; }
	// Strings are borrowed for the duration of this callback, as above.
	virtual void OnProxyFailure(const LPPRCClient client, LPCWSTR processName,
		LPCWSTR target, BOOL connectingProxy, DWORD error, LPCWSTR detail)
	{
		OnConnectionFailure(client, processName, STAGE_CONNECT, error);
	}
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
    // Snapshot only this manager's existing tasks; commit is consumed by its network-thread timer.
    virtual DWORD PrepareReconnect(BOOL decrypt) { return 0; }
    virtual void CompleteReconnect(BOOL disconnect) {}
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
#define PROXYERROR_SECURE_UNAVAILABLE	20
#define PROXYERROR_SECURE_HANDSHAKE	21
#define PROXYERROR_UDP_UNSUPPORTED	22
#define PROXYERROR_UDP_RELAY_FAILED	23
#define PROXYERROR_SSH_UNAVAILABLE 24
#define PROXYERROR_SSH_HOSTKEY_UNKNOWN 25
#define PROXYERROR_SSH_HOSTKEY_CHANGED 26
#define PROXYERROR_SSH_KEY_AUTHFAILED 27
#define PROXYERROR_SSH_KEY_FILE 28
#define PROXYERROR_DOH_FAILED 29

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

	// Append only. Tests a TCP connection through nHops (two or more) proxies
	// in order; the tester keeps its own copy of the hops.
	virtual BOOL StartChain(IProxyTesterCallback *pCallback, const LPPRCClient lpPRCClient,
		const ProxyInfo *lpHops, INT nHops) = 0;
	// Index into the chain of the hop a failure belongs to, or -1.
	virtual int GetFailedHop() = 0;
};


////////////////////////////////////////
// 获得一个IGlobalProxy对象指针。
// 
// 注意：一次GetGlobalProxyInstance的调用对应一次ReleaseGlobalProxyInstance, 内部根据计数来决定是否释放
//
///////////////////////////////////////

IGlobalProxy* WINAPI GetGlobalProxyInstance();
BOOL WINAPI ReleaseGlobalProxyInstance();
// Internal child-guard state generated when the DLL first creates the global
// proxy instance.  It remains stable across proxy stop/start cycles.
BOOL GetProxyLaneChildGuardInfo(
	LPWSTR variableName,
	DWORD variableNameCount,
	ULONGLONG *generationTime);


////////////////////////////////////////
// 在需要代理的进程调用以下API
//
///////////////////////////////////////


BOOL WINAPI gp_HookWinsock(LPCSTR lpszPRCPipeName);
// Explicit removal only: caller must prevent new affected calls and ensure no
// hook/trampoline/Bypass_* or cached extension callback is in flight. No draining
// or thread suspension is performed. Failure retains installed state; success
// restores entry points and releases hook state, but the DLL stays pinned.
BOOL WINAPI gp_UnhookWinsock();
DWORD WINAPI AttachToHandles(HANDLE hProcess, HANDLE hThread, LPCSTR szPipeName);
DWORD WINAPI AttachToI(DWORD dwPid, DWORD dwTid, LPCSTR szPipeName);


#pragma pack(pop)
