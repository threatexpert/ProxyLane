#pragma once

#include "structinfo.h"
#include "TcpProxyTask.h"
#include "UdpProxyTask.h"
#include "TimerQueue.h"
#include "TSSTL.h"
#include "ProxyModule.h"

using namespace std;

class CProxyReceptionCentre;

class CProxyXTaskMgr
	: public IProxyTaskMgr
{
public:
	CProxyXTaskMgr(CProxyReceptionCentre *pPRC);
	~CProxyXTaskMgr(void);

	//重载IProxyTaskMgr
	virtual void OnAddTask(const LPPRCClient lpC, const LPProxyInfo lpPI);
	virtual void OnDelTask(const LPPRCClient lpC);
	virtual void EnumTask(IProxyTaskMgr *pCallBack);
	virtual void OnEachTask(const LPPRCClient lpC, const LPProxyInfo lpPI);
	virtual BOOL GetTaskCount(DWORD *pCount);
	//

	BOOL TestTaskByPid(DWORD dwPid, ULONGLONG processCreateTime);

public:
	CProxyReceptionCentre *m_pPRC;
};

class CProxyTCPTaskMgr
	: public CProxyXTaskMgr
	, public CWndTimer
{
public:
	CProxyTCPTaskMgr(CProxyReceptionCentre *pPRC);
	~CProxyTCPTaskMgr(void);


	BOOL OnNewTask(SOCKET sClient, LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo);
	BOOL OnDeleteTask(CTcpProxyTask *pTask);
	VOID OnTimer(UINT_PTR nIDEvent);

	VOID RemoveAllTasks();

	void EnumTask(IProxyTaskMgr *pCallBack);
	virtual BOOL GetTaskCount(DWORD *pCount);

private:
	CTSList<CTcpProxyTask*> m_tasklist;

};

//////////////////////////////////////////////////////////////////////////

class CProxyUDPTaskMgr
	: public CProxyXTaskMgr
	, public CWndTimer
{
public:
	CProxyUDPTaskMgr(CProxyReceptionCentre *pPRC);
	~CProxyUDPTaskMgr(void);


	BOOL OnNewTask(LPPRCClient lpPRCClient, LPProxyInfo lpProxyInfo);
	BOOL OnDeleteTask(CUdpProxyTask *pTask);
	VOID OnTimer(UINT_PTR nIDEvent);

	INT  KillTasks(LPPRCClient lpPRCClient);
	VOID RemoveAllTasks();
	VOID RemoveTask(CUdpProxyTask* pTask);

	void EnumTask(IProxyTaskMgr *pCallBack);
	virtual BOOL GetTaskCount(DWORD *pCount);

	BOOL GetUDPPortState(UDPLocalProxyAddrInfo *pLPAI);
	BOOL CanStartUdpAssociation(LPProxyInfo lpProxyInfo);
	BOOL ReportUdpAssociationFailure(LPProxyInfo lpProxyInfo, int errorCode);
	VOID ReportUdpAssociationReady(LPProxyInfo lpProxyInfo);
	BOOL IsUdpPermanentlyUnsupported() const;

private:
	VOID EnsureUdpCapabilityProfile(LPProxyInfo lpProxyInfo);
	VOID FlushUdpCapabilitySummary();
	VOID RegisterRoutePort(const LPPRCClient lpPRCClient);
	VOID ClearTaskPortStates(CUdpProxyTask *pTask);
	CTSList<CUdpProxyTask*> m_tasklist;


	UDPLocalProxyAddrInfo m_PortState[0x10000];
	CStringA m_udpCapabilityKey;
	UdpAssociationPolicy::CapabilityCircuit m_udpCapability;

};
