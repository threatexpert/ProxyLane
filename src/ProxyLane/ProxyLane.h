// ProxyLane.h : PROJECT_NAME 应用程序的主头文件
//

#pragma once

#ifndef __AFXWIN_H__
	#error "在包含此文件之前包含“stdafx.h”以生成 PCH 文件"
#endif

#include "resource.h"		// 主符号
#include "AutomationOptions.h"
#include "ProfileCommandBroker.h"


// CProxyLaneApp:
// 有关此类的实现，请参阅 ProxyLane.cpp
//

class CProxyLaneApp : public CWinApp
{
public:
	CProxyLaneApp();
	const AutomationOptions& GetAutomationOptions() const { return m_automationOptions; }
	void SetAutomationExitCode(int exitCode) { m_automationExitCode = exitCode; }
	void SignalAutomationReady();
	BOOL PrepareAutomationCommandReceiver();
	BOOL ActivateProfileCommandServer(LPCTSTR profileName, HWND notifyWindow);
	void DeactivateProfileCommandServer();
	BOOL IsProfileCommandServerActive(LPCTSTR profileName = NULL) const;
	BOOL RequiresProfileCommandOwnership() const { return m_requiresProfileCommandOwnership; }
	void ReleaseAutomationLaunchGate();

// 重写
	public:
	virtual BOOL InitInstance();
	virtual int ExitInstance();

// 实现

	DECLARE_MESSAGE_MAP()

private:
	AutomationOptions m_automationOptions;
	int m_automationExitCode;
	BOOL m_requiresProfileCommandOwnership;
	CProfileCommandBroker m_profileCommandBroker;
};

extern CProxyLaneApp theApp;

class IGlobalProxy;
extern IGlobalProxy* g_GlobalProxy;
