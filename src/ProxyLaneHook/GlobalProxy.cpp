/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/


#include "stdafx.h"
#include "GlobalProxy.h"
#include "ProxyReceptionCentre.h"
#include "ProxySettings.h"
#include "ProxyLog.h"
#include "ProxyTesterMgr.h"
#include "MitmControl.h"
#include "ProxyMonitor.h"
#include "ProcessRegistry.h"
#include "SshSessionManager.h"

// The GUI keeps this DLL loaded until process exit. Service stop/start only
// recreates CGlobalProxy/PRC; all readers and writers retain this one registry.
IProxyProcessRegistry* CGlobalProxy::GetProcessRegistry()
{
	static CProcessRegistry registry;
	return &registry;
}

IProxyTlsControl* CGlobalProxy::GetTlsControl() { return &CMitmControl::Instance(); }
IProxyMonitor* CGlobalProxy::GetMonitorInstance() { return &CProxyMonitor::Instance(); }

CGlobalProxy::CGlobalProxy(void)
{
	m_bProxyEnaled = FALSE;
	//m_bSupportMethod = MAKELONG(1, 0);

	m_Ref = 0;
	m_pProxyRC = NULL;

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		return;

	m_pProxySettings = new CProxySettings;
	m_pProxyLog = new CProxyLog;
	m_pProxyTesterMgr = new CProxyTesterMgr;

}

CGlobalProxy::~CGlobalProxy(void)
{
	// GUI exits call DisableProxy first; release any remaining idle service.
	CMitmControl::Instance().ShutdownProtocol();
	delete m_pProxyLog;
	delete m_pProxySettings;
	delete m_pProxyTesterMgr;
	SshSessionManager::ShutdownCurrentThread();

	WSACleanup();
}

LPCSTR  CGlobalProxy::GetLastErrorA()
{
	m_szLastErrorA = m_szLastError;
	return m_szLastErrorA;
}

LPCWSTR CGlobalProxy::GetLastErrorW()
{
	m_szLastErrorW = m_szLastError;
	return m_szLastErrorW;
}

BOOL CGlobalProxy::IsProxyEnabled()
{
	//length = 0
	//return FALSE;
	//return (m_pProxyRC != NULL) && m_ProxyList.size();
	return m_bProxyEnaled;
}

BOOL CGlobalProxy::EnableProxy()
{
	if(!m_pProxySettings || !m_pProxyLog)
		return FALSE;

	if(m_pProxyRC != NULL)
	{
		m_szLastError = _T("The proxy is already enabled.");
		return FALSE;
	}

	m_pProxyRC = new CProxyReceptionCentre(this);
	if(m_pProxyRC == NULL)
	{
		m_szLastError = _T("Failed to create the PRC object.");
		return FALSE;
	}

	if(!m_pProxyRC->CreatePRC())
	{
		CString detail = m_pProxyRC->GetLastErrorText();
		if (detail.IsEmpty())
			m_szLastError = _T("Failed to initialize the local proxy service.");
		else
			m_szLastError.Format(_T("Failed to initialize the local proxy service: %s"),
				(LPCTSTR)detail);
		delete m_pProxyRC;
		m_pProxyRC = NULL;
		return FALSE;
	}

	m_bProxyEnaled = TRUE;

	return TRUE;
}

BOOL CGlobalProxy::DisableProxy()
{
	if(!m_pProxyRC)
		return FALSE;

	if(!m_pProxyRC->DestroyPRC())
		return FALSE;

	delete m_pProxyRC;
	m_pProxyRC = NULL;
	m_bProxyEnaled = FALSE;
	CMitmControl::Instance().ShutdownProtocol();

	return TRUE;
}

INT  CGlobalProxy::AddRef()
{
	return ++m_Ref;
}

INT  CGlobalProxy::Release()
{
	--m_Ref;

	if (m_Ref == 0)
	{
		delete this;
		return 0;
	}
	
	return m_Ref;
}

IProxyReceptionCentre* CGlobalProxy::GetPRCInstance()
{
	return m_pProxyRC;
}

IProxyLog* CGlobalProxy::GetLogInstance()
{
	return m_pProxyLog;
}

IProxySettings* CGlobalProxy::GetSettingsInstance()
{
	return m_pProxySettings;
}

IProxyTester* CGlobalProxy::CreateTester()
{
	if (!m_pProxyTesterMgr)
	{
		return NULL;
	}

	return m_pProxyTesterMgr->CreateTester();
}
