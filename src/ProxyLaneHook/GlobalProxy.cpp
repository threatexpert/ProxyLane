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
	delete m_pProxyLog;
	delete m_pProxySettings;
	delete m_pProxyTesterMgr;

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
		m_szLastError = _T("代理已经处于启用状态..");
		return FALSE;
	}

	m_pProxyRC = new CProxyReceptionCentre(this);
	if(m_pProxyRC == NULL)
	{
		m_szLastError = _T("创建 PRC 对象失败.");
		return FALSE;
	}

	if(!m_pProxyRC->CreatePRC())
	{
		m_szLastError = _T("初始化 PRC 对象失败.");
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

