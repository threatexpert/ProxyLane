#pragma once

#include "ProxyModule.h"
#include <list>

using namespace std;

class CProxyReceptionCentre;
class CProxySettings;
class CProxyLog;
class CProxyTesterMgr;

class CGlobalProxy
	: public IGlobalProxy
{
public:
	CGlobalProxy(void);
	~CGlobalProxy(void);

	LPCSTR  GetLastErrorA();
	LPCWSTR GetLastErrorW();

	IProxyReceptionCentre* GetPRCInstance();
	IProxySettings* GetSettingsInstance();
	IProxyLog* GetLogInstance();

	IProxyTester* CreateTester();

	BOOL IsProxyEnabled();
	BOOL EnableProxy();
	BOOL DisableProxy();

	INT  AddRef();
	INT  Release();

private:
	CString m_szLastError;
	CStringA m_szLastErrorA;
	CStringW m_szLastErrorW;

	INT m_Ref;

	//list<ProxyInfo> m_ProxyList;
	//CStringA  m_SelectedProxy;
	//LONG m_bSupportMethod;
	BOOL m_bProxyEnaled;

	CProxyReceptionCentre *m_pProxyRC;
	CProxySettings *m_pProxySettings;
	CProxyLog *m_pProxyLog;
	CProxyTesterMgr *m_pProxyTesterMgr;

};
