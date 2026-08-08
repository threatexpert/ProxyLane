#pragma once

#include "IniFile.h"
#include "..\ProxyLaneHook\ProxyModule.h"
#include <list>

#define CHILDFILTER_MODE_EXCLUDE  0
#define CHILDFILTER_MODE_INCLUDE  1
#define TARGETFILTER_MODE_BYPASS  0
#define TARGETFILTER_MODE_PROXY   1

struct CfgProxyItem
{
	CString strName;
	ProxyInfo pi;
	BOOL bHookTCP;
	BOOL bHookUDP;
	BOOL bBlockUDP;
	BOOL bHookChildProcess;
	int dnsOpt;
	BOOL bRedirectPrivateDNS;
	CString strRedirectDNS;
	CString strChildFilter;
	int nChildFilterMode;
	CString strTargetFilter;
	int nTargetFilterMode;
	int nTransportMode;
	CString strTransportPsk;
};

class CProxyProfileStore
{
public:
	explicit CProxyProfileStore(CIniFile& ini);

	BOOL Load(CfgProxyItem& item) const;
	int LoadAll(std::list<CfgProxyItem>& items, CString& lastSelectedName) const;
	void Save(CfgProxyItem& item);
	void Delete(LPCTSTR name);
	void SetLastSelected(LPCTSTR name);

private:
	static CString EncodeFilter(const CString& multiLine);
	static CString DecodeFilter(const CString& packed);

	CIniFile& m_ini;
};
