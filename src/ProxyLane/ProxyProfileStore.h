#pragma once

#include "IniFile.h"
#include "..\ProxyLaneHook\ProxyModule.h"
#include <list>
#include <vector>

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
	BOOL bBlockIPv6;
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
	// A chain profile (fixed when created) routes through the saved server
	// profiles in chainHops, in order; its pi is a direct placeholder.
	BOOL bChain = FALSE;
	std::vector<CString> chainHops;
};

class CProxyProfileStore
{
public:
	explicit CProxyProfileStore(CIniFile& ini);

	BOOL Load(CfgProxyItem& item) const;
	int LoadAll(std::list<CfgProxyItem>& items, CString& lastSelectedName) const;
	BOOL ListNames(std::vector<CString>& names) const;
	BOOL Save(CfgProxyItem& item);
	BOOL Delete(LPCTSTR name);
	void SetLastSelected(LPCTSTR name);

	// A saved Server-mode SOCKS5 or HTTP profile, the only kind a chain can use.
	static BOOL IsChainHop(const CfgProxyItem& item);
	// Chain profiles that list `name` as a hop.
	BOOL ListChainUsers(LPCTSTR name, std::vector<CString>& users) const;
	// Builds the route of a chain from its saved hop profiles. On failure,
	// errorKey is a localization key and errorName the offending hop, if any.
	BOOL ResolveChain(const std::vector<CString>& hops, ProxyChain& chain,
		CString& errorKey, CString& errorName) const;

private:
	static CString EncodeFilter(const CString& multiLine);
	static CString DecodeFilter(const CString& packed);

	CIniFile& m_ini;
};
