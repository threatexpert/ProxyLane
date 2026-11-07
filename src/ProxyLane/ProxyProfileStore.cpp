#include "stdafx.h"
#include "ProxyLane.h"
#include "ProxyProfileStore.h"
#include "RecentApplications.h"
#include "ConfigStorage.h"

namespace
{
	LPCTSTR kProfilePrefix = _T("proxy_");
	const int kProfilePrefixLength = 6;
}

CProxyProfileStore::CProxyProfileStore(CIniFile& ini)
	: m_ini(ini)
{
}

CString CProxyProfileStore::EncodeFilter(const CString& multiLine)
{
	CString value = multiLine;
	value.Replace(_T("\r\n"), _T("\n"));
	value.Replace(_T("\r"), _T("\n"));
	value.Replace(_T("|"), _T("\\|"));
	value.Replace(_T("\n"), _T("|"));
	return value;
}

CString CProxyProfileStore::DecodeFilter(const CString& packed)
{
	CString value;
	for (int i = 0; i < packed.GetLength(); ++i)
	{
		TCHAR ch = packed[i];
		if (ch == _T('\\') && i + 1 < packed.GetLength() && packed[i + 1] == _T('|'))
		{
			value += _T('|');
			++i;
		}
		else if (ch == _T('|'))
		{
			value += _T("\r\n");
		}
		else
		{
			value += ch;
		}
	}
	return value;
}

BOOL CProxyProfileStore::Load(CfgProxyItem& item) const
{
	CString section = kProfilePrefix + item.strName;
	item.bHookChildProcess = !!m_ini.GetDWORD(section, _T("HookChildProcess"), TRUE);
	item.bHookTCP = !!m_ini.GetDWORD(section, _T("HookTCP"), TRUE);
	item.bHookUDP = !!m_ini.GetDWORD(section, _T("HookUDP"), TRUE);
	item.bBlockUDP = !!m_ini.GetDWORD(section, _T("BlockUDP"), FALSE);
	item.bBlockIPv6 = !!m_ini.GetDWORD(section, _T("BlockIPv6"), FALSE);
	item.dnsOpt = m_ini.GetDWORD(section, _T("dnsOpt"), PSI_DNSOPT_REMOTE);
	item.bRedirectPrivateDNS = !!m_ini.GetDWORD(section,
		_T("RedirectPrivateDNS"), TRUE);
	item.strRedirectDNS = m_ini.GetString(section, _T("RedirectDNS"));
	if (item.strRedirectDNS.IsEmpty())
		item.strRedirectDNS = _T("8.8.8.8");
	item.strChildFilter = DecodeFilter(m_ini.GetString(section, _T("ChildFilter")));
	item.nChildFilterMode = (int)m_ini.GetDWORD(section, _T("ChildFilterMode"), CHILDFILTER_MODE_INCLUDE);
	item.strTargetFilter = DecodeFilter(m_ini.GetString(section, _T("TargetFilter")));
	item.nTargetFilterMode = (int)m_ini.GetDWORD(section, _T("TargetFilterMode"), TARGETFILTER_MODE_BYPASS);

	item.pi.szItemName = _T("myproxy");
	item.pi.strProxyType = m_ini.GetString(section, _T("Type"));
	// Legacy HTTP profiles now use HTTP/1.1 CONNECT; loading does not rewrite the INI.
	const int storedType = item.pi.GetProxyType();
	if (storedType == PROXYTYPE_HTTP10 || storedType == PROXYTYPE_HTTP11) item.pi.strProxyType = L"HTTP";
	item.pi.strProxyHost = m_ini.GetString(section, _T("Host"));
	item.pi.nProxyPort = m_ini.GetInt(section, _T("Port"));
	item.pi.strProxyUser = m_ini.GetString(section, _T("User"));
	item.pi.strProxyPass = m_ini.GetString(section, _T("Pass"));
	CString transport = m_ini.GetString(section, _T("Transport"));
	item.nTransportMode = transport.CompareNoCase(_T("GONC_TLS_PSK")) == 0
		? PROXY_TRANSPORT_GONC_TLS_PSK : PROXY_TRANSPORT_PLAIN;
	item.strTransportPsk = m_ini.GetString(section, _T("PSK"));

	const CString proxyType = (CString)item.pi.strProxyType;
	if (proxyType.CompareNoCase(_T("NOPROXY")) == 0)
		return TRUE; // Direct profiles have no upstream proxy endpoint.
	const BOOL supportedType = item.pi.GetProxyType() != PROXYTYPE_NOPROXY;

	return supportedType
		&& item.pi.nProxyPort != 0
		&& item.pi.strProxyHost.szbuf[0] != 0
		&& item.pi.strProxyType.szbuf[0] != 0;
}

int CProxyProfileStore::LoadAll(std::list<CfgProxyItem>& items, CString& lastSelectedName) const
{
	lastSelectedName = m_ini.GetString(_T("options"), _T("lastselected"));
	std::list<CString> sections;
	if (m_ini.GetSectionList(sections) < 0)
		return -1;

	for (std::list<CString>::const_iterator it = sections.begin(); it != sections.end(); ++it)
	{
		const CString& section = *it;
		if (section.Left(kProfilePrefixLength).CompareNoCase(kProfilePrefix) != 0
			|| section.GetLength() <= kProfilePrefixLength)
		{
			continue;
		}

		CfgProxyItem item;
		item.strName = section.Mid(kProfilePrefixLength);
		if (Load(item))
			items.push_back(item);
	}

	return (int)items.size();
}

BOOL CProxyProfileStore::ListNames(std::vector<CString>& names) const
{
	std::list<CString> sections;
	if (m_ini.GetSectionList(sections) < 0)
		return FALSE;
	std::vector<CString> loaded;
	for (const CString& section : sections)
	{
		if (section.Left(kProfilePrefixLength).CompareNoCase(kProfilePrefix) == 0 &&
			section.GetLength() > kProfilePrefixLength)
			loaded.push_back(section.Mid(kProfilePrefixLength));
	}
	names.swap(loaded);
	return TRUE;
}

BOOL CProxyProfileStore::Save(CfgProxyItem& item)
{
	return ConfigStorage::Update(m_ini.GetIniFileName(), [&](const CString& path) {
	CIniFile ini; ini.SetIniFileName(path); ini.staging = true;
	CString section = kProfilePrefix + item.strName;
	if (!ini.SetDWORD(section, _T("HookChildProcess"), item.bHookChildProcess)) return false;
	if (!ini.SetDWORD(section, _T("HookTCP"), item.bHookTCP)) return false;
	if (!ini.SetDWORD(section, _T("HookUDP"), item.bHookUDP)) return false;
	if (!ini.SetDWORD(section, _T("BlockUDP"), item.bBlockUDP)) return false;
	if (!ini.SetDWORD(section, _T("BlockIPv6"), item.bBlockIPv6)) return false;
	if (!ini.DeleteKeyName(section, _T("UDPAddr"))) return false;
	if (!ini.SetDWORD(section, _T("dnsOpt"), item.dnsOpt)) return false;
	if (!ini.SetDWORD(section, _T("RedirectPrivateDNS"), item.bRedirectPrivateDNS)) return false;
	if (!ini.SetString(section, _T("RedirectDNS"), item.strRedirectDNS)) return false;
	if (!ini.SetString(section, _T("ChildFilter"), EncodeFilter(item.strChildFilter))) return false;
	if (!ini.SetDWORD(section, _T("ChildFilterMode"), item.nChildFilterMode)) return false;
	if (!ini.SetString(section, _T("TargetFilter"), EncodeFilter(item.strTargetFilter))) return false;
	if (!ini.SetDWORD(section, _T("TargetFilterMode"), item.nTargetFilterMode)) return false;
	const int proxyType = item.pi.GetProxyType();
	const CString type = (proxyType == PROXYTYPE_HTTP10 || proxyType == PROXYTYPE_HTTP11)
		? CString(L"HTTP") : (CString)item.pi.strProxyType;
	if (!ini.SetString(section, _T("Type"), type)) return false;
	if (!ini.SetString(section, _T("Host"), (CString)item.pi.strProxyHost)) return false;
	if (!ini.SetInt(section, _T("Port"), item.pi.nProxyPort)) return false;
	if (!ini.SetString(section, _T("User"), (CString)item.pi.strProxyUser)) return false;
	if (!ini.SetString(section, _T("Pass"), (CString)item.pi.strProxyPass)) return false;
	if (!ini.SetString(section, _T("Transport"), item.nTransportMode ==
		PROXY_TRANSPORT_GONC_TLS_PSK ? _T("GONC_TLS_PSK") : _T("PLAIN"))) return false;
	// Initial secure-transport format intentionally stores the PSK directly
	// in the profile, as selected by the user.
	if (!ini.SetString(section, _T("PSK"), item.strTransportPsk)) return false;
	return ini.SetString(L"options", L"lastselected", item.strName) != FALSE;
	});
}

BOOL CProxyProfileStore::Delete(LPCTSTR name)
{
	return RecentApplications::DeleteProfile(name, m_ini.GetIniFileName());
}

void CProxyProfileStore::SetLastSelected(LPCTSTR name)
{
	m_ini.SetString(_T("options"), _T("lastselected"), name);
}
