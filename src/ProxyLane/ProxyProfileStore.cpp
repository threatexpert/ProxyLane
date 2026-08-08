#include "stdafx.h"
#include "ProxyLane.h"
#include "ProxyProfileStore.h"

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
	item.pi.strProxyHost = m_ini.GetString(section, _T("Host"));
	item.pi.nProxyPort = m_ini.GetInt(section, _T("Port"));
	item.pi.strProxyUser = m_ini.GetString(section, _T("User"));
	item.pi.strProxyPass = m_ini.GetString(section, _T("Pass"));
	CString transport = m_ini.GetString(section, _T("Transport"));
	item.nTransportMode = transport.CompareNoCase(_T("GONC_TLS_PSK")) == 0
		? PROXY_TRANSPORT_GONC_TLS_PSK : PROXY_TRANSPORT_PLAIN;
	item.strTransportPsk = m_ini.GetString(section, _T("PSK"));

	const CString proxyType = (CString)item.pi.strProxyType;
	const BOOL supportedType = item.pi.GetProxyType() != PROXYTYPE_NOPROXY
		|| proxyType.CompareNoCase(_T("NOPROXY")) == 0;

	return supportedType
		&& item.pi.nProxyPort != 0
		&& item.pi.strProxyHost.szbuf[0] != 0
		&& item.pi.strProxyType.szbuf[0] != 0;
}

int CProxyProfileStore::LoadAll(std::list<CfgProxyItem>& items, CString& lastSelectedName) const
{
	lastSelectedName = m_ini.GetString(_T("options"), _T("lastselected"));
	std::list<CString> sections;
	if (!m_ini.GetSectionList(sections))
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

void CProxyProfileStore::Save(CfgProxyItem& item)
{
	CString section = kProfilePrefix + item.strName;
	m_ini.SetDWORD(section, _T("HookChildProcess"), item.bHookChildProcess);
	m_ini.SetDWORD(section, _T("HookTCP"), item.bHookTCP);
	m_ini.SetDWORD(section, _T("HookUDP"), item.bHookUDP);
	m_ini.SetDWORD(section, _T("BlockUDP"), item.bBlockUDP);
	m_ini.DeleteKeyName(section, _T("UDPAddr"));
	m_ini.SetDWORD(section, _T("dnsOpt"), item.dnsOpt);
	m_ini.SetDWORD(section, _T("RedirectPrivateDNS"), item.bRedirectPrivateDNS);
	m_ini.SetString(section, _T("RedirectDNS"), item.strRedirectDNS);
	m_ini.SetString(section, _T("ChildFilter"), EncodeFilter(item.strChildFilter));
	m_ini.SetDWORD(section, _T("ChildFilterMode"), item.nChildFilterMode);
	m_ini.SetString(section, _T("TargetFilter"), EncodeFilter(item.strTargetFilter));
	m_ini.SetDWORD(section, _T("TargetFilterMode"), item.nTargetFilterMode);
	m_ini.SetString(section, _T("Type"), (CString)item.pi.strProxyType);
	m_ini.SetString(section, _T("Host"), (CString)item.pi.strProxyHost);
	m_ini.SetInt(section, _T("Port"), item.pi.nProxyPort);
	m_ini.SetString(section, _T("User"), (CString)item.pi.strProxyUser);
	m_ini.SetString(section, _T("Pass"), (CString)item.pi.strProxyPass);
	m_ini.SetString(section, _T("Transport"), item.nTransportMode ==
		PROXY_TRANSPORT_GONC_TLS_PSK ? _T("GONC_TLS_PSK") : _T("PLAIN"));
	// Initial secure-transport format intentionally stores the PSK directly
	// in the profile, as selected by the user.
	m_ini.SetString(section, _T("PSK"), item.strTransportPsk);
}

void CProxyProfileStore::Delete(LPCTSTR name)
{
	CString section = kProfilePrefix;
	section += name;
	m_ini.DeleteSection(section);
}

void CProxyProfileStore::SetLastSelected(LPCTSTR name)
{
	m_ini.SetString(_T("options"), _T("lastselected"), name);
}
