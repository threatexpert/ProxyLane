#include "stdafx.h"
#include "ProxyLane.h"
#include "ProxyProfileStore.h"
#include "RecentApplications.h"
#include "ConfigStorage.h"
#include "SshProfile.h"
#include "SshKeyStore.h"

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
    if (item.dnsOpt < PSI_DNSOPT_LOCAL || item.dnsOpt > PSI_DNSOPT_DOH) return FALSE;
    // Older modes may prefill the editor; an incomplete DoH profile must not
    // silently select another resolver or bootstrap address.
    item.strDohUrl = m_ini.GetString(section, L"DohUrl",
        item.dnsOpt == PSI_DNSOPT_DOH ? L"" : L"https://dns.google/dns-query");
    item.strDohBootstrap = m_ini.GetString(section, L"DohBootstrap",
        item.dnsOpt == PSI_DNSOPT_DOH ? L"" : L"8.8.8.8, 8.8.4.4");
    item.pi.dohEnabled = 0; // The active profile, not its chain nodes, chooses DNS.
	item.bRedirectPrivateDNS = !!m_ini.GetDWORD(section,
		_T("RedirectPrivateDNS"), TRUE);
	item.strRedirectDNS = m_ini.GetString(section, _T("RedirectDNS"));
	if (item.strRedirectDNS.IsEmpty())
		item.strRedirectDNS = _T("8.8.8.8");
	item.strChildFilter = DecodeFilter(m_ini.GetString(section, _T("ChildFilter")));
	item.nChildFilterMode = (int)m_ini.GetDWORD(section, _T("ChildFilterMode"), CHILDFILTER_MODE_INCLUDE);
	item.strTargetFilter = DecodeFilter(m_ini.GetString(section, _T("TargetFilter")));
	item.nTargetFilterMode = (int)m_ini.GetDWORD(section, _T("TargetFilterMode"), TARGETFILTER_MODE_BYPASS);

	item.pi.sshAuth = 0;
    item.pi.strSshKeyDigest.szbuf[0] = 0;
    SecureZeroMemory(item.pi.strSshKeyFile.szbuf, sizeof(item.pi.strSshKeyFile.szbuf));
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
	item.strTransportPsk = m_ini.GetString(section, storedType == PROXYTYPE_SSH ? L"SshHostKey" : L"PSK");
    if (storedType == PROXYTYPE_SSH) {
        const CString auth = m_ini.GetString(section, L"SshAuth", L"password");
        if (auth != L"password" && auth != L"private_key") return FALSE;
        item.pi.sshAuth = auth == L"private_key" ? 1 : 0;
        if (item.pi.sshAuth) {
            CString reference = m_ini.GetString(section, L"SshKeyFile");
            // Read the previous experimental inline format without dropping it;
            // the next explicit save removes the inline data from the INI.
            if (reference.IsEmpty()) {
                CString packed = m_ini.GetString(section, L"SshPrivateKey"); packed.Replace(L"|", L"\n");
                char legacy[SshPrivateKey::Capacity] = {};
                const bool imported = SshProfile::Encode(packed, legacy) && SshKeyStore::Import(legacy, reference);
                SecureZeroMemory(legacy, sizeof(legacy));
                if (!imported) return FALSE;
            }
            if (!SshKeyStore::ValidReference(reference) || !SshProfile::Encode(SshKeyStore::Path(reference), item.pi.strSshKeyFile.szbuf)) return FALSE;
        }
        if (item.nTransportMode != PROXY_TRANSPORT_PLAIN || m_ini.GetString(section, L"User").IsEmpty()) return FALSE;
        if (!SshProfile::Encode(m_ini.GetString(section, L"User"), item.pi.strProxyUser.szbuf) ||
            !SshProfile::Encode(m_ini.GetString(section, item.pi.sshAuth ? L"SshKeyPassphrase" : L"Pass"), item.pi.strProxyPass.szbuf) ||
            !SshProfile::ValidFingerprint(item.strTransportPsk)) return FALSE;
        item.bHookUDP = FALSE;
    }

	// Type=CHAIN marks a chain profile. Older versions do not know the type and
	// skip the profile instead of running it as something else.
	item.bChain = ((CString)item.pi.strProxyType).CompareNoCase(_T("CHAIN")) == 0;
	item.chainHops.clear();
	if (item.bChain)
	{
		// Hop1, Hop2, ... up to the first missing key; there is no hop limit.
		for (int i = 1; ; ++i)
		{
			CString key;
			key.Format(_T("Hop%d"), i);
			const CString hop = m_ini.GetString(section, key);
			if (hop.IsEmpty())
				break;
			item.chainHops.push_back(hop);
		}
		// A chain has no server of its own.
		ZeroMemory(&item.pi, sizeof(item.pi));
		item.pi.szItemName = _T("myproxy");
		item.pi.strProxyType = _T("NOPROXY");
		item.nTransportMode = PROXY_TRANSPORT_PLAIN;
		item.strTransportPsk.Empty();
		return TRUE;
	}

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


namespace
{
	bool WriteConnection(CIniFile& ini, const CString& section, CfgProxyItem& item)
	{
		const int proxyType = item.pi.GetProxyType();
		const CString type = (proxyType == PROXYTYPE_HTTP10 || proxyType == PROXYTYPE_HTTP11)
			? CString(L"HTTP") : (CString)item.pi.strProxyType;
		if (!ini.SetString(section, _T("Type"), type)) return false;
		if (!ini.SetString(section, _T("Host"), (CString)item.pi.strProxyHost)) return false;
		if (!ini.SetInt(section, _T("Port"), item.pi.nProxyPort)) return false;
		if (!ini.SetString(section, _T("User"), (proxyType == PROXYTYPE_SSH ? SshProfile::Decode(item.pi.strProxyUser.szbuf) : (CString)item.pi.strProxyUser))) return false;
		const bool keyAuth = proxyType == PROXYTYPE_SSH && item.pi.sshAuth == 1;
        if (!ini.SetString(section, L"Pass", keyAuth ? CString() : (proxyType == PROXYTYPE_SSH ? SshProfile::Decode(item.pi.strProxyPass.szbuf) : (CString)item.pi.strProxyPass))) return false;
        if (proxyType == PROXYTYPE_SSH) {
            if (item.pi.sshAuth > 1 || (keyAuth && SshKeyStore::Reference(item.pi.strSshKeyFile.szbuf).IsEmpty())) return false;
            if (!ini.SetString(section, L"SshAuth", keyAuth ? L"private_key" : L"password")) return false;
        } else if (!ini.DeleteKeyName(section, L"SshAuth")) return false;
        if (keyAuth) {
            if (!ini.SetString(section, L"SshKeyFile", SshKeyStore::Reference(item.pi.strSshKeyFile.szbuf)) ||
                !ini.SetString(section, L"SshKeyPassphrase", SshProfile::Decode(item.pi.strProxyPass.szbuf))) return false;
        } else if (!ini.DeleteKeyName(section, L"SshKeyFile") || !ini.DeleteKeyName(section, L"SshKeyPassphrase")) return false;
        if (!ini.DeleteKeyName(section, L"SshPrivateKey")) return false;
		if (!ini.SetString(section, _T("Transport"), item.nTransportMode ==
			PROXY_TRANSPORT_GONC_TLS_PSK ? _T("GONC_TLS_PSK") : _T("PLAIN"))) return false;
		// Initial secure-transport format intentionally stores the PSK directly
		// in the profile, as selected by the user.
		if (!ini.SetString(section, proxyType == PROXYTYPE_SSH ? L"SshHostKey" : L"PSK", item.strTransportPsk)) return false;
        if (!ini.DeleteKeyName(section, proxyType == PROXYTYPE_SSH ? L"PSK" : L"SshHostKey")) return false;
		return true;
	}
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
    if (!ini.SetString(section, L"DohUrl", item.strDohUrl)) return false;
    if (!ini.SetString(section, L"DohBootstrap", item.strDohBootstrap)) return false;
	if (!ini.SetDWORD(section, _T("RedirectPrivateDNS"), item.bRedirectPrivateDNS)) return false;
	if (!ini.SetString(section, _T("RedirectDNS"), item.strRedirectDNS)) return false;
	if (!ini.SetString(section, _T("ChildFilter"), EncodeFilter(item.strChildFilter))) return false;
	if (!ini.SetDWORD(section, _T("ChildFilterMode"), item.nChildFilterMode)) return false;
	if (!ini.SetString(section, _T("TargetFilter"), EncodeFilter(item.strTargetFilter))) return false;
	if (!ini.SetDWORD(section, _T("TargetFilterMode"), item.nTargetFilterMode)) return false;
	if (item.bChain)
	{
		// A chain stores its hops in place of a server.
		if (!ini.SetString(section, _T("Type"), _T("CHAIN"))) return false;
		const LPCTSTR serverKeys[] = { _T("Host"), _T("Port"), _T("User"), _T("Pass"), _T("Transport"), _T("PSK"), L"SshHostKey", L"SshAuth", L"SshPrivateKey", L"SshKeyFile", L"SshKeyPassphrase" };
		for (LPCTSTR key : serverKeys)
			if (!ini.DeleteKeyName(section, key)) return false;
	}
	else
	{
		if (!WriteConnection(ini, section, item)) return false;
	}
	// Write the hops, then drop the keys a longer chain (or a chain this profile
	// never was) may have left behind.
	const int hopCount = item.bChain ? (int)item.chainHops.size() : 0;
	for (int i = 1; ; ++i)
	{
		CString key;
		key.Format(_T("Hop%d"), i);
		if (i <= hopCount)
		{
			if (!ini.SetString(section, key, item.chainHops[i - 1])) return false;
		}
		else if (ini.GetString(section, key).IsEmpty())
			break;
		else if (!ini.DeleteKeyName(section, key)) return false;
	}
	return ini.SetString(L"options", L"lastselected", item.strName) != FALSE;
	});
}

BOOL CProxyProfileStore::SaveConnection(CfgProxyItem& item)
{
    if (!IsChainHop(item)) { SetLastError(ERROR_INVALID_DATA); return FALSE; }
    return ConfigStorage::Update(m_ini.GetIniFileName(), [&](const CString& path) {
        CIniFile ini; ini.SetIniFileName(path); ini.staging = true;
        CProxyProfileStore current(ini);
        CfgProxyItem existing; existing.strName = item.strName;
        // Do not recreate a deleted profile or overwrite a different profile kind.
        if (!current.Load(existing) || !IsChainHop(existing)) {
            SetLastError(ERROR_NOT_FOUND); return false;
        }
        return WriteConnection(ini, kProfilePrefix + item.strName, item);
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

BOOL CProxyProfileStore::IsChainHop(const CfgProxyItem& item)
{
	ProxyInfo pi = item.pi;
	const int type = pi.GetProxyType();
	return !item.bChain && (type == PROXYTYPE_SOCKS5 ||
		type == PROXYTYPE_HTTP10 || type == PROXYTYPE_HTTP11 || type == PROXYTYPE_SSH);
}

BOOL CProxyProfileStore::ListChainUsers(LPCTSTR name, std::vector<CString>& users) const
{
	users.clear();
	std::vector<CString> names;
	if (!name || !ListNames(names))
		return FALSE;
	for (const CString& candidate : names)
	{
		CfgProxyItem item;
		item.strName = candidate;
		if (!Load(item) || !item.bChain)
			continue;
		for (const CString& hop : item.chainHops)
		{
			if (hop.CompareNoCase(name) == 0)
			{
				users.push_back(candidate);
				break;
			}
		}
	}
	return TRUE;
}

BOOL CProxyProfileStore::ResolveChain(const std::vector<CString>& hops, ProxyChain& chain,
	CString& errorKey, CString& errorName) const
{
	chain.clear();
	errorName.Empty();
	if (hops.size() < 2)
	{
		errorKey = _T("profile.chain_too_short");
		return FALSE;
	}
	ProxyChain resolved(hops.size());
	for (size_t i = 0; i < hops.size(); ++i)
	{
		errorName = hops[i];
		for (size_t j = 0; j < i; ++j)
		{
			if (hops[j].CompareNoCase(hops[i]) == 0)
			{
				errorKey = _T("profile.chain_duplicate");
				return FALSE;
			}
		}
		CfgProxyItem item;
		item.strName = hops[i];
		if (!Load(item))
		{
			errorKey = _T("profile.chain_missing");
			return FALSE;
		}
		if (!IsChainHop(item))
		{
			errorKey = _T("profile.chain_invalid_hop");
			return FALSE;
		}

		ProxyInfo& hop = resolved[i];
		hop = item.pi;
		hop.szItemName = hops[i];
		hop.reserved = item.nTransportMode == PROXY_TRANSPORT_GONC_TLS_PSK
			? PROXY_TRANSPORT_GONC_TLS_PSK : PROXY_TRANSPORT_PLAIN;
		SecureZeroMemory(hop.strTransportPsk.szbuf, sizeof(hop.strTransportPsk.szbuf));
		if (hop.GetProxyType() == PROXYTYPE_SSH) {
            if (hop.reserved != PROXY_TRANSPORT_PLAIN || !hop.strProxyUser.szbuf[0] ||
                !SshProfile::ValidFingerprint(item.strTransportPsk) ||
                !SshProfile::Encode(item.strTransportPsk, hop.strTransportPsk.szbuf)) {
                errorKey = L"profile.ssh_invalid"; return FALSE;
            }
        }
        else if (hop.reserved == PROXY_TRANSPORT_GONC_TLS_PSK)
		{
			// Same UTF-8 encoding as the Profiles page uses for a single server.
			const int required = WideCharToMultiByte(CP_UTF8, 0, item.strTransportPsk,
				item.strTransportPsk.GetLength(), NULL, 0, NULL, NULL);
			if (required <= 0 || required >= (int)sizeof(hop.strTransportPsk.szbuf))
			{
				errorKey = _T("profile.psk_required");
				return FALSE;
			}
			WideCharToMultiByte(CP_UTF8, 0, item.strTransportPsk, item.strTransportPsk.GetLength(),
				hop.strTransportPsk.szbuf, required, NULL, NULL);
			hop.strTransportPsk.szbuf[required] = '\0';
		}
	}
	chain.swap(resolved);
	errorName.Empty();
	return TRUE;
}
