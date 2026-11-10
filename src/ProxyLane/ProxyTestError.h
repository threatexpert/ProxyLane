#pragma once
#include "Localization.h"
#include "../ProxyLaneHook/ProxyModule.h"

inline CString ProxyTestErrorDescription(int error, BOOL direct)
{
	if (direct && (error == PROXYERROR_NOCONN || error == PROXYERROR_REQUESTFAILED))
		return Localization::Get(L"test.direct_connection_failed");
	// Proxy negotiation errors share numeric values with Win32 errors; do not
	// pass these application codes to the Windows system message table.
	LPCTSTR key = NULL;
	switch (error)
	{
	case PROXYERROR_NOCONN: key = _T("test.no_connection"); break;
	case PROXYERROR_REQUESTFAILED: key = _T("test.target_failed"); break;
	case PROXYERROR_AUTHREQUIRED: key = _T("test.auth_required"); break;
	case PROXYERROR_AUTHTYPEUNKNOWN: key = _T("test.auth_unknown"); break;
	case PROXYERROR_AUTHFAILED:
	case PROXYERROR_AUTHNOLOGON: key = _T("test.auth_failed"); break;
	case PROXYERROR_CANTRESOLVEHOST: key = _T("test.resolve_failed"); break;
	case PROXYERROR_SECURE_UNAVAILABLE: key = _T("test.secure_unavailable"); break;
	case PROXYERROR_SECURE_HANDSHAKE: key = _T("test.secure_handshake_failed"); break;
	case PROXYERROR_SSH_KEY_FILE: key = _T("test.ssh_key_file_failed"); break;
	case PROXYERROR_SSH_KEY_AUTHFAILED: key = _T("test.ssh_key_auth_failed"); break;
	case PROXYERROR_SSH_UNAVAILABLE: key = _T("test.ssh_unavailable"); break;
	case PROXYERROR_SSH_HOSTKEY_UNKNOWN: key = _T("test.ssh_unknown_key"); break;
	case PROXYERROR_SSH_HOSTKEY_CHANGED: key = _T("test.ssh_changed_key"); break;
	case PROXYERROR_UDP_UNSUPPORTED: key = _T("test.udp_unsupported"); break;
	case PROXYERROR_UDP_RELAY_FAILED: key = _T("test.udp_relay_failed"); break;
	}
	if (key) return Localization::Get(key);

	LPTSTR buffer = NULL;
	CString description;
	if (::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS, NULL, static_cast<DWORD>(error), 0,
		reinterpret_cast<LPTSTR>(&buffer), 0, NULL))
	{
		description = buffer;
		description.Trim();
	}
	if (buffer) LocalFree(buffer);
	return description.IsEmpty() ? Localization::Get(_T("test.error_description_unavailable")) : description;
}

