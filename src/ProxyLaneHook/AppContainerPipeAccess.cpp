#ifndef PROXYLANE_PIPE_ACCESS_STANDALONE
#include "stdafx.h"
#endif
#include "AppContainerPipeAccess.h"
#include <aclapi.h>
#include <algorithm>
#include <new>

namespace
{
	CAppContainerPipeAccess g_hostPipeAccess;

	class PipeAccessLock
	{
	public:
		explicit PipeAccessLock(CRITICAL_SECTION& lock) : m_lock(lock)
		{ EnterCriticalSection(&m_lock); }
		~PipeAccessLock() { LeaveCriticalSection(&m_lock); }
	private:
		CRITICAL_SECTION& m_lock;
	};

	BOOL IsPackageSid(PSID sid)
	{
		if (!sid || !IsValidSid(sid)) return FALSE;
		const SID_IDENTIFIER_AUTHORITY appAuthority = { { 0, 0, 0, 0, 0, 15 } };
		// S-1-15-2-<seven package hash components>; excludes Everyone,
		// capabilities and the broad ALL APPLICATION PACKAGES SID.
		return memcmp(GetSidIdentifierAuthority(sid), &appAuthority,
			sizeof(appAuthority)) == 0 && *GetSidSubAuthorityCount(sid) == 8 &&
			*GetSidSubAuthority(sid, 0) == 2;
	}

	EXPLICIT_ACCESSW PackageEntry(PSID sid)
	{
		EXPLICIT_ACCESSW entry = { 0 };
		entry.grfAccessPermissions = PROXYLANE_PIPE_CLIENT_ACCESS;
		entry.grfAccessMode = GRANT_ACCESS;
		entry.grfInheritance = NO_INHERITANCE;
		entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		entry.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
		entry.Trustee.ptstrName = static_cast<LPWSTR>(sid);
		return entry;
	}
}

CAppContainerPipeAccess& GetProxyLanePipeAccess()
{
	return g_hostPipeAccess;
}

BOOL QueryProcessAppContainerSid(HANDLE process, std::vector<BYTE>& sid)
{
	sid.clear();
	HANDLE token = NULL;
	if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return FALSE;
	// Numeric information classes keep this source buildable with the XP SDK.
	const TOKEN_INFORMATION_CLASS isAppContainerClass =
		static_cast<TOKEN_INFORMATION_CLASS>(29);
	const TOKEN_INFORMATION_CLASS appContainerSidClass =
		static_cast<TOKEN_INFORMATION_CLASS>(31);
	DWORD isAppContainer = 0, bytes = 0;
	if (!GetTokenInformation(token, isAppContainerClass, &isAppContainer,
		sizeof(isAppContainer), &bytes))
	{
		const DWORD error = GetLastError();
		CloseHandle(token);
		// Pre-Windows 8 kernels have no AppContainer token information.
		if (error == ERROR_INVALID_PARAMETER) return TRUE;
		SetLastError(error);
		return FALSE;
	}
	if (!isAppContainer) { CloseHandle(token); return TRUE; }

	GetTokenInformation(token, appContainerSidClass, NULL, 0, &bytes);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof(PSID) ||
		bytes > 64 * 1024)
	{
		CloseHandle(token);
		SetLastError(ERROR_INVALID_DATA);
		return FALSE;
	}
	std::vector<BYTE> data;
	try { data.resize(bytes); }
	catch (const std::bad_alloc&)
	{
		CloseHandle(token);
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return FALSE;
	}
	if (!GetTokenInformation(token, appContainerSidClass, &data[0], bytes, &bytes))
	{
		const DWORD error = GetLastError();
		CloseHandle(token);
		SetLastError(error);
		return FALSE;
	}
	CloseHandle(token);
	PSID packageSid = *reinterpret_cast<PSID*>(&data[0]);
	const ULONG_PTR start = reinterpret_cast<ULONG_PTR>(&data[0]);
	const ULONG_PTR address = reinterpret_cast<ULONG_PTR>(packageSid);
	if (address < start || address - start > data.size() ||
		data.size() - (address - start) < 8)
	{
		SetLastError(ERROR_INVALID_SID);
		return FALSE;
	}
	const size_t sidBytes = 8 + 4 * *GetSidSubAuthorityCount(packageSid);
	if (sidBytes > data.size() - (address - start) || !IsPackageSid(packageSid))
	{
		SetLastError(ERROR_INVALID_SID);
		return FALSE;
	}
	try
	{
		sid.assign(static_cast<BYTE*>(packageSid),
			static_cast<BYTE*>(packageSid) + GetLengthSid(packageSid));
	}
	catch (const std::bad_alloc&)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return FALSE;
	}
	return TRUE;
}

CAppContainerPipeAccess::CAppContainerPipeAccess()
	: m_securityServer(INVALID_HANDLE_VALUE), m_securityClient(INVALID_HANDLE_VALUE)
{ InitializeCriticalSection(&m_lock); }

CAppContainerPipeAccess::~CAppContainerPipeAccess()
{
	// The PRC must stop/join its pipe threads before the DLL is unloaded.
	CloseSecurityHandles();
	DeleteCriticalSection(&m_lock);
}

void CAppContainerPipeAccess::CloseSecurityHandles()
{
	if (m_securityClient != INVALID_HANDLE_VALUE) CloseHandle(m_securityClient);
	if (m_securityServer != INVALID_HANDLE_VALUE) CloseHandle(m_securityServer);
	m_securityClient = m_securityServer = INVALID_HANDLE_VALUE;
}

BOOL CAppContainerPipeAccess::AuthorizeProcess(HANDLE process)
{
	std::vector<BYTE> sid;
	if (!QueryProcessAppContainerSid(process, sid)) return FALSE;
	return sid.empty() ? TRUE : AuthorizePackageSid(&sid[0]);
}

BOOL CAppContainerPipeAccess::AuthorizePackageSid(PSID sid)
{
	if (!IsPackageSid(sid)) { SetLastError(ERROR_INVALID_SID); return FALSE; }
	PipeAccessLock lock(m_lock);
	for (size_t i = 0; i < m_packageSids.size(); ++i)
		if (EqualSid(&m_packageSids[i][0], sid)) return TRUE;
	if (m_serverPipes.empty() || m_securityClient == INVALID_HANDLE_VALUE)
	{ SetLastError(ERROR_PIPE_NOT_CONNECTED); return FALSE; }

	// Allocate before touching the live DACL, so an allocation failure cannot
	// leave a grant installed but missing from the next pipe's security policy.
	try
	{
		m_packageSids.reserve(m_packageSids.size() + 1);
		std::vector<BYTE> copy(static_cast<BYTE*>(sid),
			static_cast<BYTE*>(sid) + GetLengthSid(sid));
		PACL oldAcl = NULL, newAcl = NULL;
		PSECURITY_DESCRIPTOR descriptor = NULL;
		// Synchronous server handles can be stuck in ConnectNamedPipe/ReadFile.
		// Querying their DACL also waits for that I/O, causing a deadlock before
		// the AppContainer client is authorized to connect. Use the private
		// overlapped client handle: it has no pending communication operations.
		DWORD error = GetSecurityInfo(m_securityClient, SE_KERNEL_OBJECT,
			DACL_SECURITY_INFORMATION, NULL, NULL, &oldAcl, NULL, &descriptor);
		if (error == ERROR_SUCCESS && !oldAcl) error = ERROR_INVALID_SECURITY_DESCR;
		EXPLICIT_ACCESSW entry = PackageEntry(sid);
		if (error == ERROR_SUCCESS)
			error = SetEntriesInAclW(1, &entry, oldAcl, &newAcl);
		if (error == ERROR_SUCCESS)
			// All instances of this named pipe share the object's security.
			error = SetSecurityInfo(m_securityClient, SE_KERNEL_OBJECT,
				DACL_SECURITY_INFORMATION, NULL, NULL, newAcl, NULL);
		if (newAcl) LocalFree(newAcl);
		if (descriptor) LocalFree(descriptor);
		if (error != ERROR_SUCCESS) { SetLastError(error); return FALSE; }
		m_packageSids.push_back(std::vector<BYTE>());
		m_packageSids.back().swap(copy);
		return TRUE;
	}
	catch (const std::bad_alloc&)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return FALSE;
	}
}

HANDLE CAppContainerPipeAccess::CreateServerPipe(LPCWSTR name, DWORD openMode,
	DWORD pipeMode, DWORD maxInstances, DWORD outputSize, DWORD inputSize,
	DWORD timeout, const SECURITY_ATTRIBUTES& baseAttributes)
{
	PipeAccessLock lock(m_lock);
	try
	{
		if (m_serverPipes.size() == m_serverPipes.capacity())
			m_serverPipes.reserve(m_serverPipes.empty() ? 8 : m_serverPipes.size() * 2);
		std::vector<EXPLICIT_ACCESSW> entries;
		for (size_t i = 0; i < m_packageSids.size(); ++i)
			entries.push_back(PackageEntry(&m_packageSids[i][0]));

		PACL baseAcl = NULL, sacl = NULL, grantedAcl = NULL;
		PSID owner = NULL, group = NULL;
		BOOL present = FALSE, defaulted = FALSE;
		SECURITY_DESCRIPTOR descriptor;
		if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
			!GetSecurityDescriptorDacl(baseAttributes.lpSecurityDescriptor,
				&present, &baseAcl, &defaulted) || !present || !baseAcl)
		{
			SetLastError(ERROR_INVALID_SECURITY_DESCR);
			return INVALID_HANDLE_VALUE;
		}
		DWORD error = ERROR_SUCCESS;
		if (!entries.empty())
			error = SetEntriesInAclW(static_cast<ULONG>(entries.size()),
				&entries[0], baseAcl, &grantedAcl);
		BOOL ready = error == ERROR_SUCCESS &&
			SetSecurityDescriptorDacl(&descriptor, TRUE,
				grantedAcl ? grantedAcl : baseAcl, FALSE) &&
			GetSecurityDescriptorOwner(baseAttributes.lpSecurityDescriptor, &owner, &defaulted) &&
			SetSecurityDescriptorOwner(&descriptor, owner, defaulted) &&
			GetSecurityDescriptorGroup(baseAttributes.lpSecurityDescriptor, &group, &defaulted) &&
			SetSecurityDescriptorGroup(&descriptor, group, defaulted) &&
			GetSecurityDescriptorSacl(baseAttributes.lpSecurityDescriptor, &present, &sacl, &defaulted) &&
			SetSecurityDescriptorSacl(&descriptor, present, sacl, defaulted);
		HANDLE pipe = INVALID_HANDLE_VALUE;
		if (ready)
		{
			SECURITY_ATTRIBUTES attributes = baseAttributes;
			attributes.lpSecurityDescriptor = &descriptor;
			// PIPE_ACCESS_DUPLEX already includes READ_CONTROL. CreateNamedPipe
			// accepts WRITE_DAC as an extra flag, but not READ_CONTROL itself.
			if (m_securityClient == INVALID_HANDLE_VALUE)
			{
				m_securityServer = CreateNamedPipeW(name, openMode | WRITE_DAC,
					pipeMode, maxInstances, outputSize, inputSize, timeout, &attributes);
				if (m_securityServer != INVALID_HANDLE_VALUE)
				{
					// This self-connection consumes only the private instance.
					// No client can connect to that already-connected instance,
					// and no PRC listener/worker ever owns it.
					m_securityClient = CreateFileW(name, READ_CONTROL | WRITE_DAC,
						FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
						FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
				}
				if (m_securityClient == INVALID_HANDLE_VALUE)
				{
					error = GetLastError();
					CloseSecurityHandles();
				}
			}
			if (error == ERROR_SUCCESS)
			{
				pipe = CreateNamedPipeW(name, openMode | WRITE_DAC,
					pipeMode, maxInstances, outputSize, inputSize, timeout, &attributes);
				error = pipe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
			}
		}
		else if (error == ERROR_SUCCESS) error = GetLastError();
		if (grantedAcl) LocalFree(grantedAcl);
		if (pipe != INVALID_HANDLE_VALUE) m_serverPipes.push_back(pipe);
		else if (m_serverPipes.empty()) CloseSecurityHandles();
		SetLastError(error);
		return pipe;
	}
	catch (const std::bad_alloc&)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return INVALID_HANDLE_VALUE;
	}
}

void CAppContainerPipeAccess::CloseServerPipe(HANDLE pipe)
{
	PipeAccessLock lock(m_lock);
	std::vector<HANDLE>::iterator found =
		std::find(m_serverPipes.begin(), m_serverPipes.end(), pipe);
	if (found != m_serverPipes.end())
	{
		m_serverPipes.erase(found);
		CloseHandle(pipe);
		if (m_serverPipes.empty()) CloseSecurityHandles();
	}
}
