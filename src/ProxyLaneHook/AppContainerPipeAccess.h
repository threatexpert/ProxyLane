#pragma once

#include <windows.h>
#include <vector>

// Exactly the rights requested by CPRCPipeClient. FILE_GENERIC_WRITE alone
// would also grant FILE_CREATE_PIPE_INSTANCE, which a client must not receive.
const DWORD PROXYLANE_PIPE_CLIENT_ACCESS =
	(FILE_GENERIC_READ | FILE_GENERIC_WRITE) & ~FILE_CREATE_PIPE_INSTANCE;

// An empty SID means an ordinary process (also on XP/Windows 7).
BOOL QueryProcessAppContainerSid(HANDLE process, std::vector<BYTE>& sid);

// Package grants survive a profile restart; server handles are tracked only
// while they are alive.
class CAppContainerPipeAccess
{
public:
	CAppContainerPipeAccess();
	~CAppContainerPipeAccess();
	BOOL AuthorizeProcess(HANDLE process);
	BOOL AuthorizePackageSid(PSID sid);
	HANDLE CreateServerPipe(LPCWSTR name, DWORD openMode, DWORD pipeMode,
		DWORD maxInstances, DWORD outputSize, DWORD inputSize, DWORD timeout,
		const SECURITY_ATTRIBUTES& baseAttributes);
	void CloseServerPipe(HANDLE pipe);

private:
	CAppContainerPipeAccess(const CAppContainerPipeAccess&);
	CAppContainerPipeAccess& operator=(const CAppContainerPipeAccess&);
	CRITICAL_SECTION m_lock;
	std::vector<std::vector<BYTE> > m_packageSids;
	std::vector<HANDLE> m_serverPipes;
	// A connected, private instance keeps a non-synchronous security handle.
	// It never carries PRC messages and never needs a polling worker.
	HANDLE m_securityServer;
	HANDLE m_securityClient;
	void CloseSecurityHandles(); // Caller holds m_lock (or destruction).
};

// Internal DLL-lifetime policy: CGlobalProxy itself is released/recreated on
// Stop/Start. Like the PRC pipe GUID, authorization must outlive those objects.
CAppContainerPipeAccess& GetProxyLanePipeAccess();
