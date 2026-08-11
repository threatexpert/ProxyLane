/************************************************************************/
/*                                                                      */
/*                                                                      */
/************************************************************************/

#include "stdafx.h"
#include "ProxyReceptionCentre.h"
#include "GlobalProxy.h"
#include "ProxyDataHandle.h"
#include "ProxyLog.h"
#include <vector>

#define TIMER_CHECK_REGISTERED_CLIENT 0x100
#define TIMER_CHECK_REGISTERED_CLIENT_INTERVAL 30*1000
#define CHILD_GUARD_MINIMUM_AGE_100NS (60ULL * 1000 * 1000 * 10)

typedef LONG (WINAPI *NtQuerySystemInformationProc)(
	ULONG, PVOID, ULONG, PULONG);
typedef LONG (WINAPI *NtQueryInformationProcessProc)(
	HANDLE, ULONG, PVOID, ULONG, PULONG);

struct ChildGuardUnicodeString
{
	USHORT length;
	USHORT maximumLength;
	PWSTR buffer;
};

struct ChildGuardClientId
{
	HANDLE process;
	HANDLE thread;
};

struct ChildGuardSystemThreadInformation
{
	LARGE_INTEGER kernelTime;
	LARGE_INTEGER userTime;
	LARGE_INTEGER createTime;
	ULONG waitTime;
	PVOID startAddress;
	ChildGuardClientId clientId;
	LONG priority;
	LONG basePriority;
	ULONG contextSwitches;
	ULONG threadState;
	ULONG waitReason;
};

// XP-compatible SYSTEM_PROCESS_INFORMATION layout.  Later systems retained
// these offsets while repurposing several reserved fields.
struct ChildGuardSystemProcessInformation
{
	ULONG nextEntryOffset;
	ULONG numberOfThreads;
	LARGE_INTEGER reserved[3];
	LARGE_INTEGER createTime;
	LARGE_INTEGER userTime;
	LARGE_INTEGER kernelTime;
	ChildGuardUnicodeString imageName;
	LONG basePriority;
	HANDLE processId;
	HANDLE parentProcessId;
	ULONG handleCount;
	ULONG sessionId;
	ULONG_PTR processKey;
	SIZE_T peakVirtualSize;
	SIZE_T virtualSize;
	ULONG pageFaultCount;
	SIZE_T peakWorkingSetSize;
	SIZE_T workingSetSize;
	SIZE_T quotaPeakPagedPoolUsage;
	SIZE_T quotaPagedPoolUsage;
	SIZE_T quotaPeakNonPagedPoolUsage;
	SIZE_T quotaNonPagedPoolUsage;
	SIZE_T pagefileUsage;
	SIZE_T peakPagefileUsage;
	SIZE_T privatePageCount;
	LARGE_INTEGER readOperationCount;
	LARGE_INTEGER writeOperationCount;
	LARGE_INTEGER otherOperationCount;
	LARGE_INTEGER readTransferCount;
	LARGE_INTEGER writeTransferCount;
	LARGE_INTEGER otherTransferCount;
	ChildGuardSystemThreadInformation threads[1];
};

#ifdef _WIN64
C_ASSERT(FIELD_OFFSET(ChildGuardSystemProcessInformation, threads) == 256);
#else
C_ASSERT(FIELD_OFFSET(ChildGuardSystemProcessInformation, threads) == 184);
#endif

struct ChildGuardProcessSnapshot
{
	DWORD processId;
	DWORD parentProcessId;
	DWORD threadId;
	DWORD threadCount;
	ULONGLONG createTime;
	ULONGLONG cpuTime;
	BOOL onlyThreadSuspended;
};

static BOOL QueryChildGuardProcessSnapshot(
	std::map<DWORD, ChildGuardProcessSnapshot>& processes)
{
	HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
	NtQuerySystemInformationProc query = ntdll
		? reinterpret_cast<NtQuerySystemInformationProc>(
			GetProcAddress(ntdll, "NtQuerySystemInformation"))
		: NULL;
	if (!query)
		return FALSE;

	const ULONG systemProcessInformation = 5;
	const LONG statusInfoLengthMismatch = static_cast<LONG>(0xC0000004L);
	ULONG bufferSize = 64 * 1024;
	std::vector<BYTE> buffer;
	LONG status = statusInfoLengthMismatch;
	for (int attempt = 0;
		attempt < 8 && status == statusInfoLengthMismatch;
		++attempt)
	{
		buffer.resize(bufferSize);
		ULONG required = 0;
		status = query(systemProcessInformation, &buffer[0], bufferSize,
			&required);
		if (status == statusInfoLengthMismatch)
		{
			bufferSize = required > bufferSize
				? required + 64 * 1024 : bufferSize * 2;
		}
	}
	if (status < 0 || buffer.empty())
		return FALSE;

	BYTE *address = &buffer[0];
	for (;;)
	{
		ChildGuardSystemProcessInformation *entry =
			reinterpret_cast<ChildGuardSystemProcessInformation *>(address);
		const DWORD pid = static_cast<DWORD>(
			reinterpret_cast<ULONG_PTR>(entry->processId));
		if (pid && entry->createTime.QuadPart > 0)
		{
			ChildGuardProcessSnapshot snapshot = { 0 };
			snapshot.processId = pid;
			snapshot.parentProcessId = static_cast<DWORD>(
				reinterpret_cast<ULONG_PTR>(entry->parentProcessId));
			snapshot.threadCount = entry->numberOfThreads;
			snapshot.createTime =
				static_cast<ULONGLONG>(entry->createTime.QuadPart);
			snapshot.cpuTime =
				static_cast<ULONGLONG>(entry->kernelTime.QuadPart) +
				static_cast<ULONGLONG>(entry->userTime.QuadPart);
			if (entry->numberOfThreads == 1)
			{
				const ChildGuardSystemThreadInformation& thread =
					entry->threads[0];
				snapshot.threadId = static_cast<DWORD>(
					reinterpret_cast<ULONG_PTR>(thread.clientId.thread));
				// Waiting/Suspended and Waiting/WrSuspended occur on different
				// Windows versions and suspension paths.
				snapshot.onlyThreadSuspended = thread.threadState == 5 &&
					(thread.waitReason == 5 || thread.waitReason == 12);
			}
			processes[pid] = snapshot;
		}

		if (!entry->nextEntryOffset)
			break;
		address += entry->nextEntryOffset;
	}
	return TRUE;
}

struct ChildGuardProcessBasicInformation
{
	LONG exitStatus;
	PVOID pebBaseAddress;
	ULONG_PTR affinityMask;
	LONG basePriority;
	ULONG_PTR processId;
	ULONG_PTR parentProcessId;
};

static BOOL ReadRemotePointer(
	HANDLE process,
	ULONG_PTR address,
	BOOL pointer32,
	ULONG_PTR *value)
{
	if (!value || !address)
		return FALSE;
	SIZE_T bytesRead = 0;
	if (pointer32)
	{
		ULONG value32 = 0;
		if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address),
			&value32, sizeof(value32), &bytesRead) ||
			bytesRead != sizeof(value32))
		{
			return FALSE;
		}
		*value = value32;
		return TRUE;
	}
	ULONG_PTR nativeValue = 0;
	if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address),
		&nativeValue, sizeof(nativeValue), &bytesRead) ||
		bytesRead != sizeof(nativeValue))
	{
		return FALSE;
	}
	*value = nativeValue;
	return TRUE;
}

static BOOL ReadRemoteEnvironmentBlock(
	HANDLE process,
	ULONG_PTR environmentAddress,
	std::vector<WCHAR>& environment)
{
	const SIZE_T maximumBytes = 1024 * 1024;
	SIZE_T totalBytes = 0;
	BOOL previousWasNull = FALSE;
	while (totalBytes < maximumBytes)
	{
		MEMORY_BASIC_INFORMATION memoryInfo;
		const ULONG_PTR currentAddress = environmentAddress + totalBytes;
		if (!VirtualQueryEx(process, reinterpret_cast<LPCVOID>(currentAddress),
			&memoryInfo, sizeof(memoryInfo)) ||
			memoryInfo.State != MEM_COMMIT ||
			(memoryInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
		{
			return FALSE;
		}
		const ULONG_PTR regionEnd = reinterpret_cast<ULONG_PTR>(
			memoryInfo.BaseAddress) + memoryInfo.RegionSize;
		SIZE_T bytesToRead = static_cast<SIZE_T>(regionEnd - currentAddress);
		bytesToRead = min(bytesToRead, maximumBytes - totalBytes);
		bytesToRead = min(bytesToRead, static_cast<SIZE_T>(4096));
		bytesToRead -= bytesToRead % sizeof(WCHAR);
		if (!bytesToRead)
			return FALSE;

		const size_t oldSize = environment.size();
		environment.resize(oldSize + bytesToRead / sizeof(WCHAR));
		SIZE_T bytesRead = 0;
		if (!ReadProcessMemory(process,
			reinterpret_cast<LPCVOID>(currentAddress),
			&environment[oldSize], bytesToRead, &bytesRead) || !bytesRead)
		{
			return FALSE;
		}
		environment.resize(oldSize + bytesRead / sizeof(WCHAR));
		for (size_t i = oldSize; i < environment.size(); ++i)
		{
			if (environment[i] == L'\0')
			{
				if (previousWasNull)
				{
					environment.resize(i + 1);
					return TRUE;
				}
				previousWasNull = TRUE;
			}
			else
			{
				previousWasNull = FALSE;
			}
		}
		totalBytes += bytesRead;
	}
	return FALSE;
}

static BOOL RemoteProcessHasChildGuard(
	DWORD processId,
	LPCWSTR markerName)
{
	if (!processId || !markerName || !markerName[0])
		return FALSE;
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE, processId);
	if (!process)
		return FALSE;

	HMODULE kernel32 = GetModuleHandle(_T("kernel32.dll"));
	typedef BOOL (WINAPI *IsWow64ProcessProc)(HANDLE, PBOOL);
	IsWow64ProcessProc isWow64Process = kernel32
		? reinterpret_cast<IsWow64ProcessProc>(
			GetProcAddress(kernel32, "IsWow64Process")) : NULL;
	BOOL targetWow64 = FALSE;
	if (isWow64Process)
		isWow64Process(process, &targetWow64);

#ifndef _WIN64
	BOOL currentWow64 = FALSE;
	if (isWow64Process)
		isWow64Process(GetCurrentProcess(), &currentWow64);
	// ProxyLane32 forwards to ProxyLane64 on x64.  If that invariant is ever
	// broken, skip a 64-bit target rather than interpreting 64-bit pointers.
	if (currentWow64 && !targetWow64)
	{
		CloseHandle(process);
		return FALSE;
	}
#endif

	HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
	NtQueryInformationProcessProc query = ntdll
		? reinterpret_cast<NtQueryInformationProcessProc>(
			GetProcAddress(ntdll, "NtQueryInformationProcess")) : NULL;
	ULONG_PTR pebAddress = 0;
	BOOL pointer32 = FALSE;
	if (query)
	{
#ifdef _WIN64
		if (targetWow64)
		{
			ULONG_PTR wow64Peb = 0;
			if (query(process, 26, &wow64Peb, sizeof(wow64Peb), NULL) >= 0)
			{
				pebAddress = wow64Peb;
				pointer32 = TRUE;
			}
		}
#endif
		if (!pebAddress)
		{
			ChildGuardProcessBasicInformation basicInfo = { 0 };
			if (query(process, 0, &basicInfo, sizeof(basicInfo), NULL) >= 0)
				pebAddress = reinterpret_cast<ULONG_PTR>(basicInfo.pebBaseAddress);
		}
	}

	ULONG_PTR processParameters = 0;
	ULONG_PTR environmentAddress = 0;
	const ULONG_PTR processParametersOffset = pointer32 ? 0x10 :
		(sizeof(void *) == 8 ? 0x20 : 0x10);
	const ULONG_PTR environmentOffset = pointer32 ? 0x48 :
		(sizeof(void *) == 8 ? 0x80 : 0x48);
	BOOL found = FALSE;
	if (pebAddress && ReadRemotePointer(process,
		pebAddress + processParametersOffset, pointer32, &processParameters) &&
		ReadRemotePointer(process, processParameters + environmentOffset,
			pointer32, &environmentAddress))
	{
		std::vector<WCHAR> environment;
		if (ReadRemoteEnvironmentBlock(process, environmentAddress, environment))
		{
			const WCHAR *entry = &environment[0];
			const WCHAR *end = entry + environment.size();
			const size_t markerLength = wcslen(markerName);
			while (entry < end && *entry)
			{
				const size_t remaining = static_cast<size_t>(end - entry);
				size_t length = 0;
				while (length < remaining && entry[length])
					++length;
				if (length > markerLength + 1 &&
					entry[markerLength] == L'=' &&
					_wcsnicmp(entry, markerName, markerLength) == 0 &&
					entry[markerLength + 1] == L'1' &&
					entry[markerLength + 2] == L'\0')
				{
					found = TRUE;
					break;
				}
				entry += length + 1;
			}
		}
	}
	CloseHandle(process);
	return found;
}

static BOOL QueryProcessCreateTime(DWORD processId, ULONGLONG *value)
{
	if (!value)
		return FALSE;
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (!process)
		return FALSE;
	FILETIME created, exited, kernel, user;
	BOOL ok = GetProcessTimes(process, &created, &exited, &kernel, &user);
	CloseHandle(process);
	if (ok)
		*value = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
	return ok;
}

CProxyReceptionCentre::CProxyReceptionCentre(CGlobalProxy *pGlobalProxy)
{
	InitializeCriticalSection(&m_ProcessIdentityLock);
	m_hPRCThread = NULL;
	m_dwPRCThreadId = 0;
	m_PRCWnd = NULL;
	m_hTestEvent = NULL;
	m_pTcpServer = NULL;
	m_pTcpServer6 = NULL;
	m_pUdpServer = NULL;
	m_pPipeServer = NULL;

	m_pGlobalProxy = pGlobalProxy;
	m_pProxyDataHandle = new CProxyDataHandle;
}

CProxyReceptionCentre::~CProxyReceptionCentre(void)
{
	delete m_pProxyDataHandle;
	DeleteCriticalSection(&m_ProcessIdentityLock);
}
//
//BOOL CProxyReceptionCentre::InitPRCWnd()
//{
//	WNDCLASS wndclass;
//	memset(&wndclass, 0, sizeof(wndclass));
//	wndclass.lpfnWndProc = CProxyReceptionCentre::PRCWndProc;
//	wndclass.lpszClassName = _T("PRC_WndClass");
//
//	RegisterClass(&wndclass);
//
//	m_PRCWnd = CreateWindow(_T("PRC_WndClass"), _T("PRC_Wnd"),
//		WS_OVERLAPPEDWINDOW, 0, 0, 0, 0,
//		NULL, NULL, NULL, NULL);
//
//	if(m_PRCWnd == NULL)
//		return FALSE;
//
//	return TRUE;
//}
//
//BOOL CProxyReceptionCentre::ClosePRCWnd()
//{
//	if(::IsWindow(m_PRCWnd))
//	{
//		SendMessage(m_PRCWnd, WM_CLOSE, 0, 0);
//		ATLASSERT(!::IsWindow(m_PRCWnd));
//		m_PRCWnd = NULL;
//		return TRUE;
//	}
//	return FALSE;
//}

void CProxyReceptionCentre::SetThreadStatus(threadstatus status)
{
	m_ThreadStatus = status;
	SetEvent(m_hTestEvent); 
}

LRESULT CALLBACK CProxyReceptionCentre::PRCWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{

	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;

	}
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

BOOL CProxyReceptionCentre::CreatePRC()
{
	ATLASSERT(m_hTestEvent == NULL);

	m_ThreadStatus = threadstatus_inactive;

	WSADATA wsaData;
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		return FALSE;

	m_hTestEvent = CreateEvent(0, 0, 0, 0);
	if(m_hTestEvent == NULL)
	{
		WSACleanup();
		return FALSE;
	}

	m_hPRCThread = CreateThread(0, 0, _PRCThreadProc, this, CREATE_SUSPENDED, &m_dwPRCThreadId);

	if(m_hPRCThread == NULL)
	{
		//szError
		CloseHandle(m_hTestEvent);
		m_hTestEvent = NULL;
		WSACleanup();
		return FALSE;
	}

	if (ResumeThread(m_hPRCThread) == (DWORD)-1)
	{
		if (TerminateThread(m_hPRCThread, 0))
			WaitForSingleObject(m_hPRCThread, INFINITE);
		CloseHandle(m_hPRCThread);
		m_hPRCThread = NULL;
		CloseHandle(m_hTestEvent);
		m_hTestEvent = NULL;
		WSACleanup();
		return FALSE;
	}
	WaitForSingleObject(m_hTestEvent, INFINITE);

	if(m_ThreadStatus != threadstatus_running)
	{
		CloseHandle(m_hPRCThread);
		m_hPRCThread = NULL;
		CloseHandle(m_hTestEvent);
		m_hTestEvent = NULL;
		WSACleanup();
		return FALSE;
	}


	return TRUE;
}

BOOL CProxyReceptionCentre::DestroyPRC()
{
	//close xxxx

	if (m_dwPRCThreadId == GetCurrentThreadId())
	{
		//避免在回调中试图等待自己退出
		ATLASSERT(FALSE);
		return FALSE;
	}

	KillTimer(TIMER_CHECK_REGISTERED_CLIENT);

	//if(!ClosePRCWnd())
	//{
	//	//szError
	//	return FALSE;
	//}
	::PostThreadMessage(m_dwPRCThreadId, WM_QUIT, 0, 0);

	if(m_hTestEvent)
	{
		WaitForSingleObject(m_hTestEvent, INFINITE);
		CloseHandle(m_hTestEvent);
		m_hTestEvent = NULL;
	}

	if(m_hPRCThread)
	{
		WaitForSingleObject(m_hPRCThread, INFINITE);
		CloseHandle(m_hPRCThread);
		m_hPRCThread = NULL;
	}

	ShutdownPRCServer();

	WSACleanup();

	return m_ThreadStatus == threadstatus_end;
}

DWORD WINAPI CProxyReceptionCentre::_PRCThreadProc(LPVOID lParam)
{
	CProxyReceptionCentre *_this = (CProxyReceptionCentre*)lParam;

	return _this->InternalPRCThreadProc();
}

DWORD WINAPI CProxyReceptionCentre::InternalPRCThreadProc()
{
	//if(!InitPRCWnd())
	//{
	//	//szErr
	//	SetThreadStatus(threadstatus_error);
	//	return -1;
	//}

	if(!StartupPRCServer())
	{
		//ClosePRCWnd();
		SetThreadStatus(threadstatus_error);
		return -1;
	}

	SetTimer(TIMER_CHECK_REGISTERED_CLIENT, TIMER_CHECK_REGISTERED_CLIENT_INTERVAL);

	SetThreadStatus(threadstatus_running);

	BOOL bRet;
	MSG msg;

	while( (bRet = GetMessage( &msg, NULL, 0, 0 )) != 0)
	{ 
		if (bRet == -1)
		{
			break;
		}
		else
		{
			TranslateMessage(&msg); 
			DispatchMessage(&msg); 
		}
	}

	SetThreadStatus(threadstatus_end);
	return 0;
}

BOOL CProxyReceptionCentre::StartupPRCServer()
{
	ATLASSERT(m_pTcpServer == NULL && m_pTcpServer6 == NULL && m_pUdpServer == NULL);

	if(!m_pProxyDataHandle)
		return FALSE;

	do 
	{
		m_pTcpServer = new CPRCTcpServer(this);
		if(m_pTcpServer == NULL)
		{
			m_szLastError = _T("Failed to create PRCTcpServer.");
			break;
		}

		if(!m_pTcpServer->StartupServer())
		{
			m_szLastError.Format(_T("Failed to start the IPv4 TCP listener (Winsock %d)."),
				WSAGetLastError());
			break;
		}

		m_pTcpServer6 = new CPRCTcpServer(this, AF_INET6,
			m_pTcpServer->GetTCPTaskMgr());
		if(m_pTcpServer6 == NULL)
		{
			m_szLastError = _T("Failed to create IPv6 PRCTcpServer.");
			break;
		}
		if(!m_pTcpServer6->StartupServer())
		{
			const int ipv6Error = WSAGetLastError();
			if (ipv6Error == WSAEAFNOSUPPORT ||
				ipv6Error == WSAEPROTONOSUPPORT ||
				ipv6Error == WSAEADDRNOTAVAIL ||
				ipv6Error == WSAEINVAL)
			{
				delete m_pTcpServer6;
				m_pTcpServer6 = NULL;
				PrintText(_T("IPv6 loopback is unavailable (Winsock %d); continuing with IPv4 only.\r\n"),
					ipv6Error);
			}
			else
			{
				m_szLastError.Format(_T("Failed to start the IPv6 TCP listener (Winsock %d)."),
					ipv6Error);
				break;
			}
		}

		m_pUdpServer = new CPRCUdpServer(this);
		if(m_pUdpServer == NULL)
		{
			m_szLastError = _T("Failed to create CPRCUdpServer.");
			break;
		}

		if(!m_pUdpServer->StartupServer())
		{
			m_szLastError = _T("Failed to start CPRCUdpServer.");
			break;
		}

		m_pPipeServer = new CPRCPipeServer(this);
		if(m_pPipeServer == NULL)
		{
			m_szLastError = _T("Failed to create CPRCPipeServer.");
			break;
		}

		if(!m_pPipeServer->StartupServer())
		{
			m_szLastError = _T("Failed to start CPRCPipeServer.");
			break;
		}

		return TRUE;

	} while(FALSE);

	ShutdownPRCServer();

	return FALSE;
}

BOOL CProxyReceptionCentre::ShutdownPRCServer()
{
	if(m_pPipeServer)
	{
		m_pPipeServer->ShutdownServer();
		delete m_pPipeServer;
		m_pPipeServer = NULL;
	}
	if(m_pTcpServer6)
	{
		m_pTcpServer6->ShutdownServer();
		delete m_pTcpServer6;
		m_pTcpServer6 = NULL;
	}
	if(m_pTcpServer)
	{
		m_pTcpServer->ShutdownServer();
		delete m_pTcpServer;
		m_pTcpServer = NULL;
	}
	if(m_pUdpServer)
	{
		m_pUdpServer->ShutdownServer();
		delete m_pUdpServer;
		m_pUdpServer = NULL;
	}

	return TRUE;
}

BOOL CProxyReceptionCentre::GetPRCPipeName(LPSTR lpBuf, int bufsize)
{
	if(!m_pPipeServer)
		return FALSE;

	CStringA szPipeName = (CStringA)m_pPipeServer->GetPipeName();
	if(!szPipeName.GetLength() || szPipeName.GetLength()>=bufsize)
		return FALSE;

	strcpy(lpBuf, szPipeName.GetBuffer());
	return TRUE;
}

IProxyTaskMgr* CProxyReceptionCentre::GetPTMInstance(int type)
{
	if(type == 0)//tcp
	{
		if(m_pTcpServer)
			return m_pTcpServer->GetPTMInstance();
		else
			return NULL;
	}else if(type == 1)//udp
	{
		if(m_pUdpServer)
			return m_pUdpServer->GetPTMInstance();
		else
			return NULL;
	}else
		return NULL;
}

IProxyDataHandle* CProxyReceptionCentre::GetPDHInstance()
{
	return m_pProxyDataHandle;
}

BOOL CProxyReceptionCentre::RegisterProcessIdentity(
	LPHookProcessIdentityInfo identity)
{
	if (!identity || !identity->dwProcessId || !identity->processCreateTime ||
		!identity->szAppPath[0])
		return FALSE;

	HookProcessIdentityInfo safeIdentity = *identity;
	safeIdentity.szAppPath[_countof(safeIdentity.szAppPath) - 1] = L'\0';

	EnterCriticalSection(&m_ProcessIdentityLock);
	m_ProcessIdentities[safeIdentity.dwProcessId] = safeIdentity;
	LeaveCriticalSection(&m_ProcessIdentityLock);
	return TRUE;
}

BOOL CProxyReceptionCentre::RegisterReleasedChild(LPHookNewProcessInfo child)
{
	if (!child || !child->dwProcessId || !child->processCreateTime)
		return FALSE;

	ULONGLONG actual = 0;
	if (QueryProcessCreateTime(child->dwProcessId, &actual) &&
		actual != child->processCreateTime)
	{
		return FALSE;
	}

	EnterCriticalSection(&m_ProcessIdentityLock);
	m_ReleasedChildren[child->dwProcessId] = child->processCreateTime;
	LeaveCriticalSection(&m_ProcessIdentityLock);
	return TRUE;
}

BOOL CProxyReceptionCentre::GetProcessIdentity(
	DWORD processId,
	LPWSTR appPath,
	DWORD appPathCount)
{
	if (!processId || !appPath || appPathCount == 0)
		return FALSE;
	appPath[0] = L'\0';

	BOOL found = FALSE;
	EnterCriticalSection(&m_ProcessIdentityLock);
	std::map<DWORD, HookProcessIdentityInfo>::const_iterator it =
		m_ProcessIdentities.find(processId);
	if (it != m_ProcessIdentities.end())
	{
		ULONGLONG actual = 0;
		if (!QueryProcessCreateTime(processId, &actual) ||
			actual == it->second.processCreateTime)
		{
			wcsncpy(appPath, it->second.szAppPath, appPathCount - 1);
			appPath[appPathCount - 1] = L'\0';
			found = appPath[0] != L'\0';
		}
	}
	LeaveCriticalSection(&m_ProcessIdentityLock);
	return found;
}


BOOL CProxyReceptionCentre::GetStartupInfo(LPPRCINFO lpStartupInfo)
{
	if (!lpStartupInfo)
		return FALSE;
	ZeroMemory(lpStartupInfo, sizeof(*lpStartupInfo));

	if(m_pTcpServer == NULL)
	{
		m_szLastError = _T("PRCTcpServer has not been created.");
		return FALSE;
	}

	INT addlen = sizeof(lpStartupInfo->tcpaddr);
	if(!m_pTcpServer->GetSockName(&lpStartupInfo->tcpaddr, &addlen))
	{
		m_szLastError = _T("GetSockName failed.");
		return FALSE;
	}
	if (m_pTcpServer6)
	{
		addlen = sizeof(lpStartupInfo->tcpaddr6);
		if(!m_pTcpServer6->GetSockName(&lpStartupInfo->tcpaddr6, &addlen))
		{
			m_szLastError = _T("Get IPv6 SockName failed.");
			return FALSE;
		}
	}

	GetProxyLaneChildGuardInfo(
		lpStartupInfo->childGuardName,
		_countof(lpStartupInfo->childGuardName),
		&lpStartupInfo->childGuardGenerationTime);

	//udp

	return TRUE;
}

BOOL CProxyReceptionCentre::IsFiltered(LPPRCClient lpClient)
{
	return FALSE;
}

BOOL CProxyReceptionCentre::IsFiltered(LPPRCClientInfo lpClientInfo)
{
	return FALSE;
}

BOOL CProxyReceptionCentre::RegisterClient(LPPRCClient lpClientInfo)
{
	if (!lpClientInfo || !lpClientInfo->dwPid ||
		!lpClientInfo->processCreateTime || !lpClientInfo->socketGeneration)
		return FALSE;
	ULONGLONG actual = 0;
	if (QueryProcessCreateTime(lpClientInfo->dwPid, &actual) &&
		actual != lpClientInfo->processCreateTime)
		return FALSE;
	if(lpClientInfo->sType == SOCK_STREAM)
		return RegisterTCPClient(lpClientInfo);
	else if(lpClientInfo->sType == SOCK_DGRAM)
		return RegisterUDPClient(lpClientInfo);
	else
		return FALSE;
}

BOOL CProxyReceptionCentre::RegisterTCPClient(LPPRCClient lpClientInfo)
{
	if(IsFiltered(lpClientInfo))
		return FALSE;

	CTSList<PRCClient>::critical lc = m_RegisteredClient;
	lpClientInfo->reserved = GetTickCount();
	for(list<PRCClient>::iterator it=m_RegisteredClient.begin(); it!=m_RegisteredClient.end(); it++)
	{
		//may be?
		if(lpClientInfo->dwPid == it->dwPid &&
			lpClientInfo->processCreateTime == it->processCreateTime &&
			lpClientInfo->socketGeneration == it->socketGeneration &&
			lpClientInfo->s == it->s)
		{
			*it = *lpClientInfo;
			return TRUE;
		}

	}

	m_RegisteredClient.push_back(*lpClientInfo);
	return TRUE;
}

BOOL CProxyReceptionCentre::RegisterUDPClient(LPPRCClient lpClientInfo)
{
	return m_pUdpServer->OnRegister(lpClientInfo);
}

BOOL CProxyReceptionCentre::GetUDPClientPortState(UDPLocalProxyAddrInfo *pLPAI)
{
	return m_pUdpServer->GetUDPPortState(pLPAI);
}

BOOL CProxyReceptionCentre::UnregisterClient(LPPRCClient lpClientInfo)
{
	if(lpClientInfo->sType == SOCK_STREAM)
	{
		CTSList<PRCClient>::critical lc = m_RegisteredClient;
		for(list<PRCClient>::iterator it=m_RegisteredClient.begin(); it!=m_RegisteredClient.end(); )
		{
			if(lpClientInfo->s == it->s && lpClientInfo->dwPid == it->dwPid &&
				lpClientInfo->processCreateTime == it->processCreateTime &&
				lpClientInfo->socketGeneration == it->socketGeneration)
			{
				m_RegisteredClient.erase(it++);
			}else
			{
				it++;
			}

		}
	}
	else if(lpClientInfo->sType == SOCK_DGRAM)
	{
		return m_pUdpServer->OnUnregister(lpClientInfo);
	}
	
	return FALSE;
}

BOOL CProxyReceptionCentre::GetClientInfo(SOCKET accepted, LPPRCClient lpClientInfo, BOOL bpop/* =FALSE */)
{
	_SockAddr sa1;
	int len = sizeof(_SockAddr);
	if(getpeername(accepted, &sa1, &len) != 0)
		return FALSE;

	CTSList<PRCClient>::critical lc = m_RegisteredClient;
	for(list<PRCClient>::iterator it=m_RegisteredClient.begin(); it!=m_RegisteredClient.end(); it++)
	{
		//端口一致
		if(sa1.sa_family == it->srcAddr.sa_family &&
			sa1.GetPort() == it->srcAddr.GetPort())
		{
			//bind的时候地址为0则不匹配地址
			if(it->srcAddr.IsAny() || sa1.SameAddress(it->srcAddr))
			{
				*lpClientInfo = *it;
				if(bpop)
					m_RegisteredClient.erase(it);
				return TRUE;
			}
		}
		/////////////////////////////////////////////
		//_SockAddr sa2;
		//len = sizeof(_SockAddr);
		//if(getsockname(it->s, &sa2, &len) == 0)
		//{
		//	if(sa1 == sa2)
		//	{
		//		lpClientInfo->zero();
		//		lpClientInfo->s = it->s;
		//		lpClientInfo->dstAddr = it->dstAddr;
		//		strncpy(lpClientInfo->szDomainName, it->szDomainName, sizeof(lpClientInfo->szDomainName));

		//		if(bpop)
		//			m_RegisteredClient.erase(it);
		//		return TRUE;
		//	}
		//}
		/////////////////////////////////////////////

	}

	return FALSE;
	//return m_pPipeServer->GetClientInfo(accepted, lpClientInfo, bpop);
}

VOID CProxyReceptionCentre::OnTimer(UINT_PTR nIDEvent)
{

	switch(nIDEvent)
	{
	case TIMER_CHECK_REGISTERED_CLIENT:
		{
			{
				CTSList<PRCClient>::critical lc = m_RegisteredClient;
				for(list<PRCClient>::iterator it=m_RegisteredClient.begin(); it!=m_RegisteredClient.end();)
				{
					PRCClient &prcclient = *it;

					if(GetTickCount() - prcclient.reserved > 60*1000)
					{
						//kick out
						it = m_RegisteredClient.erase(it);
					}else
					{
						it++;
					}
				}
			}
			CheckSuspendedChildren();
		}
		break;

	default:
		break;
	}


}

void CProxyReceptionCentre::CheckSuspendedChildren()
{
	WCHAR markerName[64] = L"";
	ULONGLONG markerGenerationTime = 0;
	if (!GetProxyLaneChildGuardInfo(markerName, _countof(markerName),
		&markerGenerationTime))
	{
		return;
	}

	std::map<DWORD, ChildGuardProcessSnapshot> processes;
	if (!QueryChildGuardProcessSnapshot(processes))
		return;

	// Keep normal-release and successful-Hook exclusions only for the exact
	// lifetime of the corresponding PID.  This prevents historical records
	// from accumulating and also handles PID reuse safely.
	EnterCriticalSection(&m_ProcessIdentityLock);
	for (std::map<DWORD, HookProcessIdentityInfo>::iterator it =
		m_ProcessIdentities.begin(); it != m_ProcessIdentities.end();)
	{
		std::map<DWORD, ChildGuardProcessSnapshot>::const_iterator current =
			processes.find(it->first);
		if (current == processes.end() ||
			current->second.createTime != it->second.processCreateTime)
			m_ProcessIdentities.erase(it++);
		else
			++it;
	}
	for (std::map<DWORD, ULONGLONG>::iterator it =
		m_ReleasedChildren.begin(); it != m_ReleasedChildren.end();)
	{
		std::map<DWORD, ChildGuardProcessSnapshot>::const_iterator current =
			processes.find(it->first);
		if (current == processes.end() || current->second.createTime != it->second)
			m_ReleasedChildren.erase(it++);
		else
			++it;
	}
	LeaveCriticalSection(&m_ProcessIdentityLock);

	for (std::map<DWORD, SuspendedChildObservation>::iterator it =
		m_SuspendedChildObservations.begin();
		it != m_SuspendedChildObservations.end();)
	{
		std::map<DWORD, ChildGuardProcessSnapshot>::const_iterator current =
			processes.find(it->first);
		if (current == processes.end() ||
			current->second.createTime != it->second.processCreateTime)
			m_SuspendedChildObservations.erase(it++);
		else
			++it;
	}
	for (std::map<DWORD, ULONGLONG>::iterator it =
		m_ProcessedSuspendedChildren.begin();
		it != m_ProcessedSuspendedChildren.end();)
	{
		std::map<DWORD, ChildGuardProcessSnapshot>::const_iterator current =
			processes.find(it->first);
		if (current == processes.end() || current->second.createTime != it->second)
			m_ProcessedSuspendedChildren.erase(it++);
		else
			++it;
	}

	FILETIME nowFileTime;
	GetSystemTimeAsFileTime(&nowFileTime);
	const ULONGLONG now =
		(static_cast<ULONGLONG>(nowFileTime.dwHighDateTime) << 32) |
		nowFileTime.dwLowDateTime;
	std::map<DWORD, SuspendedChildObservation> nextObservations;

	for (std::map<DWORD, ChildGuardProcessSnapshot>::const_iterator it =
		processes.begin(); it != processes.end(); ++it)
	{
		const ChildGuardProcessSnapshot& child = it->second;
		if (child.createTime < markerGenerationTime ||
			now < child.createTime ||
			now - child.createTime < CHILD_GUARD_MINIMUM_AGE_100NS ||
			child.threadCount != 1 || !child.onlyThreadSuspended ||
			!child.threadId)
		{
			continue;
		}

		// The original parent must be gone.  A PID that now has a creation time
		// newer than the child is a reused PID and is treated as gone as well.
		std::map<DWORD, ChildGuardProcessSnapshot>::const_iterator parent =
			processes.find(child.parentProcessId);
		if (child.parentProcessId && parent != processes.end() &&
			parent->second.createTime <= child.createTime)
		{
			continue;
		}

		BOOL excluded = FALSE;
		EnterCriticalSection(&m_ProcessIdentityLock);
		std::map<DWORD, HookProcessIdentityInfo>::const_iterator identity =
			m_ProcessIdentities.find(child.processId);
		if (identity != m_ProcessIdentities.end() &&
			identity->second.processCreateTime == child.createTime)
		{
			excluded = TRUE;
		}
		std::map<DWORD, ULONGLONG>::const_iterator released =
			m_ReleasedChildren.find(child.processId);
		if (released != m_ReleasedChildren.end() &&
			released->second == child.createTime)
		{
			excluded = TRUE;
		}
		LeaveCriticalSection(&m_ProcessIdentityLock);
		std::map<DWORD, ULONGLONG>::const_iterator processed =
			m_ProcessedSuspendedChildren.find(child.processId);
		if (excluded || (processed != m_ProcessedSuspendedChildren.end() &&
			processed->second == child.createTime))
		{
			continue;
		}

		if (!RemoteProcessHasChildGuard(child.processId, markerName))
			continue;

		SuspendedChildObservation observation = { 0 };
		observation.processCreateTime = child.createTime;
		observation.cpuTime = child.cpuTime;
		observation.consecutiveChecks = 1;
		std::map<DWORD, SuspendedChildObservation>::const_iterator previous =
			m_SuspendedChildObservations.find(child.processId);
		if (previous != m_SuspendedChildObservations.end() &&
			previous->second.processCreateTime == child.createTime &&
			previous->second.cpuTime == child.cpuTime)
		{
			observation.consecutiveChecks =
				previous->second.consecutiveChecks + 1;
		}
		nextObservations[child.processId] = observation;
		if (observation.consecutiveChecks < 2)
			continue;

		// Re-read all volatile facts immediately before terminating the process.
		std::map<DWORD, ChildGuardProcessSnapshot> recheckProcesses;
		if (!QueryChildGuardProcessSnapshot(recheckProcesses))
			continue;
		std::map<DWORD, ChildGuardProcessSnapshot>::const_iterator recheck =
			recheckProcesses.find(child.processId);
		if (recheck == recheckProcesses.end() ||
			recheck->second.createTime != child.createTime ||
			recheck->second.threadCount != 1 ||
			!recheck->second.onlyThreadSuspended ||
			recheck->second.threadId != child.threadId ||
			recheck->second.cpuTime != child.cpuTime ||
			!RemoteProcessHasChildGuard(child.processId, markerName))
		{
			continue;
		}

		HANDLE process = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
			FALSE, child.processId);
		if (!process)
			continue;
		FILETIME created = { 0 }, exited = { 0 }, kernel = { 0 }, user = { 0 };
		if (!GetProcessTimes(process, &created, &exited, &kernel, &user) ||
			((static_cast<ULONGLONG>(created.dwHighDateTime) << 32) |
				created.dwLowDateTime) != child.createTime)
		{
			CloseHandle(process);
			continue;
		}
		BOOL releaseWasRegistered = FALSE;
		EnterCriticalSection(&m_ProcessIdentityLock);
		std::map<DWORD, HookProcessIdentityInfo>::const_iterator finalIdentity =
			m_ProcessIdentities.find(child.processId);
		std::map<DWORD, ULONGLONG>::const_iterator finalRelease =
			m_ReleasedChildren.find(child.processId);
		releaseWasRegistered =
			(finalIdentity != m_ProcessIdentities.end() &&
				finalIdentity->second.processCreateTime == child.createTime) ||
			(finalRelease != m_ReleasedChildren.end() &&
				finalRelease->second == child.createTime);
		LeaveCriticalSection(&m_ProcessIdentityLock);
		if (releaseWasRegistered)
		{
			CloseHandle(process);
			continue;
		}

		if (!TerminateProcess(process, ERROR_PROCESS_ABORTED))
		{
			const DWORD error = GetLastError();
			CloseHandle(process);
			PrintText(_T("Failed to terminate orphaned suspended child: PID %lu, thread %lu, error %lu.\r\n"),
				child.processId, child.threadId, error);
			continue;
		}
		CloseHandle(process);

		m_ProcessedSuspendedChildren[child.processId] = child.createTime;
		PrintText(_T("Terminated orphaned suspended child: PID %lu, thread %lu.\r\n"),
			child.processId, child.threadId);
	}

	m_SuspendedChildObservations.swap(nextObservations);
}

BOOL CProxyReceptionCentre::GetProxySettingsInfo(LPProxySettingsInfo lpPSI)
{
	IProxySettings* pPS = m_pGlobalProxy->GetSettingsInstance();

	if (!pPS)
	{
		return FALSE;
	}

	return pPS->GetProxySettings(lpPSI);
}


BOOL CProxyReceptionCentre::GetProxyInfo(LPPRCClient lpClientInfo, LPProxyInfo lpPI)
{
	IProxySettings* pPS = m_pGlobalProxy->GetSettingsInstance();

	if (!pPS)
	{
		return FALSE;
	}

	return pPS->GetProxyInfo(lpClientInfo, lpPI);
}
