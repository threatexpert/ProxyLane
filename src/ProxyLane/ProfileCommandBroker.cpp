#include "stdafx.h"
#include "ProfileCommandBroker.h"

#include <Aclapi.h>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

namespace
{
	const DWORD kCommandMagic = 0x434C5050; // PPLC
	const DWORD kCommandVersion = 1;
	const DWORD kMaxCommandBytes = 60 * 1024;
	const DWORD kMaxProfileChars = 255;
	const DWORD kMaxTargetChars = 32767;
	const DWORD kMaxArguments = 128;

	struct CommandHeader
	{
		DWORD magic;
		DWORD version;
		DWORD totalBytes;
		DWORD profileChars;
		DWORD targetChars;
		DWORD argumentCount;
	};

	struct CommandResponse
	{
		DWORD magic;
		DWORD version;
		DWORD size;
		int exitCode;
	};

	class CCurrentUserSecurity
	{
	public:
		CCurrentUserSecurity()
			: m_tokenUser(NULL)
			, m_systemSid(NULL)
			, m_acl(NULL)
			, m_valid(FALSE)
		{
			ZeroMemory(&m_attributes, sizeof(m_attributes));
			ZeroMemory(&m_descriptor, sizeof(m_descriptor));
		}

		~CCurrentUserSecurity()
		{
			if (m_acl)
				LocalFree(m_acl);
			if (m_systemSid)
				FreeSid(m_systemSid);
			delete[] reinterpret_cast<BYTE*>(m_tokenUser);
		}

		BOOL Initialize()
		{
			HANDLE token = NULL;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
				return FALSE;

			DWORD required = 0;
			GetTokenInformation(token, TokenUser, NULL, 0, &required);
			if (!required)
			{
				CloseHandle(token);
				return FALSE;
			}

			m_tokenUser = reinterpret_cast<PTOKEN_USER>(new BYTE[required]);
			if (!m_tokenUser || !GetTokenInformation(
				token, TokenUser, m_tokenUser, required, &required))
			{
				CloseHandle(token);
				return FALSE;
			}
			CloseHandle(token);

			SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
			if (!AllocateAndInitializeSid(
				&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
				0, 0, 0, 0, 0, 0, 0, &m_systemSid))
			{
				return FALSE;
			}

			EXPLICIT_ACCESS entries[2];
			ZeroMemory(entries, sizeof(entries));
			for (int i = 0; i < 2; ++i)
			{
				entries[i].grfAccessPermissions = GENERIC_ALL;
				entries[i].grfAccessMode = SET_ACCESS;
				entries[i].grfInheritance = NO_INHERITANCE;
				entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
				entries[i].Trustee.TrusteeType = TRUSTEE_IS_USER;
			}
			entries[0].Trustee.ptstrName = reinterpret_cast<LPTSTR>(m_tokenUser->User.Sid);
			entries[1].Trustee.ptstrName = reinterpret_cast<LPTSTR>(m_systemSid);

			if (SetEntriesInAcl(_countof(entries), entries, NULL, &m_acl) != ERROR_SUCCESS)
				return FALSE;
			if (!InitializeSecurityDescriptor(&m_descriptor, SECURITY_DESCRIPTOR_REVISION) ||
				!SetSecurityDescriptorDacl(&m_descriptor, TRUE, m_acl, FALSE))
			{
				return FALSE;
			}

			m_attributes.nLength = sizeof(m_attributes);
			m_attributes.lpSecurityDescriptor = &m_descriptor;
			m_attributes.bInheritHandle = FALSE;
			m_valid = TRUE;
			return TRUE;
		}

		LPSECURITY_ATTRIBUTES Get()
		{
			return m_valid ? &m_attributes : NULL;
		}

	private:
		PTOKEN_USER m_tokenUser;
		PSID m_systemSid;
		PACL m_acl;
		SECURITY_DESCRIPTOR m_descriptor;
		SECURITY_ATTRIBUTES m_attributes;
		BOOL m_valid;
	};

	void HashBytes(ULONGLONG& hash, const BYTE* bytes, size_t length, ULONGLONG prime)
	{
		for (size_t i = 0; i < length; ++i)
		{
			hash ^= bytes[i];
			hash *= prime;
		}
	}

		BOOL BuildProfileObjectNames(
		LPCTSTR profileName,
		CString& pipeName,
		CString& mutexName)
	{
		CString normalized(profileName ? profileName : _T(""));
		normalized.Trim();
		normalized.MakeLower();
		if (normalized.IsEmpty())
			return FALSE;

		TCHAR modulePath[MAX_PATH] = { 0 };
		DWORD moduleLength = GetModuleFileName(NULL, modulePath, _countof(modulePath));
		if (!moduleLength || moduleLength >= _countof(modulePath))
			return FALSE;
		CString installationPath(modulePath);
		int separator = installationPath.ReverseFind(_T('\\'));
		if (separator >= 0)
			installationPath = installationPath.Left(separator);
		installationPath.TrimRight(_T("\\/"));
		installationPath.MakeLower();
		if (installationPath.IsEmpty())
			return FALSE;

		HANDLE token = NULL;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
			return FALSE;
		DWORD required = 0;
		GetTokenInformation(token, TokenUser, NULL, 0, &required);
		std::vector<BYTE> tokenBuffer(required);
		if (!required || !GetTokenInformation(
			token, TokenUser, &tokenBuffer[0], required, &required))
		{
			CloseHandle(token);
			return FALSE;
		}
		CloseHandle(token);

		PTOKEN_USER tokenUser = reinterpret_cast<PTOKEN_USER>(&tokenBuffer[0]);
		const DWORD sidLength = GetLengthSid(tokenUser->User.Sid);
		DWORD sessionId = 0;
		ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

		ULONGLONG hash1 = 14695981039346656037ui64;
		ULONGLONG hash2 = 1099511628211ui64 ^ 0x9E3779B97F4A7C15ui64;
		const BYTE* profileBytes = reinterpret_cast<const BYTE*>((LPCTSTR)normalized);
		const size_t profileBytesLength = normalized.GetLength() * sizeof(TCHAR);
		const BYTE* installationBytes =
			reinterpret_cast<const BYTE*>((LPCTSTR)installationPath);
		const size_t installationBytesLength =
			installationPath.GetLength() * sizeof(TCHAR);
		HashBytes(hash1, profileBytes, profileBytesLength, 1099511628211ui64);
		HashBytes(hash2, profileBytes, profileBytesLength, 14029467366897019727ui64);
		HashBytes(hash1, installationBytes, installationBytesLength, 1099511628211ui64);
		HashBytes(hash2, installationBytes, installationBytesLength,
			14029467366897019727ui64);
		HashBytes(hash1, reinterpret_cast<const BYTE*>(tokenUser->User.Sid), sidLength,
			1099511628211ui64);
		HashBytes(hash2, reinterpret_cast<const BYTE*>(tokenUser->User.Sid), sidLength,
			14029467366897019727ui64);
		HashBytes(hash1, reinterpret_cast<const BYTE*>(&sessionId), sizeof(sessionId),
			1099511628211ui64);
		HashBytes(hash2, reinterpret_cast<const BYTE*>(&sessionId), sizeof(sessionId),
			14029467366897019727ui64);

		CString suffix;
		suffix.Format(_T("%016I64X%016I64X"), hash1, hash2);
		pipeName = _T("\\\\.\\pipe\\ProxyLane.ProfileCommand.") + suffix;
		mutexName = _T("Local\\ProxyLane.ProfileLaunch.") + suffix;
		return TRUE;
	}

	void AppendDword(std::vector<BYTE>& bytes, DWORD value)
	{
		const BYTE* data = reinterpret_cast<const BYTE*>(&value);
		bytes.insert(bytes.end(), data, data + sizeof(value));
	}

	BOOL AppendString(std::vector<BYTE>& bytes, const CString& value, DWORD maxChars)
	{
		if (value.GetLength() < 0 || static_cast<DWORD>(value.GetLength()) > maxChars)
			return FALSE;
		AppendDword(bytes, static_cast<DWORD>(value.GetLength()));
		const BYTE* data = reinterpret_cast<const BYTE*>((LPCTSTR)value);
		bytes.insert(bytes.end(), data, data + value.GetLength() * sizeof(TCHAR));
		return bytes.size() <= kMaxCommandBytes;
	}

	BOOL ReadDword(const BYTE*& cursor, const BYTE* end, DWORD& value)
	{
		if (end - cursor < static_cast<ptrdiff_t>(sizeof(value)))
			return FALSE;
		memcpy(&value, cursor, sizeof(value));
		cursor += sizeof(value);
		return TRUE;
	}

	BOOL ReadString(
		const BYTE*& cursor,
		const BYTE* end,
		CString& value,
		DWORD maxChars)
	{
		DWORD chars = 0;
		if (!ReadDword(cursor, end, chars) || chars > maxChars ||
			static_cast<ULONGLONG>(end - cursor) <
			static_cast<ULONGLONG>(chars) * sizeof(TCHAR))
		{
			return FALSE;
		}
		if (chars)
			value.SetString(reinterpret_cast<LPCTSTR>(cursor), chars);
		else
			value.Empty();
		cursor += chars * sizeof(TCHAR);
		return TRUE;
	}

	BOOL SerializeCommand(
		const AutomationOptions& options,
		std::vector<BYTE>& bytes)
	{
		if (options.targetArguments.size() > kMaxArguments)
			return FALSE;

		bytes.clear();
		CommandHeader header = { 0 };
		header.magic = kCommandMagic;
		header.version = kCommandVersion;
		header.argumentCount = static_cast<DWORD>(options.targetArguments.size());
		bytes.resize(sizeof(header));
		if (!AppendString(bytes, options.profileName, kMaxProfileChars) ||
			!AppendString(bytes, options.targetPath, kMaxTargetChars))
		{
			return FALSE;
		}
		for (size_t i = 0; i < options.targetArguments.size(); ++i)
		{
			if (!AppendString(bytes, options.targetArguments[i], kMaxTargetChars))
				return FALSE;
		}
		header.totalBytes = static_cast<DWORD>(bytes.size());
		header.profileChars = static_cast<DWORD>(options.profileName.GetLength());
		header.targetChars = static_cast<DWORD>(options.targetPath.GetLength());
		memcpy(&bytes[0], &header, sizeof(header));
		return bytes.size() <= kMaxCommandBytes;
	}

	BOOL ParseCommand(
		const BYTE* bytes,
		DWORD byteCount,
		AutomationOptions& options)
	{
		if (!bytes || byteCount < sizeof(CommandHeader))
			return FALSE;
		CommandHeader header;
		memcpy(&header, bytes, sizeof(header));
		if (header.magic != kCommandMagic || header.version != kCommandVersion ||
			header.totalBytes != byteCount || byteCount > kMaxCommandBytes ||
			header.argumentCount > kMaxArguments)
		{
			return FALSE;
		}

		const BYTE* cursor = bytes + sizeof(header);
		const BYTE* end = bytes + byteCount;
		if (!ReadString(cursor, end, options.profileName, kMaxProfileChars) ||
			!ReadString(cursor, end, options.targetPath, kMaxTargetChars) ||
			header.profileChars != static_cast<DWORD>(options.profileName.GetLength()) ||
			header.targetChars != static_cast<DWORD>(options.targetPath.GetLength()))
		{
			return FALSE;
		}
		for (DWORD i = 0; i < header.argumentCount; ++i)
		{
			CString argument;
			if (!ReadString(cursor, end, argument, kMaxTargetChars))
				return FALSE;
			options.targetArguments.push_back(argument);
		}
		options.enabled = TRUE;
		return cursor == end;
	}

	BOOL WaitForOverlappedIo(
		HANDLE pipeHandle,
		HANDLE stopEvent,
		OVERLAPPED& overlapped,
		BOOL operationStarted,
		DWORD initialError,
		DWORD& transferred)
	{
		if (operationStarted)
			return TRUE;
		if (initialError != ERROR_IO_PENDING)
			return FALSE;
		HANDLE waits[] = { stopEvent, overlapped.hEvent };
		DWORD waitResult = WaitForMultipleObjects(_countof(waits), waits, FALSE, INFINITE);
		if (waitResult == WAIT_OBJECT_0)
		{
			CancelIo(pipeHandle);
			// OVERLAPPED and its event must remain alive until the cancelled I/O
			// has completed, including on Windows XP.
			WaitForSingleObject(overlapped.hEvent, INFINITE);
			GetOverlappedResult(pipeHandle, &overlapped, &transferred, FALSE);
			return FALSE;
		}
		if (waitResult != WAIT_OBJECT_0 + 1)
			return FALSE;
		return GetOverlappedResult(pipeHandle, &overlapped, &transferred, FALSE);
	}

	BOOL ReadPipeMessage(
		HANDLE pipeHandle,
		HANDLE stopEvent,
		BYTE* buffer,
		DWORD capacity,
		DWORD& bytesRead)
	{
		OVERLAPPED overlapped = { 0 };
		overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!overlapped.hEvent)
			return FALSE;
		BOOL started = ReadFile(pipeHandle, buffer, capacity, &bytesRead, &overlapped);
		DWORD error = started ? ERROR_SUCCESS : GetLastError();
		BOOL result = WaitForOverlappedIo(
			pipeHandle, stopEvent, overlapped, started, error, bytesRead);
		CloseHandle(overlapped.hEvent);
		return result;
	}

	BOOL WritePipeMessage(
		HANDLE pipeHandle,
		HANDLE stopEvent,
		const void* buffer,
		DWORD bytesToWrite)
	{
		OVERLAPPED overlapped = { 0 };
		overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!overlapped.hEvent)
			return FALSE;
		DWORD bytesWritten = 0;
		BOOL started = WriteFile(
			pipeHandle, buffer, bytesToWrite, &bytesWritten, &overlapped);
		DWORD error = started ? ERROR_SUCCESS : GetLastError();
		BOOL result = WaitForOverlappedIo(
			pipeHandle, stopEvent, overlapped, started, error, bytesWritten) &&
			bytesWritten == bytesToWrite;
		CloseHandle(overlapped.hEvent);
		return result;
	}
}

CProfileCommandRequest::CProfileCommandRequest()
	: references(2)
	, cancelled(FALSE)
	, completedEvent(CreateEvent(NULL, TRUE, FALSE, NULL))
	, exitCode(AUTOMATION_EXIT_CREATE_PROCESS_FAILED)
{
}

CProfileCommandRequest::~CProfileCommandRequest()
{
	if (completedEvent)
		CloseHandle(completedEvent);
}

void CProfileCommandRequest::AddRef()
{
	InterlockedIncrement(&references);
}

void CProfileCommandRequest::Release()
{
	if (InterlockedDecrement(&references) == 0)
		delete this;
}

CProfileCommandBroker::CProfileCommandBroker()
	: m_notifyWindow(NULL)
	, m_stopEvent(NULL)
	, m_readyEvent(NULL)
	, m_serverThread(NULL)
	, m_launchGate(NULL)
	, m_serverReady(FALSE)
{
}

CProfileCommandBroker::~CProfileCommandBroker()
{
	StopServer();
	ReleaseLaunchGate();
}

ProfileCommandForwardResult CProfileCommandBroker::Forward(
	const AutomationOptions& options,
	int& exitCode)
{
	exitCode = AUTOMATION_EXIT_COMMAND_FORWARD_FAILED;
	CString pipeName;
	CString mutexName;
	if (!BuildProfileObjectNames(options.profileName, pipeName, mutexName))
		return PROFILE_COMMAND_TRANSPORT_FAILED;

	HANDLE pipeHandle = CreateFile(
		pipeName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (pipeHandle == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY)
	{
		if (WaitNamedPipe(pipeName, 5000))
		{
			pipeHandle = CreateFile(
				pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL,
				OPEN_EXISTING, 0, NULL);
		}
	}
	if (pipeHandle == INVALID_HANDLE_VALUE)
	{
		DWORD error = GetLastError();
		if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
		{
			return PROFILE_COMMAND_NOT_FOUND;
		}
		return PROFILE_COMMAND_TRANSPORT_FAILED;
	}

	DWORD mode = PIPE_READMODE_MESSAGE;
	if (!SetNamedPipeHandleState(pipeHandle, &mode, NULL, NULL))
	{
		CloseHandle(pipeHandle);
		return PROFILE_COMMAND_TRANSPORT_FAILED;
	}

	std::vector<BYTE> request;
	if (!SerializeCommand(options, request))
	{
		CloseHandle(pipeHandle);
		exitCode = AUTOMATION_EXIT_INVALID_COMMAND_LINE;
		return PROFILE_COMMAND_TRANSPORT_FAILED;
	}
	DWORD written = 0;
	if (!WriteFile(pipeHandle, &request[0], static_cast<DWORD>(request.size()),
		&written, NULL) || written != request.size())
	{
		CloseHandle(pipeHandle);
		return PROFILE_COMMAND_TRANSPORT_FAILED;
	}

	CommandResponse response = { 0 };
	DWORD bytesRead = 0;
	BOOL readResult = ReadFile(
		pipeHandle, &response, sizeof(response), &bytesRead, NULL);
	CloseHandle(pipeHandle);
	if (!readResult || bytesRead != sizeof(response) ||
		response.magic != kCommandMagic || response.version != kCommandVersion ||
		response.size != sizeof(response))
	{
		return PROFILE_COMMAND_TRANSPORT_FAILED;
	}
	exitCode = response.exitCode;
	return PROFILE_COMMAND_HANDLED;
}

BOOL CProfileCommandBroker::AcquireLaunchGate(LPCTSTR profileName)
{
	ReleaseLaunchGate();
	CString pipeName;
	if (!BuildProfileObjectNames(profileName, pipeName, m_mutexName))
		return FALSE;

	CCurrentUserSecurity security;
	if (!security.Initialize())
		return FALSE;
	m_launchGate = CreateMutex(security.Get(), FALSE, m_mutexName);
	if (!m_launchGate)
		return FALSE;
	DWORD waitResult = WaitForSingleObject(m_launchGate, INFINITE);
	if (waitResult != WAIT_OBJECT_0 && waitResult != WAIT_ABANDONED)
	{
		CloseHandle(m_launchGate);
		m_launchGate = NULL;
		return FALSE;
	}
	return TRUE;
}

void CProfileCommandBroker::ReleaseLaunchGate()
{
	if (!m_launchGate)
		return;
	ReleaseMutex(m_launchGate);
	CloseHandle(m_launchGate);
	m_launchGate = NULL;
	m_mutexName.Empty();
}

BOOL CProfileCommandBroker::StartServer(LPCTSTR profileName, HWND notifyWindow)
{
	CString requested(profileName ? profileName : _T(""));
	requested.Trim();
	if (requested.IsEmpty() || !IsWindow(notifyWindow))
		return FALSE;
	if (IsServerActive(requested))
		return TRUE;

	StopServer();
	if (!BuildProfileObjectNames(requested, m_pipeName, m_mutexName))
		return FALSE;

	CCurrentUserSecurity gateSecurity;
	if (!gateSecurity.Initialize())
		return FALSE;
	HANDLE electionGate = CreateMutex(gateSecurity.Get(), FALSE, m_mutexName);
	if (!electionGate)
		return FALSE;
	// Manual instances must never block their UI while another automation
	// instance is starting this profile. The automation owner already holds
	// this mutex recursively on the same UI thread, so a zero-time election is
	// sufficient for both paths.
	DWORD waitResult = WaitForSingleObject(electionGate, 0);
	if (waitResult != WAIT_OBJECT_0 && waitResult != WAIT_ABANDONED)
	{
		CloseHandle(electionGate);
		return FALSE;
	}

	m_profileName = requested;
	m_notifyWindow = notifyWindow;
	m_stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	m_readyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	InterlockedExchange(&m_serverReady, FALSE);
	if (m_stopEvent && m_readyEvent)
	{
		m_serverThread = CreateThread(NULL, 0, ServerThreadProc, this, 0, NULL);
		if (m_serverThread)
			WaitForSingleObject(m_readyEvent, INFINITE);
	}

	ReleaseMutex(electionGate);
	CloseHandle(electionGate);

	if (InterlockedCompareExchange(&m_serverReady, FALSE, FALSE))
		return TRUE;
	StopServer();
	return FALSE;
}

void CProfileCommandBroker::StopServer()
{
	if (m_stopEvent)
		SetEvent(m_stopEvent);
	if (m_serverThread)
	{
		WaitForSingleObject(m_serverThread, INFINITE);
		CloseHandle(m_serverThread);
	}
	if (m_readyEvent)
		CloseHandle(m_readyEvent);
	if (m_stopEvent)
		CloseHandle(m_stopEvent);
	m_serverThread = NULL;
	m_readyEvent = NULL;
	m_stopEvent = NULL;
	m_notifyWindow = NULL;
	InterlockedExchange(&m_serverReady, FALSE);
	m_profileName.Empty();
	m_pipeName.Empty();
}

BOOL CProfileCommandBroker::IsServerActive(LPCTSTR profileName) const
{
	if (!InterlockedCompareExchange(
		const_cast<volatile LONG*>(&m_serverReady), FALSE, FALSE))
	{
		return FALSE;
	}
	if (!profileName || !profileName[0])
		return TRUE;
	CString requested(profileName);
	requested.Trim();
	return requested.CompareNoCase(m_profileName) == 0;
}

DWORD WINAPI CProfileCommandBroker::ServerThreadProc(LPVOID context)
{
	return reinterpret_cast<CProfileCommandBroker*>(context)->ServerThread();
}

DWORD CProfileCommandBroker::ServerThread()
{
	CCurrentUserSecurity security;
	if (!security.Initialize())
	{
		SetEvent(m_readyEvent);
		return ERROR_ACCESS_DENIED;
	}

	HANDLE pipeHandle = CreateNamedPipe(
		m_pipeName,
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		1,
		kMaxCommandBytes,
		kMaxCommandBytes,
		0,
		security.Get());
	if (pipeHandle == INVALID_HANDLE_VALUE)
	{
		SetEvent(m_readyEvent);
		return GetLastError();
	}

	InterlockedExchange(&m_serverReady, TRUE);
	SetEvent(m_readyEvent);

	HANDLE connectedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!connectedEvent)
	{
		CloseHandle(pipeHandle);
		return GetLastError();
	}

	while (WaitForSingleObject(m_stopEvent, 0) != WAIT_OBJECT_0)
	{
		ResetEvent(connectedEvent);
		OVERLAPPED overlapped = { 0 };
		overlapped.hEvent = connectedEvent;
		BOOL connected = ConnectNamedPipe(pipeHandle, &overlapped);
		DWORD error = connected ? ERROR_SUCCESS : GetLastError();
		if (!connected && error == ERROR_PIPE_CONNECTED)
		{
			connected = TRUE;
		}
		else if (!connected && error == ERROR_IO_PENDING)
		{
			HANDLE waits[] = { m_stopEvent, connectedEvent };
			DWORD waitResult = WaitForMultipleObjects(
				_countof(waits), waits, FALSE, INFINITE);
			if (waitResult == WAIT_OBJECT_0)
			{
				CancelIo(pipeHandle);
				DWORD transferred = 0;
				WaitForSingleObject(connectedEvent, INFINITE);
				GetOverlappedResult(
					pipeHandle, &overlapped, &transferred, FALSE);
				break;
			}
			DWORD transferred = 0;
			connected = waitResult == WAIT_OBJECT_0 + 1 &&
				GetOverlappedResult(pipeHandle, &overlapped, &transferred, FALSE);
		}

		if (connected)
		{
			ProcessClient(pipeHandle);
			DisconnectNamedPipe(pipeHandle);
		}
		else if (WaitForSingleObject(m_stopEvent, 0) != WAIT_OBJECT_0)
		{
			break;
		}
	}

	CloseHandle(connectedEvent);
	CloseHandle(pipeHandle);
	InterlockedExchange(&m_serverReady, FALSE);
	return ERROR_SUCCESS;
}

BOOL CProfileCommandBroker::ProcessClient(HANDLE pipeHandle)
{
	std::vector<BYTE> buffer(kMaxCommandBytes);
	DWORD bytesRead = 0;
	if (!ReadPipeMessage(pipeHandle, m_stopEvent, &buffer[0],
		static_cast<DWORD>(buffer.size()), bytesRead))
	{
		return FALSE;
	}

	AutomationOptions options;
	CommandResponse response = { kCommandMagic, kCommandVersion,
		sizeof(CommandResponse), AUTOMATION_EXIT_INVALID_COMMAND_LINE };
	if (!ParseCommand(&buffer[0], bytesRead, options) ||
		options.profileName.CompareNoCase(m_profileName) != 0)
	{
		return WritePipeMessage(pipeHandle, m_stopEvent, &response, sizeof(response));
	}

	CProfileCommandRequest* request = new CProfileCommandRequest();
	if (!request || !request->completedEvent)
	{
		if (request)
		{
			request->Release();
			request->Release();
		}
		response.exitCode = AUTOMATION_EXIT_CREATE_PROCESS_FAILED;
		return WritePipeMessage(pipeHandle, m_stopEvent, &response, sizeof(response));
	}
	request->profileName = options.profileName;
	request->targetPath = options.targetPath;
	request->targetArguments = options.targetArguments;

	if (!PostMessage(m_notifyWindow, WM_PROFILE_COMMAND_REQUEST, 0,
		reinterpret_cast<LPARAM>(request)))
	{
		request->Release();
		request->Release();
		response.exitCode = AUTOMATION_EXIT_CREATE_PROCESS_FAILED;
		return WritePipeMessage(pipeHandle, m_stopEvent, &response, sizeof(response));
	}

	HANDLE waits[] = { m_stopEvent, request->completedEvent };
	DWORD waitResult = WaitForMultipleObjects(_countof(waits), waits, FALSE, INFINITE);
	if (waitResult == WAIT_OBJECT_0 + 1)
	{
		response.exitCode = request->exitCode;
		request->Release();
		return WritePipeMessage(pipeHandle, m_stopEvent, &response, sizeof(response));
	}

	InterlockedExchange(&request->cancelled, TRUE);
	request->Release();
	return FALSE;
}
