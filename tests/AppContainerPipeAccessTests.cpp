#include "AppContainerPipeAccess.h"
#include <aclapi.h>
#include <sddl.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <thread>
#include <future>
#include <chrono>
#include <atomic>

namespace
{
	void Check(bool result, const char *message)
	{
		if (!result) throw std::runtime_error(std::string(message) +
			" (error " + std::to_string(GetLastError()) + ")");
	}

	struct TestSid
	{
		PSID sid;
		explicit TestSid(LPCWSTR text) : sid(NULL)
		{ Check(ConvertStringSidToSidW(text, &sid) != FALSE, "parse SID"); }
		~TestSid() { LocalFree(sid); }
	};

	struct TestAttributes : SECURITY_ATTRIBUTES
	{
		TestAttributes()
		{
			HANDLE token;
			Check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != FALSE, "open token");
			DWORD size = 0;
			GetTokenInformation(token, TokenUser, NULL, 0, &size);
			std::vector<BYTE> data(size);
			const BOOL read = GetTokenInformation(token, TokenUser, &data[0], size, &size);
			CloseHandle(token);
			Check(read != FALSE, "read owner");
			LPWSTR owner = NULL;
			Check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(&data[0])->User.Sid,
				&owner) != FALSE, "owner SID text");
			std::wstring sddl = L"D:(A;;GA;;;SY)(A;;GA;;;";
			sddl += owner;
			LocalFree(owner);
			sddl += L")(A;;0x0012019b;;;WD)S:(ML;;NW;;;LW)";
			nLength = sizeof(*this);
			bInheritHandle = FALSE;
			lpSecurityDescriptor = NULL;
			Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),
				SDDL_REVISION_1, &lpSecurityDescriptor, NULL) != FALSE, "baseline descriptor");
		}
		~TestAttributes() { LocalFree(lpSecurityDescriptor); }
	};

	// Creates only our own suspended process. No installed application is
	// launched, injected into, stopped, or reconfigured by this test.
	struct TestAppContainer
	{
		typedef HRESULT (WINAPI *CreateProfile)(PCWSTR, PCWSTR, PCWSTR,
			PSID_AND_ATTRIBUTES, DWORD, PSID*);
		typedef HRESULT (WINAPI *DeleteProfile)(PCWSTR);
		HMODULE library;
		DeleteProfile deleteProfile;
		std::wstring name;
		PSID sid;
		PROCESS_INFORMATION process;
		bool created;
		TestAppContainer() : library(NULL), deleteProfile(NULL), sid(NULL), created(false)
		{ ZeroMemory(&process, sizeof(process)); }
		~TestAppContainer()
		{
			if (process.hProcess)
			{
				TerminateProcess(process.hProcess, 0);
				WaitForSingleObject(process.hProcess, 5000);
				CloseHandle(process.hThread);
				CloseHandle(process.hProcess);
			}
			if (sid) FreeSid(sid);
			if (created && FAILED(deleteProfile(name.c_str())))
				std::cerr << "Failed to remove temporary AppContainer profile" << std::endl;
			if (library) FreeLibrary(library);
		}
		void Finish()
		{
			if (process.hProcess)
			{
				Check(TerminateProcess(process.hProcess, 0) != FALSE, "stop our suspended test process");
				Check(WaitForSingleObject(process.hProcess, 5000) == WAIT_OBJECT_0, "join test process");
				CloseHandle(process.hThread);
				CloseHandle(process.hProcess);
				ZeroMemory(&process, sizeof(process));
			}
			if (created)
			{
				Check(SUCCEEDED(deleteProfile(name.c_str())), "remove temporary AppContainer profile");
				created = false;
			}
		}
		bool Start()
		{
			library = LoadLibraryW(L"userenv.dll");
			CreateProfile createProfile = library ? reinterpret_cast<CreateProfile>(
				GetProcAddress(library, "CreateAppContainerProfile")) : NULL;
			deleteProfile = library ? reinterpret_cast<DeleteProfile>(
				GetProcAddress(library, "DeleteAppContainerProfile")) : NULL;
			if (!createProfile || !deleteProfile) return false;
			name = L"ProxyLane.PipeAccessTest." + std::to_wstring(GetCurrentProcessId()) +
				L"." + std::to_wstring(GetTickCount());
			Check(SUCCEEDED(createProfile(name.c_str(), name.c_str(),
				L"Temporary ProxyLane pipe ACL test", NULL, 0, &sid)), "create temporary AppContainer");
			created = true;
			SIZE_T size = 0;
			InitializeProcThreadAttributeList(NULL, 1, 0, &size);
			std::vector<BYTE> storage(size);
			STARTUPINFOEXW startup = { 0 };
			startup.StartupInfo.cb = sizeof(startup);
			startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(&storage[0]);
			Check(InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size) != FALSE,
				"initialize process attributes");
			SECURITY_CAPABILITIES capabilities = { 0 };
			capabilities.AppContainerSid = sid;
			const BOOL updated = UpdateProcThreadAttribute(startup.lpAttributeList, 0,
				PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities, sizeof(capabilities), NULL, NULL);
			WCHAR image[MAX_PATH];
			GetSystemDirectoryW(image, MAX_PATH);
			const std::wstring executable = std::wstring(image) + L"\\cmd.exe";
			const BOOL launched = updated && CreateProcessW(executable.c_str(), NULL, NULL,
				NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
				NULL, NULL, &startup.StartupInfo, &process);
			const DWORD error = GetLastError();
			DeleteProcThreadAttributeList(startup.lpAttributeList);
			SetLastError(error);
			Check(launched != FALSE, "create suspended AppContainer test process");
			return true;
		}
	};

	DWORD ReadGrant(HANDLE pipe, PSID sid, DWORD *count = NULL)
	{
		PACL acl = NULL;
		PSECURITY_DESCRIPTOR descriptor = NULL;
		const DWORD error = GetSecurityInfo(pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
			NULL, NULL, &acl, NULL, &descriptor);
		Check(error == ERROR_SUCCESS && acl, "read pipe DACL");
		DWORD mask = 0, matches = 0;
		for (DWORD i = 0; i < acl->AceCount; ++i)
		{
			PVOID address;
			Check(GetAce(acl, i, &address) != FALSE, "read ACE");
			ACCESS_ALLOWED_ACE *ace = static_cast<ACCESS_ALLOWED_ACE*>(address);
			if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && EqualSid(&ace->SidStart, sid))
			{ mask |= ace->Mask; ++matches; }
		}
		LocalFree(descriptor);
		if (count) *count = matches;
		return mask;
	}

	HANDLE CreatePipe(CAppContainerPipeAccess& access, const std::wstring& name,
		const TestAttributes& attributes)
	{
		HANDLE pipe = access.CreateServerPipe(name.c_str(), PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
			PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, attributes);
		Check(pipe != INVALID_HANDLE_VALUE, "create server pipe");
		return pipe;
	}

	void ProbePendingConnectAuthorization(const TestAttributes& attributes)
	{
		CAppContainerPipeAccess access;
		const std::wstring name = L"\\\\.\\pipe\\ProxyLanePendingGrantTest-" +
			std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount());
		HANDLE pipe = CreatePipe(access, name, attributes);
		HANDLE started = CreateEventW(NULL, TRUE, FALSE, NULL);
		std::thread listener([&]() {
			SetEvent(started);
			ConnectNamedPipe(pipe, NULL);
		});
		WaitForSingleObject(started, 5000);
		Sleep(50); // Let the synchronous ConnectNamedPipe enter the kernel.
		TestSid package(L"S-1-15-2-21-22-23-24-25-26-27");
		std::future<BOOL> grant = std::async(std::launch::async, [&]() {
			return access.AuthorizePackageSid(package.sid);
		});
		const bool timely = grant.wait_for(std::chrono::seconds(1)) == std::future_status::ready;
		// Always release the pending connect before joining, including on failure.
		// This prevents the regression test itself from permanently hanging.
		HANDLE client = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE,
			0, NULL, OPEN_EXISTING, 0, NULL);
		listener.join();
		const BOOL authorized = grant.get();
		if (client != INVALID_HANDLE_VALUE) CloseHandle(client);
		DisconnectNamedPipe(pipe);
		CloseHandle(started);
		access.CloseServerPipe(pipe);
		std::cout << "Pending ConnectNamedPipe authorization: " << (timely ? "returned" : "BLOCKED") << std::endl;
		Check(timely && authorized, "authorization must not wait for an unrelated pipe connection");
	}

	void ProbePendingReadAuthorization(const TestAttributes& attributes)
	{
		CAppContainerPipeAccess access;
		const std::wstring name = L"\\\\.\\pipe\\ProxyLanePendingReadGrantTest-" +
			std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount());
		HANDLE pipe = CreatePipe(access, name, attributes);
		HANDLE client = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE,
			0, NULL, OPEN_EXISTING, 0, NULL);
		Check(client != INVALID_HANDLE_VALUE, "connect pending-read test client");
		HANDLE started = CreateEventW(NULL, TRUE, FALSE, NULL);
		std::thread reader([&]() {
			SetEvent(started);
			char data;
			DWORD bytes;
			ReadFile(pipe, &data, 1, &bytes, NULL);
		});
		WaitForSingleObject(started, 5000);
		Sleep(50);
		TestSid package(L"S-1-15-2-31-32-33-34-35-36-37");
		std::future<BOOL> grant = std::async(std::launch::async, [&]() {
			return access.AuthorizePackageSid(package.sid);
		});
		const bool timely = grant.wait_for(std::chrono::seconds(1)) == std::future_status::ready;
		const char data = 'Q';
		DWORD bytes;
		WriteFile(client, &data, 1, &bytes, NULL); // Unblock the reader even on regression.
		reader.join();
		const BOOL authorized = grant.get();
		CloseHandle(client);
		DisconnectNamedPipe(pipe);
		CloseHandle(started);
		access.CloseServerPipe(pipe);
		std::cout << "Pending ReadFile authorization: " << (timely ? "returned" : "BLOCKED") << std::endl;
		Check(timely && authorized, "authorization must not wait for a pending pipe read");
	}

	void ProbeAppContainer(CAppContainerPipeAccess& access, HANDLE pipe,
		HANDLE otherPipe, const std::wstring& name, HANDLE process)
	{
		std::vector<BYTE> sid;
		const BOOL queried = QueryProcessAppContainerSid(process, sid);
		Check(queried && !sid.empty(), "read real AppContainer SID");
		HANDLE token = NULL, impersonation = NULL;
		Check(OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &token) != FALSE,
			"open AppContainer token");
		Check(DuplicateToken(token, SecurityImpersonation, &impersonation) != FALSE,
			"duplicate AppContainer token");
		CloseHandle(token);
		Check(ImpersonateLoggedOnUser(impersonation) != FALSE, "impersonate AppContainer before grant");
		HANDLE denied = CreateFileW(name.c_str(), PROXYLANE_PIPE_CLIENT_ACCESS,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
		const DWORD deniedError = GetLastError();
		Check(RevertToSelf() != FALSE, "revert AppContainer impersonation");
		if (denied != INVALID_HANDLE_VALUE) CloseHandle(denied);
		Check(denied == INVALID_HANDLE_VALUE && deniedError == ERROR_ACCESS_DENIED,
			"AppContainer must be denied before grant");
		Check(access.AuthorizeProcess(process) != FALSE, "authorize real process before injection");
		Check(ReadGrant(pipe, &sid[0]) == PROXYLANE_PIPE_CLIENT_ACCESS, "real package minimal rights");
		Check(ImpersonateLoggedOnUser(impersonation) != FALSE, "impersonate AppContainer after grant");
		HANDLE client = CreateFileW(name.c_str(), PROXYLANE_PIPE_CLIENT_ACCESS,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
		const DWORD clientError = GetLastError();
		HANDLE competingServer = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
			PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
		const DWORD serverError = GetLastError();
		Check(RevertToSelf() != FALSE, "revert AppContainer impersonation");
		CloseHandle(impersonation);
		if (competingServer != INVALID_HANDLE_VALUE) CloseHandle(competingServer);
		Check(competingServer == INVALID_HANDLE_VALUE && serverError == ERROR_ACCESS_DENIED,
			"AppContainer cannot create competing server instance");
		SetLastError(clientError);
		Check(client != INVALID_HANDLE_VALUE, "AppContainer must connect after grant");
		const char request = 'Q', response = 'R';
		char received = 0;
		DWORD bytes = 0, available = 0;
		Check(WriteFile(client, &request, 1, &bytes, NULL) && bytes == 1, "AppContainer pipe write");
		HANDLE connected = pipe;
		if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL) || available == 0)
			connected = otherPipe;
		Check(PeekNamedPipe(connected, NULL, 0, NULL, &available, NULL) && available == 1,
			"server received AppContainer request");
		Check(ReadFile(connected, &received, 1, &bytes, NULL) && bytes == 1 && received == request,
			"server reads AppContainer request");
		Check(WriteFile(connected, &response, 1, &bytes, NULL) && bytes == 1, "server replies");
		Check(ReadFile(client, &received, 1, &bytes, NULL) && bytes == 1 && received == response,
			"AppContainer pipe read");
		CloseHandle(client);
		DisconnectNamedPipe(connected);
		std::cout << "Real AppContainer token: denied before grant, read/write after grant, server creation denied" << std::endl;
	}
}

int main()
{
	try
	{
		TestAttributes attributes;
		ProbePendingConnectAuthorization(attributes);
		ProbePendingReadAuthorization(attributes);
		CAppContainerPipeAccess& access = GetProxyLanePipeAccess();
		const std::wstring name = L"\\\\.\\pipe\\ProxyLanePipeAccessTest-" +
			std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount());
		HANDLE first = CreatePipe(access, name, attributes);
		HANDLE second = CreatePipe(access, name, attributes);
		TestSid packageA(L"S-1-15-2-1-2-3-4-5-6-7");
		TestSid packageB(L"S-1-15-2-8-9-10-11-12-13-14");
		TestSid allPackages(L"S-1-15-2-1"), everyone(L"S-1-1-0");
		Check(!access.AuthorizePackageSid(allPackages.sid), "reject all-package grant");
		Check(!access.AuthorizePackageSid(everyone.sid), "reject Everyone grant");
		Check(!access.AuthorizePackageSid(NULL), "reject null SID");
		Check(ReadGrant(first, packageA.sid) == 0, "no unrequested package grant");
		Check(access.AuthorizeProcess(GetCurrentProcess()) != FALSE, "ordinary process unchanged");
		Check(access.AuthorizePackageSid(packageA.sid) != FALSE, "authorize package A");
		Check(ReadGrant(first, packageA.sid) == PROXYLANE_PIPE_CLIENT_ACCESS, "live pipe A grant");
		Check(ReadGrant(second, packageA.sid) == PROXYLANE_PIPE_CLIENT_ACCESS, "all live instances grant");
		Check(access.AuthorizePackageSid(packageB.sid) != FALSE, "authorize package B");
		Check(access.AuthorizePackageSid(packageA.sid) != FALSE, "repeat grant");
		DWORD count = 0;
		Check(ReadGrant(first, packageA.sid, &count) == PROXYLANE_PIPE_CLIENT_ACCESS && count == 1,
			"repeat grant must not duplicate ACE");
		Check((ReadGrant(first, packageA.sid) & (FILE_CREATE_PIPE_INSTANCE | WRITE_DAC | WRITE_OWNER | DELETE)) == 0,
			"package must not gain server/admin rights");
		Check(ReadGrant(first, packageB.sid) == PROXYLANE_PIPE_CLIENT_ACCESS, "package B grant");
		Check(ReadGrant(first, allPackages.sid) == 0, "no broad package grant installed");
		std::atomic<bool> concurrentOK(true);
		std::vector<std::thread> workers;
		for (int index = 0; index < 4; ++index)
		{
			workers.push_back(std::thread([&]()
			{
				for (int iteration = 0; iteration < 30; ++iteration)
				{
					if (!access.AuthorizePackageSid(packageA.sid)) concurrentOK = false;
					HANDLE pipe = access.CreateServerPipe(name.c_str(), PIPE_ACCESS_DUPLEX,
						PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
						PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, attributes);
					if (pipe == INVALID_HANDLE_VALUE) concurrentOK = false;
					else access.CloseServerPipe(pipe);
				}
			}));
		}
		for (size_t i = 0; i < workers.size(); ++i) workers[i].join();
		Check(concurrentOK.load(), "concurrent authorization/create/close");
		TestAppContainer container;
		if (container.Start()) ProbeAppContainer(access, first, second, name, container.process.hProcess);
		access.CloseServerPipe(first);
		access.CloseServerPipe(second);
		// All instances are gone: this is a new kernel object, like restarting PRC.
		HANDLE restarted = CreatePipe(access, name, attributes);
		Check(ReadGrant(restarted, packageA.sid) == PROXYLANE_PIPE_CLIENT_ACCESS, "restart retains A");
		Check(ReadGrant(restarted, packageB.sid) == PROXYLANE_PIPE_CLIENT_ACCESS, "restart retains B");
		access.CloseServerPipe(restarted);
		container.Finish();
		std::cout << "AppContainer pipe access tests passed" << std::endl;
		return 0;
	}
	catch (const std::exception& error)
	{
		std::cerr << error.what() << std::endl;
		return 1;
	}
}
