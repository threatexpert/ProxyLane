#include "ProcessRegistry.h"
#include "ProcessImagePath.h"
#include <iostream>
#include <thread>

static int RegistryFailure(int line)
{
	std::cerr << "ProcessRegistry test failed at line " << line << std::endl;
	return 1;
}

static ULONGLONG CreationTime(HANDLE process)
{
	FILETIME created, exited, kernel, user;
	if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
	return ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
}

static bool SnapshotParsingTests()
{
	using namespace ProxyProcessIdentity;
	SystemProcessPrefix entries[2] = {};
	entries[0].nextEntryOffset = sizeof(SystemProcessPrefix);
	entries[0].processId = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(41));
	entries[0].createTime.QuadPart = 100;
	entries[1].processId = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(42));
	entries[1].createTime.QuadPart = 200;
	const BYTE* bytes = reinterpret_cast<const BYTE*>(entries);
	Snapshot snapshot;
	HookProcessIdentityInfo identity = {};
	identity.dwProcessId = 42;
	identity.processCreateTime = 200;
	if (snapshot.HasExited(identity)) return false; // Unknown is not gone.
	if (!ReadSnapshot(bytes, sizeof(entries), snapshot) || snapshot.creationTimes[42] != 200 ||
		snapshot.HasExited(identity)) return false;
	identity.processCreateTime = 199;
	if (!snapshot.HasExited(identity)) return false; // PID reused.
	identity.dwProcessId = 43;
	if (!snapshot.HasExited(identity)) return false; // PID absent.
	// A failed read must invalidate the previous successful snapshot, and no
	// partial data may be used to declare an unobserved process gone.
	const auto invalid = [&](const BYTE* data, size_t size) {
		return !ReadSnapshot(data, size, snapshot) && !snapshot.complete &&
			snapshot.creationTimes.empty() && snapshot.processes.empty() && !snapshot.HasExited(identity);
	};
	if (!invalid(NULL, sizeof(entries)) || !invalid(bytes, 0) ||
		!invalid(bytes, sizeof(SystemProcessPrefix) - 1) || !invalid(bytes, sizeof(entries) - 1)) return false;
	entries[0].nextEntryOffset = 1;
	if (!invalid(bytes, sizeof(entries))) return false;
	entries[0].nextEntryOffset = MAXDWORD;
	if (!invalid(bytes, sizeof(entries))) return false;
	entries[0].nextEntryOffset = sizeof(entries);
	if (!invalid(bytes, sizeof(entries))) return false;
	entries[0].nextEntryOffset = sizeof(SystemProcessPrefix);
	entries[1].processId = entries[0].processId;
	if (!invalid(bytes, sizeof(entries))) return false;
	entries[1].processId = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(42));
	entries[1].createTime.QuadPart = 0;
	identity.dwProcessId = 42;
	return ReadSnapshot(bytes, sizeof(entries), snapshot) && !snapshot.HasExited(identity);
}

static bool SnapshotDetailsTests()
{
	using namespace ProxyProcessIdentity;
	struct Buffer { SystemProcessPrefix entries[2]; WCHAR name[8]; } buffer = {};
	buffer.entries[0].nextEntryOffset = sizeof(SystemProcessPrefix);
	buffer.entries[0].processId = reinterpret_cast<HANDLE>(41);
	buffer.entries[0].createTime.QuadPart = 100;
	SystemProcessPrefix& child = buffer.entries[1];
	child.processId = reinterpret_cast<HANDLE>(42);
	child.parentProcessId = reinterpret_cast<HANDLE>(41);
	child.createTime.QuadPart = 200;
	child.sessionId = 7;
	CopyMemory(buffer.name, L"git.exeX", sizeof(buffer.name)); // No terminator.
	child.imageBuffer = buffer.name;
	child.imageLength = child.imageMaximumLength = 7 * sizeof(WCHAR);
	const BYTE* bytes = reinterpret_cast<const BYTE*>(&buffer);
	Snapshot snapshot;
	if (!ReadSnapshot(bytes, sizeof(buffer), snapshot) || snapshot.processes.size() != 2) return false;
	const Process& process = snapshot.processes[1];
	if (snapshot.processes[0].pid != 41 || process.pid != 42 || process.parentPid != 41 ||
		process.creationTime != 200 || process.name != L"git.exe" || process.sessionId != 7) return false;
	buffer.name[0] = L'X';
	if (process.name != L"git.exe") return false; // Own the name after the query buffer is gone.
	const auto invalid = [&]() {
		return !ReadSnapshot(bytes, sizeof(buffer), snapshot) && !snapshot.complete &&
			snapshot.processes.empty() && snapshot.creationTimes.empty();
	};
	child.imageLength = 1;
	if (!invalid()) return false;
	child.imageLength = child.imageMaximumLength + sizeof(WCHAR);
	if (!invalid()) return false;
	child.imageLength = child.imageMaximumLength;
	child.imageBuffer = NULL;
	if (!invalid()) return false;
	child.imageBuffer = reinterpret_cast<PWSTR>(reinterpret_cast<ULONG_PTR>(bytes) - sizeof(WCHAR));
	if (!invalid()) return false;
	child.imageBuffer = buffer.name + 7;
	return invalid(); // Name extends past the returned buffer.
}

static bool ImagePathTests()
{
	ProcessImagePath::Resolver resolver;
	resolver.windowsDirectory = L"C:\\Windows";
	resolver.drives.push_back(std::make_pair(L"\\Device\\HarddiskVolume1", L"C:"));
	resolver.drives.push_back(std::make_pair(L"\\Device\\HarddiskVolume10", L"D:"));
	resolver.drives.push_back(std::make_pair(L"\\Device\\HarddiskVolume1\\apps", L"E:"));
	const WCHAR* cases[][2] = {
		{ L"\\Device\\HarddiskVolume1\\Windows\\a.exe", L"C:\\Windows\\a.exe" },
		{ L"\\device\\harddiskvolume10\\a.exe", L"D:\\a.exe" },
		{ L"\\Device\\HarddiskVolume100\\a.exe", L"\\Device\\HarddiskVolume100\\a.exe" },
		{ L"\\Device\\HarddiskVolume1\\apps\\a.exe", L"E:\\a.exe" },
		{ L"\\SystemRoot\\system32\\a.exe", L"C:\\Windows\\system32\\a.exe" },
		{ L"\\SystemRootOther\\a.exe", L"\\SystemRootOther\\a.exe" },
		{ L"system32\\a.exe", L"C:\\Windows\\system32\\a.exe" },
		{ L"\\??\\C:\\a.exe", L"C:\\a.exe" },
		{ L"\\??\\UNC\\server\\share\\a.exe", L"\\\\server\\share\\a.exe" },
		{ L"\\??\\Volume{123}\\a.exe", L"\\\\?\\Volume{123}\\a.exe" },
		{ L"\\Device\\Mup\\server\\share\\a.exe", L"\\\\server\\share\\a.exe" },
		{ L"\\Device\\LanmanRedirector\\;Z:123\\server\\share\\a.exe", L"\\\\server\\share\\a.exe" },
		{ L"C:\\a.exe", L"C:\\a.exe" }, { L"", L"" }
	};
	for (size_t i = 0; i < _countof(cases); ++i)
		if (resolver.Convert(cases[i][0]) != cases[i][1]) return false;
	resolver.Refresh();
	WCHAR ownPath[32768] = {};
	std::wstring nativePath;
	if (!GetModuleFileNameW(NULL, ownPath, _countof(ownPath)) ||
		!ProcessImagePath::Query(GetCurrentProcessId(), nativePath) ||
		_wcsicmp(resolver.Convert(nativePath).c_str(), ownPath)) return false;
	nativePath = L"stale";
	return !ProcessImagePath::Query(0, nativePath) && nativePath.empty();
}

int ProcessRegistryTestsMain()
{
	if (!SnapshotParsingTests() || !SnapshotDetailsTests() || !ImagePathTests()) return RegistryFailure(__LINE__);
	CProcessRegistry registry;
	HookProcessIdentityInfo identity = { 0 }, result = { 0 };
	if (registry.Register(&identity) || registry.Update(0, 100, 0) ||
		registry.Update(41, 0, 0)) return RegistryFailure(__LINE__);
	identity.dwProcessId = 41;
	identity.processCreateTime = 100;
	wcscpy_s(identity.szAppPath, L"C:\\test.exe");
	if (!registry.Register(&identity) || !registry.Get(41, 100, &result) ||
		result.hookState != PROCESS_HOOK_STATE_PENDING) return RegistryFailure(__LINE__);
	registry.Update(41, 100, ERROR_ACCESS_DENIED);
	if (!registry.Get(41, 100, &result) || result.hookState != PROCESS_HOOK_STATE_FAILED ||
		result.hookError != ERROR_ACCESS_DENIED) return RegistryFailure(__LINE__);
	// Concurrent pipe callbacks and late path reports converge on one record.
	std::thread first([&]() {
		for (int i = 0; i < 1000; ++i) registry.Update(41, 100, 0);
	});
	std::thread second([&]() {
		for (int i = 0; i < 1000; ++i) registry.Register(&identity);
	});
	first.join(); second.join();
	registry.Update(41, 100, ERROR_ACCESS_DENIED);
	if (!registry.Get(41, 100, &result) || result.hookState != PROCESS_HOOK_STATE_SUCCEEDED ||
		result.hookError || wcscmp(result.szAppPath, identity.szAppPath)) return RegistryFailure(__LINE__);
	// The success notification can precede a valid path registration.
	registry.Update(42, 200, 0);
	identity.dwProcessId = 42; identity.processCreateTime = 200;
	registry.Register(&identity);
	if (!registry.Get(42, 200, &result) || result.hookState != PROCESS_HOOK_STATE_SUCCEEDED ||
		!result.szAppPath[0]) return RegistryFailure(__LINE__);
	// PID reuse resets state/path, and an old delayed report cannot undo it.
	registry.Update(42, 300, ERROR_ACCESS_DENIED);
	if (registry.Register(&identity) || registry.Update(42, 200, 0) ||
		registry.Get(42, 200, &result)) return RegistryFailure(__LINE__);
	if (!registry.Get(42, 300, &result) || result.szAppPath[0] ||
		result.hookState != PROCESS_HOOK_STATE_FAILED) return RegistryFailure(__LINE__);
	// Failed/pending entries are excluded; each call includes newly registered
	// successes. An undersized buffer must not return a usable partial snapshot.
	HookProcessIdentityInfo snapshot[2] = {};
	if (registry.SnapshotHooked(NULL, 0) != 1 || registry.SnapshotHooked(snapshot, 2) != 1 ||
		snapshot[0].dwProcessId != 41 || snapshot[0].processCreateTime != 100) return RegistryFailure(__LINE__);
	registry.Update(43, 400, 0);
	snapshot[0].dwProcessId = 12345;
	if (registry.SnapshotHooked(snapshot, 1) != 2 || snapshot[0].dwProcessId != 12345 ||
		registry.SnapshotHooked(snapshot, 2) != 2 || snapshot[1].dwProcessId != 43 ||
		snapshot[1].processCreateTime != 400) return RegistryFailure(__LINE__);
	registry.Update(43, 500, ERROR_ACCESS_DENIED);
	if (registry.SnapshotHooked(snapshot, 2) != 1) return RegistryFailure(__LINE__);
	std::thread registration([&]() {
		for (DWORD i = 1000; i < 2000; ++i) registry.Update(i, i, 0);
	});
	for (int i = 0; i < 100; ++i)
	{
		HookProcessIdentityInfo concurrent[1001] = {};
		const DWORD count = registry.SnapshotHooked(concurrent, 1001);
		if (count < 1 || count > 1001) { registration.join(); return RegistryFailure(__LINE__); }
		for (DWORD j = 0; j < count; ++j)
			if (concurrent[j].hookState != PROCESS_HOOK_STATE_SUCCEEDED)
			{ registration.join(); return RegistryFailure(__LINE__); }
	}
	registration.join();
	if (registry.SnapshotHooked(NULL, 0) != 1001) return RegistryFailure(__LINE__);

	CProcessRegistry live;
	const DWORD pid = GetCurrentProcessId();
	const ULONGLONG created = CreationTime(GetCurrentProcess());
	ProxyProcessIdentity::Snapshot systemSnapshot;
	if (!ProxyProcessIdentity::QuerySnapshot(systemSnapshot) || systemSnapshot.creationTimes[pid] != created)
		return RegistryFailure(__LINE__);
	live.Update(pid, created, 0);
	if (live.SnapshotHooked(snapshot, 2) != 1 || ProxyProcessIdentity::HasExited(snapshot[0])) return RegistryFailure(__LINE__);
	live.PruneExited();
	if (!live.Get(pid, created, &result)) return RegistryFailure(__LINE__);
	// An existing PID with a different creation time is also safely removed.
	CProcessRegistry reused;
	reused.Update(pid, created - 1, 0);
	if (reused.SnapshotHooked(snapshot, 2) != 1 || !ProxyProcessIdentity::HasExited(snapshot[0])) return RegistryFailure(__LINE__);
	reused.PruneExited();
	if (reused.Get(pid, created - 1, &result)) return RegistryFailure(__LINE__);

	WCHAR executable[MAX_PATH] = { 0 };
	GetSystemDirectoryW(executable, MAX_PATH);
	wcscat_s(executable, L"\\cmd.exe");
	WCHAR command[] = L"cmd.exe /d /c exit 0";
	STARTUPINFOW startup = { sizeof(startup) };
	PROCESS_INFORMATION child = { 0 };
	if (!CreateProcessW(executable, command, NULL, NULL, FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &child)) return RegistryFailure(__LINE__);
	const ULONGLONG childTime = CreationTime(child.hProcess);
	live.Update(child.dwProcessId, childTime, 0);
	live.PruneExited();
	bool passed = live.Get(child.dwProcessId, childTime, &result) != FALSE;
	ResumeThread(child.hThread);
	if (WaitForSingleObject(child.hProcess, 10000) != WAIT_OBJECT_0)
	{
		TerminateProcess(child.hProcess, 1);
		passed = false;
	}
	live.PruneExited();
	passed = passed && !live.Get(child.dwProcessId, childTime, &result) &&
		live.Get(pid, created, &result);
	CloseHandle(child.hThread); CloseHandle(child.hProcess);
	if (!passed) return RegistryFailure(__LINE__);
	// A real process with an empty DACL cannot be reopened for queries. Keep
	// its registered identity rather than interpreting access denial as exit.
	ACL acl;
	SECURITY_DESCRIPTOR descriptor;
	if (!InitializeAcl(&acl, sizeof(acl), ACL_REVISION) ||
		!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
		!SetSecurityDescriptorDacl(&descriptor, TRUE, &acl, FALSE)) return RegistryFailure(__LINE__);
	SECURITY_ATTRIBUTES attributes = { sizeof(attributes), &descriptor, FALSE };
	WCHAR protectedCommand[] = L"cmd.exe /d /c exit 0";
	if (!CreateProcessW(executable, protectedCommand, &attributes, NULL, FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &child)) return RegistryFailure(__LINE__);
	const ULONGLONG protectedTime = CreationTime(child.hProcess);
	const BOOL queried = ProxyProcessIdentity::QuerySnapshot(systemSnapshot);
	bool childDetailsFound = false;
	for (const auto& process : systemSnapshot.processes)
		if (process.pid == child.dwProcessId && process.parentPid == GetCurrentProcessId() &&
			process.creationTime == protectedTime && _wcsicmp(process.name.c_str(), L"cmd.exe") == 0)
			childDetailsFound = true;
	if (!queried || !childDetailsFound || systemSnapshot.creationTimes[child.dwProcessId] != protectedTime)
	{
		TerminateProcess(child.hProcess, 1);
		WaitForSingleObject(child.hProcess, 5000);
		CloseHandle(child.hThread); CloseHandle(child.hProcess);
		return RegistryFailure(__LINE__);
	}
	CProcessRegistry protectedRegistry;
	protectedRegistry.Update(child.dwProcessId, protectedTime, 0);
	HANDLE denied = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, child.dwProcessId);
	const DWORD openError = GetLastError();
	passed = !denied && openError == ERROR_ACCESS_DENIED;
	if (!passed) std::cerr << "Expected query access denial, handle=" << denied << ", error=" << openError << std::endl;
	if (denied) CloseHandle(denied);
	// Query even a child whose DACL denies limited query rights. The original
	// create-process handle is retained only for test-owned cleanup.
	HANDLE limitedDenied = OpenProcess(0x1000, FALSE, child.dwProcessId);
	if (limitedDenied || GetLastError() != ERROR_ACCESS_DENIED) passed = false;
	if (limitedDenied) CloseHandle(limitedDenied);
	ProcessImagePath::Resolver resolver;
	resolver.Refresh();
	std::wstring protectedPath;
	// The handle-based API supplies an independent expected path, including
	// the SysWOW64 location when this test executable runs as 32-bit.
	WCHAR expectedPath[32768] = {};
	DWORD expectedLength = _countof(expectedPath);
	if (!QueryFullProcessImageNameW(child.hProcess, 0, expectedPath, &expectedLength) ||
		!ProcessImagePath::Query(child.dwProcessId, protectedPath) ||
		_wcsicmp(resolver.Convert(protectedPath).c_str(), expectedPath))
	{
		std::cerr << "PID-only image path query failed for inaccessible child" << std::endl;
		passed = false;
	}
	passed = passed && protectedRegistry.SnapshotHooked(snapshot, 2) == 1 &&
		!ProxyProcessIdentity::HasExited(snapshot[0]);
	protectedRegistry.PruneExited();
	passed = passed && protectedRegistry.Get(child.dwProcessId, protectedTime, &result);
	if (!passed) std::cerr << "Protected live identity was not retained" << std::endl;
	// Simulate a stale registration whose PID now belongs to this inaccessible
	// child. The old lifetime must be removed without touching the live child.
	CProcessRegistry protectedReused;
	protectedReused.Update(child.dwProcessId, protectedTime - 1, 0);
	protectedReused.PruneExited();
	if (protectedReused.Get(child.dwProcessId, protectedTime - 1, &result) ||
		WaitForSingleObject(child.hProcess, 0) != WAIT_TIMEOUT)
	{ std::cerr << "Reused PID with denied query was not recognized" << std::endl; passed = false; }
	// Changing the process DACL must not affect snapshot-based lifetime
	// checks, including services that allow queries but deny synchronization.
	BYTE worldSid[SECURITY_MAX_SID_SIZE];
	DWORD worldSidSize = sizeof(worldSid);
	DWORD queryAclStorage[128] = {};
	PACL queryAcl = reinterpret_cast<PACL>(queryAclStorage);
	if (!CreateWellKnownSid(WinWorldSid, NULL, worldSid, &worldSidSize) ||
		!InitializeAcl(queryAcl, sizeof(queryAclStorage), ACL_REVISION) ||
		!AddAccessAllowedAce(queryAcl, ACL_REVISION, PROCESS_QUERY_INFORMATION | 0x1000, worldSid) ||
		!SetSecurityDescriptorDacl(&descriptor, TRUE, queryAcl, FALSE) ||
		!SetKernelObjectSecurity(child.hProcess, DACL_SECURITY_INFORMATION, &descriptor))
		passed = false;
	else
	{
		HANDLE queryOnly = OpenProcess(0x1000, FALSE, child.dwProcessId);
		HANDLE waitDenied = OpenProcess(SYNCHRONIZE | 0x1000, FALSE, child.dwProcessId);
		if (!queryOnly || waitDenied || GetLastError() != ERROR_ACCESS_DENIED) passed = false;
		if (queryOnly) CloseHandle(queryOnly);
		if (waitDenied) CloseHandle(waitDenied);
		HookProcessIdentityInfo queryIdentity = {};
		queryIdentity.dwProcessId = child.dwProcessId;
		queryIdentity.processCreateTime = protectedTime;
		if (ProxyProcessIdentity::HasExited(queryIdentity)) passed = false;
		queryIdentity.processCreateTime = protectedTime - 1;
		if (!ProxyProcessIdentity::HasExited(queryIdentity)) passed = false;
	}
	// Restore the empty DACL for the retained, exited-object regression below.
	if (!SetSecurityDescriptorDacl(&descriptor, TRUE, &acl, FALSE) ||
		!SetKernelObjectSecurity(child.hProcess, DACL_SECURITY_INFORMATION, &descriptor)) passed = false;
	ResumeThread(child.hThread);
	if (WaitForSingleObject(child.hProcess, 10000) != WAIT_OBJECT_0)
	{
		TerminateProcess(child.hProcess, 1);
		WaitForSingleObject(child.hProcess, 10000);
		passed = false;
	}
	// Keep the exited object alive through its original handles. Query access
	// is still denied, but it must no longer block ProxyLane's exit warning.
	protectedRegistry.PruneExited();
	if (protectedRegistry.Get(child.dwProcessId, protectedTime, &result))
	{ std::cerr << "Exited protected identity with retained handles was not pruned" << std::endl; passed = false; }
	CloseHandle(child.hThread); CloseHandle(child.hProcess);
	// Removal remains stable after the retained handles are closed.
	for (int i = 0; i < 100 && protectedRegistry.Get(child.dwProcessId, protectedTime, &result); ++i)
	{
		protectedRegistry.PruneExited();
		Sleep(10);
	}
	if (protectedRegistry.Get(child.dwProcessId, protectedTime, &result))
	{ std::cerr << "Exited protected identity was not pruned" << std::endl; passed = false; }
	if (!passed) return RegistryFailure(__LINE__);
	std::cout << "ProcessRegistry tests passed" << std::endl;
	return 0;
}
