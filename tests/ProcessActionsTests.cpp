#include "ProcessActions.h"
#include <iostream>
#include <string>

int ProcessActionsTestsMain()
{
	int failures = 0;
	if (ProcessActions::OpenForTermination(GetCurrentProcessId(), 1) ||
		ProcessActions::OpenForTermination(0, 1) || ProcessActions::OpenForTermination(4, 1)) ++failures;
	WCHAR system[MAX_PATH] = { 0 };
	GetSystemDirectoryW(system, MAX_PATH);
	std::wstring executable = std::wstring(system) + L"\\cmd.exe";
	STARTUPINFOW startup = { sizeof(startup) };
	PROCESS_INFORMATION child = { 0 };
	// Only this test's own child is terminated; no existing process is touched.
	if (!CreateProcessW(executable.c_str(), NULL, NULL, NULL, FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &child)) return 1;
	const ULONGLONG created = ProcessActions::CreationTime(child.hProcess);
	std::vector<ProcessActions::TerminationTarget> invalidTargets;
	ProcessActions::TerminationTarget wrongIdentity = { child.dwProcessId, created + 1 };
	ProcessActions::TerminationTarget self = { GetCurrentProcessId(),
		ProcessActions::CreationTime(GetCurrentProcess()) };
	invalidTargets.push_back(wrongIdentity);
	invalidTargets.push_back(self);
	const std::vector<DWORD> rejected = ProcessActions::TerminateExactProcesses(invalidTargets);
	if (rejected[0] || !rejected[1] ||
		WaitForSingleObject(child.hProcess, 0) != WAIT_TIMEOUT) ++failures;
	HANDLE wrong = ProcessActions::OpenForTermination(child.dwProcessId, created + 1);
	if (!wrong && GetLastError() != ERROR_NOT_FOUND) ++failures;
	if (wrong) { ++failures; CloseHandle(wrong); }
	HANDLE unknown = ProcessActions::OpenForTermination(child.dwProcessId, 0);
	if (!unknown && GetLastError() != ERROR_INVALID_DATA) ++failures;
	if (unknown) { ++failures; CloseHandle(unknown); }
	if (WaitForSingleObject(child.hProcess, 0) != WAIT_TIMEOUT) ++failures;
	HANDLE held = ProcessActions::OpenForTermination(child.dwProcessId, created);
	std::vector<ProcessActions::TerminationTarget> targets;
	ProcessActions::TerminationTarget exact = { child.dwProcessId, created };
	targets.push_back(exact);
	targets.push_back(exact); // A duplicate/naturally exited target is harmless.
	const std::vector<DWORD> ended = ProcessActions::TerminateExactProcesses(targets);
	if (ended[0] || ended[1])
		std::cerr << "Batch termination errors: " << ended[0] << ", " << ended[1] << std::endl;
	if (!held || ended[0] || ended[1] || WaitForSingleObject(held, 0) != WAIT_OBJECT_0)
		++failures;
	const std::vector<DWORD> alreadyExited = ProcessActions::TerminateExactProcesses(targets);
	if (alreadyExited[0] || alreadyExited[1])
		std::cerr << "Already exited errors: " << alreadyExited[0] << ", " << alreadyExited[1] << std::endl;
	if (alreadyExited[0] || alreadyExited[1]) ++failures;
	if (held) CloseHandle(held);
	HANDLE exited = ProcessActions::OpenForTermination(child.dwProcessId, created);
	if (exited) { ++failures; CloseHandle(exited); }
	// Cleanup the owned child even if a check failed.
	if (WaitForSingleObject(child.hProcess, 0) != WAIT_OBJECT_0) TerminateProcess(child.hProcess, 1);
	WaitForSingleObject(child.hProcess, 5000);
	CloseHandle(child.hThread);
	CloseHandle(child.hProcess);
	// A live access-denied process must still fail, but its exited kernel
	// object must not produce error 5 merely because we retain a handle.
	ACL acl;
	SECURITY_DESCRIPTOR descriptor;
	if (!InitializeAcl(&acl, sizeof(acl), ACL_REVISION) ||
		!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
		!SetSecurityDescriptorDacl(&descriptor, TRUE, &acl, FALSE)) return 1;
	SECURITY_ATTRIBUTES attributes = { sizeof(attributes), &descriptor, FALSE };
	WCHAR command[] = L"cmd.exe /d /c exit 0";
	if (!CreateProcessW(executable.c_str(), command, &attributes, NULL, FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &child)) return 1;
	targets.clear();
	ProcessActions::TerminationTarget protectedTarget = {
		child.dwProcessId, ProcessActions::CreationTime(child.hProcess) };
	targets.push_back(protectedTarget);
	const std::vector<DWORD> denied = ProcessActions::TerminateExactProcesses(targets);
	if (denied[0] != ERROR_ACCESS_DENIED ||
		WaitForSingleObject(child.hProcess, 0) != WAIT_TIMEOUT) ++failures;
	// A different lifetime at the same inaccessible PID is not our target.
	targets[0].creationTime = protectedTarget.creationTime - 1;
	const std::vector<DWORD> reusedDenied = ProcessActions::TerminateExactProcesses(targets);
	if (reusedDenied[0] || WaitForSingleObject(child.hProcess, 0) != WAIT_TIMEOUT)
	{
		std::cerr << "Reused inaccessible PID error: " << reusedDenied[0] << std::endl;
		++failures;
	}
	targets[0] = protectedTarget;
	ResumeThread(child.hThread);
	if (WaitForSingleObject(child.hProcess, 10000) != WAIT_OBJECT_0)
	{
		++failures;
		TerminateProcess(child.hProcess, 1);
		WaitForSingleObject(child.hProcess, 5000);
	}
	const std::vector<DWORD> exitedDenied = ProcessActions::TerminateExactProcesses(targets);
	if (exitedDenied[0])
	{
		std::cerr << "Exited access-denied object error: " << exitedDenied[0] << std::endl;
		++failures;
	}
	CloseHandle(child.hThread);
	CloseHandle(child.hProcess);
	std::cout << "ProcessActions tests " << (failures ? "FAILED" : "passed") << std::endl;
	return failures ? 1 : 0;
}
