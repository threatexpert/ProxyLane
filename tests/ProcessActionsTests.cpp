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
	HANDLE wrong = ProcessActions::OpenForTermination(child.dwProcessId, created + 1);
	if (wrong) { ++failures; CloseHandle(wrong); }
	HANDLE unknown = ProcessActions::OpenForTermination(child.dwProcessId, 0);
	if (unknown) { ++failures; CloseHandle(unknown); }
	if (WaitForSingleObject(child.hProcess, 0) != WAIT_TIMEOUT) ++failures;
	HANDLE held = ProcessActions::OpenForTermination(child.dwProcessId, created);
	if (!held || !TerminateProcess(held, 1) || WaitForSingleObject(held, 5000) != WAIT_OBJECT_0)
		++failures;
	if (held) CloseHandle(held);
	HANDLE exited = ProcessActions::OpenForTermination(child.dwProcessId, created);
	if (exited) { ++failures; CloseHandle(exited); }
	// Cleanup the owned child even if a check failed.
	if (WaitForSingleObject(child.hProcess, 0) != WAIT_OBJECT_0) TerminateProcess(child.hProcess, 1);
	WaitForSingleObject(child.hProcess, 5000);
	CloseHandle(child.hThread);
	CloseHandle(child.hProcess);
	std::cout << "ProcessActions tests " << (failures ? "FAILED" : "passed") << std::endl;
	return failures ? 1 : 0;
}
