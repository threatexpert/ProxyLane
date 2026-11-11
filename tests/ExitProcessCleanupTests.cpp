#include "ExitProcessCleanup.h"
#include <iostream>
#include <string>

namespace
{
	struct Process { DWORD pid; ULONGLONG startTimeValue; };
}

int ExitProcessCleanupTestsMain()
{
	int failures = 0;
	HANDLE cancel = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!cancel) return 1;
	WCHAR system[MAX_PATH] = {};
	GetSystemDirectoryW(system, MAX_PATH);
	const std::wstring executable = std::wstring(system) + L"\\cmd.exe";
	std::vector<PROCESS_INFORMATION> owned;
	bool spawnFailed = false;
	// Replace each terminated process with a new, real owned process. New
	// arrivals must not reset the round's total budget, including enumeration.
	const DWORD started = GetTickCount();
	auto replenishing = [&](std::vector<Process>& processes) {
		Sleep(40);
		STARTUPINFOW startup = {sizeof(startup)};
		PROCESS_INFORMATION child = {};
		processes.clear();
		if (!CreateProcessW(executable.c_str(), NULL, NULL, NULL, FALSE,
			CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &startup, &child))
		{ spawnFailed = true; return; }
		owned.push_back(child);
		Process process = {child.dwProcessId, ProcessActions::CreationTime(child.hProcess)};
		processes.push_back(process);
	};
	const auto timedOut = ExitProcessCleanup::Run<Process>(replenishing, cancel, 250);
	const DWORD elapsed = GetTickCount() - started;
	if (spawnFailed || timedOut.status != ExitProcessCleanup::TimedOut ||
		elapsed < 250 || elapsed > 1500 || owned.size() < 2 || timedOut.processes.size() != 1)
		++failures;
	if (!owned.empty() && WaitForSingleObject(owned.back().hProcess, 0) != WAIT_TIMEOUT)
		++failures; // Nothing new is killed after the deadline.
	auto remaining = [&](std::vector<Process>& processes) {
		processes.clear();
		for (size_t i = 0; i < owned.size(); ++i)
			if (WaitForSingleObject(owned[i].hProcess, 0) == WAIT_TIMEOUT)
			{
				Process process = {owned[i].dwProcessId, ProcessActions::CreationTime(owned[i].hProcess)};
				processes.push_back(process);
			}
	};
	// Cancellation does not terminate the survivor; continuing gets a fresh
	// budget and waits for the quiet period after the survivor has exited.
	SetEvent(cancel);
	if (ExitProcessCleanup::Run<Process>(remaining, cancel).status != ExitProcessCleanup::Cancelled)
		++failures;
	if (!owned.empty() && WaitForSingleObject(owned.back().hProcess, 0) != WAIT_TIMEOUT)
		++failures;
	ResetEvent(cancel);
	if (ExitProcessCleanup::Run<Process>(remaining, cancel, 1500).status != ExitProcessCleanup::Completed)
		++failures;
	for (size_t i = 0; i < owned.size(); ++i)
	{
		if (WaitForSingleObject(owned[i].hProcess, 0) != WAIT_OBJECT_0)
		{ ++failures; TerminateProcess(owned[i].hProcess, 1); }
		WaitForSingleObject(owned[i].hProcess, 5000);
		CloseHandle(owned[i].hThread);
		CloseHandle(owned[i].hProcess);
	}
	CloseHandle(cancel);
	std::cout << "ExitProcessCleanup tests " << (failures ? "FAILED" : "passed") << std::endl;
	return failures ? 1 : 0;
}
