#pragma once
#include "ProcessActions.h"
#include <algorithm>

namespace ExitProcessCleanup
{
	const DWORD RoundTimeoutMs = 10000;
	enum Status { Completed, TimedOut, Cancelled, Failed };

	template<class Process> struct Result
	{
		Status status = Failed;
		std::vector<Process> processes;
		std::vector<DWORD> errors;
	};

	// Only the worker calls snapshot. No UI access or message pumping here.
	// A fresh invocation gets a fresh total budget; batches never reset it.
	template<class Process, class Snapshot>
	Result<Process> Run(Snapshot snapshot, HANDLE cancel, DWORD budgetMs = RoundTimeoutMs)
	{
		Result<Process> result;
		const DWORD started = GetTickCount();
		DWORD emptySince = started;
		bool wasEmpty = false;
		for (;;)
		{
			if (WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0)
			{ result.status = Cancelled; return result; }
			snapshot(result.processes);
			const DWORD now = GetTickCount(), elapsed = now - started;
			if (elapsed >= budgetMs)
			{ result.status = TimedOut; return result; }
			if (result.processes.empty())
			{
				if (!wasEmpty) emptySince = now;
				wasEmpty = true;
				if (now - emptySince >= 500)
				{ result.status = Completed; return result; }
				WaitForSingleObject(cancel, (std::min)(50UL, budgetMs - elapsed));
				continue;
			}
			wasEmpty = false;
			std::vector<ProcessActions::TerminationTarget> targets;
			for (size_t i = 0; i < result.processes.size(); ++i)
			{
				ProcessActions::TerminationTarget target = {
					result.processes[i].pid, result.processes[i].startTimeValue };
				targets.push_back(target);
			}
			const DWORD beforeBatch = GetTickCount() - started;
			if (beforeBatch >= budgetMs)
			{ result.status = TimedOut; return result; }
			result.errors = ProcessActions::TerminateExactProcesses(targets,
				budgetMs - beforeBatch, cancel);
			for (size_t i = 0; i < result.errors.size(); ++i)
			{
				if (result.errors[i] == ERROR_CANCELLED)
				{ result.status = Cancelled; return result; }
				// Pending exits share the total budget instead of failing a round early.
				if (result.errors[i] && result.errors[i] != ERROR_TIMEOUT)
				{ result.status = Failed; return result; }
			}
			result.errors.clear();
		}
	}
}
