#include "ScopedProcessSuspension.h"
#include <iostream>
#include <stdexcept>

namespace
{
	int suspends, resumes;
	bool failSuspend, failFirstResume;
	LONG WINAPI Suspend(HANDLE) { ++suspends; return failSuspend ? -1 : 0; }
	LONG WINAPI Resume(HANDLE) { ++resumes; return failFirstResume && resumes == 1 ? -1 : 0; }
	void Reset() { suspends = resumes = 0; failSuspend = failFirstResume = false; }
	HANDLE OwnedHandle() { return CreateEventW(NULL, TRUE, FALSE, NULL); }
}

int ScopedProcessSuspensionTestsMain()
{
	int failures = 0;
	Reset();
	{ CScopedProcessSuspension guard(OwnedHandle(), Suspend, Resume); }
	if (suspends != 1 || resumes != 1) ++failures;
	Reset();
	{ CScopedProcessSuspension guard(OwnedHandle(), Suspend, Resume);
		if (!guard.Resume() || !guard.Resume()) ++failures; }
	if (suspends != 1 || resumes != 1) ++failures;
	Reset();
	try { CScopedProcessSuspension guard(OwnedHandle(), Suspend, Resume);
		throw std::runtime_error("early exit"); } catch (const std::runtime_error&) {}
	if (suspends != 1 || resumes != 1) ++failures;
	Reset();
	failSuspend = true;
	{ CScopedProcessSuspension guard(OwnedHandle(), Suspend, Resume); }
	if (suspends != 1 || resumes != 0) ++failures;
	Reset();
	{ CScopedProcessSuspension guard(OwnedHandle(), Suspend, NULL); }
	if (suspends != 0 || resumes != 0) ++failures;
	Reset();
	failFirstResume = true;
	{ CScopedProcessSuspension guard(OwnedHandle(), Suspend, Resume);
		if (guard.Resume() || guard.ResumeStatus() >= 0) ++failures; }
	if (resumes != 2) ++failures;
	std::cout << "Scoped process suspension tests " << (failures ? "FAILED" : "passed") << std::endl;
	return failures ? 1 : 0;
}
