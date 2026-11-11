#include "AsyncSnapshot.h"
#include <iostream>
#include <atomic>
#include <stdexcept>

namespace {
	struct Gate {
		HANDLE entered = CreateEventW(NULL, TRUE, FALSE, NULL);
		HANDLE release = CreateEventW(NULL, TRUE, FALSE, NULL);
		HANDLE exited = CreateEventW(NULL, TRUE, FALSE, NULL);
		~Gate() { CloseHandle(entered); CloseHandle(release); CloseHandle(exited); }
	};
	bool Idle(AsyncSnapshot<int>& query) {
		const DWORD start = GetTickCount();
		while (query.Busy() && GetTickCount() - start < 3000) Sleep(1);
		return !query.Busy();
	}
}

int AsyncSnapshotTestsMain()
{
	int failures = 0;
	auto gate = std::make_shared<Gate>();
	AsyncSnapshot<int> query;
	if (!query.Request([gate](int& value) {
		SetEvent(gate->entered);
		WaitForSingleObject(gate->release, 5000);
		value = 41;
		return true;
	})) return 1;
	if (WaitForSingleObject(gate->entered, 3000) != WAIT_OBJECT_0) ++failures;
	const DWORD start = GetTickCount();
	for (int i = 0; i < 1000; ++i) {
		if (query.Request([](int&) { return true; }) || query.Take()) ++failures;
	}
	query.Cancel();
	// Cancelling/reopening must not spawn another blocked query, or wait for one.
	if (query.Request([](int&) { return true; }) || query.Take()) ++failures;
	if (GetTickCount() - start > 250) ++failures;
	SetEvent(gate->release);
	if (!Idle(query) || query.Take()) ++failures; // No late result after collapse.
	if (!query.Request([](int& value) { value = 42; return true; }) || !Idle(query)) ++failures;
	auto result = query.Take();
	if (!result || !result->succeeded || result->value != 42 || query.Take()) ++failures;
	if (!query.Request([](int&) { return false; }) || !Idle(query)) ++failures;
	result = query.Take();
	if (!result || result->succeeded) ++failures;
	if (!query.Request([](int&) -> bool { throw std::runtime_error("query failure"); }) || !Idle(query)) ++failures;
	result = query.Take();
	if (!result || result->succeeded) ++failures;
	if (!query.Request([](int& value) { value = 43; return true; }) || !Idle(query)) ++failures;
	result = query.Take();
	if (!result || !result->succeeded || result->value != 43) ++failures;

	// Closing the owner never joins a stuck worker; it holds only its own state.
	gate = std::make_shared<Gate>();
	std::unique_ptr<AsyncSnapshot<int>> closing(new AsyncSnapshot<int>);
	if (!closing->Request([gate](int&) {
		SetEvent(gate->entered);
		WaitForSingleObject(gate->release, 5000);
		SetEvent(gate->exited);
		return true;
	})) ++failures;
	if (WaitForSingleObject(gate->entered, 3000) != WAIT_OBJECT_0) ++failures;
	const DWORD closeStart = GetTickCount();
	closing.reset();
	if (GetTickCount() - closeStart > 250) ++failures;
	SetEvent(gate->release);
	if (WaitForSingleObject(gate->exited, 3000) != WAIT_OBJECT_0) ++failures;
	if (failures) std::cerr << "AsyncSnapshot failures: " << failures << std::endl;
	else std::cout << "AsyncSnapshot slow-query isolation, single-flight, cancellation, failure recovery and close: PASS" << std::endl;
	return failures ? 1 : 0;
}
