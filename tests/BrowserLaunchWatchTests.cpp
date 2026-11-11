#include "BrowserLaunchWatch.h"
#include "ProcessCommandLine.h"
#include <iostream>

int BrowserLaunchWatchTestsMain()
{
	using namespace BrowserLaunchWatch;
	const auto check = [](bool passed, int line) {
		if (!passed) std::cerr << "Browser launch observation failed at " << line << std::endl;
		return passed;
	};
#define VERIFY(x) if (!check((x), __LINE__)) return 1
	VERIFY(Supported(L"C:\\Apps\\msedge.exe") && Supported(L"C:/Apps/CHROME.EXE"));
	VERIFY(!Supported(L"C:\\msedge.exe\\helper.exe") && !Supported(L"msedgewebview2.exe") && !Supported(L"firefox.exe"));
	VERIFY(ObservationMs == 2500);
	VERIFY(Classify(L"") == Unknown);
	VERIFY(Classify(L"\"C:\\Apps\\chrome.exe\" --user-data-dir=\"my --type=utility\" https://example/--type=renderer") == Main);
	VERIFY(Classify(L"chrome.exe --type=renderer") == Other);
	VERIFY(Classify(L"chrome.exe --type=utility --utility-sub-type=audio.mojom.AudioService") == Other);
	VERIFY(Classify(L"chrome.exe --type=utility --utility-sub-type=network.mojom.NetworkService") == Network);
	VERIFY(Classify(L"chrome.exe -- --type=renderer") == Main);
	VERIFY(Classify(L"chrome.exe --type") == Other);
	Observation observation;
	observation.launched = { 100, 500 };
	observation.started = 1000;
	observation.candidates = { {10, 100}, {11, 110}, {12, 120}, {13, 130} };
	ProxyProcessIdentity::Snapshot snapshot;
	snapshot.complete = TRUE;
	snapshot.creationTimes = { {100, 500}, {10, 100}, {11, 110}, {12, 121}, {14, 140} };
	std::vector<Identity> candidates;
	// A long-running independent profile never triggers merely because other profiles exist.
	VERIFY(Evaluate(observation, 2000, snapshot, candidates) == Pending && candidates.empty());
	VERIFY(Evaluate(observation, 3501, snapshot, candidates) == Discard);
	snapshot.creationTimes.erase(100);
	VERIFY(Evaluate(observation, 3500, snapshot, candidates) == Suggest);
	// Hooked roots remain candidates: their network service may be unhooked.
	VERIFY(candidates.size() == 2 && candidates[0].pid == 10 && candidates[0].time == 100);
	VERIFY(Evaluate(observation, 3501, snapshot, candidates) == Discard && candidates.empty());
	snapshot.complete = FALSE;
	VERIFY(Evaluate(observation, 2000, snapshot, candidates) == Pending);
	snapshot.complete = TRUE;
	snapshot.creationTimes[100] = 0;
	VERIFY(Evaluate(observation, 2000, snapshot, candidates) == Pending);
	snapshot.creationTimes[100] = 501; // New lifetime at launched PID.
	VERIFY(Evaluate(observation, 2000, snapshot, candidates) == Suggest);
	snapshot.creationTimes[10] = 101; // Candidate reused before viewing.
	VERIFY(!Matches(snapshot, observation.candidates[0]));
	snapshot.creationTimes.erase(11);
	VERIFY(Evaluate(observation, 2000, snapshot, candidates) == Discard);
	snapshot.creationTimes[10] = 100;
	observation.started = MAXDWORD - 100;
	VERIFY(Evaluate(observation, 200, snapshot, candidates) == Suggest); // Tick wrap.
	observation.launched.time = 0;
	VERIFY(Evaluate(observation, 200, snapshot, candidates) == Discard);
	observation.launched.time = 500;
	observation.candidates.clear();
	VERIFY(Evaluate(observation, 200, snapshot, candidates) == Discard);

	const std::wstring path = L"C:\\Apps\\chrome.exe";
	std::vector<Node> nodes = {
		{{10,100}, 1, 7, path, Main},
		{{11,110}, 10, 7, path, Other}, // Intermediate process, not necessarily injected.
		{{12,120}, 11, 7, path, Network},
		{{13,130}, 10, 7, path, Other}, // Renderer, irrelevant to network coverage.
		{{20,200}, 1, 7, path, Main}, // Independent user directory.
		{{21,210}, 20, 7, path, Network}
	};
	std::set<DWORD> injected;
	const auto hooked = [&](const Identity& identity) { return injected.count(identity.pid) != 0; };
	const std::vector<Identity> roots = {{10,100}};
	const auto incomplete = [&]() { return IncompleteInstances(nodes, roots, hooked); };
	VERIFY(Instances(nodes).size() == 2 && incomplete().size() == 1);
	VERIFY(incomplete()[0].networks.size() == 1 && incomplete()[0].networks[0].pid == 12);
	injected = {10};
	VERIFY(incomplete().size() == 1); // Main only is insufficient.
	injected = {12};
	VERIFY(incomplete().size() == 1); // Network only is insufficient.
	injected = {10,12};
	VERIFY(incomplete().empty()); // Ignore renderer failures and other profiles.
	nodes[2].identity = {14,140}; // Replacement network service must be checked afresh.
	VERIFY(incomplete().size() == 1);
	injected.insert(14);
	VERIFY(incomplete().empty());
	nodes.push_back({{15,150}, 10, 7, path, Network});
	VERIFY(incomplete().size() == 1); // Every identified network process must be hooked.
	nodes.pop_back();
	nodes[2].sessionId = 8;
	VERIFY(incomplete().size() == 1 && incomplete()[0].networks.empty());
	nodes[2].sessionId = 7;
	nodes[2].path = L"C:\\Other\\chrome.exe";
	VERIFY(incomplete()[0].networks.empty());
	nodes[2].path = path;
	nodes[1].identity.time = 1000; // Reused parent PID is not a valid ancestor.
	VERIFY(incomplete()[0].networks.empty());
	nodes[1].identity.time = 110;
	nodes[2].role = Unknown;
	VERIFY(incomplete().size() == 1 && incomplete()[0].networks.empty());
	nodes[2].role = Network;
	nodes[0].role = Unknown;
	VERIFY(incomplete().size() == 1); // An unreadable root is not proof of coverage.
	nodes[0].role = Main;
	nodes[0].identity.time = 101;
	VERIFY(incomplete().empty()); // Original root exited and PID was reused.
	nodes[0].identity.time = 100;
	nodes[1].parentPid = 14;
	nodes[1].identity.time = nodes[2].identity.time;
	VERIFY(incomplete()[0].networks.empty()); // Cycle terminates, never assigns another root.

	// Exercise native and legacy command-line readers on a real, owned process.
	FILETIME created, exited, kernel, user;
	VERIFY(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user));
	const ULONGLONG time = (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
	std::wstring commandLine;
	VERIFY(ProcessCommandLine::Query(GetCurrentProcessId(), time, commandLine) && commandLine == GetCommandLineW());
	VERIFY(!ProcessCommandLine::Query(GetCurrentProcessId(), time + 1, commandLine));
	const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	const auto query = reinterpret_cast<ProcessCommandLine::QueryInformation>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
	VERIFY(ProcessCommandLine::LegacyQuery(GetCurrentProcess(), query, ntdll, commandLine) && commandLine == GetCommandLineW());
#undef VERIFY
	std::cout << "Browser launch observation tests passed" << std::endl;
	return 0;
}
