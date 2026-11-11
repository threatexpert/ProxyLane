#pragma once
#include "../ProxyLaneHook/ProcessIdentity.h"
#include <shellapi.h>
#include <set>
#pragma comment(lib, "shell32.lib")

namespace BrowserLaunchWatch
{
	const DWORD ObservationMs = 2500;
	struct Identity { DWORD pid; ULONGLONG time; };
	enum Role { Unknown, Main, Network, Other };
	struct Node
	{
		Identity identity;
		DWORD parentPid, sessionId;
		std::wstring path;
		Role role;
	};
	struct Instance
	{
		Node main;
		std::vector<Identity> networks;
	};
	struct Observation
	{
		Identity launched = {};
		DWORD started = 0;
		std::vector<Identity> candidates;
		std::wstring path;
		DWORD sessionId = 0;
	};
	enum Result { Pending, Discard, Suggest };

	// Parse switches as arguments, never search URLs or profile names for substrings.
	inline Role Classify(const std::wstring& commandLine)
	{
		if (commandLine.empty()) return Unknown;
		int count = 0;
		LPWSTR* args = CommandLineToArgvW(commandLine.c_str(), &count);
		if (!args) return Unknown;
		std::wstring type, subtype;
		for (int i = 1; i < count; ++i)
		{
			const std::wstring arg(args[i]);
			if (arg == L"--") break;
			if (arg.compare(0, 7, L"--type=") == 0) type = arg.substr(7);
			else if (arg == L"--type") type = L"?"; // Malformed/ambiguous role is not a browser root.
			else if (arg.compare(0, 19, L"--utility-sub-type=") == 0) subtype = arg.substr(19);
		}
		LocalFree(args);
		return type.empty() ? Main : type == L"utility" && subtype == L"network.mojom.NetworkService" ? Network : Other;
	}

	inline const Node* Parent(const Node& node, const std::map<DWORD, const Node*>& nodes)
	{
		const auto found = nodes.find(node.parentPid);
		if (found == nodes.end()) return NULL;
		const Node* parent = found->second;
		return parent->identity.pid != node.identity.pid && parent->identity.time && node.identity.time &&
			parent->identity.time <= node.identity.time && parent->sessionId == node.sessionId &&
			!_wcsicmp(parent->path.c_str(), node.path.c_str()) ? parent : NULL;
	}

	inline std::vector<Instance> Instances(const std::vector<Node>& processes)
	{
		std::map<DWORD, const Node*> nodes;
		for (const auto& node : processes) nodes[node.identity.pid] = &node;
		std::vector<Instance> result;
		std::map<DWORD, size_t> roots;
		for (const auto& node : processes)
		{
			if (!node.identity.pid || !node.identity.time) continue;
			if (node.role != Main && !(node.role == Unknown && !Parent(node, nodes))) continue;
			roots[node.identity.pid] = result.size();
			result.push_back({ node, {} });
		}
		for (const auto& node : processes)
		{
			if (node.role != Network) continue;
			std::set<DWORD> visited;
			const Node* ancestor = &node;
			while ((ancestor = Parent(*ancestor, nodes)) != NULL && visited.insert(ancestor->identity.pid).second)
			{
				const auto root = roots.find(ancestor->identity.pid);
				if (root == roots.end()) continue;
				result[root->second].networks.push_back(node.identity);
				break;
			}
		}
		return result;
	}

	template<class IsHooked>
	std::vector<Instance> IncompleteInstances(const std::vector<Node>& nodes,
		const std::vector<Identity>& roots, IsHooked isHooked)
	{
		std::vector<Instance> result;
		for (const auto& instance : Instances(nodes))
		{
			bool existed = false;
			for (const auto& root : roots)
				if (root.pid == instance.main.identity.pid && root.time == instance.main.identity.time) existed = true;
			if (!existed) continue;
			bool covered = instance.main.role == Main && isHooked(instance.main.identity) && !instance.networks.empty();
			for (const auto& network : instance.networks) covered = covered && isHooked(network);
			if (!covered) result.push_back(instance);
		}
		return result;
	}

	inline bool Supported(const std::wstring& path)
	{
		const size_t slash = path.find_last_of(L"\\/");
		const std::wstring name = path.substr(slash == std::wstring::npos ? 0 : slash + 1);
		return !_wcsicmp(name.c_str(), L"msedge.exe") || !_wcsicmp(name.c_str(), L"chrome.exe");
	}
	inline bool Matches(const ProxyProcessIdentity::Snapshot& snapshot, const Identity& identity)
	{
		const auto found = snapshot.creationTimes.find(identity.pid);
		return snapshot.complete && identity.pid && identity.time &&
			found != snapshot.creationTimes.end() && found->second == identity.time;
	}

	// No inference from a failed snapshot, a late timer, or a missing timestamp.
	// "Suggest" means possible handoff, never proof of which profile received it.
	inline Result Evaluate(const Observation& observation, DWORD now,
		const ProxyProcessIdentity::Snapshot& snapshot,
		std::vector<Identity>& candidates)
	{
		candidates.clear();
		if (!observation.launched.pid || !observation.launched.time ||
			now - observation.started > ObservationMs || observation.candidates.empty()) return Discard;
		if (!snapshot.complete) return Pending;
		const auto launched = snapshot.creationTimes.find(observation.launched.pid);
		if (launched != snapshot.creationTimes.end() &&
			(!launched->second || launched->second == observation.launched.time)) return Pending;
		for (const auto& candidate : observation.candidates)
			if (candidate.pid != observation.launched.pid && Matches(snapshot, candidate))
				candidates.push_back(candidate);
		return candidates.empty() ? Discard : Suggest;
	}
}
