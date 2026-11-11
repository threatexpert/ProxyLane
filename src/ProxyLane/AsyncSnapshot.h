#pragma once
#include <windows.h>
#include <memory>
#include <mutex>
#include <thread>

// One in-flight query and one result, with no UI pointers or completion messages.
// Cancellation invalidates late results; it never waits for a slow OS query.
template<class T> class AsyncSnapshot
{
public:
	struct Result { T value; bool succeeded = false; DWORD elapsed = 0; };
private:
	struct State {
		std::mutex mutex;
		bool busy = false;
		unsigned long long generation = 0;
		std::unique_ptr<Result> ready;
	};
	std::shared_ptr<State> m_state = std::make_shared<State>();
public:
	AsyncSnapshot() = default;
	AsyncSnapshot(const AsyncSnapshot&) = delete;
	AsyncSnapshot& operator=(const AsyncSnapshot&) = delete;
	~AsyncSnapshot() { Cancel(); }

	template<class Query> bool Request(Query query)
	{
		auto state = m_state;
		unsigned long long generation;
		{
			std::lock_guard<std::mutex> lock(state->mutex);
			if (state->busy || state->ready) return false;
			state->busy = true;
			generation = state->generation;
		}
		try {
			std::thread worker([state, generation, query]() mutable {
				SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
				std::unique_ptr<Result> result;
				try {
					result.reset(new Result);
					const DWORD start = GetTickCount();
					result->succeeded = query(result->value);
					result->elapsed = GetTickCount() - start;
				} catch (...) {} // Failure is a result too; subsequent requests can retry.
				std::lock_guard<std::mutex> lock(state->mutex);
				if (generation == state->generation) state->ready = std::move(result);
				state->busy = false;
			});
			worker.detach();
			return true;
		} catch (...) {
			std::lock_guard<std::mutex> lock(state->mutex);
			state->busy = false;
			return false;
		}
	}
	std::unique_ptr<Result> Take()
	{
		std::lock_guard<std::mutex> lock(m_state->mutex);
		return std::move(m_state->ready);
	}
	bool Busy() const
	{
		std::lock_guard<std::mutex> lock(m_state->mutex);
		return m_state->busy;
	}
	void Cancel()
	{
		std::lock_guard<std::mutex> lock(m_state->mutex);
		++m_state->generation;
		m_state->ready.reset();
	}
};
