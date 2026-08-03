#pragma once

#include <cassert>
#include <cstddef>
#include <list>

template <typename T>
class CBoundedLogQueue
{
public:
	struct Batch
	{
		Batch()
			: dropped(0)
			, hasMore(false)
		{
		}

		std::list<T> entries;
		size_t dropped;
		bool hasMore;
	};

	CBoundedLogQueue(size_t capacity, size_t batchSize)
		: m_capacity(capacity)
		, m_batchSize(batchSize)
		, m_dropped(0)
		, m_notificationPending(false)
	{
		assert(m_capacity > 0);
		assert(m_batchSize > 0);
	}

	bool Push(const T& value)
	{
		if (m_entries.size() >= m_capacity)
		{
			m_entries.pop_front();
			++m_dropped;
		}

		m_entries.push_back(value);
		if (m_notificationPending)
			return false;

		m_notificationPending = true;
		return true;
	}

	Batch TakeBatch()
	{
		Batch batch;
		batch.dropped = m_dropped;
		m_dropped = 0;

		for (size_t count = 0;
			count < m_batchSize && !m_entries.empty(); ++count)
		{
			batch.entries.splice(batch.entries.end(),
				m_entries, m_entries.begin());
		}

		batch.hasMore = !m_entries.empty();
		if (!batch.hasMore)
			m_notificationPending = false;

		return batch;
	}

	void OnNotificationPostFailed()
	{
		m_notificationPending = false;
	}

	size_t Size() const
	{
		return m_entries.size();
	}

private:
	std::list<T> m_entries;
	size_t m_capacity;
	size_t m_batchSize;
	size_t m_dropped;
	bool m_notificationPending;
};
