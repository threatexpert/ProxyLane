#include "BoundedLogQueue.h"

#include <cassert>
#include <iostream>

static void TestSingleNotificationAndResetAfterDrain()
{
	CBoundedLogQueue<int> queue(3, 2);

	assert(queue.Push(10));
	assert(!queue.Push(11));

	CBoundedLogQueue<int>::Batch batch = queue.TakeBatch();
	assert(batch.entries.size() == 2);
	assert(batch.entries.front() == 10);
	assert(batch.entries.back() == 11);
	assert(batch.dropped == 0);
	assert(!batch.hasMore);

	assert(queue.Push(12));
}

static void TestDropOldestAndDrainInFifoBatches()
{
	const size_t capacity = 5000;
	const size_t batchSize = 500;
	CBoundedLogQueue<int> queue(capacity, batchSize);

	for (int value = 0; value < 5002; ++value)
	{
		bool shouldNotify = queue.Push(value);
		assert(shouldNotify == (value == 0));
	}

	assert(queue.Size() == capacity);

	int expected = 2;
	size_t total = 0;
	size_t dropped = 0;
	bool hasMore = true;
	while (hasMore)
	{
		CBoundedLogQueue<int>::Batch batch = queue.TakeBatch();
		assert(batch.entries.size() <= batchSize);
		dropped += batch.dropped;

		for (std::list<int>::const_iterator it = batch.entries.begin();
			it != batch.entries.end(); ++it)
		{
			assert(*it == expected);
			++expected;
			++total;
		}
		hasMore = batch.hasMore;
	}

	assert(total == capacity);
	assert(dropped == 2);
	assert(expected == 5002);
	assert(queue.Size() == 0);
}

static void TestPostFailureAllowsAnotherNotification()
{
	CBoundedLogQueue<int> queue(5, 2);

	assert(queue.Push(1));
	queue.OnNotificationPostFailed();
	assert(queue.Push(2));
}

static void TestContinuationKeepsNotificationPending()
{
	CBoundedLogQueue<int> queue(5, 1);

	assert(queue.Push(1));
	assert(!queue.Push(2));
	CBoundedLogQueue<int>::Batch first = queue.TakeBatch();
	assert(first.hasMore);
	assert(!queue.Push(3));

	CBoundedLogQueue<int>::Batch second = queue.TakeBatch();
	CBoundedLogQueue<int>::Batch third = queue.TakeBatch();
	assert(second.entries.front() == 2);
	assert(second.hasMore);
	assert(third.entries.front() == 3);
	assert(!third.hasMore);
}

int main()
{
	TestSingleNotificationAndResetAfterDrain();
	TestDropOldestAndDrainInFifoBatches();
	TestPostFailureAllowsAnotherNotification();
	TestContinuationKeepsNotificationPending();

	std::cout << "BoundedLogQueue tests passed" << std::endl;
	return 0;
}
