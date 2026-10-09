#include "TrafficStatistics.h"
#include "TrafficRateSampler.h"

#include <iostream>
#include <thread>
#include <vector>
#include <cstdlib>

static void Require(bool condition)
{
	if (!condition)
	{
		std::cerr << "Traffic statistics test failed" << std::endl;
		std::exit(1);
	}
}

int TrafficStatisticsTestsMain()
{
	CTrafficStatistics totals;
	ULONGLONG upload, download;
	totals.RecordTransfer(false, -1);
	totals.RecordTransfer(true, 0);
	totals.GetTotals(upload, download);
	Require(upload == 0 && download == 0);

	// Simultaneous writers and UI snapshots, exceeding 32-bit byte counts.
	std::vector<std::thread> workers;
	for (int i = 0; i < 4; ++i)
		workers.push_back(std::thread([&totals, i]() {
			for (int j = 0; j < 10000; ++j)
				totals.RecordTransfer(i % 2 != 0, 300000);
		}));
	ULONGLONG previousUpload = 0, previousDownload = 0;
	for (int i = 0; i < 10000; ++i)
	{
		totals.GetTotals(upload, download);
		Require(upload >= previousUpload && download >= previousDownload);
		previousUpload = upload;
		previousDownload = download;
	}
	for (size_t i = 0; i < workers.size(); ++i)
		workers[i].join();
	totals.GetTotals(upload, download);
	Require(upload == 6000000000ULL && download == 6000000000ULL);
	totals.Reset();
	totals.GetTotals(upload, download);
	Require(upload == 0 && download == 0);

	CTrafficRateSampler sampler;
	double up, down;
	sampler.Reset(5000000000ULL, 6000000000ULL, 100);
	// Timer delivery can be delayed: use measured elapsed time, not one second.
	sampler.Sample(5000003000ULL, 6000006000ULL, 1600, up, down);
	Require(up == 2000 && down == 4000);
	sampler.Sample(5000003000ULL, 6000006000ULL, 2600, up, down);
	Require(up == 0 && down == 0);
	// A restart must not underflow into a huge rate.
	sampler.Sample(0, 0, 3600, up, down);
	Require(up == 0 && down == 0);
	sampler.Sample(1000, 2000, 4600, up, down);
	Require(up == 1000 && down == 2000);
	// Preserve byte deltas when two samples have the same timestamp.
	sampler.Sample(2000, 4000, 4600, up, down);
	Require(up == 0 && down == 0);
	sampler.Sample(3000, 6000, 5600, up, down);
	Require(up == 2000 && down == 4000);
	sampler.Reset(0, 0, 0xFFFFFF00);
	sampler.Sample(1000, 2000, 744, up, down);
	Require(up == 1000 && down == 2000);
	std::cout << "Traffic statistics tests passed" << std::endl;
	return 0;
}
