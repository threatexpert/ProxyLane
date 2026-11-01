#pragma once

// Pure paging geometry shared by mouse/touch input and regression tests.
namespace LaunchPanelPaging
{
	inline int PageCount(int count, int capacity)
	{
		return count > 0 && capacity > 0 ? (count - 1) / capacity + 1 : 1;
	}
	inline int ClampPage(int page, int pages)
	{
		return page < 0 ? 0 : (page >= pages ? pages - 1 : page);
	}
	inline double DragOffset(double offset, double maximum)
	{
		if (offset < 0) return offset * 0.25;
		if (offset > maximum) return maximum + (offset - maximum) * 0.25;
		return offset;
	}
	inline int ReleasePage(int originPage, int deltaX, int width, int threshold, int pages)
	{
		if (width < 1) return 0;
		int page = static_cast<int>(originPage - static_cast<double>(deltaX) / width + 0.5);
		// A deliberate short swipe advances one page; a small movement snaps back.
		if (page == originPage && (deltaX >= threshold || deltaX <= -threshold))
			page += deltaX < 0 ? 1 : -1;
		return ClampPage(page, pages);
	}
	inline double Ease(double progress)
	{
		if (progress >= 1) return 1;
		if (progress <= 0) return 0;
		const double remaining = 1 - progress;
		return 1 - remaining * remaining * remaining;
	}
}
