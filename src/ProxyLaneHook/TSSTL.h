#pragma once

#include <list>

using namespace std;


//Thread Safe List


template<class _Ty,
class _Ax = allocator<_Ty> >
class CTSList
	: public list<_Ty,_Ax> 
{
public:

	class critical
	{
	public:
		critical(CTSList<_Ty,_Ax> &ls)
		{
			m_hEvent = ls.m_eventlock;
			WaitForSingleObject(m_hEvent, -1);
		}
		~critical()
		{
			SetEvent(m_hEvent);
		}

	private:
		HANDLE m_hEvent;
	};

	CTSList(void)
	{
		m_eventlock = CreateEvent(0, 0, 1, 0);
	}

	~CTSList(void)
	{
		CloseHandle(m_eventlock);
	}

	HANDLE m_eventlock;
};