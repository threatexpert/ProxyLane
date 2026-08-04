/************************************************************************/
/*                                                                      */
/************************************************************************/

#if !defined(C_TimerQueue_H__EB442DEA_F326_46fb_AD76_5AE99E54CEF8__INCLUDED_)
#define C_TimerQueue_H__EB442DEA_F326_46fb_AD76_5AE99E54CEF8__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef _WIN32_WINNT
	#define _WIN32_WINNT 0x0500
#endif

#include <windows.h>
#include <stdio.h>
#include <map>
#include <assert.h>

using namespace std;

class CTimerQueue
{

	class CPerTimer 
	{
	public:
		CPerTimer()
		{
			ZeroMemory(this, sizeof(*this));
		}

		~CPerTimer()
		{
			if(hTimer != NULL)
			{
				//INVALID_HANDLE_VALUE: the function waits for the timer callback function to complete before returning.
				DeleteTimerQueueTimer(hTimerQueue, hTimer, INVALID_HANDLE_VALUE);
				hTimer = NULL;
			}		
		}

		BOOL KillTimer()
		{
			BOOL ret = FALSE;
			if(hTimer != NULL)
			{
				ret = DeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
				if(ret || GetLastError() == ERROR_IO_PENDING)
				{
					ret = TRUE;
					hTimer = NULL;
				}else
				{
					//ATLTRACE("DeleteTimerQueueTimer err: %d\r\n", GetLastError());
				}
				return ret;
			}
			return ret;
		}

		CTimerQueue *pParent;
		HANDLE hTimerQueue;
		UINT_PTR nIDEvent;
		HANDLE hTimer;
		UINT uElapse;
	};


public:

	CTimerQueue(void)
	{
		m_hTimerQueue = NULL;
	}

	~CTimerQueue(void)
	{
		DestroyTimerQueue(TRUE);
	}

	BOOL SetTimer(__in UINT_PTR nIDEvent, __in UINT DueTime, __in UINT uElapse, __in ULONG Flags)
	{
		if(m_hTimerQueue == NULL)
		{
			if((m_hTimerQueue = CreateTimerQueue()) == NULL)
			{
				//ATLTRACE("CreateTimerQueue failed (%d)\n", GetLastError());
				return FALSE;
			}
		}

		m_Timermap[nIDEvent].pParent = this;
		m_Timermap[nIDEvent].hTimerQueue = m_hTimerQueue;

		CPerTimer &perTimer = m_Timermap[nIDEvent];

		//ATLTRACE("perTimer: %x\r\n", &perTimer);

		if(perTimer.hTimer != NULL)	
		{
			if(!perTimer.KillTimer())
				return FALSE;
		}
		
		perTimer.nIDEvent = nIDEvent;
		perTimer.uElapse = uElapse;

		if (!CreateTimerQueueTimer(
			&perTimer.hTimer, m_hTimerQueue, TimerRoutine, &perTimer, DueTime, uElapse, Flags))
		{
			//ATLTRACE("CreateTimerQueueTimer failed (%d)\n", GetLastError());
			return FALSE;
		}

		return TRUE;
	}

	BOOL IsTimerEnabled(__in UINT_PTR uIDEvent)
	{
		map<UINT_PTR, CPerTimer>::iterator it = m_Timermap.find(uIDEvent);
		if(it == m_Timermap.end())
			return FALSE;
		else
			return TRUE;
	}

	BOOL SetTimer(__in UINT_PTR nIDEvent, __in UINT uElapse)
	{
		//参数2 的uElapse 表示 在 uElapse秒后触发第一次OnTimer
		return SetTimer(nIDEvent, uElapse, uElapse, WT_EXECUTEINTIMERTHREAD);
	}

	BOOL KillTimer(__in UINT_PTR uIDEvent)
	{
		map<UINT_PTR, CPerTimer>::iterator it = m_Timermap.find(uIDEvent);
		if(it == m_Timermap.end())
			return FALSE;
		
		CPerTimer &perTimer = it->second;
		return perTimer.KillTimer();
	}

	//不能在OnTimer内部调用，否则会出现锁死或其它问题
	BOOL KillAllTimer(BOOL bWait)
	{
		if(bWait == TRUE)
		{
			m_Timermap.clear();
			return TRUE;
		}else
		{
			for(map<UINT_PTR, CPerTimer>::iterator it = m_Timermap.begin();
				it != m_Timermap.end();
				it++)
			{
				if(!it->second.KillTimer())
					return FALSE;
			}
			return TRUE;
		}

	};

	VOID DestroyTimerQueue(BOOL bWait)
	{
		if(m_hTimerQueue != NULL)
		{
			if(KillAllTimer(TRUE))
			{
				if(DeleteTimerQueueEx(m_hTimerQueue, bWait?INVALID_HANDLE_VALUE:NULL) == TRUE || GetLastError() == ERROR_IO_PENDING)
				{
					m_hTimerQueue = NULL;
					//ATLTRACE("DeleteTimerQueue == success\r\n");
					return;
				}
			}
			//ATLTRACE("DestroyTimerQueue err: %d\r\n", GetLastError());
		}
	};

	static VOID CALLBACK TimerRoutine(
		PVOID lpParameter,
		BOOLEAN TimerOrWaitFired
		)
	{
		CPerTimer *pPerTimer = (CPerTimer*)lpParameter;

		pPerTimer->pParent->OnTimer(pPerTimer->nIDEvent);
	}


	virtual VOID OnTimer(UINT_PTR nIDEvent)
	{

	}

private:
	HANDLE m_hTimerQueue;
	map<UINT_PTR /*nIDEvent*/, CPerTimer> m_Timermap;
};

//2008.1.1 add
class CWndTimer
{
public:
	CWndTimer()
	{
		m_hTimerWnd = NULL;
		InitWnd();
	}
	~CWndTimer()
	{
		if(m_hTimerWnd)
			DestroyWnd();

	}

	HWND GetHwnd()
	{
		return m_hTimerWnd;
	}

	BOOL SetTimer(__in UINT_PTR nIDEvent, __in UINT uElapse)
	{
		if(m_hTimerWnd == NULL)
		{
			return FALSE;
		}

		return ::SetTimer(m_hTimerWnd, nIDEvent, uElapse, NULL) != 0;
	}

	BOOL KillTimer(__in UINT_PTR uIDEvent)
	{
		if(m_hTimerWnd == NULL)
			return FALSE;
		return ::KillTimer(m_hTimerWnd, uIDEvent);
	}

	virtual VOID OnTimer(UINT_PTR nIDEvent)
	{

	}

	virtual VOID OnMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{

	}

	BOOL InitWnd()
	{
		assert(m_hTimerWnd == NULL);

		WNDCLASS wndclass;
		memset(&wndclass, 0, sizeof(wndclass));
		wndclass.lpfnWndProc = CWndTimer::WndProc;
		wndclass.lpszClassName = _T("CWndTimer");

		RegisterClass(&wndclass);

		m_hTimerWnd = CreateWindowEx(0, _T("CWndTimer"), _T("WndTimer"),
			WS_OVERLAPPEDWINDOW, 0, 0, 0, 0,
			NULL, NULL, NULL, NULL);

		if(m_hTimerWnd == NULL)
			return FALSE;

		SetWindowLongPtr(m_hTimerWnd, GWLP_USERDATA, (LONG_PTR)this);

		return TRUE;
	};

	BOOL DestroyWnd()
	{
		return ::DestroyWindow(m_hTimerWnd);
	}

private:

	static LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		CWndTimer *_this = (CWndTimer*)GetWindowLongPtr(hWnd, GWLP_USERDATA);

		if (!_this)
		{
			return DefWindowProc(hWnd, uMsg, wParam, lParam);
		}

		BOOL bHandled = FALSE;
		switch(uMsg)
		{

		case WM_TIMER:
			_this->OnTimer(wParam);
			return 0;

		default:
			{
				_this->OnMessage(uMsg, wParam, lParam, bHandled);
				if (bHandled)
					return 0;
			}
		}
		return DefWindowProc(hWnd, uMsg, wParam, lParam);
	}


public:
	HWND m_hTimerWnd;
};

#endif //C_TimerQueue_H__EB442DEA_F326_46fb_AD76_5AE99E54CEF8__INCLUDED_
