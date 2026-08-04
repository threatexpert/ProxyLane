#if !defined(AFX_TIMEOUTMONITOR_H__C5C2E8A2_5742_2F43_A6D5_F07BA59ECDEA__INCLUDED_)
#define AFX_TIMEOUTMONITOR_H__C5C2E8A2_5742_2F43_A6D5_F07BA59ECDEA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000



//各种状态的超时索引
typedef enum 
{
	TM_0 = 0,
	TM_DNS,
	TM_CONN, 
	TM_RECV,
	TM_SEND,
	TM_IDLE,
	TM_SHUT,
	TM_CLOSE,

	TM_COUNT,
}em_TMTimeOut;

class CTimeoutMonitor
{
public:
	CTimeoutMonitor()
	{
		m_Time = GetTickCount();
		m_timeout = 20*1000; //20 sec
		m_bValid = TRUE;
	}
private:
	DWORD m_Time;
	DWORD m_timeout;
	BOOL  m_bValid;

public:

	VOID SetTimeoutVal(DWORD val)
	{
		m_timeout = val;
	}

	VOID Enable()
	{
		m_bValid = TRUE;
	}

	VOID Disable()
	{
		m_bValid = FALSE;
	}

	VOID Update()
	{
		m_Time = GetTickCount();
	}

	DWORD Get()
	{
		return m_Time;
	}

	BOOL IsTimeout()
	{
		if(m_bValid == FALSE)
			return FALSE;

		return GetTickCount() - m_Time > m_timeout;
	}
};


#endif // !defined(AFX_TIMEOUTMONITOR_H__C5C2E8A2_5742_2F43_A6D5_F07BA59ECDEA__INCLUDED_)
