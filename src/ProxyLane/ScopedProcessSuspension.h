#pragma once
#include <windows.h>

// Owns the target handle and balances only the process-wide suspension that
// this scope added. Both APIs must be present before suspending anything.
class CScopedProcessSuspension
{
public:
	typedef LONG (WINAPI *ProcessAction)(HANDLE);
	CScopedProcessSuspension(HANDLE process, ProcessAction suspend, ProcessAction resume)
		: m_process(process), m_resume(resume), m_suspended(FALSE), m_resumeStatus(0)
	{
		if (process && suspend && resume && suspend(process) >= 0) m_suspended = TRUE;
	}
	~CScopedProcessSuspension()
	{
		Resume(); // Also covers early returns and C++ exceptions.
		if (m_process) CloseHandle(m_process);
	}
	BOOL Resume()
	{
		if (!m_suspended) return TRUE;
		m_resumeStatus = m_resume(m_process);
		if (m_resumeStatus < 0) return FALSE; // Destructor can retry once.
		m_suspended = FALSE;
		return TRUE;
	}
	LONG ResumeStatus() const { return m_resumeStatus; }

private:
	CScopedProcessSuspension(const CScopedProcessSuspension&);
	CScopedProcessSuspension& operator=(const CScopedProcessSuspension&);
	HANDLE m_process;
	ProcessAction m_resume;
	BOOL m_suspended;
	LONG m_resumeStatus;
};
