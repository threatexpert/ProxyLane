#pragma once
#include "ExitProcessesDialog.h"
#include "ExitProcessCleanup.h"
#include "Page3.h"
#include <afxcmn.h>

// Confirmation, cleanup and timeout share this one window. The worker never
// touches controls; its result is read only after its thread has finished.
class CExitCleanupDialog : public CExitProcessesDialog
{
public:
	CExitCleanupDialog(CPage3* page, UINT count, const CString& processes, CWnd* parent)
		: CExitProcessesDialog(count, processes, parent), m_page(page) {}
	~CExitCleanupDialog()
	{
		if (m_refreshWorker)
		{
			WaitForSingleObject(m_refreshWorker->m_hThread, INFINITE);
			delete m_refreshWorker;
		}
		if (m_worker)
		{
			SetEvent(m_cancel);
			WaitForSingleObject(m_worker->m_hThread, INFINITE);
			delete m_worker;
		}
		if (m_cancel) CloseHandle(m_cancel);
	}

	ExitProcessCleanup::Result<_myPROCESSINFO> result;
	DWORD workerError = ERROR_SUCCESS;

protected:
	BOOL OnInitDialog() override
	{
		CExitProcessesDialog::OnInitDialog();
		CRect area;
		GetDlgItem(IDC_EXIT_WARNING)->GetWindowRect(&area);
		ScreenToClient(&area);
		const int barHeight = UiTheme::ScaleForWindow(m_hWnd, 4);
		CClientDC dc(this);
		CFont* oldFont = dc.SelectObject(&m_uiFont);
		TEXTMETRIC metrics = {};
		dc.GetTextMetrics(&metrics);
		dc.SelectObject(oldFont);
		area.top = min(area.bottom - barHeight,
			area.top + metrics.tmHeight + UiTheme::ScaleForWindow(m_hWnd, 8));
		area.bottom = area.top + barHeight;
		area.right = area.left + UiTheme::ScaleForWindow(m_hWnd, 96);
		m_progress.Create(WS_CHILD | PBS_MARQUEE, area, this, IDC_EXIT_PROGRESS);
		SetTimer(2, 250, NULL);
		return FALSE;
	}
	void OnOK() override
	{
		if (!m_worker) EndDialog(IDOK);
	}
	void OnCancel() override
	{
		if (!m_worker) { EndDialog(IDCANCEL); return; }
		SetEvent(m_cancel);
		GetDlgItem(IDCANCEL)->EnableWindow(FALSE);
		if (m_slowShown)
			SetDlgItemText(IDC_EXIT_WARNING, Localization::Get(_T("exit.stopping")));
	}
	BOOL OnCommand(WPARAM wParam, LPARAM lParam) override
	{
		if (LOWORD(wParam) == IDC_EXIT_HIDE_TRAY && HIWORD(wParam) == BN_CLICKED)
		{
			// Stop automatic exit before dismissing the confirmation. If cleanup
			// is active, cancel it asynchronously and let its worker finish first.
			m_hideRequested = true;
			KillTimer(2);
			m_discardRefresh = true;
			m_emptySnapshot = false;
			if (!m_worker) EndDialog(IDC_EXIT_HIDE_TRAY);
			else
			{
				SetEvent(m_cancel);
				GetDlgItem(IDC_EXIT_HIDE_TRAY)->EnableWindow(FALSE);
				GetDlgItem(IDCANCEL)->EnableWindow(FALSE);
			}
			return TRUE;
		}
		if (LOWORD(wParam) == IDC_EXIT_TERMINATE && HIWORD(wParam) == BN_CLICKED)
		{
			if (!m_worker) StartCleanup();
			return TRUE;
		}
		return CModernDialog::OnCommand(wParam, lParam);
	}
	LRESULT WindowProc(UINT message, WPARAM wParam, LPARAM lParam) override
	{
		if (message == WM_TIMER && wParam == 2)
		{
			RefreshProcesses();
			return 0;
		}
		if (message == WM_TIMER && wParam == 1 && m_worker)
		{
			if (WaitForSingleObject(m_worker->m_hThread, 0) == WAIT_OBJECT_0)
				FinishCleanup();
			else if (!m_slowShown && GetTickCount() - m_started >= 500 &&
				WaitForSingleObject(m_cancel, 0) != WAIT_OBJECT_0 &&
				InterlockedCompareExchange(&m_hasProcesses, 0, 0))
			{
				// Do not flash a status just for the final quiet-period checks
				// after all processes have already exited.
				m_slowShown = true;
				SetDlgItemText(IDC_EXIT_WARNING, Localization::Get(_T("exit.cleaning")));
				SetDlgItemText(IDCANCEL, Localization::Get(_T("exit.stop_cleanup")));
				if (m_progress.GetSafeHwnd())
				{
					m_progress.SendMessage(PBM_SETMARQUEE, TRUE, 40);
					m_progress.ShowWindow(SW_SHOW);
				}
			}
			return 0;
		}
		return CExitProcessesDialog::WindowProc(message, wParam, lParam);
	}

private:
	void RefreshProcesses()
	{
		if (m_hideRequested) return;
		// Checking registered processes stays off the UI thread. At most one
		// refresh runs at a time; read its snapshot only after the thread exits.
		if (m_refreshWorker)
		{
			if (WaitForSingleObject(m_refreshWorker->m_hThread, 0) != WAIT_OBJECT_0) return;
			delete m_refreshWorker;
			m_refreshWorker = NULL;
			if (!m_worker && !m_discardRefresh && m_refreshSucceeded)
			{
				ShowProcesses(m_refreshProcesses);
				if (m_refreshProcesses.empty())
				{
					if (m_emptySnapshot)
					{
						KillTimer(2);
						EndDialog(IDOK);
						return;
					}
					m_emptySnapshot = true;
				}
				else m_emptySnapshot = false;
			}
			else m_emptySnapshot = false;
			m_discardRefresh = false;
		}
		if (m_worker || GetTickCount() - m_lastRefresh < 500) return;
		m_lastRefresh = GetTickCount();
		m_refreshSucceeded = FALSE;
		m_refreshWorker = AfxBeginThread(RefreshWork, this, THREAD_PRIORITY_NORMAL, 0, CREATE_SUSPENDED);
		if (!m_refreshWorker) { m_emptySnapshot = false; return; }
		m_refreshWorker->m_bAutoDelete = FALSE;
		m_refreshWorker->ResumeThread();
	}
	void ShowProcesses(const std::vector<_myPROCESSINFO>& processes)
	{
		CString details;
		for (size_t i = 0; i < processes.size(); ++i)
		{
			CString line;
			line.Format(_T("%s  (PID %lu)\r\n"), processes[i].proname, processes[i].pid);
			details += line;
		}
		const UINT count = static_cast<UINT>(processes.size());
		UpdateProcesses(count, details);
		const CString warning = Localization::Format(
			m_timedOut ? _T("exit.timeout") : _T("exit.processes_warning"), count);
		CString previous;
		GetDlgItemText(IDC_EXIT_WARNING, previous);
		if (previous != warning) SetDlgItemText(IDC_EXIT_WARNING, warning);
	}
	static UINT RefreshWork(LPVOID context)
	{
		CExitCleanupDialog* self = static_cast<CExitCleanupDialog*>(context);
		try
		{
			self->m_refreshSucceeded = self->m_page->GetRunningHookedProcesses(self->m_refreshProcesses);
		}
		catch (...) { self->m_refreshSucceeded = FALSE; }
		return 0;
	}
	void StartCleanup()
	{
		// A snapshot started before this round must never replace its result
		// or trigger an automatic exit after the round times out.
		m_discardRefresh = m_refreshWorker != NULL;
		m_emptySnapshot = false;
		GetDlgItem(IDOK)->EnableWindow(FALSE);
		GetDlgItem(IDC_EXIT_TERMINATE)->EnableWindow(FALSE);
		SetDefID(IDCANCEL);
		GetDlgItem(IDCANCEL)->SetFocus();
		result = ExitProcessCleanup::Result<_myPROCESSINFO>();
		workerError = ERROR_SUCCESS;
		m_slowShown = false;
		InterlockedExchange(&m_hasProcesses, 1);
		if (!m_cancel) m_cancel = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!m_cancel)
		{ workerError = GetLastError(); EndDialog(IDABORT); return; }
		ResetEvent(m_cancel);
		m_started = GetTickCount();
		if (!SetTimer(1, 50, NULL))
		{ workerError = ERROR_NOT_ENOUGH_MEMORY; EndDialog(IDABORT); return; }
		m_worker = AfxBeginThread(Work, this, THREAD_PRIORITY_NORMAL, 0, CREATE_SUSPENDED);
		if (!m_worker)
		{ workerError = ERROR_NOT_ENOUGH_MEMORY; EndDialog(IDABORT); return; }
		m_worker->m_bAutoDelete = FALSE;
		m_worker->ResumeThread();
	}
	void FinishCleanup()
	{
		KillTimer(1);
		delete m_worker;
		m_worker = NULL;
		if (m_progress.GetSafeHwnd())
		{
			m_progress.SendMessage(PBM_SETMARQUEE, FALSE, 0);
			m_progress.ShowWindow(SW_HIDE);
		}
		if (m_hideRequested)
		{
			EndDialog(IDC_EXIT_HIDE_TRAY);
			return;
		}
		if (result.status == ExitProcessCleanup::TimedOut)
		{
			m_timedOut = true;
			ShowProcesses(result.processes);
			SetDlgItemText(IDC_EXIT_TERMINATE, Localization::Get(_T("exit.continue")));
			SetDlgItemText(IDCANCEL, Localization::Get(_T("exit.return")));
			GetDlgItem(IDOK)->EnableWindow(TRUE);
			GetDlgItem(IDCANCEL)->EnableWindow(TRUE);
			GetDlgItem(IDC_EXIT_TERMINATE)->EnableWindow(TRUE);
			SetDefID(IDC_EXIT_HIDE_TRAY);
			GetDlgItem(IDC_EXIT_HIDE_TRAY)->SetFocus();
			return;
		}
		EndDialog(result.status == ExitProcessCleanup::Completed ? IDOK :
			(result.status == ExitProcessCleanup::Cancelled ? IDCANCEL : IDABORT));
	}
	static UINT Work(LPVOID context)
	{
		CExitCleanupDialog* self = static_cast<CExitCleanupDialog*>(context);
		try
		{
			self->result = ExitProcessCleanup::Run<_myPROCESSINFO>(
				[self](std::vector<_myPROCESSINFO>& processes) {
					if (!self->m_page->GetRunningHookedProcesses(processes)) throw DWORD(ERROR_RETRY);
					InterlockedExchange(&self->m_hasProcesses, processes.empty() ? 0 : 1);
				}, self->m_cancel);
		}
		catch (DWORD error)
		{ self->workerError = error; self->result.status = ExitProcessCleanup::Failed; }
		catch (...)
		{ self->workerError = ERROR_NOT_ENOUGH_MEMORY; self->result.status = ExitProcessCleanup::Failed; }
		return 0;
	}
	CPage3* m_page;
	CWinThread* m_refreshWorker = NULL;
	std::vector<_myPROCESSINFO> m_refreshProcesses;
	BOOL m_refreshSucceeded = FALSE;
	DWORD m_lastRefresh = 0;
	bool m_discardRefresh = false;
	bool m_emptySnapshot = false;
	bool m_timedOut = false;
	bool m_hideRequested = false;
	CWinThread* m_worker = NULL;
	HANDLE m_cancel = NULL;
	DWORD m_started = 0;
	volatile LONG m_hasProcesses = 0;
	bool m_slowShown = false;
	CProgressCtrl m_progress;
};
