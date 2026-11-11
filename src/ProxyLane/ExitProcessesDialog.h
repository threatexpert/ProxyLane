#pragma once
#include "ModernUI.h"
#include "Localization.h"
#include "resource.h"

class CExitProcessesDialog : public CModernDialog
{
public:
	CExitProcessesDialog(UINT count, const CString& processes, CWnd* parent)
		: CModernDialog(IDD_EXIT_PROCESSES, parent), m_count(count), m_processes(processes) {}

protected:
	BOOL OnInitDialog() override
	{
		CModernDialog::OnInitDialog();
		SetWindowText(Localization::Get(_T("exit.processes_title")));
		SetDlgItemText(IDC_EXIT_WARNING,
			Localization::Format(_T("exit.processes_warning"), m_count));
		SetDlgItemText(IDC_EXIT_PROCESSES, m_processes);
		SetDlgItemText(IDC_EXIT_HIDE_TRAY, Localization::Get(_T("exit.hide_tray")));
		SetDlgItemText(IDCANCEL, Localization::Get(_T("exit.return")));
		SetDlgItemText(IDOK, Localization::Get(_T("exit.anyway")));
		SetDlgItemText(IDC_EXIT_TERMINATE, Localization::Get(_T("exit.terminate")));
		m_returnButton.SubclassDlgItem(IDCANCEL, this);
		m_hideButton.SubclassDlgItem(IDC_EXIT_HIDE_TRAY, this);
		m_exitButton.SubclassDlgItem(IDOK, this);
		m_terminateButton.SubclassDlgItem(IDC_EXIT_TERMINATE, this);
		m_terminateButton.SetVisualStyle(CModernButton::STYLE_DANGER);
		LayoutDialog();
		SetDefID(IDC_EXIT_HIDE_TRAY);
		GetDlgItem(IDC_EXIT_HIDE_TRAY)->SetFocus();
		return FALSE;
	}
	void OnOK() override { EndDialog(IDOK); }
	void OnCancel() override { EndDialog(IDCANCEL); }
	BOOL OnCommand(WPARAM wParam, LPARAM lParam) override
	{
		if ((LOWORD(wParam) == IDC_EXIT_TERMINATE || LOWORD(wParam) == IDC_EXIT_HIDE_TRAY) &&
			HIWORD(wParam) == BN_CLICKED)
		{
			EndDialog(LOWORD(wParam));
			return TRUE;
		}
		return CModernDialog::OnCommand(wParam, lParam);
	}
	void UpdateProcesses(UINT count, const CString& processes)
	{
		if (m_count == count && m_processes == processes) return;
		m_count = count;
		m_processes = processes;
		// Keep the existing rectangle even if the number of survivors changes.
		// Scroll instead of resizing or moving the dialog during cleanup.
		CWnd* list = GetDlgItem(IDC_EXIT_PROCESSES);
		list->SetRedraw(FALSE);
		list->ShowScrollBar(SB_BOTH, FALSE);
		list->SetWindowText(processes);
		CRect area;
		list->GetClientRect(&area);
		CClientDC dc(list);
		CFont* oldFont = dc.SelectObject(&m_uiFont);
		TEXTMETRIC metrics = {};
		dc.GetTextMetrics(&metrics);
		int position = 0, longest = 0;
		while (position >= 0 && position < processes.GetLength())
			longest = max(longest, dc.GetTextExtent(processes.Tokenize(_T("\r\n"), position)).cx);
		dc.SelectObject(oldFont);
		const int padding = UiTheme::ScaleForWindow(m_hWnd, 4);
		bool vertical = count * metrics.tmHeight > static_cast<UINT>(max(0, area.Height() - padding));
		const bool horizontal = longest > area.Width() - padding - (vertical ? GetSystemMetrics(SM_CXVSCROLL) : 0);
		vertical = vertical || count * metrics.tmHeight > static_cast<UINT>(max(0,
			area.Height() - padding - (horizontal ? GetSystemMetrics(SM_CYHSCROLL) : 0)));
		list->ShowScrollBar(SB_VERT, vertical);
		list->ShowScrollBar(SB_HORZ, horizontal);
		list->SetRedraw(TRUE);
		list->Invalidate();
	}

private:
	void LayoutDialog()
	{
		// Match the application's pixel-based layouts instead of depending on
		// dialog units, which can leave oversized controls at high DPI.
		const auto scale = [this](int value) { return UiTheme::ScaleForWindow(m_hWnd, value); };
		CRect owner;
		CWnd* parent = GetParent();
		if (parent) parent = parent->GetTopLevelParent();
		if (parent) parent->GetWindowRect(&owner);
		else GetWindowRect(&owner);
		MONITORINFO monitor = {sizeof(monitor)};
		if (!GetMonitorInfo(MonitorFromRect(&owner, MONITOR_DEFAULTTONEAREST), &monitor))
			SystemParametersInfo(SPI_GETWORKAREA, 0, &monitor.rcWork, 0);
		CRect work(monitor.rcWork), frame(0, 0, 0, 0);
		AdjustWindowRectEx(&frame, GetStyle(), FALSE, GetExStyle());
		const int margin = scale(12), gap = scale(10), buttonGap = scale(8);
		const int buttonHeight = scale(30);
		CClientDC dc(this);
		CFont* oldFont = dc.SelectObject(&m_uiFont);
		CModernButton* buttons[] = {&m_hideButton, &m_returnButton, &m_exitButton, &m_terminateButton};
		const int buttonCount = _countof(buttons);
		int buttonWidths[buttonCount], totalButtonWidth = (buttonCount - 1) * buttonGap;
		for (int i = 0; i < buttonCount; ++i)
		{
			CString label;
			buttons[i]->GetWindowText(label);
			buttonWidths[i] = max(scale(72), dc.GetTextExtent(label).cx + scale(24));
			// Reserve space for cleanup captions so controls stay in place.
			if (i == 1) buttonWidths[i] = max(buttonWidths[i],
				dc.GetTextExtent(Localization::Get(_T("exit.stop_cleanup"))).cx + scale(24));
			if (i == 3) buttonWidths[i] = max(buttonWidths[i],
				dc.GetTextExtent(Localization::Get(_T("exit.continue"))).cx + scale(24));
			totalButtonWidth += buttonWidths[i];
		}
		const int width = min(max(scale(560), totalButtonWidth + 2 * margin),
			work.Width() - scale(32) - frame.Width());
		const int contentWidth = width - 2 * margin;
		// Wrap buttons on narrow screens rather than placing them off-window.
		int buttonRows[buttonCount] = {}, buttonOffsets[buttonCount] = {}, rowWidths[buttonCount] = {};
		int row = 0;
		for (int i = 0; i < buttonCount; ++i)
		{
			buttonWidths[i] = min(buttonWidths[i], contentWidth);
			if (rowWidths[row] && rowWidths[row] + buttonGap + buttonWidths[i] > contentWidth) ++row;
			buttonRows[i] = row;
			buttonOffsets[i] = rowWidths[row] ? rowWidths[row] + buttonGap : 0;
			rowWidths[row] = buttonOffsets[i] + buttonWidths[i];
		}
		const int buttonsHeight = (row + 1) * buttonHeight + row * buttonGap;
		CString warning;
		GetDlgItemText(IDC_EXIT_WARNING, warning);
		CRect warningRect(0, 0, contentWidth, 0);
		dc.DrawText(warning, &warningRect, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
		CRect timeoutRect(0, 0, contentWidth, 0);
		dc.DrawText(Localization::Format(_T("exit.timeout"), m_count), &timeoutRect,
			DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
		const int warningHeight = max(warningRect.Height(), timeoutRect.Height()) + scale(2);
		TEXTMETRIC metrics = {};
		dc.GetTextMetrics(&metrics);
		int longestLine = 0, position = 0;
		while (position >= 0 && position < m_processes.GetLength())
		{
			const CString line = m_processes.Tokenize(_T("\r\n"), position);
			longestLine = max(longestLine, dc.GetTextExtent(line).cx);
		}
		const bool verticalScroll = m_count > 10;
		const bool horizontalScroll = longestLine > contentWidth - scale(8)
			- (verticalScroll ? GetSystemMetrics(SM_CXVSCROLL) : 0);
		const int rows = static_cast<int>(min(max(m_count, 2U), 10U));
		int listHeight = rows * metrics.tmHeight + scale(8)
			+ (horizontalScroll ? GetSystemMetrics(SM_CYHSCROLL) : 0);
		listHeight = min(listHeight, work.Height() - scale(32) - frame.Height()
			- 2 * margin - warningHeight - 2 * gap - buttonsHeight);
		dc.SelectObject(oldFont);

		const int listTop = margin + warningHeight + gap;
		const int buttonTop = listTop + listHeight + gap;
		const int height = buttonTop + buttonsHeight + margin;
		const int outerWidth = width + frame.Width(), outerHeight = height + frame.Height();
		const int left = max(work.left, min(owner.CenterPoint().x - outerWidth / 2, work.right - outerWidth));
		const int top = max(work.top, min(owner.CenterPoint().y - outerHeight / 2, work.bottom - outerHeight));
		SetWindowPos(NULL, left, top, outerWidth, outerHeight, SWP_NOZORDER | SWP_NOACTIVATE);
		GetDlgItem(IDC_EXIT_WARNING)->MoveWindow(margin, margin, contentWidth, warningHeight);
		CWnd* list = GetDlgItem(IDC_EXIT_PROCESSES);
		list->MoveWindow(margin, listTop, contentWidth, listHeight);
		list->ShowScrollBar(SB_VERT, verticalScroll || listHeight < rows * metrics.tmHeight + scale(8));
		list->ShowScrollBar(SB_HORZ, horizontalScroll);
		for (int i = 0; i < buttonCount; ++i)
		{
			buttons[i]->MoveWindow(width - margin - rowWidths[buttonRows[i]] + buttonOffsets[i],
				buttonTop + buttonRows[i] * (buttonHeight + buttonGap), buttonWidths[i], buttonHeight);
		}
	}

	UINT m_count;
	CString m_processes;
	CModernButton m_hideButton;
	CModernButton m_returnButton;
	CModernButton m_exitButton;
	CModernButton m_terminateButton;
};
