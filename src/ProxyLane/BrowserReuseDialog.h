#pragma once
#include "ModernUI.h"
#include "Localization.h"
#include "resource.h"

class CBrowserReuseDialog : public CModernDialog
{
public:
	CBrowserReuseDialog(const CString& name, const CString& candidates, CWnd* parent)
		: CModernDialog(IDD_BROWSER_REUSE, parent), m_name(name), m_candidates(candidates) {}
protected:
	BOOL OnInitDialog() override
	{
		CModernDialog::OnInitDialog();
		SetWindowText(Localization::Get(_T("browser_reuse.title")));
		const CString warning = Localization::Format(_T("browser_reuse.warning"), static_cast<LPCTSTR>(m_name));
		SetDlgItemText(IDC_BROWSER_REUSE_WARNING, warning);
		SetDlgItemText(IDC_BROWSER_REUSE_PROCESSES, m_candidates);
		SetDlgItemText(IDOK, Localization::Get(_T("browser_reuse.view")));
		SetDlgItemText(IDCANCEL, Localization::Get(_T("browser_reuse.dismiss")));
		SetDlgItemText(IDC_BROWSER_REUSE_TERMINATE, Localization::Get(_T("browser_reuse.terminate")));
		SetDlgItemText(IDC_BROWSER_REUSE_PROXY, Localization::Get(_T("browser_reuse.proxy")));
		m_terminate.SubclassDlgItem(IDC_BROWSER_REUSE_TERMINATE, this);
		m_proxy.SubclassDlgItem(IDC_BROWSER_REUSE_PROXY, this);
		m_view.SubclassDlgItem(IDOK, this);
		m_dismiss.SubclassDlgItem(IDCANCEL, this);
		m_view.SetVisualStyle(CModernButton::STYLE_PRIMARY);
		const auto scale = [this](int value) { return UiTheme::ScaleForWindow(m_hWnd, value); };
		const int margin = scale(16), gap = scale(12), buttonHeight = scale(30);
		CClientDC dc(this);
		CFont* old = dc.SelectObject(&m_uiFont);
		const int terminateWidth = dc.GetTextExtent(Localization::Get(_T("browser_reuse.terminate"))).cx + scale(30);
		const int proxyWidth = dc.GetTextExtent(Localization::Get(_T("browser_reuse.proxy"))).cx + scale(30);
		const int viewWidth = dc.GetTextExtent(Localization::Get(_T("browser_reuse.view"))).cx + scale(30);
		const int dismissWidth = dc.GetTextExtent(Localization::Get(_T("browser_reuse.dismiss"))).cx + scale(30);
		const int width = max(scale(580), 2 * margin + 3 * gap + terminateWidth + proxyWidth + viewWidth + dismissWidth);
		CRect text(0, 0, width - 2 * margin, 0);
		dc.DrawText(warning, &text, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
		dc.SelectObject(old);
		const int listTop = margin + text.Height() + gap, listHeight = scale(130);
		const int buttonTop = listTop + listHeight + gap;
		CRect frame(0, 0, width, buttonTop + buttonHeight + margin);
		AdjustWindowRectEx(&frame, GetStyle(), FALSE, GetExStyle());
		SetWindowPos(NULL, 0, 0, frame.Width(), frame.Height(), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
		GetDlgItem(IDC_BROWSER_REUSE_WARNING)->MoveWindow(margin, margin, width - 2 * margin, text.Height());
		GetDlgItem(IDC_BROWSER_REUSE_PROCESSES)->MoveWindow(margin, listTop, width - 2 * margin, listHeight);
		m_dismiss.MoveWindow(width - margin - dismissWidth, buttonTop, dismissWidth, buttonHeight);
		m_view.MoveWindow(width - margin - dismissWidth - gap - viewWidth, buttonTop, viewWidth, buttonHeight);
		m_proxy.MoveWindow(width - margin - dismissWidth - 2 * gap - viewWidth - proxyWidth,
			buttonTop, proxyWidth, buttonHeight);
		m_terminate.MoveWindow(width - margin - dismissWidth - 3 * gap - viewWidth - proxyWidth - terminateWidth,
			buttonTop, terminateWidth, buttonHeight);
		CenterWindow(GetParent());
		SetDefID(IDOK);
		// This dialog is opened only after the user clicks the tray notification.
		m_view.SetFocus();
		return FALSE;
	}
	LRESULT WindowProc(UINT message, WPARAM wparam, LPARAM lparam) override
	{
		if (message == WM_COMMAND && HIWORD(wparam) == BN_CLICKED &&
			(LOWORD(wparam) == IDC_BROWSER_REUSE_TERMINATE || LOWORD(wparam) == IDC_BROWSER_REUSE_PROXY))
		{
			EndDialog(LOWORD(wparam));
			return 0;
		}
		return CModernDialog::WindowProc(message, wparam, lparam);
	}
	void OnOK() override { EndDialog(IDOK); }
	void OnCancel() override { EndDialog(IDCANCEL); }
private:
	CString m_name, m_candidates;
	CModernButton m_terminate, m_proxy, m_view, m_dismiss;
};
