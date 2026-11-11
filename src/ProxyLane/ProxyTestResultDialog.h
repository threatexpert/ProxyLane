#pragma once
#include "ModernUI.h"
#include "Localization.h"
#include "resource.h"
#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

// A native, accessible result row. Shape and caption carry the same meaning as
// colour, so the report is also understandable without colour perception.
class CProxyTestResultRow : public CStatic
{
public:
	enum State { Passed, Failed, Warning, Skipped };
	State state = Skipped;
	CFont* headingFont = NULL;
	bool emphasizeDetail = false;
	CString title, status, detail;
	void Set(State value, const CString& heading, const CString& label, const CString& description, bool emphasis = false)
	{
		state = value; title = heading; status = label; detail = description;
		emphasizeDetail = emphasis;
		m_detailAction = emphasis ? Localization::Get(L"test.result.udp_suggest_action") : CString();
		SetWindowText(title + _T(" — ") + status + _T("\r\n") + detail);
		// Set is called after Create has finished; avoid nested MFC window
		// creation from PreSubclassWindow for dynamically-created rows.
		ModifyStyle(0, SS_NOTIFY);
		if (!m_tooltip.GetSafeHwnd() && m_tooltip.Create(GetParent(), TTS_ALWAYSTIP | TTS_NOPREFIX))
			m_tooltip.SetDelayTime(TTDT_AUTOPOP, 20000);
		UpdateOverflowTooltip();
	}
protected:
	BOOL PreTranslateMessage(MSG* message) override
	{
		if (message && m_tooltip.GetSafeHwnd())
		{
			if (message->message == WM_MOUSEMOVE) UpdateOverflowTooltip();
			m_tooltip.RelayEvent(message);
		}
		return CStatic::PreTranslateMessage(message);
	}
	LRESULT WindowProc(UINT message, WPARAM wParam, LPARAM lParam) override
	{
		const LRESULT result = CStatic::WindowProc(message, wParam, lParam);
		if (message == WM_SIZE || message == WM_SETFONT) UpdateOverflowTooltip();
		return result;
	}
	void DrawItem(LPDRAWITEMSTRUCT item) override
	{
		CDC dc; dc.Attach(item->hDC);
		const int saved = dc.SaveDC();
		const auto s = [this](int v) { return UiTheme::ScaleForWindow(m_hWnd, v); };
		CRect rect(item->rcItem);
		const COLORREF color = state == Passed ? UiTheme::Success() :
			state == Failed ? UiTheme::Danger() : state == Warning ? RGB(156, 98, 12) :
			UiTheme::TextSecondary();
		const COLORREF soft = state == Passed ? UiTheme::SuccessSoft() :
			state == Failed ? UiTheme::DangerSoft() : state == Warning ? RGB(255, 247, 224) :
			UiTheme::Surface();
		dc.FillSolidRect(rect, UiTheme::PageBackground());
		UiTheme::FillRoundRect(dc, rect, s(9), UiTheme::Surface(), UiTheme::BorderSoft());
		dc.SetBkMode(TRANSPARENT); dc.SelectObject(GetFont());
		CRect statusRect(rect.right-s(148), s(7), rect.right-s(10), s(29));
		UiTheme::FillRoundRect(dc, statusRect, s(5), soft, CLR_NONE);
		const int x = statusRect.left+s(14), y = statusRect.CenterPoint().y;
		CPen pen(PS_SOLID, max(2, s(2)), color); dc.SelectObject(&pen);
		if (state == Passed)
		{
			dc.MoveTo(x-s(5), y); dc.LineTo(x-s(1), y+s(4)); dc.LineTo(x+s(6), y-s(4));
		}
		else if (state == Failed)
		{
			dc.MoveTo(x-s(4), y-s(4)); dc.LineTo(x+s(4), y+s(4));
			dc.MoveTo(x+s(4), y-s(4)); dc.LineTo(x-s(4), y+s(4));
		}
		else if (state == Skipped) { dc.MoveTo(x-s(5), y); dc.LineTo(x+s(5), y); }
		else
		{
			dc.MoveTo(x, y-s(5)); dc.LineTo(x, y+s(1));
			dc.MoveTo(x, y+s(4)); dc.LineTo(x, y+s(6));
		}
		dc.SetBkMode(TRANSPARENT); dc.SelectObject(GetFont());
		dc.SetTextColor(color);
		CRect statusText = statusRect; statusText.left += s(25);
		dc.DrawText(status, statusText, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
		CRect titleRect(s(12), s(7), statusRect.left-s(8), s(29));
		dc.SetTextColor(UiTheme::TextPrimary());
		if (headingFont) dc.SelectObject(headingFont);
		dc.DrawText(title, titleRect, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
		dc.SelectObject(GetFont());
		CRect detailRect = DetailRect();
		dc.SetTextColor(UiTheme::TextSecondary());
		if (emphasizeDetail)
		{
			// A quiet advisory strip, separate from the factual result badge.
			CRect strip(s(8), s(30), rect.right-s(8), rect.bottom-s(5));
			UiTheme::FillRoundRect(dc, strip, s(4), RGB(255, 248, 222), CLR_NONE);
			dc.FillSolidRect(strip.left, strip.top+s(3), max(2, s(2)), strip.Height()-s(6), RGB(202, 165, 48));
			const int cx = s(19), cy = strip.CenterPoint().y;
			CPen alertPen(PS_SOLID, max(1, s(1)), RGB(185, 145, 39));
			CBrush alertBrush(RGB(247, 213, 109));
			CPen* oldPen = dc.SelectObject(&alertPen);
			CBrush* oldBrush = dc.SelectObject(&alertBrush);
			POINT triangle[] = {{cx, cy-s(6)}, {cx+s(7), cy+s(6)}, {cx-s(7), cy+s(6)}};
			dc.Polygon(triangle, 3);
			CPen markPen(PS_SOLID, max(1, s(1)), RGB(76, 65, 34));
			dc.SelectObject(&markPen);
			dc.MoveTo(cx, cy-s(3)); dc.LineTo(cx, cy+s(1));
			dc.MoveTo(cx, cy+s(3)); dc.LineTo(cx, cy+s(4));
			dc.SelectObject(oldBrush); dc.SelectObject(oldPen);
			dc.SetTextColor(UiTheme::TextPrimary());
		}
		RenderDetail(dc, &detailRect);
		dc.RestoreDC(saved); dc.Detach();
	}
private:
	// Measure and paint the same mixed-weight text so overflow tooltips stay accurate.
	CSize RenderDetail(CDC& dc, const CRect* bounds = NULL)
	{
		CString parts[] = {detail, CString(), CString()};
		const int action = m_detailAction.IsEmpty() ? -1 : detail.Find(m_detailAction);
		if (action >= 0)
		{
			parts[0] = detail.Left(action); parts[1] = m_detailAction;
			parts[2] = detail.Mid(action+m_detailAction.GetLength());
		}
		CSize extent(0, 0);
		CFont* old = dc.SelectObject(GetFont());
		for (int i=0; i<3; ++i)
		{
			dc.SelectObject(i == 1 && headingFont ? headingFont : GetFont());
			const CSize size = dc.GetTextExtent(parts[i]);
			if (bounds && !parts[i].IsEmpty() && extent.cx < bounds->Width())
			{
				CRect segment(*bounds); segment.left += extent.cx;
				dc.DrawText(parts[i], segment, DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX |
					(emphasizeDetail ? DT_VCENTER : 0));
			}
			extent.cx += size.cx; extent.cy = max(extent.cy, size.cy);
		}
		dc.SelectObject(old);
		return extent;
	}
	CRect DetailRect() const
	{
		CRect rect; GetClientRect(&rect);
		return CRect(UiTheme::ScaleForWindow(m_hWnd, emphasizeDetail ? 32 : 12),
			UiTheme::ScaleForWindow(m_hWnd, emphasizeDetail ? 30 : 32),
			rect.right-UiTheme::ScaleForWindow(m_hWnd, 12), rect.bottom-UiTheme::ScaleForWindow(m_hWnd, 5));
	}
	void UpdateOverflowTooltip()
	{
		if (!GetSafeHwnd() || !m_tooltip.GetSafeHwnd()) return;
		const CRect rect = DetailRect();
		CClientDC dc(this);
		const CSize extent = RenderDetail(dc);
		const bool truncated = !rect.IsRectEmpty() && !detail.IsEmpty() &&
			(extent.cx > rect.Width() || extent.cy > rect.Height() ||
			 detail.Find(_T('\n')) >= 0 || detail.Find(_T('\r')) >= 0);
		if (!truncated)
		{
			if (m_tooltip.GetToolCount()) { m_tooltip.Pop(); m_tooltip.DelTool(this, 1); }
			m_tooltipText.Empty();
			return;
		}
		m_tooltip.SetMaxTipWidth(UiTheme::ScaleForWindow(m_hWnd, 420));
		if (!m_tooltip.GetToolCount())
		{
			m_tooltipText = detail;
			m_tooltip.AddTool(this, m_tooltipText, rect, 1);
		}
		else if (m_tooltipText != detail)
		{
			m_tooltipText = detail;
			m_tooltip.UpdateTipText(m_tooltipText, this, 1);
		}
		m_tooltip.SetToolRect(this, 1, rect);
	}
	CString m_tooltipText, m_detailAction;
	CToolTipCtrl m_tooltip;
};

// Ordinary results contain exactly three rows and one Close button. SSH first
// use additionally needs the actual fingerprint and an explicit trust decision.
class CProxyTestResultDialog : public CModernDialog
{
public:
	struct Row { CProxyTestResultRow::State state; CString title, status, detail; bool emphasizeDetail = false; };
	CProxyTestResultDialog(const std::vector<Row>& rows, const CString& trustMessage, CWnd* parent)
		: CModernDialog(IDD_PROXY_TEST_RESULT, parent), m_rows(rows), m_trustMessage(trustMessage) {}
protected:
	BOOL OnInitDialog() override
	{
		CModernDialog::OnInitDialog();
		SetWindowText(Localization::Get(_T("test.title")));
		UiTheme::CreateUiFont(m_headingFont, m_hWnd, 9, FW_SEMIBOLD);
		const CRect empty(0, 0, 0, 0);
		for (size_t i = 0; i < 3; ++i)
		{
			const Row& row = m_rows[i];
			m_cards[i].Create(_T(""), WS_CHILD | WS_VISIBLE | SS_OWNERDRAW, empty, this, 1201 + (UINT)i);
			m_cards[i].SetFont(&m_uiFont);
			m_cards[i].headingFont = &m_headingFont;
			m_cards[i].Set(row.state, row.title, row.status, row.detail, row.emphasizeDetail);
		}
		if (!m_trustMessage.IsEmpty())
		{
			m_trust.Create(m_trustMessage, WS_CHILD | WS_VISIBLE | SS_NOPREFIX, empty, this, 1207);
			m_action.Create(Localization::Get(_T("test.result.trust_key")),
				WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, empty, this, IDYES);
			m_action.SetVisualStyle(CModernButton::STYLE_PRIMARY);
		}
		m_close.Create(Localization::Get(_T("test.result.close")), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
			empty, this, IDCANCEL);
		UiTheme::ApplyFontToChildren(this, &m_uiFont);
		CRect owner; GetParent()->GetTopLevelParent()->GetWindowRect(&owner);
		MONITORINFO monitor = {sizeof(monitor)};
		if (!GetMonitorInfo(MonitorFromRect(&owner, MONITOR_DEFAULTTONEAREST), &monitor))
			SystemParametersInfo(SPI_GETWORKAREA, 0, &monitor.rcWork, 0);
		CRect work(monitor.rcWork), frame(0,0,0,0);
		AdjustWindowRectEx(&frame, GetStyle(), FALSE, GetExStyle());
		const int width = min(S(440) + frame.Width(), work.Width()-S(24));
		if (!m_trustMessage.IsEmpty())
		{
			CClientDC dc(this); CFont* old = dc.SelectObject(&m_uiFont);
			CRect text(0, 0, width-frame.Width()-S(24), 0);
			dc.DrawText(m_trustMessage, text, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
			m_trustHeight = text.Height()+S(12); dc.SelectObject(old);
		}
		const int height = S(246) + m_trustHeight + frame.Height();
		SetWindowPos(NULL, max(work.left, min(owner.CenterPoint().x-width/2, work.right-width)),
			max(work.top, min(owner.CenterPoint().y-height/2, work.bottom-height)), width, height, SWP_NOZORDER);
		Layout();
		SetDefID(IDCANCEL); m_close.SetFocus();
		return FALSE;
	}
	void OnOK() override { EndDialog(IDCANCEL); }
	void OnCancel() override { EndDialog(IDCANCEL); }
	BOOL OnCommand(WPARAM wParam, LPARAM lParam) override
	{
		if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == IDYES && !m_trustMessage.IsEmpty())
		{ EndDialog(IDYES); return TRUE; }
		return CModernDialog::OnCommand(wParam, lParam);
	}
	LRESULT WindowProc(UINT message, WPARAM wParam, LPARAM lParam) override
	{
		const LRESULT result = CModernDialog::WindowProc(message, wParam, lParam);
		if ((message == WM_SIZE || message == WM_DPICHANGED) && m_close.GetSafeHwnd()) Layout();
		return result;
	}
private:
	int S(int value) const { return UiTheme::ScaleForWindow(m_hWnd, value); }
	void Layout()
	{
		CRect area; GetClientRect(&area);
		const int margin = S(12), width = area.Width()-2*margin;
		int top = margin;
		for (int i=0; i<3; ++i)
		{
			m_cards[i].MoveWindow(margin, top, width, S(56));
			top += S(62);
		}
		const int buttonTop = area.bottom-margin-S(30);
		if (m_trust.GetSafeHwnd())
		{
			m_trust.MoveWindow(margin, top, width, max(0, buttonTop-top-S(6)));
			m_action.MoveWindow(area.right-margin-S(90)-S(192), buttonTop, S(192), S(30));
		}
		m_close.MoveWindow(area.right-margin-S(80), buttonTop, S(80), S(30));
	}
	std::vector<Row> m_rows;
	CString m_trustMessage;
	int m_trustHeight = 0;
	CProxyTestResultRow m_cards[3];
	CStatic m_trust;
	CModernButton m_action, m_close;
	CFont m_headingFont;
};
