#include "stdafx.h"
#include "ProxyLane.h"
#include "ModernUI.h"
#include "resource.h"
#include "Localization.h"

namespace UiTheme
{
	COLORREF WindowBackground()  { return RGB(245, 247, 250); }
	COLORREF PageBackground()    { return RGB(255, 255, 255); }
	COLORREF SidebarBackground() { return RGB(249, 250, 251); }
	COLORREF TextPrimary()       { return RGB(23, 32, 51); }
	COLORREF TextSecondary()     { return RGB(102, 112, 133); }
	COLORREF Border()            { return RGB(218, 223, 230); }
	COLORREF Accent()            { return RGB(37, 99, 235); }
	COLORREF AccentHover()       { return RGB(29, 78, 216); }
	COLORREF AccentSoft()        { return RGB(232, 239, 254); }
	COLORREF Success()           { return RGB(22, 163, 74); }
	COLORREF SuccessSoft()       { return RGB(230, 247, 236); }
	COLORREF Danger()            { return RGB(220, 38, 38); }
	COLORREF DangerSoft()        { return RGB(254, 235, 235); }

	int ScaleForWindow(HWND hWnd, int value)
	{
		HDC dc = ::GetDC(hWnd);
		int dpi = dc ? ::GetDeviceCaps(dc, LOGPIXELSX) : 96;
		if (dc)
			::ReleaseDC(hWnd, dc);
		return MulDiv(value, dpi, 96);
	}

	BOOL CreateUiFont(CFont& font, HWND hWnd, int pointSize, int weight, LPCTSTR faceName)
	{
		if (font.GetSafeHandle())
			font.DeleteObject();

		HDC dc = ::GetDC(hWnd);
		int dpi = dc ? ::GetDeviceCaps(dc, LOGPIXELSY) : 96;
		if (dc)
			::ReleaseDC(hWnd, dc);

		return font.CreateFont(
			-MulDiv(pointSize, dpi, 72), 0, 0, 0, weight,
			FALSE, FALSE, FALSE, DEFAULT_CHARSET,
			OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
			DEFAULT_PITCH | FF_DONTCARE, faceName);
	}

	void ApplyFontToChildren(CWnd* parent, CFont* font)
	{
		if (!parent || !font || !font->GetSafeHandle())
			return;

		for (CWnd* child = parent->GetWindow(GW_CHILD); child;
			child = child->GetWindow(GW_HWNDNEXT))
		{
			child->SetFont(font, FALSE);
		}
	}
}

IMPLEMENT_DYNAMIC(CModernDialog, CDialog)

CModernDialog::CModernDialog(UINT templateId, CWnd* parent)
	: CDialog(templateId, parent)
	, m_templateId(templateId)
{
}

CModernDialog::~CModernDialog()
{
}

BOOL CModernDialog::OnInitDialog()
{
	CDialog::OnInitDialog();

	m_backgroundBrush.DeleteObject();
	m_backgroundBrush.CreateSolidBrush(UiTheme::PageBackground());
	UiTheme::CreateUiFont(m_uiFont, m_hWnd, 9, FW_NORMAL);
	UiTheme::CreateUiFont(m_titleFont, m_hWnd, 16, FW_SEMIBOLD);
	SetFont(&m_uiFont, FALSE);
	UiTheme::ApplyFontToChildren(this, &m_uiFont);
	Localization::ApplyDialog(this, m_templateId);

	CWnd* title = GetDlgItem(IDC_STATIC_PAGE_TITLE);
	if (title)
		title->SetFont(&m_titleFont, FALSE);
	LayoutPageHeader();

	return TRUE;
}

BEGIN_MESSAGE_MAP(CModernDialog, CDialog)
	ON_WM_SIZE()
	ON_WM_ERASEBKGND()
	ON_WM_CTLCOLOR()
END_MESSAGE_MAP()

void CModernDialog::OnSize(UINT type, int cx, int cy)
{
	CDialog::OnSize(type, cx, cy);
	LayoutPageHeader();
}

void CModernDialog::LayoutPageHeader()
{
	if (!GetSafeHwnd())
		return;

	CRect client;
	GetClientRect(&client);
	const int rightMargin = UiTheme::ScaleForWindow(m_hWnd, 8);
	const UINT headerIds[] = { IDC_STATIC_PAGE_TITLE, IDC_STATIC_PAGE_SUBTITLE };
	for (int i = 0; i < _countof(headerIds); ++i)
	{
		CWnd* header = GetDlgItem(headerIds[i]);
		if (!header || !header->GetSafeHwnd())
			continue;

		CRect rect;
		header->GetWindowRect(&rect);
		ScreenToClient(&rect);
		header->MoveWindow(rect.left, rect.top,
			max(0, client.right - rightMargin - rect.left), rect.Height());
	}
}

BOOL CModernDialog::OnEraseBkgnd(CDC* dc)
{
	CRect rect;
	GetClientRect(&rect);
	dc->FillSolidRect(rect, UiTheme::PageBackground());
	return TRUE;
}

HBRUSH CModernDialog::OnCtlColor(CDC* dc, CWnd* wnd, UINT ctlColor)
{
	if (ctlColor == CTLCOLOR_STATIC || ctlColor == CTLCOLOR_BTN || ctlColor == CTLCOLOR_DLG)
	{
		dc->SetBkMode(TRANSPARENT);
		if (wnd && wnd->GetDlgCtrlID() == IDC_STATIC_PAGE_SUBTITLE)
			dc->SetTextColor(UiTheme::TextSecondary());
		else
			dc->SetTextColor(UiTheme::TextPrimary());
		return (HBRUSH)m_backgroundBrush.GetSafeHandle();
	}

	return CDialog::OnCtlColor(dc, wnd, ctlColor);
}

IMPLEMENT_DYNAMIC(CModernButton, CButton)

CModernButton::CModernButton()
	: m_visualStyle(STYLE_SECONDARY)
	, m_hot(FALSE)
{
}

void CModernButton::SetVisualStyle(VisualStyle style)
{
	m_visualStyle = style;
	if (GetSafeHwnd())
		Invalidate(FALSE);
}

void CModernButton::PreSubclassWindow()
{
	ModifyStyle(0x0000000F, BS_OWNERDRAW);
	CButton::PreSubclassWindow();
}

BEGIN_MESSAGE_MAP(CModernButton, CButton)
	ON_WM_MOUSEMOVE()
	ON_MESSAGE(WM_MOUSELEAVE, OnMouseLeave)
END_MESSAGE_MAP()

void CModernButton::OnMouseMove(UINT flags, CPoint point)
{
	if (!m_hot)
	{
		m_hot = TRUE;
		TRACKMOUSEEVENT track = { sizeof(track), TME_LEAVE, m_hWnd, 0 };
		_TrackMouseEvent(&track);
		Invalidate(FALSE);
	}
	CButton::OnMouseMove(flags, point);
}

LRESULT CModernButton::OnMouseLeave(WPARAM, LPARAM)
{
	m_hot = FALSE;
	Invalidate(FALSE);
	return 0;
}

void CModernButton::DrawItem(LPDRAWITEMSTRUCT info)
{
	CDC dc;
	dc.Attach(info->hDC);
	CRect rect(info->rcItem);
	BOOL disabled = (info->itemState & ODS_DISABLED) != 0;
	BOOL pressed = (info->itemState & ODS_SELECTED) != 0;

	COLORREF fill = RGB(255, 255, 255);
	COLORREF border = UiTheme::Border();
	COLORREF text = UiTheme::TextPrimary();

	if (m_visualStyle == STYLE_PRIMARY)
	{
		fill = pressed || m_hot ? UiTheme::AccentHover() : UiTheme::Accent();
		border = fill;
		text = RGB(255, 255, 255);
	}
	else if (m_visualStyle == STYLE_DANGER)
	{
		fill = pressed || m_hot ? UiTheme::Danger() : RGB(255, 255, 255);
		border = UiTheme::Danger();
		text = pressed || m_hot ? RGB(255, 255, 255) : UiTheme::Danger();
	}
	else if (pressed || m_hot)
	{
		fill = UiTheme::AccentSoft();
		border = UiTheme::Accent();
		text = UiTheme::Accent();
	}

	if (disabled)
	{
		fill = RGB(244, 245, 247);
		border = RGB(225, 228, 233);
		text = RGB(160, 166, 177);
	}

	dc.FillSolidRect(rect, UiTheme::PageBackground());
	rect.DeflateRect(1, 1);
	CPen pen(PS_SOLID, 1, border);
	CBrush brush(fill);
	CPen* oldPen = dc.SelectObject(&pen);
	CBrush* oldBrush = dc.SelectObject(&brush);
	dc.RoundRect(rect, CPoint(UiTheme::ScaleForWindow(m_hWnd, 7), UiTheme::ScaleForWindow(m_hWnd, 7)));
	dc.SelectObject(oldBrush);
	dc.SelectObject(oldPen);

	CString caption;
	GetWindowText(caption);
	dc.SetBkMode(TRANSPARENT);
	dc.SetTextColor(text);
	CFont* font = GetFont();
	CFont* oldFont = font ? dc.SelectObject(font) : NULL;
	dc.DrawText(caption, rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
	if (oldFont)
		dc.SelectObject(oldFont);

	if ((info->itemState & ODS_FOCUS) && !disabled)
	{
		CRect focus = rect;
		focus.DeflateRect(4, 3);
		dc.DrawFocusRect(focus);
	}

	dc.Detach();
}

IMPLEMENT_DYNAMIC(CStatusLabel, CStatic)

CStatusLabel::CStatusLabel()
	: m_tone(TONE_NEUTRAL),
	m_twoLine(FALSE)
{
}

void CStatusLabel::SetStatus(LPCTSTR text, Tone tone)
{
	m_tone = tone;
	m_twoLine = FALSE;
	m_primaryText.Empty();
	m_secondaryText.Empty();
	SetWindowText(text ? text : _T(""));
	if (GetSafeHwnd())
	{
		Invalidate(FALSE);
		UpdateOverflowTooltip();
	}
}

void CStatusLabel::SetTwoLineStatus(LPCTSTR primaryText, LPCTSTR secondaryText, Tone tone)
{
	m_tone = tone;
	m_twoLine = TRUE;
	m_primaryText = primaryText ? primaryText : _T("");
	m_secondaryText = secondaryText ? secondaryText : _T("");
	SetWindowText(m_secondaryText);
	if (GetSafeHwnd())
	{
		Invalidate(FALSE);
		UpdateOverflowTooltip();
	}
}

void CStatusLabel::PreSubclassWindow()
{
	ModifyStyle(0x0000001F, SS_OWNERDRAW | SS_NOTIFY);
	CStatic::PreSubclassWindow();
	CWnd* parent = GetParent();
	if (parent && m_tooltip.Create(parent, TTS_ALWAYSTIP | TTS_NOPREFIX))
	{
		m_tooltip.AddTool(this, _T(" "));
		m_tooltip.SetMaxTipWidth(UiTheme::ScaleForWindow(m_hWnd, 420));
		m_tooltip.Activate(FALSE);
		UpdateOverflowTooltip();
	}
}

BEGIN_MESSAGE_MAP(CStatusLabel, CStatic)
	ON_WM_SIZE()
END_MESSAGE_MAP()

BOOL CStatusLabel::PreTranslateMessage(MSG* message)
{
	if (message && m_tooltip.GetSafeHwnd())
	{
		if (message->message == WM_MOUSEMOVE)
			UpdateOverflowTooltip();
		m_tooltip.RelayEvent(message);
	}
	return CStatic::PreTranslateMessage(message);
}

void CStatusLabel::OnSize(UINT type, int cx, int cy)
{
	CStatic::OnSize(type, cx, cy);
	UpdateOverflowTooltip();
}

void CStatusLabel::UpdateOverflowTooltip()
{
	if (!GetSafeHwnd() || !m_tooltip.GetSafeHwnd())
		return;

	CRect client;
	GetClientRect(&client);
	if (client.IsRectEmpty())
	{
		m_tooltip.Activate(FALSE);
		return;
	}

	CClientDC dc(this);
	CFont* font = GetFont();
	CFont* oldFont = font ? dc.SelectObject(font) : NULL;
	BOOL truncated = FALSE;
	CString fullText;

	if (m_twoLine)
	{
		const int horizontalPadding = UiTheme::ScaleForWindow(m_hWnd, 9);
		const int dotSize = UiTheme::ScaleForWindow(m_hWnd, 6);
		const int dotGap = UiTheme::ScaleForWindow(m_hWnd, 6);
		const int innerWidth = max(0, client.Width() - horizontalPadding * 2);
		const int primaryWidth = max(0, innerWidth - dotSize - dotGap);
		truncated = dc.GetTextExtent(m_primaryText).cx > primaryWidth ||
			dc.GetTextExtent(m_secondaryText).cx > innerWidth;
		fullText = m_primaryText;
		if (!m_secondaryText.IsEmpty())
		{
			if (!fullText.IsEmpty())
				fullText += _T("\r\n");
			fullText += m_secondaryText;
		}
	}
	else
	{
		GetWindowText(fullText);
		const int horizontalPadding = UiTheme::ScaleForWindow(m_hWnd, 8);
		const int availableWidth = max(0, client.Width() -
			UiTheme::ScaleForWindow(m_hWnd, 2) - horizontalPadding * 2);
		truncated = dc.GetTextExtent(fullText).cx > availableWidth;
	}

	if (oldFont)
		dc.SelectObject(oldFont);

	if (!truncated || fullText.IsEmpty())
	{
		m_tooltip.Pop();
		m_tooltip.Activate(FALSE);
		m_tooltipText.Empty();
		return;
	}

	if (m_tooltipText != fullText)
	{
		m_tooltipText = fullText;
		m_tooltip.UpdateTipText(m_tooltipText, this);
	}
	m_tooltip.Activate(TRUE);
}

void CStatusLabel::DrawItem(LPDRAWITEMSTRUCT info)
{
	CDC dc;
	dc.Attach(info->hDC);
	CRect rect(info->rcItem);
	COLORREF fill = RGB(242, 244, 247);
	COLORREF border = UiTheme::Border();
	COLORREF text = UiTheme::TextSecondary();

	if (m_tone == TONE_INFO)
	{
		fill = UiTheme::AccentSoft();
		border = RGB(191, 209, 250);
		text = UiTheme::Accent();
	}
	else if (m_tone == TONE_WARNING)
	{
		fill = RGB(255, 247, 230);
		border = RGB(245, 196, 113);
		text = RGB(180, 83, 9);
	}
	else if (m_tone == TONE_SUCCESS)
	{
		fill = UiTheme::SuccessSoft();
		border = RGB(184, 229, 198);
		text = UiTheme::Success();
	}
	else if (m_tone == TONE_DANGER)
	{
		fill = UiTheme::DangerSoft();
		border = RGB(247, 194, 194);
		text = UiTheme::Danger();
	}

	dc.FillSolidRect(rect, UiTheme::PageBackground());
	rect.DeflateRect(1, 1);
	CPen pen(PS_SOLID, 1, border);
	CBrush brush(fill);
	CPen* oldPen = dc.SelectObject(&pen);
	CBrush* oldBrush = dc.SelectObject(&brush);
	dc.RoundRect(rect, CPoint(UiTheme::ScaleForWindow(m_hWnd, 10), UiTheme::ScaleForWindow(m_hWnd, 10)));
	dc.SelectObject(oldBrush);
	dc.SelectObject(oldPen);

	dc.SetBkMode(TRANSPARENT);
	CFont* font = GetFont();
	CFont* oldFont = font ? dc.SelectObject(font) : NULL;

	if (m_twoLine)
	{
		const int horizontalPadding = UiTheme::ScaleForWindow(m_hWnd, 9);
		const int verticalPadding = UiTheme::ScaleForWindow(m_hWnd, 5);
		const int primaryHeight = UiTheme::ScaleForWindow(m_hWnd, 22);
		const int dotSize = UiTheme::ScaleForWindow(m_hWnd, 6);
		const int dotGap = UiTheme::ScaleForWindow(m_hWnd, 6);
		CRect inner(rect);
		inner.DeflateRect(horizontalPadding, verticalPadding);

		CRect primaryRect(inner.left + dotSize + dotGap, inner.top,
			inner.right, min(inner.bottom, inner.top + primaryHeight));
		CRect dotRect(inner.left,
			primaryRect.CenterPoint().y - dotSize / 2,
			inner.left + dotSize,
			primaryRect.CenterPoint().y - dotSize / 2 + dotSize);
		CPen dotPen(PS_SOLID, 1, text);
		CBrush dotBrush(text);
		oldPen = dc.SelectObject(&dotPen);
		oldBrush = dc.SelectObject(&dotBrush);
		dc.Ellipse(dotRect);
		dc.SelectObject(oldBrush);
		dc.SelectObject(oldPen);

		dc.SetTextColor(text);
		dc.DrawText(m_primaryText, primaryRect,
			DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);

		CRect secondaryRect(inner.left, primaryRect.bottom, inner.right, inner.bottom);
		dc.SetTextColor(UiTheme::TextPrimary());
		dc.DrawText(m_secondaryText, secondaryRect,
			DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
	}
	else
	{
		CString caption;
		GetWindowText(caption);
		dc.SetTextColor(text);
		rect.DeflateRect(UiTheme::ScaleForWindow(m_hWnd, 8), 0);
		dc.DrawText(caption, rect,
			DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
	}
	if (oldFont)
		dc.SelectObject(oldFont);
	dc.Detach();
}
