#include "stdafx.h"
#include "ProxyLane.h"
#include "ModernUI.h"
#include "resource.h"
#include "Localization.h"
#include <gdiplus.h>
#include <vector>
#include "GlyphData.h"
#pragma comment(lib, "gdiplus.lib")

namespace
{
	const UINT WM_STATUS_LABEL_INITIALIZE_TOOLTIP = WM_APP + 1;
}

namespace UiTheme
{
	COLORREF WindowBackground()  { return RGB(255, 255, 255); }
	COLORREF PageBackground()    { return RGB(255, 255, 255); }
	COLORREF SidebarBackground() { return RGB(249, 250, 251); }
	COLORREF TextPrimary()       { return RGB(23, 32, 51); }
	COLORREF TextSecondary()     { return RGB(102, 112, 133); }
	COLORREF Border()            { return RGB(218, 223, 230); }
	COLORREF Accent()            { return RGB(37, 99, 235); }
	COLORREF AccentHover()       { return RGB(29, 78, 216); }
	COLORREF AccentSoft()        { return RGB(232, 239, 254); }
	COLORREF AccentSoftBorder()  { return RGB(207, 220, 251); }
	COLORREF Surface()           { return RGB(249, 250, 252); }
	COLORREF Success()           { return RGB(22, 163, 74); }
	COLORREF SuccessSoft()       { return RGB(230, 247, 236); }
	COLORREF Danger()            { return RGB(220, 38, 38); }
	COLORREF DangerSoft()        { return RGB(254, 235, 235); }

	COLORREF BorderSoft()        { return RGB(231, 235, 241); }

	namespace
	{
		void EnsureGdiplus()
		{
			// Started once and left to the OS at process exit.
			static ULONG_PTR token = 0;
			if (token) return;
			Gdiplus::GdiplusStartupInput input;
			Gdiplus::GdiplusStartup(&token, &input, NULL);
		}

		Gdiplus::Color ToColor(COLORREF color)
		{
			return Gdiplus::Color(255, GetRValue(color), GetGValue(color), GetBValue(color));
		}
	}

	void FillRoundRect(HDC dc, const CRect& rect, int radius, COLORREF fill, COLORREF border)
	{
		if (!dc || rect.Width() < 2 || rect.Height() < 2) return;
		EnsureGdiplus();
		Gdiplus::Graphics graphics(dc);
		graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
		// Coordinates are pixel edges; a 1px border is centred half a pixel inside.
		graphics.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);
		const Gdiplus::REAL inset = border != CLR_NONE ? 0.5f : 0.0f;
		const Gdiplus::REAL x = rect.left + inset, y = rect.top + inset;
		const Gdiplus::REAL w = rect.Width() - inset * 2, h = rect.Height() - inset * 2;
		Gdiplus::REAL d = static_cast<Gdiplus::REAL>(radius) * 2;
		if (d > w) d = w;
		if (d > h) d = h;
		Gdiplus::GraphicsPath path;
		path.AddArc(x, y, d, d, 180, 90);
		path.AddArc(x + w - d, y, d, d, 270, 90);
		path.AddArc(x + w - d, y + h - d, d, d, 0, 90);
		path.AddArc(x, y + h - d, d, d, 90, 90);
		path.CloseFigure();
		if (fill != CLR_NONE)
		{
			Gdiplus::SolidBrush brush(ToColor(fill));
			graphics.FillPath(&brush, &path);
		}
		if (border != CLR_NONE)
		{
			Gdiplus::Pen pen(ToColor(border), 1.0f);
			graphics.DrawPath(&pen, &path);
		}
	}

	void DrawGlyph(HDC dc, Glyph glyph, const CRect& box, COLORREF color, float strokePx)
	{
		if (!dc || box.Width() < 4) return;
		EnsureGdiplus();
		Gdiplus::Graphics graphics(dc);
		graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
		graphics.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);
		Gdiplus::Pen pen(ToColor(color), strokePx);
		pen.SetStartCap(Gdiplus::LineCapRound);
		pen.SetEndCap(Gdiplus::LineCapRound);
		pen.SetLineJoin(Gdiplus::LineJoinRound);
		// Icons supplied as vector outlines: log, settings (proxy page) and the proxy tool.
		const GlyphData::Outline* outlines = NULL;
		int outlineCount = 0;
		if (glyph == GLYPH_LOG) { outlines = GlyphData::kLog; outlineCount = GlyphData::kLogCount; }
		else if (glyph == GLYPH_PROXY) { outlines = GlyphData::kSettings; outlineCount = GlyphData::kSettingsCount; }
		else if (glyph == GLYPH_PROXY_TOOL) { outlines = GlyphData::kProxyTool; outlineCount = GlyphData::kProxyToolCount; }
		if (outlines)
		{
			const float side = static_cast<float>(min(box.Width(), box.Height())) * 1.08f;
			const float left = box.left + (box.Width() - side) / 2, top = box.top + (box.Height() - side) / 2;
			Gdiplus::GraphicsPath shape(Gdiplus::FillModeWinding);
			for (int i = 0; i < outlineCount; ++i)
			{
				std::vector<Gdiplus::PointF> pts(outlines[i].count);
				for (int k = 0; k < outlines[i].count; ++k)
					pts[k] = Gdiplus::PointF(left + outlines[i].points[k * 2] * side, top + outlines[i].points[k * 2 + 1] * side);
				shape.StartFigure();
				shape.AddPolygon(&pts[0], outlines[i].count);
			}
			Gdiplus::SolidBrush brush(ToColor(color));
			graphics.FillPath(&brush, &shape);
			return;
		}
		const float unit = box.Width() / 16.0f;
		auto P = [&](float px, float py) { return Gdiplus::PointF(box.left + px * unit, box.top + py * unit); };
		auto line = [&](float x1, float y1, float x2, float y2) { graphics.DrawLine(&pen, P(x1, y1), P(x2, y2)); };
		auto ellipse = [&](float x1, float y1, float x2, float y2) {
			const Gdiplus::PointF a = P(x1, y1), b = P(x2, y2);
			graphics.DrawEllipse(&pen, a.X, a.Y, b.X - a.X, b.Y - a.Y);
		};
		auto box2 = [&](float x1, float y1, float x2, float y2, float r) {
			const Gdiplus::PointF a = P(x1, y1), b = P(x2, y2);
			const float dd = r * 2 * unit;
			Gdiplus::GraphicsPath path;
			path.AddArc(a.X, a.Y, dd, dd, 180, 90);
			path.AddArc(b.X - dd, a.Y, dd, dd, 270, 90);
			path.AddArc(b.X - dd, b.Y - dd, dd, dd, 0, 90);
			path.AddArc(a.X, b.Y - dd, dd, dd, 90, 90);
			path.CloseFigure();
			graphics.DrawPath(&pen, &path);
		};
		switch (glyph)
		{
		case GLYPH_APPS:
			box2(2, 2, 7, 7, 1.5f); box2(9, 2, 14, 7, 1.5f);
			box2(2, 9, 7, 14, 1.5f); box2(9, 9, 14, 14, 1.5f);
			break;
		case GLYPH_PROXY:
			line(2, 4, 14, 4); line(2, 8, 14, 8); line(2, 12, 14, 12);
			ellipse(9, 2.2f, 12.6f, 5.8f); ellipse(3.4f, 6.2f, 7, 9.8f); ellipse(10, 10.2f, 13.6f, 13.8f);
			break;
		case GLYPH_LOG:
			line(6, 4, 14, 4); line(6, 8, 14, 8); line(6, 12, 14, 12);
			line(2.5f, 4, 3.2f, 4); line(2.5f, 8, 3.2f, 8); line(2.5f, 12, 3.2f, 12);
			break;
		case GLYPH_MONITOR:
			{
				Gdiplus::PointF pts[] = { P(1, 8), P(4.5f, 8), P(6.5f, 3), P(9.5f, 13), P(11.5f, 8), P(15, 8) };
				graphics.DrawLines(&pen, pts, 6);
			}
			break;
		case GLYPH_ABOUT:
			ellipse(2, 2, 14, 14); line(8, 7.2f, 8, 11); line(8, 4.8f, 8, 5.0f);
			break;
		case GLYPH_DROP:
			line(8, 2.5f, 8, 10.5f); line(4.5f, 7, 8, 10.5f); line(11.5f, 7, 8, 10.5f);
			line(3, 13.5f, 13, 13.5f);
			break;
		case GLYPH_CHEVRON_DOWN:
			line(4, 6, 8, 10); line(12, 6, 8, 10);
			break;
		case GLYPH_CHEVRON_UP:
			line(4, 10, 8, 6); line(12, 10, 8, 6);
			break;
		}
	}

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

void CModernDialog::OnOK()
{
	// Embedded navigation pages have no modal result. CDialog::OnOK would
	// call EndDialog and hide them when Enter reaches the dialog manager.
	if (!(GetStyle() & WS_CHILD)) CDialog::OnOK();
}

void CModernDialog::OnCancel()
{
	// Keep Esc handling in controls (combos, process finder, etc.) intact;
	// suppress only the final dialog-cancellation action for child pages.
	if (!(GetStyle() & WS_CHILD)) CDialog::OnCancel();
}

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
	// Fixed pixel geometry: the dialog-unit rectangles are based on the 8pt
	// template font and are too short for the 16pt title, which then gets its
	// descenders clipped.
	const UINT headerIds[] = { IDC_STATIC_PAGE_TITLE, IDC_STATIC_PAGE_SUBTITLE };
	const int tops[] = { UiTheme::ScaleForWindow(m_hWnd, 4), UiTheme::ScaleForWindow(m_hWnd, 38) };
	const int heights[] = { UiTheme::ScaleForWindow(m_hWnd, 36), UiTheme::ScaleForWindow(m_hWnd, 18) };
	for (int i = 0; i < _countof(headerIds); ++i)
	{
		CWnd* header = GetDlgItem(headerIds[i]);
		if (!header || !header->GetSafeHwnd())
			continue;

		CRect rect;
		header->GetWindowRect(&rect);
		ScreenToClient(&rect);
		header->MoveWindow(rect.left, tops[i],
			max(0, client.right - rightMargin - rect.left), heights[i]);
	}
}

BOOL CModernDialog::OnEraseBkgnd(CDC* dc)
{
	CRect rect;
	GetClientRect(&rect);
	dc->FillSolidRect(rect, UiTheme::PageBackground());
	return TRUE;
}

BOOL CModernDialog::UsesSecondaryText(UINT controlId) const
{
	return controlId == IDC_STATIC_PAGE_SUBTITLE;
}

HBRUSH CModernDialog::OnCtlColor(CDC* dc, CWnd* wnd, UINT ctlColor)
{
	if (ctlColor == CTLCOLOR_STATIC || ctlColor == CTLCOLOR_BTN || ctlColor == CTLCOLOR_DLG)
	{
		dc->SetBkMode(TRANSPARENT);
		if (wnd && UsesSecondaryText(wnd->GetDlgCtrlID()))
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
	, m_backdrop(UiTheme::PageBackground())
	, m_hot(FALSE)
{
}

void CModernButton::SetBackdropColor(COLORREF color)
{
	m_backdrop = color;
	if (GetSafeHwnd())
		Invalidate(FALSE);
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
	// Paint into an off-screen bitmap so hover/press changes do not flicker.
	CDC target;
	target.Attach(info->hDC);
	CRect clientRect;
	GetClientRect(&clientRect);
	// Cover the whole client area, not only rcItem, so no part keeps the dialog brush.
	target.FillSolidRect(clientRect, m_backdrop);
	CRect rect(0, 0, clientRect.Width(), clientRect.Height());
	CDC dc;
	CBitmap buffer;
	dc.CreateCompatibleDC(&target);
	buffer.CreateCompatibleBitmap(&target, max(1, rect.Width()), max(1, rect.Height()));
	CBitmap* oldBuffer = dc.SelectObject(&buffer);
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

	dc.FillSolidRect(rect, m_backdrop);
	rect.DeflateRect(1, 1);
	CPen pen(PS_SOLID, 1, border);
	CBrush brush(fill);
	CPen* oldPen = dc.SelectObject(&pen);
	CBrush* oldBrush = dc.SelectObject(&brush);
	UiTheme::FillRoundRect(dc.m_hDC, rect, UiTheme::ScaleForWindow(m_hWnd, 6), fill, border);
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

	if ((info->itemState & ODS_FOCUS) && !(info->itemState & ODS_NOFOCUSRECT) && !disabled)
	{
		// Keyboard focus ring instead of the dotted rectangle.
		const int radius = UiTheme::ScaleForWindow(m_hWnd, 6);
		if (m_visualStyle == STYLE_PRIMARY)
		{
			CRect inner = rect;
			inner.DeflateRect(2, 2);
			UiTheme::FillRoundRect(dc.m_hDC, inner, max(1, radius - 2), CLR_NONE, RGB(255, 255, 255));
		}
		else
		{
			UiTheme::FillRoundRect(dc.m_hDC, rect, radius, CLR_NONE, UiTheme::Accent());
			CRect inner = rect;
			inner.DeflateRect(1, 1);
			UiTheme::FillRoundRect(dc.m_hDC, inner, max(1, radius - 1), CLR_NONE, UiTheme::Accent());
		}
	}

	target.BitBlt(0, 0, clientRect.Width(), clientRect.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBuffer);
	target.Detach();
}

IMPLEMENT_DYNAMIC(CStatusLabel, CStatic)

CStatusLabel::CStatusLabel()
	: m_tone(TONE_NEUTRAL),
	m_backdrop(UiTheme::PageBackground()),
	m_twoLine(FALSE)
{
}

void CStatusLabel::SetBackdropColor(COLORREF color)
{
	m_backdrop = color;
	if (GetSafeHwnd())
		Invalidate(FALSE);
}

void CStatusLabel::SetStatus(LPCTSTR text, Tone tone)
{
	m_tone = tone;
	m_twoLine = FALSE;
	m_primaryText.Empty();
	m_secondaryText.Empty();
	m_uploadText.Empty();
	m_downloadText.Empty();
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
	m_uploadText.Empty();
	m_downloadText.Empty();
	SetWindowText(m_secondaryText);
	if (GetSafeHwnd())
	{
		Invalidate(FALSE);
		UpdateOverflowTooltip();
	}
}

void CStatusLabel::SetTrafficRates(LPCTSTR uploadText, LPCTSTR downloadText)
{
	if (m_uploadText == uploadText && m_downloadText == downloadText)
		return;
	m_uploadText = uploadText;
	m_downloadText = downloadText;
	SetWindowText(m_secondaryText + _T("\r\n") + m_uploadText + _T("\r\n") + m_downloadText);
	Invalidate(FALSE);
	UpdateOverflowTooltip();
}

void CStatusLabel::PreSubclassWindow()
{
	ModifyStyle(0x0000001F, SS_OWNERDRAW | SS_NOTIFY);
	CStatic::PreSubclassWindow();

	// A dynamically-created CStatusLabel reaches PreSubclassWindow while MFC's
	// CBT window-creation hook is still attaching this CWnd. Creating another
	// CWnd here would nest AfxHookWindowCreate and assert in Debug builds.
	PostMessage(WM_STATUS_LABEL_INITIALIZE_TOOLTIP);
}

LRESULT CStatusLabel::OnInitializeTooltip(WPARAM, LPARAM)
{
	if (m_tooltip.GetSafeHwnd())
		return 0;

	CWnd* parent = GetParent();
	if (parent && m_tooltip.Create(parent, TTS_ALWAYSTIP | TTS_NOPREFIX))
	{
		m_tooltip.AddTool(this, _T(" "));
		m_tooltip.SetMaxTipWidth(UiTheme::ScaleForWindow(m_hWnd, 420));
		m_tooltip.Activate(FALSE);
		UpdateOverflowTooltip();
	}
	return 0;
}

BEGIN_MESSAGE_MAP(CStatusLabel, CStatic)
	ON_WM_SIZE()
	ON_MESSAGE(WM_STATUS_LABEL_INITIALIZE_TOOLTIP, OnInitializeTooltip)
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
		if (!m_uploadText.IsEmpty())
		{
			truncated = truncated || dc.GetTextExtent(m_uploadText).cx > innerWidth ||
				dc.GetTextExtent(m_downloadText).cx > innerWidth;
			fullText += _T("\r\n") + m_uploadText + _T("\r\n") + m_downloadText;
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
	CDC target;
	target.Attach(info->hDC);
	CRect clientRect;
	GetClientRect(&clientRect);
	// Cover the whole client area, not only rcItem, so no part keeps the dialog brush.
	target.FillSolidRect(clientRect, m_backdrop);
	CRect rect(0, 0, clientRect.Width(), clientRect.Height());
	CDC dc;
	CBitmap buffer;
	dc.CreateCompatibleDC(&target);
	buffer.CreateCompatibleBitmap(&target, max(1, rect.Width()), max(1, rect.Height()));
	CBitmap* oldBuffer = dc.SelectObject(&buffer);
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

	dc.FillSolidRect(rect, m_backdrop);
	rect.DeflateRect(1, 1);
	CPen pen(PS_SOLID, 1, border);
	CBrush brush(fill);
	CPen* oldPen = dc.SelectObject(&pen);
	CBrush* oldBrush = dc.SelectObject(&brush);
	UiTheme::FillRoundRect(dc.m_hDC, rect, UiTheme::ScaleForWindow(m_hWnd, 9), fill, border);
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
		if (!m_uploadText.IsEmpty())
			secondaryRect.bottom = min(inner.bottom, secondaryRect.top + primaryHeight);
		dc.SetTextColor(UiTheme::TextPrimary());
		dc.DrawText(m_secondaryText, secondaryRect,
			DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
		if (!m_uploadText.IsEmpty())
		{
			CRect rateRect(inner.left, secondaryRect.bottom + UiTheme::ScaleForWindow(m_hWnd, 4),
				inner.right, inner.bottom);
			rateRect.bottom = min(inner.bottom, rateRect.top + primaryHeight);
			dc.SetTextColor(UiTheme::TextSecondary());
			dc.DrawText(m_uploadText, rateRect,
				DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
			rateRect.OffsetRect(0, primaryHeight);
			dc.DrawText(m_downloadText, rateRect,
				DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
		}
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
	target.BitBlt(0, 0, clientRect.Width(), clientRect.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBuffer);
	target.Detach();
}

IMPLEMENT_DYNAMIC(CCardFrame, CButton)

BEGIN_MESSAGE_MAP(CCardFrame, CButton)
	ON_WM_ERASEBKGND()
	ON_WM_NCHITTEST()
END_MESSAGE_MAP()

void CCardFrame::PreSubclassWindow()
{
	ModifyStyle(0x0000000F, BS_OWNERDRAW);
	CButton::PreSubclassWindow();
}

BOOL CCardFrame::OnEraseBkgnd(CDC*)
{
	return TRUE;
}

void CCardFrame::DrawItem(LPDRAWITEMSTRUCT info)
{
	CDC dc;
	dc.Attach(info->hDC);
	CRect rect(info->rcItem);
	rect.DeflateRect(0, 0, 1, 1);

	UiTheme::FillRoundRect(dc.m_hDC, rect, UiTheme::ScaleForWindow(m_hWnd, 12), CLR_NONE, UiTheme::BorderSoft());

	CString caption;
	GetWindowText(caption);
	if (!caption.IsEmpty())
	{
		LOGFONT logFont = { 0 };
		CFont* font = GetFont();
		if (font) font->GetLogFont(&logFont);
		logFont.lfWeight = FW_SEMIBOLD;
		CFont titleFont;
		titleFont.CreateFontIndirect(&logFont);
		CFont* oldFont = dc.SelectObject(&titleFont);
		dc.SetBkMode(TRANSPARENT);
		dc.SetTextColor(UiTheme::TextPrimary());
		CRect title(rect.left + UiTheme::ScaleForWindow(m_hWnd, 16), rect.top + UiTheme::ScaleForWindow(m_hWnd, 9),
			rect.right - UiTheme::ScaleForWindow(m_hWnd, 16), rect.top + UiTheme::ScaleForWindow(m_hWnd, 29));
		dc.DrawText(caption, title, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
		dc.SelectObject(oldFont);
	}
	dc.Detach();
}

IMPLEMENT_DYNAMIC(CSoftEdit, CEdit)

BEGIN_MESSAGE_MAP(CSoftEdit, CEdit)
	ON_WM_NCCALCSIZE()
	ON_WM_NCPAINT()
	ON_WM_SETFOCUS()
	ON_WM_KILLFOCUS()
	ON_WM_ENABLE()
	ON_WM_NCHITTEST()
END_MESSAGE_MAP()

void CSoftEdit::PreSubclassWindow()
{
	ModifyStyle(WS_BORDER, 0);
	ModifyStyleEx(WS_EX_CLIENTEDGE | WS_EX_STATICEDGE | WS_EX_WINDOWEDGE, 0, SWP_FRAMECHANGED);
	CEdit::PreSubclassWindow();
}

void CSoftEdit::OnNcCalcSize(BOOL calcValidRects, NCCALCSIZE_PARAMS* params)
{
	CEdit::OnNcCalcSize(calcValidRects, params);
	if (!calcValidRects) return;
	RECT& area = params->rgrc[0];
	const int padX = UiTheme::ScaleForWindow(m_hWnd, 9);
	int padY;
	if (GetStyle() & ES_MULTILINE)
		padY = UiTheme::ScaleForWindow(m_hWnd, 7);
	else
	{
		// Centre the single text line vertically inside the field.
		int textHeight = UiTheme::ScaleForWindow(m_hWnd, 16);
		if (CDC* dc = GetDC())
		{
			CFont* font = GetFont();
			CFont* oldFont = font ? dc->SelectObject(font) : NULL;
			TEXTMETRIC metrics = { 0 };
			if (dc->GetTextMetrics(&metrics)) textHeight = metrics.tmHeight;
			if (oldFont) dc->SelectObject(oldFont);
			ReleaseDC(dc);
		}
		padY = max(2, (area.bottom - area.top - textHeight) / 2);
	}
	area.left += padX;
	area.right -= (GetStyle() & WS_VSCROLL) ? 0 : padX;
	area.top += padY;
	area.bottom -= padY;
	if (area.right < area.left) area.right = area.left;
	if (area.bottom < area.top) area.bottom = area.top;
}

void CSoftEdit::OnNcPaint()
{
	CRect window;
	GetWindowRect(&window);
	CRect client;
	GetClientRect(&client);
	ClientToScreen(&client);
	client.OffsetRect(-window.left, -window.top);
	window.OffsetRect(-window.left, -window.top);

	CWindowDC dc(this);
	dc.ExcludeClipRect(&client);
	dc.FillSolidRect(window, UiTheme::PageBackground());
	const BOOL enabled = IsWindowEnabled();
	const BOOL focused = ::GetFocus() == m_hWnd;
	COLORREF border = focused ? UiTheme::Accent() : (enabled ? RGB(208, 214, 223) : UiTheme::BorderSoft());
	UiTheme::FillRoundRect(dc.m_hDC, window, UiTheme::ScaleForWindow(m_hWnd, 8),
		RGB(255, 255, 255), border);
	// Scroll bars of multi-line edits are painted by the default handler.
	Default();
}

void CSoftEdit::OnSetFocus(CWnd* oldWindow)
{
	CEdit::OnSetFocus(oldWindow);
	RedrawWindow(NULL, NULL, RDW_FRAME | RDW_INVALIDATE);
}

void CSoftEdit::OnKillFocus(CWnd* newWindow)
{
	CEdit::OnKillFocus(newWindow);
	RedrawWindow(NULL, NULL, RDW_FRAME | RDW_INVALIDATE);
}

void CSoftEdit::OnEnable(BOOL enable)
{
	CEdit::OnEnable(enable);
	RedrawWindow(NULL, NULL, RDW_FRAME | RDW_INVALIDATE);
}

LRESULT CSoftEdit::OnNcHitTest(CPoint point)
{
	// The padding is part of the field: clicking it must focus and place the caret.
	const LRESULT hit = CEdit::OnNcHitTest(point);
	return (hit == HTVSCROLL || hit == HTHSCROLL) ? hit : HTCLIENT;
}

LRESULT CCardFrame::OnNcHitTest(CPoint)
{
	// Like a stock group box, let clicks fall through to the controls it frames.
	return HTTRANSPARENT;
}

IMPLEMENT_DYNAMIC(CSoftCombo, CComboBox)

BEGIN_MESSAGE_MAP(CSoftCombo, CComboBox)
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_MOUSEMOVE()
	ON_MESSAGE(WM_MOUSELEAVE, OnMouseLeave)
	ON_WM_ENABLE()
	ON_CONTROL_REFLECT_EX(CBN_SETFOCUS, OnStateChanged)
	ON_CONTROL_REFLECT_EX(CBN_KILLFOCUS, OnStateChanged)
	ON_CONTROL_REFLECT_EX(CBN_DROPDOWN, OnStateChanged)
	ON_CONTROL_REFLECT_EX(CBN_CLOSEUP, OnStateChanged)
	ON_CONTROL_REFLECT_EX(CBN_SELCHANGE, OnStateChanged)
END_MESSAGE_MAP()

CSoftCombo::CSoftCombo()
	: m_hot(FALSE)
{
}

void CSoftCombo::PreSubclassWindow()
{
	// The edit child of an editable combo paints itself; keep it out of our DC.
	ModifyStyle(0, WS_CLIPCHILDREN);
	CComboBox::PreSubclassWindow();
}

BOOL CSoftCombo::OnEraseBkgnd(CDC*)
{
	return TRUE;
}

BOOL CSoftCombo::OnStateChanged()
{
	Invalidate(FALSE);
	return FALSE; // let the parent handle the notification too
}

void CSoftCombo::OnEnable(BOOL enable)
{
	CComboBox::OnEnable(enable);
	Invalidate(FALSE);
}

void CSoftCombo::OnMouseMove(UINT flags, CPoint point)
{
	if (!m_hot)
	{
		m_hot = TRUE;
		TRACKMOUSEEVENT track = { sizeof(track), TME_LEAVE, m_hWnd, 0 };
		_TrackMouseEvent(&track);
		Invalidate(FALSE);
	}
	CComboBox::OnMouseMove(flags, point);
}

LRESULT CSoftCombo::OnMouseLeave(WPARAM, LPARAM)
{
	m_hot = FALSE;
	Invalidate(FALSE);
	return 0;
}

void CSoftCombo::OnPaint()
{
	// Keep typed text off the rounded border. The edit child resets its
	// margins whenever its font changes, so re-apply them here.
	if (CWnd* edit = GetWindow(GW_CHILD))
	{
		const int margin = UiTheme::ScaleForWindow(m_hWnd, 7);
		if (LOWORD(edit->SendMessage(EM_GETMARGINS)) != margin)
			edit->SendMessage(EM_SETMARGINS, EC_LEFTMARGIN, MAKELONG(margin, 0));
	}
	CPaintDC paint(this);
	CRect client;
	GetClientRect(&client);
	if (client.IsRectEmpty()) return;

	CDC dc;
	CBitmap buffer;
	dc.CreateCompatibleDC(&paint);
	buffer.CreateCompatibleBitmap(&paint, client.Width(), client.Height());
	CBitmap* oldBuffer = dc.SelectObject(&buffer);

	const BOOL enabled = IsWindowEnabled();
	CWnd* focus = GetFocus();
	const BOOL focused = focus && (focus == this || focus->GetParent() == this);
	const BOOL dropped = GetDroppedState();
	COLORREF border = !enabled ? UiTheme::BorderSoft()
		: (focused || dropped) ? UiTheme::Accent()
		: m_hot ? RGB(184, 193, 207) : RGB(208, 214, 223);

	dc.FillSolidRect(client, UiTheme::PageBackground());
	UiTheme::FillRoundRect(dc.m_hDC, client, UiTheme::ScaleForWindow(m_hWnd, 8), RGB(255, 255, 255), border);

	// Arrow.
	// Kept inside the native button area so the edit child of an editable combo never covers it.
	const int arrow = UiTheme::ScaleForWindow(m_hWnd, 10);
	CRect arrowRect(client.right - UiTheme::ScaleForWindow(m_hWnd, 8) - arrow, client.CenterPoint().y - arrow / 2,
		client.right - UiTheme::ScaleForWindow(m_hWnd, 8), client.CenterPoint().y - arrow / 2 + arrow);
	UiTheme::DrawGlyph(dc.m_hDC, dropped ? UiTheme::GLYPH_CHEVRON_UP : UiTheme::GLYPH_CHEVRON_DOWN, arrowRect,
		enabled ? UiTheme::TextSecondary() : RGB(176, 182, 192), max(1.4f, UiTheme::ScaleForWindow(m_hWnd, 3) / 2.0f));

	// Selected text (editable combos show it in their own edit child).
	if ((GetStyle() & 0x3) == CBS_DROPDOWNLIST)
	{
		CString text;
		const int selection = GetCurSel();
		if (selection != CB_ERR) GetLBText(selection, text);
		CFont* font = GetFont();
		CFont* oldFont = font ? dc.SelectObject(font) : NULL;
		dc.SetBkMode(TRANSPARENT);
		dc.SetTextColor(enabled ? UiTheme::TextPrimary() : RGB(160, 166, 177));
		CRect textRect(client.left + UiTheme::ScaleForWindow(m_hWnd, 10), client.top,
			arrowRect.left - UiTheme::ScaleForWindow(m_hWnd, 6), client.bottom);
		dc.DrawText(text, textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
		if (oldFont) dc.SelectObject(oldFont);
	}

	paint.BitBlt(0, 0, client.Width(), client.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBuffer);
}
