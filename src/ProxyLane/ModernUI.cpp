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
	namespace
	{
		const UINT WM_CARD_SEND_TO_BACK = WM_APP + 2;
		const UINT_PTR kToggleAnimationTimer = 0x51;
		const DWORD kToggleAnimationMs = 140;
		BOOL g_dark = TRUE;
		const TCHAR kBundledFace[] = _T("Noto Sans SC");
		BOOL g_bundledFontReady = FALSE;

		inline COLORREF Pick(COLORREF dark, COLORREF light) { return g_dark ? dark : light; }
	}

	BOOL IsDark() { return g_dark; }

	COLORREF WindowBackground()  { return Pick(RGB(19, 20, 23), RGB(241, 242, 246)); }
	COLORREF PageBackground()    { return WindowBackground(); }
	COLORREF SidebarBackground() { return Pick(RGB(23, 24, 27), RGB(233, 235, 240)); }
	COLORREF TextPrimary()       { return Pick(RGB(243, 244, 246), RGB(21, 23, 28)); }
	COLORREF TextSecondary()     { return Pick(RGB(174, 177, 184), RGB(85, 90, 101)); }
	COLORREF TextDisabled()      { return Pick(RGB(112, 115, 122), RGB(160, 166, 177)); }
	COLORREF Border()            { return Pick(RGB(68, 70, 77), RGB(201, 204, 212)); }
	COLORREF BorderSoft()        { return Pick(RGB(48, 49, 54), RGB(226, 228, 234)); }
	COLORREF Accent()            { return RGB(31, 111, 235); }
	COLORREF AccentHover()       { return Pick(RGB(59, 130, 240), RGB(26, 95, 204)); }
	COLORREF AccentText()        { return Pick(RGB(130, 180, 255), RGB(26, 95, 204)); }
	COLORREF AccentSoft()        { return Pick(RGB(29, 47, 77), RGB(226, 236, 253)); }
	COLORREF AccentSoftBorder()  { return Pick(RGB(44, 70, 112), RGB(207, 220, 251)); }
	COLORREF Surface()           { return Pick(RGB(35, 36, 40), RGB(255, 255, 255)); }
	COLORREF Inner()             { return Pick(RGB(46, 47, 52), RGB(238, 240, 244)); }
	COLORREF Hover()             { return Pick(RGB(56, 58, 64), RGB(226, 228, 234)); }
	COLORREF Success()           { return Pick(RGB(79, 209, 154), RGB(11, 122, 75)); }
	COLORREF SuccessSoft()       { return Pick(RGB(22, 58, 43), RGB(223, 243, 233)); }
	COLORREF Danger()            { return Pick(RGB(255, 143, 143), RGB(190, 42, 42)); }
	COLORREF DangerSoft()        { return Pick(RGB(67, 31, 31), RGB(251, 232, 232)); }
	COLORREF Warning()           { return Pick(RGB(242, 177, 94), RGB(168, 86, 0)); }
	COLORREF WarningSoft()       { return Pick(RGB(64, 44, 20), RGB(252, 238, 221)); }

	namespace
	{
		void RegisterBundledFont(UINT resourceId)
		{
			HINSTANCE module = AfxGetResourceHandle();
			HRSRC info = ::FindResource(module, MAKEINTRESOURCE(resourceId), RT_RCDATA);
			HGLOBAL data = info ? ::LoadResource(module, info) : NULL;
			const void* bytes = data ? ::LockResource(data) : NULL;
			DWORD installed = 0;
			if (bytes && ::AddFontMemResourceEx(const_cast<void*>(bytes), ::SizeofResource(module, info), NULL, &installed))
				g_bundledFontReady = TRUE;
		}

		// Windows 10 1809 and later accept these; older systems simply ignore them.
		typedef HRESULT (WINAPI *SetWindowThemeFn)(HWND, LPCWSTR, LPCWSTR);
		SetWindowThemeFn WindowThemeApi()
		{
			static SetWindowThemeFn api = reinterpret_cast<SetWindowThemeFn>(
				::GetProcAddress(::LoadLibrary(_T("uxtheme.dll")), "SetWindowTheme"));
			return api;
		}
	}

	void Initialize()
	{
		// Without this Windows stretches the whole window on scaled displays, which
		// is what makes the text blurry. Layout code already scales by the real DPI.
		typedef BOOL (WINAPI *SetProcessDPIAwareFn)();
		if (SetProcessDPIAwareFn api = reinterpret_cast<SetProcessDPIAwareFn>(
			::GetProcAddress(::GetModuleHandle(_T("user32.dll")), "SetProcessDPIAware")))
			api();
		RegisterBundledFont(IDR_FONT_UI_REGULAR);
		RegisterBundledFont(IDR_FONT_UI_BOLD);

		TCHAR theme[16] = { 0 };
		::GetPrivateProfileString(_T("options"), _T("Theme"), _T("dark"), theme, _countof(theme), Localization::SettingsPath());
		g_dark = _tcsicmp(theme, _T("light")) != 0;
	}

	void SetDark(BOOL dark)
	{
		g_dark = dark;
		::WritePrivateProfileString(_T("options"), _T("Theme"), dark ? _T("dark") : _T("light"), Localization::SettingsPath());
	}

	void ApplyWindowChrome(HWND hWnd)
	{
		typedef HRESULT (WINAPI *DwmSetAttrFn)(HWND, DWORD, LPCVOID, DWORD);
		static DwmSetAttrFn api = reinterpret_cast<DwmSetAttrFn>(
			::GetProcAddress(::LoadLibrary(_T("dwmapi.dll")), "DwmSetWindowAttribute"));
		if (!api) return;
		const BOOL dark = g_dark;
		api(hWnd, 20, &dark, sizeof(dark));
		api(hWnd, 19, &dark, sizeof(dark));
		const COLORREF caption = SidebarBackground();
		api(hWnd, 35, &caption, sizeof(caption));
	}

	void ApplyControlTheme(HWND hWnd)
	{
		if (SetWindowThemeFn api = WindowThemeApi())
			api(hWnd, g_dark ? L"DarkMode_Explorer" : L"Explorer", NULL);
	}

	void ApplyListColors(HWND hWnd)
	{
		ListView_SetBkColor(hWnd, Surface());
		ListView_SetTextBkColor(hWnd, Surface());
		ListView_SetTextColor(hWnd, TextPrimary());
		ApplyControlTheme(hWnd);
		::SetWindowLong(hWnd, GWL_STYLE, ::GetWindowLong(hWnd, GWL_STYLE) & ~WS_BORDER);
		::SetWindowLong(hWnd, GWL_EXSTYLE, ::GetWindowLong(hWnd, GWL_EXSTYLE) & ~(WS_EX_CLIENTEDGE | WS_EX_STATICEDGE));
		::SetWindowPos(hWnd, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
		HWND header = ListView_GetHeader(hWnd);
		if (header && !CWnd::FromHandlePermanent(header))
		{
			CSoftHeader* soft = new CSoftHeader;
			soft->SubclassWindow(header);
		}
	}

	HBRUSH BrushFor(COLORREF color)
	{
		static std::vector<std::pair<COLORREF, HBRUSH>> brushes;
		for (size_t i = 0; i < brushes.size(); ++i)
			if (brushes[i].first == color) return brushes[i].second;
		HBRUSH brush = ::CreateSolidBrush(color);
		brushes.push_back(std::make_pair(color, brush));
		return brush;
	}

	COLORREF BackdropFor(CWnd* control)
	{
		CWnd* parent = control ? control->GetParent() : NULL;
		if (!parent) return PageBackground();
		CWnd* permanentParent = CWnd::FromHandlePermanent(parent->m_hWnd);
		if (permanentParent && permanentParent->IsKindOf(RUNTIME_CLASS(CModernDialog)))
			return static_cast<CModernDialog*>(permanentParent)->BackdropForChild(control);
		return BackdropAmongCards(parent, control);
	}

	COLORREF BackdropAmongCards(CWnd* parent, CWnd* control)
	{
		CRect rect;
		control->GetWindowRect(&rect);
		const CPoint centre = rect.CenterPoint();
		for (CWnd* sibling = parent->GetWindow(GW_CHILD); sibling; sibling = sibling->GetWindow(GW_HWNDNEXT))
		{
			if (sibling->m_hWnd == control->m_hWnd || !sibling->IsWindowVisible()) continue;
			CWnd* permanent = CWnd::FromHandlePermanent(sibling->m_hWnd);
			if (!permanent || !permanent->IsKindOf(RUNTIME_CLASS(CCardFrame))) continue;
			CRect card;
			sibling->GetWindowRect(&card);
			if (card.PtInRect(centre)) return Surface();
		}
		return PageBackground();
	}

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

		void PaintElevationBadge(Gdiplus::Graphics& graphics, const CRect& rect)
		{
			graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
			const float x = static_cast<float>(rect.left), y = static_cast<float>(rect.top);
			const float w = static_cast<float>(rect.Width()), h = static_cast<float>(rect.Height());
			Gdiplus::PointF points[] = {
				{ x + w * .50f, y + h * .08f }, { x + w * .88f, y + h * .20f },
				{ x + w * .84f, y + h * .59f }, { x + w * .70f, y + h * .80f },
				{ x + w * .50f, y + h * .94f }, { x + w * .30f, y + h * .80f },
				{ x + w * .16f, y + h * .59f }, { x + w * .12f, y + h * .20f }
			};
			Gdiplus::GraphicsPath shield;
			shield.AddPolygon(points, _countof(points));
			Gdiplus::SolidBrush blue(Gdiplus::Color(255, 37, 99, 190));
			Gdiplus::SolidBrush gold(Gdiplus::Color(255, 250, 202, 64));
			graphics.FillPath(&blue, &shield);
			const Gdiplus::GraphicsState state = graphics.Save();
			graphics.SetClip(&shield, Gdiplus::CombineModeIntersect);
			graphics.FillRectangle(&gold, x, y, w * .5f, h * .5f);
			graphics.FillRectangle(&gold, x + w * .5f, y + h * .5f, w * .5f, h * .5f);
			graphics.Restore(state);
			Gdiplus::Pen outline(Gdiplus::Color(255, 255, 255, 255), max(1.0f, w / 12.0f));
			outline.SetLineJoin(Gdiplus::LineJoinRound);
			graphics.DrawPath(&outline, &shield);
		}
	}

	void DrawElevationBadge(HDC dc, const CRect& rect)
	{
		if (!dc || rect.Width() < 4 || rect.Height() < 4) return;
		EnsureGdiplus();
		Gdiplus::Graphics graphics(dc);
		PaintElevationBadge(graphics, rect);
	}

	HICON CreateElevationOverlay(int iconSize)
	{
		if (iconSize < 4) return NULL;
		EnsureGdiplus();
		Gdiplus::Bitmap bitmap(iconSize, iconSize, PixelFormat32bppARGB);
		{
			Gdiplus::Graphics graphics(&bitmap);
			graphics.Clear(Gdiplus::Color(0, 0, 0, 0));
			const int side = max(4, iconSize * 3 / 4);
			PaintElevationBadge(graphics, CRect(iconSize - side, iconSize - side, iconSize, iconSize));
		}
		HICON icon = NULL;
		bitmap.GetHICON(&icon);
		return icon;
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
		case GLYPH_GLOBE:
			ellipse(2, 2, 14, 14); line(2, 8, 14, 8); ellipse(5.4f, 2, 10.6f, 14);
			break;
		case GLYPH_TABLE:
			box2(2, 2.5f, 14, 13.5f, 2); line(2, 6.5f, 14, 6.5f); line(6.5f, 6.5f, 6.5f, 13.5f);
			break;
		case GLYPH_MOON:
			{
				Gdiplus::GraphicsPath moon;
				const Gdiplus::PointF a = P(2.2f, 2.2f);
				moon.AddArc(a.X, a.Y, 11.6f * unit, 11.6f * unit, 300, 300);
				const Gdiplus::PointF b = P(7.4f, 0.4f);
				moon.AddArc(b.X, b.Y, 8.2f * unit, 8.2f * unit, 190, -180);
				moon.CloseFigure();
				graphics.DrawPath(&pen, &moon);
			}
			break;
		case GLYPH_SIDEBAR:
			box2(2, 3, 14, 13, 2); line(6.5f, 3, 6.5f, 13);
			break;
		case GLYPH_ARROW_UP:
			line(8, 13, 8, 3); line(3.8f, 7.2f, 8, 3); line(12.2f, 7.2f, 8, 3);
			break;
		case GLYPH_ARROW_DOWN:
			line(8, 3, 8, 13); line(3.8f, 8.8f, 8, 13); line(12.2f, 8.8f, 8, 13);
			break;
		case GLYPH_CHECK:
			line(3, 8.4f, 6.6f, 12); line(13, 4.4f, 6.6f, 12);
			break;
		case GLYPH_MINUS:
			line(3.5f, 8, 12.5f, 8);
			break;
		}
	}

	void DrawFilledGlyph(HDC dc, Glyph glyph, const CRect& box, COLORREF color)
	{
		if (!dc || box.Width() < 4 || glyph != GLYPH_PLAY) return;
		EnsureGdiplus();
		Gdiplus::Graphics graphics(dc);
		graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
		const float x = static_cast<float>(box.left), y = static_cast<float>(box.top);
		const float w = static_cast<float>(box.Width()), h = static_cast<float>(box.Height());
		Gdiplus::GraphicsPath path;
		Gdiplus::PointF points[] = { { x + w * .16f, y + h * .04f }, { x + w * .96f, y + h * .5f }, { x + w * .16f, y + h * .96f } };
		path.AddPolygon(points, 3);
		Gdiplus::SolidBrush brush(ToColor(color));
		Gdiplus::Pen pen(ToColor(color), w * .1f);
		pen.SetLineJoin(Gdiplus::LineJoinRound);
		graphics.FillPath(&brush, &path);
		graphics.DrawPath(&pen, &path);
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
			OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_NATURAL_QUALITY,
			DEFAULT_PITCH | FF_DONTCARE,
			faceName ? faceName : (g_bundledFontReady ? kBundledFace : _T("Segoe UI")));
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

COLORREF CModernDialog::BackdropForChild(CWnd* child)
{
	CRect rect;
	child->GetWindowRect(&rect);
	const CPoint centre = rect.CenterPoint();
	for (size_t i = 0; i < m_cards.size(); ++i)
	{
		if (m_cards[i] == child->m_hWnd || !::IsWindowVisible(m_cards[i])) continue;
		CRect card;
		::GetWindowRect(m_cards[i], &card);
		if (card.PtInRect(centre)) return UiTheme::Surface();
	}
	return UiTheme::PageBackground();
}

BOOL CModernDialog::OnInitDialog()
{
	CDialog::OnInitDialog();

	m_backgroundBrush.DeleteObject();
	m_backgroundBrush.CreateSolidBrush(UiTheme::PageBackground());
	UiTheme::CreateUiFont(m_uiFont, m_hWnd, 10, FW_NORMAL);
	UiTheme::CreateUiFont(m_titleFont, m_hWnd, 16, FW_BOLD);
	SetFont(&m_uiFont, FALSE);
	UiTheme::ApplyFontToChildren(this, &m_uiFont);
	Localization::ApplyDialog(this, m_templateId);
	AdoptNativeControls();
	// Controls paint their own background, so the page skips them entirely.
	ModifyStyle(0, WS_CLIPCHILDREN);
	if (!(GetStyle() & WS_CHILD))
		UiTheme::ApplyWindowChrome(m_hWnd);

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

		const int left = UiTheme::ScaleForWindow(m_hWnd, 8);
		header->MoveWindow(left, tops[i], max(0, client.right - rightMargin - left), heights[i]);
	}
}

void CModernDialog::AdoptNativeControls()
{
	m_cards.clear();
	for (CWnd* child = GetWindow(GW_CHILD); child; child = child->GetWindow(GW_HWNDNEXT))
	{
		TCHAR className[32] = { 0 };
		::GetClassName(child->m_hWnd, className, _countof(className));
		if (_tcsicmp(className, WC_LISTVIEW) == 0)
		{
			UiTheme::ApplyListColors(child->m_hWnd);
			continue;
		}
		if (_tcsnicmp(className, _T("RICHEDIT"), 8) == 0)
		{
			child->ModifyStyle(WS_BORDER, 0, SWP_FRAMECHANGED);
			child->ModifyStyleEx(WS_EX_CLIENTEDGE | WS_EX_STATICEDGE, 0, SWP_FRAMECHANGED);
			child->SendMessage(EM_SETBKGNDCOLOR, 0, UiTheme::Surface());
			UiTheme::ApplyControlTheme(child->m_hWnd);
			continue;
		}
		if (_tcsicmp(className, WC_TREEVIEW) == 0)
		{
			UiTheme::ApplyControlTheme(child->m_hWnd);
			continue;
		}
		if (_tcsicmp(className, _T("Edit")) == 0)
		{
			if (child->GetStyle() & ES_MULTILINE)
				UiTheme::ApplyControlTheme(child->m_hWnd);
			if (!CWnd::FromHandlePermanent(child->m_hWnd))
			{
				CSoftEdit* edit = new CSoftEdit;
				edit->m_autoDelete = TRUE;
				edit->SubclassWindow(child->m_hWnd);
			}
			continue;
		}
		if (CWnd* permanent = CWnd::FromHandlePermanent(child->m_hWnd))
		{
			if (permanent->IsKindOf(RUNTIME_CLASS(CCardFrame)))
				m_cards.push_back(child->m_hWnd);
			continue;
		}
		if (_tcsicmp(className, _T("Button")) != 0)
			continue;
		const DWORD type = child->GetStyle() & BS_TYPEMASK;
		if (type == BS_GROUPBOX)
		{
			CCardFrame* card = new CCardFrame;
			card->m_autoDelete = TRUE;
			card->SubclassWindow(child->m_hWnd);
			m_cards.push_back(child->m_hWnd);
		}
		else if (type == BS_CHECKBOX || type == BS_AUTOCHECKBOX || type == BS_RADIOBUTTON || type == BS_AUTORADIOBUTTON)
		{
			CToggleButton* toggle = new CToggleButton;
			toggle->m_autoDelete = TRUE;
			toggle->SubclassWindow(child->m_hWnd);
		}
	}
}

BOOL CModernDialog::OnEraseBkgnd(CDC* dc)
{
	CRect rect;
	GetClientRect(&rect);
	dc->FillSolidRect(rect, UiTheme::PageBackground());
	// Cards are painted here rather than by their frames so that controls placed
	// over a frame never fight it for the same pixels.
	for (CWnd* child = GetWindow(GW_CHILD); child; child = child->GetWindow(GW_HWNDNEXT))
	{
		CWnd* permanent = CWnd::FromHandlePermanent(child->m_hWnd);
		if (!permanent || !permanent->IsKindOf(RUNTIME_CLASS(CCardFrame)) || !child->IsWindowVisible())
			continue;
		CRect card;
		child->GetWindowRect(&card);
		ScreenToClient(&card);
		UiTheme::FillRoundRect(dc->m_hDC, card, UiTheme::ScaleForWindow(m_hWnd, 14), UiTheme::Surface(), CLR_NONE);
	}
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
		TCHAR className[16] = { 0 };
		if (wnd) ::GetClassName(wnd->m_hWnd, className, _countof(className));
		// Read-only edits arrive as CTLCOLOR_STATIC but are drawn as fields.
		if (_tcsicmp(className, _T("Edit")) == 0)
		{
			dc->SetBkColor(UiTheme::Inner());
			dc->SetTextColor((wnd->GetStyle() & ES_MULTILINE) ? UiTheme::TextPrimary() : UiTheme::TextSecondary());
			return UiTheme::BrushFor(UiTheme::Inner());
		}
		const COLORREF backdrop = wnd ? UiTheme::BackdropFor(wnd) : UiTheme::PageBackground();
		dc->SetBkMode(TRANSPARENT);
		dc->SetBkColor(backdrop);
		if (wnd && UsesSecondaryText(wnd->GetDlgCtrlID()))
			dc->SetTextColor(UiTheme::TextSecondary());
		else
			dc->SetTextColor(UiTheme::TextPrimary());
		return UiTheme::BrushFor(backdrop);
	}
	if (ctlColor == CTLCOLOR_LISTBOX && wnd && wnd->GetParent() == this)
	{
		dc->SetBkColor(UiTheme::Surface());
		dc->SetTextColor(UiTheme::TextPrimary());
		return UiTheme::BrushFor(UiTheme::Surface());
	}
	if (ctlColor == CTLCOLOR_EDIT || ctlColor == CTLCOLOR_LISTBOX)
	{
		dc->SetBkColor(UiTheme::Inner());
		dc->SetTextColor(UiTheme::TextPrimary());
		return UiTheme::BrushFor(UiTheme::Inner());
	}

	return CDialog::OnCtlColor(dc, wnd, ctlColor);
}

IMPLEMENT_DYNAMIC(CModernButton, CButton)

CModernButton::CModernButton()
	: m_visualStyle(STYLE_SECONDARY)
	, m_backdrop(CLR_NONE)
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
	const COLORREF backdrop = m_backdrop != CLR_NONE ? m_backdrop : UiTheme::BackdropFor(this);
	// Cover the whole client area, not only rcItem, so no part keeps the dialog brush.
	target.FillSolidRect(clientRect, backdrop);
	CRect rect(0, 0, clientRect.Width(), clientRect.Height());
	CDC dc;
	CBitmap buffer;
	dc.CreateCompatibleDC(&target);
	buffer.CreateCompatibleBitmap(&target, max(1, rect.Width()), max(1, rect.Height()));
	CBitmap* oldBuffer = dc.SelectObject(&buffer);
	BOOL disabled = (info->itemState & ODS_DISABLED) != 0;
	BOOL pressed = (info->itemState & ODS_SELECTED) != 0;

	COLORREF fill = UiTheme::Inner();
	COLORREF text = UiTheme::TextPrimary();

	if (m_visualStyle == STYLE_PRIMARY || m_visualStyle == STYLE_PILL_ACTIVE)
	{
		fill = pressed || m_hot ? UiTheme::AccentHover() : UiTheme::Accent();
		text = RGB(255, 255, 255);
	}
	else if (m_visualStyle == STYLE_DANGER)
	{
		fill = UiTheme::DangerSoft();
		text = UiTheme::Danger();
	}
	else if (m_visualStyle == STYLE_GHOST)
	{
		fill = pressed || m_hot ? UiTheme::Hover() : backdrop;
		text = pressed || m_hot ? UiTheme::TextPrimary() : UiTheme::TextSecondary();
	}
	else if (pressed || m_hot)
	{
		fill = UiTheme::Hover();
	}

	if (disabled)
	{
		fill = UiTheme::Inner();
		text = UiTheme::TextDisabled();
	}

	dc.FillSolidRect(rect, backdrop);
	// Fully rounded ends; FillRoundRect clamps the radius to the height.
	const int radius = rect.Height();
	UiTheme::FillRoundRect(dc.m_hDC, rect, radius, fill, CLR_NONE);

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
		CRect ring = rect;
		ring.DeflateRect(1, 1);
		UiTheme::FillRoundRect(dc.m_hDC, ring, radius, CLR_NONE,
			m_visualStyle == STYLE_PRIMARY || m_visualStyle == STYLE_PILL_ACTIVE ? RGB(255, 255, 255) : UiTheme::AccentText());
	}

	target.BitBlt(0, 0, clientRect.Width(), clientRect.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBuffer);
	target.Detach();
}

IMPLEMENT_DYNAMIC(CToggleButton, CButton)

BEGIN_MESSAGE_MAP(CToggleButton, CButton)
	ON_MESSAGE(BM_GETCHECK, OnGetCheck)
	ON_MESSAGE(BM_SETCHECK, OnSetCheck)
	ON_WM_GETDLGCODE()
	ON_CONTROL_REFLECT_EX(BN_CLICKED, OnClicked)
	ON_WM_LBUTTONDBLCLK()
	ON_WM_MOUSEMOVE()
	ON_MESSAGE(WM_MOUSELEAVE, OnMouseLeave)
	ON_WM_TIMER()
END_MESSAGE_MAP()

CToggleButton::CToggleButton()
	: m_radio(FALSE), m_automatic(TRUE), m_autoDelete(FALSE), m_check(BST_UNCHECKED), m_hot(FALSE)
	, m_knob(0), m_animStart(0)
{
}

void CToggleButton::OnTimer(UINT_PTR timer)
{
	if (timer != UiTheme::kToggleAnimationTimer)
	{
		CButton::OnTimer(timer);
		return;
	}
	const float target = m_check == BST_CHECKED ? 1.0f : 0.0f;
	const float progress = min(1.0f, static_cast<float>(GetTickCount() - m_animStart) / UiTheme::kToggleAnimationMs);
	// Ease out: quick start, gentle stop.
	const float eased = 1.0f - (1.0f - progress) * (1.0f - progress);
	m_knob = target > 0.5f ? eased : 1.0f - eased;
	if (progress >= 1.0f)
	{
		m_knob = target;
		KillTimer(UiTheme::kToggleAnimationTimer);
	}
	Invalidate(FALSE);
}

void CToggleButton::PreSubclassWindow()
{
	const DWORD type = GetStyle() & BS_TYPEMASK;
	m_radio = type == BS_RADIOBUTTON || type == BS_AUTORADIOBUTTON;
	m_automatic = type == BS_AUTOCHECKBOX || type == BS_AUTORADIOBUTTON;
	// Not subclassed yet, so this still reaches the native button's state.
	m_check = static_cast<int>(::SendMessage(m_hWnd, BM_GETCHECK, 0, 0));
	m_knob = m_check == BST_CHECKED ? 1.0f : 0.0f;
	ModifyStyle(BS_TYPEMASK, BS_OWNERDRAW);
	CButton::PreSubclassWindow();
}

void CToggleButton::PostNcDestroy()
{
	CButton::PostNcDestroy();
	if (m_autoDelete) delete this;
}

LRESULT CToggleButton::OnGetCheck(WPARAM, LPARAM)
{
	return m_check;
}

LRESULT CToggleButton::OnSetCheck(WPARAM state, LPARAM)
{
	if (m_check != static_cast<int>(state))
	{
		m_check = static_cast<int>(state);
		if (!m_radio && IsWindowVisible())
		{
			m_animStart = GetTickCount();
			SetTimer(UiTheme::kToggleAnimationTimer, 15, NULL);
		}
		else
		{
			m_knob = m_check == BST_CHECKED ? 1.0f : 0.0f;
		}
		Invalidate(FALSE);
	}
	return 0;
}

UINT CToggleButton::OnGetDlgCode()
{
	return DLGC_BUTTON | (m_radio ? DLGC_RADIOBUTTON : 0);
}

BOOL CToggleButton::OnClicked()
{
	if (m_automatic)
	{
		if (m_radio)
		{
			CWnd* parent = GetParent();
			for (HWND other = ::GetNextDlgGroupItem(parent->m_hWnd, m_hWnd, TRUE);
				other && other != m_hWnd; other = ::GetNextDlgGroupItem(parent->m_hWnd, other, TRUE))
			{
				if (::SendMessage(other, WM_GETDLGCODE, 0, 0) & DLGC_RADIOBUTTON)
					::SendMessage(other, BM_SETCHECK, BST_UNCHECKED, 0);
			}
			SetCheck(BST_CHECKED);
		}
		else
		{
			SetCheck(m_check == BST_CHECKED ? BST_UNCHECKED : BST_CHECKED);
		}
	}
	return FALSE; // the parent still receives BN_CLICKED
}

void CToggleButton::OnLButtonDblClk(UINT flags, CPoint point)
{
	// A quick second click should toggle again, not turn into BN_DOUBLECLICKED.
	SendMessage(WM_LBUTTONDOWN, flags, MAKELPARAM(point.x, point.y));
}

void CToggleButton::OnMouseMove(UINT flags, CPoint point)
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

LRESULT CToggleButton::OnMouseLeave(WPARAM, LPARAM)
{
	m_hot = FALSE;
	Invalidate(FALSE);
	return 0;
}

void CToggleButton::DrawItem(LPDRAWITEMSTRUCT info)
{
	CDC target;
	target.Attach(info->hDC);
	CRect rect;
	GetClientRect(&rect);
	CDC dc;
	CBitmap buffer;
	dc.CreateCompatibleDC(&target);
	buffer.CreateCompatibleBitmap(&target, max(1, rect.Width()), max(1, rect.Height()));
	CBitmap* oldBuffer = dc.SelectObject(&buffer);
	const COLORREF backdrop = UiTheme::BackdropFor(this);
	dc.FillSolidRect(rect, backdrop);

	const BOOL disabled = (info->itemState & ODS_DISABLED) != 0;
	const BOOL checked = m_check == BST_CHECKED;
	const BOOL focused = (info->itemState & ODS_FOCUS) && !(info->itemState & ODS_NOFOCUSRECT);
	CString caption;
	GetWindowText(caption);
	dc.SetBkMode(TRANSPARENT);
	CFont* font = GetFont();
	CFont* oldFont = font ? dc.SelectObject(font) : NULL;

	if (m_radio)
	{
		const COLORREF fill = checked ? (disabled ? UiTheme::Border() : UiTheme::Accent())
			: (m_hot && !disabled ? UiTheme::Hover() : UiTheme::Inner());
		UiTheme::FillRoundRect(dc.m_hDC, rect, rect.Height(), fill, CLR_NONE);
		dc.SetTextColor(checked ? RGB(255, 255, 255) : (disabled ? UiTheme::TextDisabled() : UiTheme::TextSecondary()));
		dc.DrawText(caption, rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
		if (focused)
		{
			CRect ring = rect;
			ring.DeflateRect(1, 1);
			UiTheme::FillRoundRect(dc.m_hDC, ring, ring.Height(), CLR_NONE, checked ? RGB(255, 255, 255) : UiTheme::AccentText());
		}
	}
	else
	{
		const int trackHeight = UiTheme::ScaleForWindow(m_hWnd, 18);
		const int trackWidth = UiTheme::ScaleForWindow(m_hWnd, 32);
		const int knob = trackHeight - UiTheme::ScaleForWindow(m_hWnd, 6);
		const int inset = (trackHeight - knob) / 2;
		const int top = rect.CenterPoint().y - trackHeight / 2;
		CRect track(rect.left, top, rect.left + trackWidth, top + trackHeight);
		const COLORREF on = disabled ? UiTheme::Border() : UiTheme::Accent();
		const COLORREF off = disabled ? UiTheme::Inner() : UiTheme::Border();
		auto mix = [this](COLORREF a, COLORREF b) {
			return RGB(GetRValue(a) + (GetRValue(b) - GetRValue(a)) * m_knob,
				GetGValue(a) + (GetGValue(b) - GetGValue(a)) * m_knob,
				GetBValue(a) + (GetBValue(b) - GetBValue(a)) * m_knob);
		};
		UiTheme::FillRoundRect(dc.m_hDC, track, trackHeight, mix(off, on), CLR_NONE);
		const int travel = track.Width() - inset * 2 - knob;
		const int knobLeft = track.left + inset + static_cast<int>(travel * m_knob + 0.5f);
		UiTheme::FillRoundRect(dc.m_hDC, CRect(knobLeft, top + inset, knobLeft + knob, top + inset + knob), knob,
			disabled ? UiTheme::TextDisabled() : RGB(255, 255, 255), CLR_NONE);
		if (focused)
			UiTheme::FillRoundRect(dc.m_hDC, track, trackHeight, CLR_NONE, UiTheme::AccentText());
		CRect label = rect;
		label.left = track.right + UiTheme::ScaleForWindow(m_hWnd, 8);
		dc.SetTextColor(disabled ? UiTheme::TextDisabled() : UiTheme::TextPrimary());
		dc.DrawText(caption, label, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
	}
	if (oldFont) dc.SelectObject(oldFont);
	target.BitBlt(0, 0, rect.Width(), rect.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBuffer);
	target.Detach();
}

IMPLEMENT_DYNAMIC(CStatusLabel, CStatic)

CStatusLabel::CStatusLabel()
	: m_tone(TONE_NEUTRAL),
	m_backdrop(CLR_NONE),
	m_twoLine(FALSE), m_compact(FALSE)
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

void CStatusLabel::SetTwoLineStatus(LPCTSTR primaryText, LPCTSTR secondaryText, Tone tone, BOOL compact)
{
	if (m_twoLine && m_primaryText == primaryText && m_secondaryText == secondaryText && m_tone == tone && m_compact == compact) return;
	m_compact = compact;
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

void CStatusLabel::SetDetailText(const CString& text)
{
	if (m_detailText == text) return;
	m_detailText = text;
	UpdateOverflowTooltip();
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

	if (!m_detailText.IsEmpty())
	{
		fullText = m_detailText;
		if (!m_uploadText.IsEmpty()) fullText += L"\r\n" + m_uploadText + L"\r\n" + m_downloadText;
		truncated = TRUE;
	}
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
	const COLORREF backdrop = m_backdrop != CLR_NONE ? m_backdrop : UiTheme::BackdropFor(this);
	// Cover the whole client area, not only rcItem, so no part keeps the dialog brush.
	target.FillSolidRect(clientRect, backdrop);
	CRect rect(0, 0, clientRect.Width(), clientRect.Height());
	CDC dc;
	CBitmap buffer;
	dc.CreateCompatibleDC(&target);
	buffer.CreateCompatibleBitmap(&target, max(1, rect.Width()), max(1, rect.Height()));
	CBitmap* oldBuffer = dc.SelectObject(&buffer);
	COLORREF fill = UiTheme::Inner();
	COLORREF text = UiTheme::TextSecondary();

	if (m_tone == TONE_INFO)
	{
		fill = UiTheme::AccentSoft();
		text = UiTheme::AccentText();
	}
	else if (m_tone == TONE_WARNING)
	{
		fill = UiTheme::WarningSoft();
		text = UiTheme::Warning();
	}
	else if (m_tone == TONE_SUCCESS)
	{
		fill = UiTheme::SuccessSoft();
		text = UiTheme::Success();
	}
	else if (m_tone == TONE_DANGER)
	{
		fill = UiTheme::DangerSoft();
		text = UiTheme::Danger();
	}

	dc.FillSolidRect(rect, backdrop);
	UiTheme::FillRoundRect(dc.m_hDC, rect, UiTheme::ScaleForWindow(m_hWnd, 10), fill, CLR_NONE);
	CPen* oldPen = NULL;
	CBrush* oldBrush = NULL;

	dc.SetBkMode(TRANSPARENT);
	CFont* font = GetFont();
	CFont* oldFont = font ? dc.SelectObject(font) : NULL;

	if (m_twoLine)
	{
		const int horizontalPadding = UiTheme::ScaleForWindow(m_hWnd, 9);
		const int verticalPadding = UiTheme::ScaleForWindow(m_hWnd, 5);
		const int primaryHeight = UiTheme::ScaleForWindow(m_hWnd, m_compact ? 18 : 22);
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
		if (!m_detailFont.GetSafeHandle()) UiTheme::CreateUiFont(m_detailFont, m_hWnd, 10, FW_NORMAL);
		CFont* primaryFont = dc.SelectObject(&m_detailFont);
		dc.SetTextColor(UiTheme::TextSecondary());
		dc.DrawText(m_secondaryText, secondaryRect,
			DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
		dc.SelectObject(primaryFont);
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
	ON_MESSAGE(UiTheme::WM_CARD_SEND_TO_BACK, OnSendToBack)
END_MESSAGE_MAP()

void CCardFrame::PreSubclassWindow()
{
	// Behind every sibling and clipped by them, so it never paints over a control.
	ModifyStyle(0x0000000F, BS_OWNERDRAW | WS_CLIPSIBLINGS);
	CButton::PreSubclassWindow();
	PostMessage(UiTheme::WM_CARD_SEND_TO_BACK);
}

LRESULT CCardFrame::OnSendToBack(WPARAM, LPARAM)
{
	SetWindowPos(&wndBottom, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
	return 0;
}

void CCardFrame::PostNcDestroy()
{
	CButton::PostNcDestroy();
	if (m_autoDelete) delete this;
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

	// The parent clips its children, so the card fills its own rectangle.
	CRect full;
	GetClientRect(&full);
	dc.FillSolidRect(full, UiTheme::PageBackground());
	UiTheme::FillRoundRect(dc.m_hDC, full, UiTheme::ScaleForWindow(m_hWnd, 14), UiTheme::Surface(), CLR_NONE);
	CString caption;
	GetWindowText(caption);
	if (!caption.IsEmpty())
	{
		LOGFONT logFont = { 0 };
		CFont* font = GetFont();
		if (font) font->GetLogFont(&logFont);
		logFont.lfWeight = FW_BOLD;
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

IMPLEMENT_DYNAMIC(CSoftTab, CTabCtrl)

BEGIN_MESSAGE_MAP(CSoftTab, CTabCtrl)
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_SIZE()
END_MESSAGE_MAP()

void CSoftTab::PreSubclassWindow()
{
	// Fixed widths keep the native scroll arrows from ever appearing.
	ModifyStyle(0, TCS_FIXEDWIDTH);
	CTabCtrl::PreSubclassWindow();
	SetPadding(CSize(0, 0));
	SetMinTabWidth(0);
}

BOOL CSoftTab::OnEraseBkgnd(CDC*)
{
	return TRUE;
}

void CSoftTab::OnSize(UINT type, int cx, int cy)
{
	CTabCtrl::OnSize(type, cx, cy);
	const int count = max(1, GetItemCount());
	SetItemSize(CSize(min(UiTheme::ScaleForWindow(m_hWnd, 96), max(1, cx / count - 2)), max(1, cy - 2)));
	if (CWnd* arrows = GetWindow(GW_CHILD))
		arrows->ShowWindow(SW_HIDE);
}

void CSoftTab::OnPaint()
{
	CPaintDC paint(this);
	CRect client;
	GetClientRect(&client);
	if (client.IsRectEmpty()) return;
	CDC dc;
	CBitmap buffer;
	dc.CreateCompatibleDC(&paint);
	buffer.CreateCompatibleBitmap(&paint, client.Width(), client.Height());
	CBitmap* oldBuffer = dc.SelectObject(&buffer);
	dc.FillSolidRect(client, UiTheme::BackdropFor(this));
	dc.SetBkMode(TRANSPARENT);
	CFont* font = GetFont();
	CFont* oldFont = font ? dc.SelectObject(font) : NULL;
	const int selected = GetCurSel();
	const int gap = UiTheme::ScaleForWindow(m_hWnd, 2);
	for (int i = 0; i < GetItemCount(); ++i)
	{
		CRect item;
		if (!GetItemRect(i, &item)) continue;
		item.DeflateRect(gap, 0);
		item.top = client.top;
		item.bottom = client.bottom;
		UiTheme::FillRoundRect(dc.m_hDC, item, item.Height(), i == selected ? UiTheme::Accent() : UiTheme::Inner(), CLR_NONE);
		TCHAR text[64] = { 0 };
		TCITEM info = { 0 };
		info.mask = TCIF_TEXT;
		info.pszText = text;
		info.cchTextMax = _countof(text);
		GetItem(i, &info);
		dc.SetTextColor(i == selected ? RGB(255, 255, 255) : UiTheme::TextSecondary());
		dc.DrawText(text, item, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
	}
	if (oldFont) dc.SelectObject(oldFont);
	paint.BitBlt(0, 0, client.Width(), client.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBuffer);
}

IMPLEMENT_DYNAMIC(CSoftHeader, CHeaderCtrl)

BEGIN_MESSAGE_MAP(CSoftHeader, CHeaderCtrl)
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
END_MESSAGE_MAP()

void CSoftHeader::PostNcDestroy()
{
	CHeaderCtrl::PostNcDestroy();
	delete this;
}

BOOL CSoftHeader::OnEraseBkgnd(CDC*)
{
	return TRUE;
}

void CSoftHeader::OnPaint()
{
	CPaintDC paint(this);
	CRect client;
	GetClientRect(&client);
	if (client.IsRectEmpty()) return;
	CDC dc;
	CBitmap buffer;
	dc.CreateCompatibleDC(&paint);
	buffer.CreateCompatibleBitmap(&paint, client.Width(), client.Height());
	CBitmap* oldBuffer = dc.SelectObject(&buffer);
	dc.FillSolidRect(client, UiTheme::Inner());
	dc.SetBkMode(TRANSPARENT);
	CFont* font = GetParent() ? GetParent()->GetFont() : GetFont();
	CFont* oldFont = font ? dc.SelectObject(font) : NULL;
	dc.SetTextColor(UiTheme::TextSecondary());
	const int pad = UiTheme::ScaleForWindow(m_hWnd, 8);
	for (int i = 0; i < GetItemCount(); ++i)
	{
		CRect item;
		if (!GetItemRect(i, &item)) continue;
		TCHAR text[128] = { 0 };
		HDITEM info = { 0 };
		info.mask = HDI_TEXT | HDI_FORMAT;
		info.pszText = text;
		info.cchTextMax = _countof(text);
		GetItem(i, &info);
		CRect label = item;
		label.DeflateRect(pad, 0);
		const BOOL sorted = (info.fmt & (HDF_SORTUP | HDF_SORTDOWN)) != 0;
		if (sorted) label.right -= UiTheme::ScaleForWindow(m_hWnd, 14);
		dc.DrawText(text, label, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
		if (sorted)
		{
			const int size = UiTheme::ScaleForWindow(m_hWnd, 10);
			CRect arrow(item.right - pad - size, item.CenterPoint().y - size / 2, item.right - pad, item.CenterPoint().y - size / 2 + size);
			UiTheme::DrawGlyph(dc.m_hDC, (info.fmt & HDF_SORTUP) ? UiTheme::GLYPH_CHEVRON_UP : UiTheme::GLYPH_CHEVRON_DOWN, arrow, UiTheme::TextSecondary(), 1.4f);
		}
		dc.FillSolidRect(item.right - 1, item.top + item.Height() / 4, 1, item.Height() / 2, UiTheme::Border());
	}
	if (oldFont) dc.SelectObject(oldFont);
	paint.BitBlt(0, 0, client.Width(), client.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBuffer);
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

void CSoftEdit::PostNcDestroy()
{
	CEdit::PostNcDestroy();
	if (m_autoDelete) delete this;
}

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
	dc.FillSolidRect(window, UiTheme::BackdropFor(this));
	const BOOL focused = ::GetFocus() == m_hWnd;
	UiTheme::FillRoundRect(dc.m_hDC, window, UiTheme::ScaleForWindow(m_hWnd, 8),
		UiTheme::Inner(), focused ? UiTheme::Accent() : CLR_NONE);
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
	const COLORREF border = enabled && (focused || dropped) ? UiTheme::Accent() : CLR_NONE;

	dc.FillSolidRect(client, UiTheme::BackdropFor(this));
	UiTheme::FillRoundRect(dc.m_hDC, client, UiTheme::ScaleForWindow(m_hWnd, 8),
		m_hot && enabled ? UiTheme::Hover() : UiTheme::Inner(), border);

	// Arrow.
	// Kept inside the native button area so the edit child of an editable combo never covers it.
	const int arrow = UiTheme::ScaleForWindow(m_hWnd, 10);
	CRect arrowRect(client.right - UiTheme::ScaleForWindow(m_hWnd, 8) - arrow, client.CenterPoint().y - arrow / 2,
		client.right - UiTheme::ScaleForWindow(m_hWnd, 8), client.CenterPoint().y - arrow / 2 + arrow);
	UiTheme::DrawGlyph(dc.m_hDC, dropped ? UiTheme::GLYPH_CHEVRON_UP : UiTheme::GLYPH_CHEVRON_DOWN, arrowRect,
		enabled ? UiTheme::TextSecondary() : UiTheme::TextDisabled(), max(1.4f, UiTheme::ScaleForWindow(m_hWnd, 3) / 2.0f));

	// Selected text (editable combos show it in their own edit child).
	if ((GetStyle() & 0x3) == CBS_DROPDOWNLIST)
	{
		CString text;
		const int selection = GetCurSel();
		if (selection != CB_ERR) GetLBText(selection, text);
		CFont* font = GetFont();
		CFont* oldFont = font ? dc.SelectObject(font) : NULL;
		dc.SetBkMode(TRANSPARENT);
		dc.SetTextColor(enabled ? UiTheme::TextPrimary() : UiTheme::TextDisabled());
		CRect textRect(client.left + UiTheme::ScaleForWindow(m_hWnd, 10), client.top,
			arrowRect.left - UiTheme::ScaleForWindow(m_hWnd, 6), client.bottom);
		dc.DrawText(text, textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
		if (oldFont) dc.SelectObject(oldFont);
	}

	paint.BitBlt(0, 0, client.Width(), client.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBuffer);
}
