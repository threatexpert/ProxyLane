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

	void DrawRemoveBadge(HDC dc, const CRect& rect, BOOL pressed)
	{
		if (!dc || rect.Width() < 8 || rect.Height() < 8) return;
		EnsureGdiplus();
		Gdiplus::Graphics graphics(dc);
		graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
		graphics.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);
		const Gdiplus::REAL size = static_cast<Gdiplus::REAL>(min(rect.Width(), rect.Height()));
		const Gdiplus::REAL x = rect.left + (rect.Width() - size) / 2, y = rect.top + (rect.Height() - size) / 2;
		const Gdiplus::REAL ring = max(1.5f, size / 10.0f);
		// Soft shadow lifts the badge off the tile border it overlaps.
		Gdiplus::SolidBrush shadow(Gdiplus::Color(40, 15, 23, 42));
		graphics.FillEllipse(&shadow, x, y + ring * 0.6f, size, size);
		Gdiplus::SolidBrush white(Gdiplus::Color(255, 255, 255, 255));
		graphics.FillEllipse(&white, x, y, size, size);
		Gdiplus::SolidBrush disc(pressed ? Gdiplus::Color(255, 185, 28, 28) : ToColor(Danger()));
		graphics.FillEllipse(&disc, x + ring, y + ring, size - ring * 2, size - ring * 2);
		const Gdiplus::REAL arm = size * 0.17f, cx = x + size / 2, cy = y + size / 2;
		Gdiplus::Pen cross(Gdiplus::Color(255, 255, 255, 255), max(1.5f, size / 9.0f));
		cross.SetStartCap(Gdiplus::LineCapRound);
		cross.SetEndCap(Gdiplus::LineCapRound);
		graphics.DrawLine(&cross, cx - arm, cy - arm, cx + arm, cy + arm);
		graphics.DrawLine(&cross, cx + arm, cy - arm, cx - arm, cy + arm);
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
		}
	}

	int WindowDpi(HWND hWnd)
	{
		// Resolved at run time: the XP-compatible SDK has no declaration and
		// older systems have no export.
		typedef UINT(WINAPI* GetDpiForWindowFn)(HWND);
		static const GetDpiForWindowFn getDpiForWindow = reinterpret_cast<GetDpiForWindowFn>(
			::GetProcAddress(::GetModuleHandle(_T("user32.dll")), "GetDpiForWindow"));
		if (getDpiForWindow && hWnd)
		{
			const UINT dpi = getDpiForWindow(hWnd);
			if (dpi)
				return static_cast<int>(dpi);
		}

		HDC dc = ::GetDC(hWnd);
		int dpi = dc ? ::GetDeviceCaps(dc, LOGPIXELSX) : 96;
		if (dc)
			::ReleaseDC(hWnd, dc);
		return dpi;
	}

	int ScaleForWindow(HWND hWnd, int value)
	{
		return MulDiv(value, WindowDpi(hWnd), 96);
	}

	namespace
	{
		int CALLBACK MarkFontFound(const LOGFONT*, const TEXTMETRIC*, DWORD, LPARAM found)
		{
			*reinterpret_cast<BOOL*>(found) = TRUE;
			return 0;
		}

		BOOL IsFontInstalled(LPCTSTR faceName)
		{
			LOGFONT query = { 0 };
			query.lfCharSet = DEFAULT_CHARSET;
			_tcsncpy_s(query.lfFaceName, faceName, _TRUNCATE);
			BOOL found = FALSE;
			HDC dc = ::GetDC(NULL);
			if (dc)
			{
				::EnumFontFamiliesEx(dc, &query, MarkFontFound, reinterpret_cast<LPARAM>(&found), 0);
				::ReleaseDC(NULL, dc);
			}
			return found;
		}

		// Segoe UI has no CJK glyphs, so GDI font linking fills them from the first
		// linked font that has them. On systems whose link chain lists Meiryo UI first,
		// Chinese text comes out with Japanese glyph forms, so name a Chinese face.
		LPCTSTR DefaultFaceName()
		{
			if (Localization::CurrentLanguage().CompareNoCase(_T("zh-CN")) != 0)
				return _T("Segoe UI");

			static LPCTSTR chineseFace = NULL;
			if (!chineseFace)
			{
				static const LPCTSTR candidates[] = {
					_T("Microsoft YaHei UI"), _T("Microsoft YaHei"), _T("SimSun") };
				chineseFace = candidates[_countof(candidates) - 1];
				for (int i = 0; i < _countof(candidates); ++i)
				{
					if (IsFontInstalled(candidates[i]))
					{
						chineseFace = candidates[i];
						break;
					}
				}
			}
			return chineseFace;
		}

		struct UiFontRecord
		{
			CFont* font;
			HWND owner;
			int pointSize;
			int weight;
			CString faceName;
		};

		std::vector<UiFontRecord>& UiFontRecords()
		{
			static std::vector<UiFontRecord> records;
			return records;
		}

		BOOL IsWithin(HWND root, HWND hWnd)
		{
			return hWnd == root || ::IsChild(root, hWnd);
		}

		HFONT MakeUiFont(const UiFontRecord& record)
		{
			return ::CreateFont(
				-MulDiv(record.pointSize, WindowDpi(record.owner), 72), 0, 0, 0, record.weight,
				FALSE, FALSE, FALSE, DEFAULT_CHARSET,
				OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
				DEFAULT_PITCH | FF_DONTCARE, record.faceName);
		}

		struct FontSwap
		{
			HFONT oldFont;
			HFONT newFont;
		};

		void SwapWindowFont(HWND hWnd, const std::vector<FontSwap>& swaps)
		{
			const HFONT current = reinterpret_cast<HFONT>(::SendMessage(hWnd, WM_GETFONT, 0, 0));
			if (!current)
				return;
			for (size_t i = 0; i < swaps.size(); ++i)
			{
				if (swaps[i].oldFont == current)
				{
					::SendMessage(hWnd, WM_SETFONT, reinterpret_cast<WPARAM>(swaps[i].newFont), FALSE);
					return;
				}
			}
		}

		BOOL CALLBACK SwapChildFont(HWND child, LPARAM swaps)
		{
			SwapWindowFont(child, *reinterpret_cast<const std::vector<FontSwap>*>(swaps));
			return TRUE;
		}
	}

	BOOL CreateUiFont(CFont& font, HWND hWnd, int pointSize, int weight, LPCTSTR faceName)
	{
		if (font.GetSafeHandle())
			font.DeleteObject();

		UiFontRecord spec = { &font, hWnd, pointSize, weight, faceName ? faceName : DefaultFaceName() };
		std::vector<UiFontRecord>& records = UiFontRecords();
		size_t index = 0;
		while (index < records.size() && records[index].font != &font)
			++index;
		if (index == records.size())
			records.push_back(spec);
		else
			records[index] = spec;

		return font.Attach(MakeUiFont(spec));
	}

	void RescaleUiFonts(HWND root)
	{
		std::vector<FontSwap> swaps;
		std::vector<UiFontRecord>& records = UiFontRecords();
		for (size_t i = 0; i < records.size(); ++i)
		{
			UiFontRecord& record = records[i];
			if (!::IsWindow(record.owner) || !IsWithin(root, record.owner) || !record.font->GetSafeHandle())
				continue;
			const HFONT newFont = MakeUiFont(record);
			if (!newFont)
				continue;
			FontSwap swap = { static_cast<HFONT>(record.font->Detach()), newFont };
			record.font->Attach(newFont);
			swaps.push_back(swap);
		}
		if (swaps.empty())
			return;

		// Controls keep the HFONT they were given, so hand each one its replacement
		// before the old fonts are deleted.
		SwapWindowFont(root, swaps);
		::EnumChildWindows(root, SwapChildFont, reinterpret_cast<LPARAM>(&swaps));
		for (size_t i = 0; i < swaps.size(); ++i)
			::DeleteObject(swaps[i].oldFont);
	}

	void ForgetUiFonts(HWND root)
	{
		std::vector<UiFontRecord>& records = UiFontRecords();
		for (size_t i = records.size(); i-- > 0;)
		{
			if (!::IsWindow(records[i].owner) || IsWithin(root, records[i].owner))
				records.erase(records.begin() + i);
		}
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
	, m_dpi(96)
{
}

CModernDialog::~CModernDialog()
{
}

BOOL CModernDialog::OnInitDialog()
{
	CDialog::OnInitDialog();

	m_dpi = UiTheme::WindowDpi(m_hWnd);
	// Per-monitor v2 would otherwise rescale template dialogs on its own and fight
	// the pixel layouts below; OnDpiChanged does the whole job instead.
	typedef BOOL(WINAPI* SetDialogDpiChangeBehaviorFn)(HWND, int, int);
	static const SetDialogDpiChangeBehaviorFn setDialogDpiChangeBehavior =
		reinterpret_cast<SetDialogDpiChangeBehaviorFn>(::GetProcAddress(
			::GetModuleHandle(_T("user32.dll")), "SetDialogDpiChangeBehavior"));
	const int DDC_DISABLE_ALL = 0x0001;
	if (setDialogDpiChangeBehavior)
		setDialogDpiChangeBehavior(m_hWnd, DDC_DISABLE_ALL, DDC_DISABLE_ALL);

	m_backgroundBrush.DeleteObject();
	m_backgroundBrush.CreateSolidBrush(UiTheme::PageBackground());
	m_fieldBrush.CreateSolidBrush(RGB(255, 255, 255));
	m_disabledFieldBrush.CreateSolidBrush(UiTheme::Surface());
	UiTheme::CreateUiFont(m_uiFont, m_hWnd, 9, FW_NORMAL);
	UiTheme::CreateUiFont(m_titleFont, m_hWnd, 16, FW_SEMIBOLD);
	SetFont(&m_uiFont, FALSE);
	UiTheme::ApplyFontToChildren(this, &m_uiFont);
	Localization::ApplyDialog(this, m_templateId);

	// Resource-only fields/checks in secondary dialogs use the same controls as
	// the main pages. DDX-bound and dynamically created controls own their wrappers.
	for (HWND child = ::GetWindow(m_hWnd, GW_CHILD); child; child = ::GetWindow(child, GW_HWNDNEXT))
	{
		CWnd* control = CWnd::FromHandlePermanent(child);
		if (!control)
		{
			TCHAR name[32] = {};
			::GetClassName(child, name, _countof(name));
			if (_tcsicmp(name, _T("Edit")) == 0)
			{
				CSoftEdit* field = new CSoftEdit;
				field->m_autoDelete = true;
				if (!field->SubclassWindow(child)) delete field;
			}
			else if (_tcsicmp(name, _T("Button")) == 0)
			{
				const DWORD type = ::GetWindowLong(child, GWL_STYLE) & BS_TYPEMASK;
				if (type == BS_CHECKBOX || type == BS_AUTOCHECKBOX || type == BS_RADIOBUTTON || type == BS_AUTORADIOBUTTON)
				{
					CToggleButton* toggle = new CToggleButton;
					toggle->m_autoDelete = TRUE;
					if (!toggle->SubclassWindow(child)) delete toggle;
				}
			}
			control = CWnd::FromHandlePermanent(child);
		}
		// Localized labels contain a literal "&" (e.g. "Settings & About"); a static
		// without SS_NOPREFIX would treat it as a mnemonic and drop it.
		TCHAR className[32] = {};
		::GetClassName(child, className, _countof(className));
		const DWORD style = ::GetWindowLong(child, GWL_STYLE);
		const DWORD staticType = style & SS_TYPEMASK;
		if (_tcsicmp(className, _T("Static")) == 0
			&& (staticType <= SS_RIGHT || staticType == SS_SIMPLE || staticType == SS_LEFTNOWORDWRAP))
			::SetWindowLong(child, GWL_STYLE, style | SS_NOPREFIX);
		// Subclassing is now complete, so our non-client padding participates.
		if (control && control->IsKindOf(RUNTIME_CLASS(CSoftEdit)))
			control->SetWindowPos(NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
	}

	CWnd* title = GetDlgItem(IDC_STATIC_PAGE_TITLE);
	if (title)
		title->SetFont(&m_titleFont, FALSE);
	LayoutPageHeader();

	return TRUE;
}

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

BEGIN_MESSAGE_MAP(CModernDialog, CDialog)
	ON_WM_SIZE()
	ON_WM_ERASEBKGND()
	ON_WM_CTLCOLOR()
	ON_WM_DESTROY()
	ON_MESSAGE(WM_DPICHANGED, OnDpiChanged)
END_MESSAGE_MAP()

namespace
{
	struct DpiChange
	{
		HWND root;
		int oldDpi;
		int newDpi;
	};

	BOOL CALLBACK RefreshChildForDpi(HWND child, LPARAM param)
	{
		const DpiChange& change = *reinterpret_cast<const DpiChange*>(param);
		TCHAR className[32] = {};
		::GetClassName(child, className, _countof(className));

		// Controls placed only by the dialog template (secondary dialogs) keep their
		// pixel rectangles; scale them. Pages with their own layout re-place theirs.
		if (::GetParent(child) == change.root)
		{
			CRect rect;
			::GetWindowRect(child, &rect);
			::MapWindowPoints(NULL, change.root, reinterpret_cast<LPPOINT>(&rect), 2);
			::SetWindowPos(child, NULL,
				MulDiv(rect.left, change.newDpi, change.oldDpi), MulDiv(rect.top, change.newDpi, change.oldDpi),
				MulDiv(rect.Width(), change.newDpi, change.oldDpi), MulDiv(rect.Height(), change.newDpi, change.oldDpi),
				SWP_NOZORDER | SWP_NOACTIVATE);
		}

		if (_tcsicmp(className, WC_LISTVIEW) == 0)
		{
			const HWND header = reinterpret_cast<HWND>(::SendMessage(child, LVM_GETHEADER, 0, 0));
			const int columns = header ? static_cast<int>(::SendMessage(header, HDM_GETITEMCOUNT, 0, 0)) : 0;
			for (int column = 0; column < columns; ++column)
			{
				const int width = static_cast<int>(::SendMessage(child, LVM_GETCOLUMNWIDTH, column, 0));
				::SendMessage(child, LVM_SETCOLUMNWIDTH, column,
					MAKELPARAM(MulDiv(width, change.newDpi, change.oldDpi), 0));
			}
		}

		// Non-client padding (rounded edits) is computed from the window DPI.
		::SetWindowPos(child, NULL, 0, 0, 0, 0,
			SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
		return TRUE;
	}

	// Containers and embedded pages lay out on WM_SIZE; a move to the same pixel
	// size sends none, so give them one. Parents are visited before children.
	BOOL CALLBACK RelayoutChildForDpi(HWND child, LPARAM root)
	{
		TCHAR className[32] = {};
		::GetClassName(child, className, _countof(className));
		if (::GetParent(child) != reinterpret_cast<HWND>(root) && _tcscmp(className, _T("#32770")) != 0)
			return TRUE;
		CRect client;
		::GetClientRect(child, &client);
		::SendMessage(child, WM_SIZE, SIZE_RESTORED, MAKELPARAM(client.Width(), client.Height()));
		return TRUE;
	}
}

void CModernDialog::OnDestroy()
{
	UiTheme::ForgetUiFonts(m_hWnd);
	CDialog::OnDestroy();
}

LRESULT CModernDialog::OnDpiChanged(WPARAM wParam, LPARAM lParam)
{
	const int oldDpi = m_dpi;
	const int newDpi = LOWORD(wParam);
	if (newDpi <= 0 || oldDpi <= 0)
		return 0;
	m_dpi = newDpi;

	UiTheme::RescaleUiFonts(m_hWnd);
	if (newDpi != oldDpi)
	{
		DpiChange change = { m_hWnd, oldDpi, newDpi };
		::EnumChildWindows(m_hWnd, RefreshChildForDpi, reinterpret_cast<LPARAM>(&change));
	}

	const RECT* suggested = reinterpret_cast<const RECT*>(lParam);
	if (suggested)
		SetWindowPos(NULL, suggested->left, suggested->top,
			suggested->right - suggested->left, suggested->bottom - suggested->top,
			SWP_NOZORDER | SWP_NOACTIVATE);
	// The pixel size may not change, so run the layouts with the new metrics anyway.
	CRect client;
	GetClientRect(&client);
	SendMessage(WM_SIZE, SIZE_RESTORED, MAKELPARAM(client.Width(), client.Height()));
	::EnumChildWindows(m_hWnd, RelayoutChildForDpi, reinterpret_cast<LPARAM>(m_hWnd));
	RedrawWindow(NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
	return 0;
}

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
	if (wnd && wnd->IsKindOf(RUNTIME_CLASS(CSoftEdit)))
	{
		const BOOL enabled = wnd->IsWindowEnabled();
		dc->SetTextColor(enabled ? UiTheme::TextPrimary() : RGB(160, 166, 177));
		dc->SetBkColor(enabled ? RGB(255, 255, 255) : UiTheme::Surface());
		return (HBRUSH)(enabled ? m_fieldBrush.GetSafeHandle() : m_disabledFieldBrush.GetSafeHandle());
	}
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
	, m_icon(ICON_NONE)
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

void CModernButton::SetIcon(Icon icon)
{
	if (m_icon == icon) return;
	m_icon = icon;
	if (GetSafeHwnd()) Invalidate(FALSE);
}

int CModernButton::IconWidth() const
{
	// 14px icon plus a 6px gap before the caption.
	return m_icon == ICON_NONE ? 0 : UiTheme::ScaleForWindow(m_hWnd, 20);
}

namespace
{
	void DrawButtonIcon(HDC hdc, CModernButton::Icon icon, const CRect& box, COLORREF color, float stroke)
	{
		Gdiplus::Graphics graphics(hdc);
		graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
		Gdiplus::Pen pen(Gdiplus::Color(255, GetRValue(color), GetGValue(color), GetBValue(color)), stroke);
		pen.SetStartCap(Gdiplus::LineCapRound);
		pen.SetEndCap(Gdiplus::LineCapRound);
		pen.SetLineJoin(Gdiplus::LineJoinRound);
		const Gdiplus::REAL x = static_cast<Gdiplus::REAL>(box.left), y = static_cast<Gdiplus::REAL>(box.top);
		const Gdiplus::REAL w = static_cast<Gdiplus::REAL>(box.Width()), h = static_cast<Gdiplus::REAL>(box.Height());
		if (icon == CModernButton::ICON_POWER)
		{
			// Open ring with the gap at the top, and a stem through the gap.
			const Gdiplus::REAL inset = stroke / 2 + w * 0.06f;
			graphics.DrawArc(&pen, x + inset, y + inset + h * 0.04f, w - inset * 2, h - inset * 2, 300.0f, 300.0f);
			graphics.DrawLine(&pen, x + w / 2, y + stroke / 2, x + w / 2, y + h * 0.48f);
		}
		else if (icon == CModernButton::ICON_GAUGE)
		{
			// Speedometer traced from the supplied 1024-unit artwork: an arc open at
			// the bottom (centre 518,578, radius 350) and a needle from a hub at
			// 531,695 to 690,492. Its 150..890 horizontal extent fills the box.
			const Gdiplus::REAL unit = w / 740.0f;
			const Gdiplus::REAL ox = x - 150.0f * unit, oy = y + (h - 600.0f * unit) / 2 - 215.0f * unit;
			auto px = [&](Gdiplus::REAL v) { return ox + v * unit; };
			auto py = [&](Gdiplus::REAL v) { return oy + v * unit; };
			const Gdiplus::REAL radius = 350.0f * unit;
			graphics.DrawArc(&pen, px(518) - radius, py(578) - radius, radius * 2, radius * 2, 153.0f, 234.0f);
			graphics.DrawLine(&pen, px(531), py(695), px(690), py(492));
			Gdiplus::SolidBrush hub(Gdiplus::Color(255, GetRValue(color), GetGValue(color), GetBValue(color)));
			const Gdiplus::REAL hubRadius = max(stroke * 1.1f, 107.0f * unit);
			graphics.FillEllipse(&hub, px(531) - hubRadius, py(695) - hubRadius, hubRadius * 2, hubRadius * 2);
		}
	}
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

	if (m_visualStyle == STYLE_SOFT)
	{
		fill = pressed || m_hot ? RGB(219, 230, 253) : UiTheme::AccentSoft();
		border = pressed || m_hot ? UiTheme::Accent() : RGB(191, 209, 250);
		text = UiTheme::Accent();
	}

	if (m_visualStyle == STYLE_GHOST)
	{
		fill = pressed || m_hot ? UiTheme::AccentSoft() : m_backdrop;
		border = CLR_NONE;
		text = pressed || m_hot ? UiTheme::TextPrimary() : UiTheme::TextSecondary();
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
	UiTheme::FillRoundRect(dc.m_hDC, rect, m_visualStyle == STYLE_GHOST ? rect.Height() : UiTheme::ScaleForWindow(m_hWnd, 6), fill, border);
	dc.SelectObject(oldBrush);
	dc.SelectObject(oldPen);

	CString caption;
	GetWindowText(caption);
	dc.SetBkMode(TRANSPARENT);
	dc.SetTextColor(text);
	CFont* font = GetFont();
	CFont* oldFont = font ? dc.SelectObject(font) : NULL;
	CRect textRect = rect;
	if (m_icon != ICON_NONE)
	{
		// Centre icon and caption as one group.
		const int iconSize = UiTheme::ScaleForWindow(m_hWnd, 14);
		const int captionWidth = dc.GetTextExtent(caption).cx;
		const int groupLeft = max(rect.left + 2, rect.CenterPoint().x - (IconWidth() + captionWidth) / 2);
		const int iconTop = rect.top + (rect.Height() - iconSize) / 2;
		DrawButtonIcon(dc.m_hDC, m_icon, CRect(groupLeft, iconTop, groupLeft + iconSize, iconTop + iconSize), text,
			max(1.5f, UiTheme::ScaleForWindow(m_hWnd, 16) / 10.0f));
		textRect.left = groupLeft + IconWidth();
		dc.DrawText(caption, textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
	}
	else
		dc.DrawText(caption, textRect, DT_CENTER |
			DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
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

// Switch drawing and interaction adapted from lijing6006/ProxyLane PR #3.
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
	if (timer != 0x51)
	{
		CButton::OnTimer(timer);
		return;
	}
	const float target = m_check == BST_CHECKED ? 1.0f : 0.0f;
	const float progress = min(1.0f, static_cast<float>(GetTickCount() - m_animStart) / 140);
	// Ease out: quick start, gentle stop.
	const float eased = 1.0f - (1.0f - progress) * (1.0f - progress);
	m_knob = target > 0.5f ? eased : 1.0f - eased;
	if (progress >= 1.0f)
	{
		m_knob = target;
		KillTimer(0x51);
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
	if (m_radio)
		ModifyStyle(state == BST_CHECKED ? 0 : WS_TABSTOP, state == BST_CHECKED ? WS_TABSTOP : 0);
	if (m_check != static_cast<int>(state))
	{
		m_check = static_cast<int>(state);
		if (!m_radio && IsWindowVisible())
		{
			m_animStart = GetTickCount();
			SetTimer(0x51, 15, NULL);
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
	const COLORREF backdrop = UiTheme::PageBackground();
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
			: (m_hot && !disabled ? UiTheme::AccentSoft() : UiTheme::Surface());
		UiTheme::FillRoundRect(dc.m_hDC, rect, rect.Height(), fill, CLR_NONE);
		dc.SetTextColor(checked ? RGB(255, 255, 255) : (disabled ? RGB(160, 166, 177) : UiTheme::TextSecondary()));
		dc.DrawText(caption, rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
		if (focused)
		{
			CRect ring = rect;
			ring.DeflateRect(1, 1);
			UiTheme::FillRoundRect(dc.m_hDC, ring, ring.Height(), CLR_NONE, checked ? RGB(255, 255, 255) : UiTheme::Accent());
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
		const COLORREF off = disabled ? UiTheme::Surface() : UiTheme::Border();
		auto mix = [this](COLORREF a, COLORREF b) {
			return RGB(GetRValue(a) + (GetRValue(b) - GetRValue(a)) * m_knob,
				GetGValue(a) + (GetGValue(b) - GetGValue(a)) * m_knob,
				GetBValue(a) + (GetBValue(b) - GetBValue(a)) * m_knob);
		};
		UiTheme::FillRoundRect(dc.m_hDC, track, trackHeight, mix(off, on), CLR_NONE);
		const int travel = track.Width() - inset * 2 - knob;
		const int knobLeft = track.left + inset + static_cast<int>(travel * m_knob + 0.5f);
		UiTheme::FillRoundRect(dc.m_hDC, CRect(knobLeft, top + inset, knobLeft + knob, top + inset + knob), knob,
			disabled ? RGB(160, 166, 177) : RGB(255, 255, 255), CLR_NONE);
		if (focused)
			UiTheme::FillRoundRect(dc.m_hDC, track, trackHeight, CLR_NONE, UiTheme::Accent());
		CRect label = rect;
		label.left = track.right + UiTheme::ScaleForWindow(m_hWnd, 8);
		dc.SetTextColor(disabled ? RGB(160, 166, 177) : UiTheme::TextPrimary());
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
	m_backdrop(UiTheme::PageBackground()),
	m_twoLine(FALSE), m_compact(FALSE), m_inline(FALSE)
{
}

void CStatusLabel::SetInlineStyle(BOOL inlineStyle)
{
	m_inline = inlineStyle;
	if (GetSafeHwnd())
	{
		Invalidate(FALSE);
		UpdateOverflowTooltip();
	}
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
	SetWindowText(m_secondaryText + _T("\r\n\u2191 ") + m_uploadText + _T("\r\n\u2193 ") + m_downloadText);
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
			fullText += _T("\r\n\u2191 ") + m_uploadText + _T("\r\n\u2193 ") + m_downloadText;
		}
	}
	else
	{
		GetWindowText(fullText);
		const int horizontalPadding = UiTheme::ScaleForWindow(m_hWnd, 8);
		const int availableWidth = m_inline
			? max(0, client.Width() - UiTheme::ScaleForWindow(m_hWnd, 14))
			: max(0, client.Width() - UiTheme::ScaleForWindow(m_hWnd, 2) - horizontalPadding * 2);
		truncated = dc.GetTextExtent(fullText).cx > availableWidth;
	}

	if (oldFont)
		dc.SelectObject(oldFont);

	if (!m_detailText.IsEmpty())
	{
		fullText = m_detailText;
		if (!m_uploadText.IsEmpty()) fullText += L"\r\n\u2191 " + m_uploadText + L"\r\n\u2193 " + m_downloadText;
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

namespace
{
	Gdiplus::Color StatusColor(COLORREF color, BYTE alpha = 255)
	{
		return Gdiplus::Color(alpha, GetRValue(color), GetGValue(color), GetBValue(color));
	}

	// Status dot with a soft halo, centred in `box`.
	void DrawStatusDot(HDC hdc, const CRect& box, COLORREF color)
	{
		Gdiplus::Graphics graphics(hdc);
		graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
		const Gdiplus::REAL size = static_cast<Gdiplus::REAL>(min(box.Width(), box.Height()));
		const Gdiplus::REAL cx = box.left + box.Width() / 2.0f, cy = box.top + box.Height() / 2.0f;
		Gdiplus::SolidBrush halo(StatusColor(color, 48));
		graphics.FillEllipse(&halo, cx - size / 2, cy - size / 2, size, size);
		Gdiplus::SolidBrush dot(StatusColor(color));
		const Gdiplus::REAL inner = size * 0.5f;
		graphics.FillEllipse(&dot, cx - inner / 2, cy - inner / 2, inner, inner);
	}

	// Upload / download arrow: a stem and a chevron head.
	void DrawRateArrow(HDC hdc, const CRect& box, BOOL up, COLORREF color, float stroke)
	{
		Gdiplus::Graphics graphics(hdc);
		graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
		Gdiplus::Pen pen(StatusColor(color), stroke);
		pen.SetStartCap(Gdiplus::LineCapRound);
		pen.SetEndCap(Gdiplus::LineCapRound);
		pen.SetLineJoin(Gdiplus::LineJoinRound);
		const Gdiplus::REAL x = static_cast<Gdiplus::REAL>(box.left), y = static_cast<Gdiplus::REAL>(box.top);
		const Gdiplus::REAL w = static_cast<Gdiplus::REAL>(box.Width()), h = static_cast<Gdiplus::REAL>(box.Height());
		const Gdiplus::REAL cx = x + w / 2, tip = up ? y + stroke / 2 : y + h - stroke / 2, tail = up ? y + h - stroke / 2 : y + stroke / 2;
		const Gdiplus::REAL head = (up ? 1 : -1) * w * 0.42f;
		graphics.DrawLine(&pen, cx, tip, cx, tail);
		const Gdiplus::PointF chevron[] = { { cx - w * 0.42f, tip + head }, { cx, tip }, { cx + w * 0.42f, tip + head } };
		graphics.DrawLines(&pen, chevron, _countof(chevron));
	}
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
	const BOOL inlineStatus = m_inline && !m_twoLine;
	CPen* oldPen = NULL;
	CBrush* oldBrush = NULL;
	if (m_twoLine)
	{
		// Neutral (stopped) stays white; an active tone keeps its tinted card so
		// a running proxy stands out in the sidebar.
		rect.DeflateRect(1, 1);
		if (m_tone == TONE_NEUTRAL) { fill = RGB(255, 255, 255); border = UiTheme::BorderSoft(); }
		UiTheme::FillRoundRect(dc.m_hDC, rect, UiTheme::ScaleForWindow(m_hWnd, 10), fill, border);
	}
	else if (!inlineStatus)
	{
		rect.DeflateRect(1, 1);
		UiTheme::FillRoundRect(dc.m_hDC, rect, UiTheme::ScaleForWindow(m_hWnd, 9), fill, border);
	}

	dc.SetBkMode(TRANSPARENT);
	CFont* font = GetFont();
	CFont* oldFont = font ? dc.SelectObject(font) : NULL;

	if (m_twoLine)
	{
		// Header: status dot and title; below it the profile name, aligned with
		// the title. When rates are present, a divider and two label/value rows.
		auto S = [this](int value) { return UiTheme::ScaleForWindow(m_hWnd, value); };
		CRect inner(rect);
		inner.DeflateRect(S(12), S(9));
		const int titleHeight = S(20), lineHeight = S(18), dotSize = S(12);
		const COLORREF title = m_tone == TONE_NEUTRAL ? UiTheme::TextSecondary() : text;
		const COLORREF dot = m_tone == TONE_NEUTRAL ? RGB(160, 166, 177) : text;
		const int textLeft = inner.left + dotSize + S(6);

		CRect titleRect(textLeft, inner.top, inner.right, inner.top + titleHeight);
		DrawStatusDot(dc.m_hDC, CRect(inner.left, titleRect.CenterPoint().y - dotSize / 2,
			inner.left + dotSize, titleRect.CenterPoint().y - dotSize / 2 + dotSize), dot);
		dc.SetTextColor(title);
		dc.DrawText(m_primaryText, titleRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);

		if (!m_detailFont.GetSafeHandle()) UiTheme::CreateUiFont(m_detailFont, m_hWnd, 9, FW_NORMAL);
		CFont* titleFont = dc.SelectObject(&m_detailFont);
		CRect profileRect(textLeft, titleRect.bottom, inner.right, titleRect.bottom + lineHeight);
		dc.SetTextColor(UiTheme::TextPrimary());
		dc.DrawText(m_secondaryText, profileRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);

		if (!m_uploadText.IsEmpty())
		{
			const int dividerY = profileRect.bottom + S(7);
			dc.FillSolidRect(inner.left, dividerY, inner.Width(), 1, border);
			const int arrowSize = S(10);
			const float stroke = max(1.3f, S(14) / 10.0f);
			CRect row(inner.left, dividerY + S(7), inner.right, dividerY + S(7) + lineHeight);
			for (int i = 0; i < 2; ++i)
			{
				const BOOL up = i == 0;
				const int arrowTop = row.CenterPoint().y - arrowSize / 2;
				DrawRateArrow(dc.m_hDC, CRect(row.left + S(1), arrowTop, row.left + S(1) + arrowSize, arrowTop + arrowSize),
					up, up ? UiTheme::Accent() : UiTheme::Success(), stroke);
				CRect label(row.left + arrowSize + S(7), row.top, row.right, row.bottom);
				dc.SetTextColor(UiTheme::TextSecondary());
				dc.DrawText(Localization::Get(up ? L"status.upload" : L"status.download"), label,
					DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
				dc.SetTextColor(UiTheme::TextPrimary());
				dc.DrawText(up ? m_uploadText : m_downloadText, row,
					DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
				row.OffsetRect(0, lineHeight + S(2));
			}
		}
		dc.SelectObject(titleFont);
	}
	else if (inlineStatus)
	{
		CString caption;
		GetWindowText(caption);
		const int dotSize = UiTheme::ScaleForWindow(m_hWnd, 6);
		const int dotGap = UiTheme::ScaleForWindow(m_hWnd, 8);
		const int dotLeft = UiTheme::ScaleForWindow(m_hWnd, 2);
		const int dotTop = rect.CenterPoint().y - dotSize / 2;
		CPen dotPen(PS_SOLID, 1, text);
		CBrush dotBrush(text);
		oldPen = dc.SelectObject(&dotPen);
		oldBrush = dc.SelectObject(&dotBrush);
		dc.Ellipse(dotLeft, dotTop, dotLeft + dotSize, dotTop + dotSize);
		dc.SelectObject(oldBrush);
		dc.SelectObject(oldPen);

		dc.SetTextColor(text);
		CRect textRect(rect);
		textRect.left = dotLeft + dotSize + dotGap;
		dc.DrawText(caption, textRect,
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

void CSoftEdit::PostNcDestroy()
{
	CEdit::PostNcDestroy();
	if (m_autoDelete) delete this;
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
	// Let Windows draw the native scroll bars first, then draw our frame last.
	// Otherwise themed EDIT painting can replace the rounded outline.
	Default();
	CRect window;
	GetWindowRect(&window);
	const CPoint origin = window.TopLeft();
	CRect client;
	GetClientRect(&client);
	ClientToScreen(&client);
	client.OffsetRect(-window.left, -window.top);
	window.OffsetRect(-window.left, -window.top);

	CWindowDC dc(this);
	dc.ExcludeClipRect(&client);
	for (LONG object : { OBJID_VSCROLL, OBJID_HSCROLL })
	{
		SCROLLBARINFO bar = { sizeof(bar) };
		if (::GetScrollBarInfo(m_hWnd, object, &bar) && !(bar.rgstate[0] & STATE_SYSTEM_INVISIBLE))
		{
			CRect scroll(bar.rcScrollBar); scroll.OffsetRect(-origin.x, -origin.y);
			dc.ExcludeClipRect(scroll);
		}
	}
	dc.FillSolidRect(window, UiTheme::PageBackground());
	const BOOL enabled = IsWindowEnabled();
	const BOOL focused = ::GetFocus() == m_hWnd;
	COLORREF border = focused ? UiTheme::Accent() : (enabled ? RGB(208, 214, 223) : UiTheme::BorderSoft());
	UiTheme::FillRoundRect(dc.m_hDC, window, UiTheme::ScaleForWindow(m_hWnd, 8),
		enabled ? RGB(255, 255, 255) : UiTheme::Surface(), border);
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

namespace
{
	// An editable combo creates its edit child with ES_NOHIDESEL and selects the
	// whole text whenever it updates it (selection change, resize), so an
	// unfocused combo showed highlighted text. Keep a selection only while the
	// edit has focus.
	LRESULT CALLBACK ComboEditSubclassProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam,
		UINT_PTR id, DWORD_PTR)
	{
		if (message == EM_SETSEL && ::GetFocus() != hWnd)
		{
			wParam = static_cast<WPARAM>(-1);
			lParam = 0;
		}
		else if (message == WM_NCDESTROY)
		{
			::RemoveWindowSubclass(hWnd, ComboEditSubclassProc, id);
		}
		const LRESULT result = ::DefSubclassProc(hWnd, message, wParam, lParam);
		if (message == WM_KILLFOCUS)
			::DefSubclassProc(hWnd, EM_SETSEL, static_cast<WPARAM>(-1), 0);
		return result;
	}
}

void CSoftCombo::PreSubclassWindow()
{
	// The edit child of an editable combo paints itself; keep it out of our DC.
	ModifyStyle(0, WS_CLIPCHILDREN);
	CComboBox::PreSubclassWindow();
	if ((GetStyle() & 0x3) == CBS_DROPDOWN)
	{
		if (CWnd* edit = GetWindow(GW_CHILD))
		{
			::SetWindowSubclass(edit->m_hWnd, ComboEditSubclassProc, 0, 0);
			if (::GetFocus() != edit->m_hWnd)
				edit->SendMessage(EM_SETSEL, static_cast<WPARAM>(-1), 0);
		}
	}
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
