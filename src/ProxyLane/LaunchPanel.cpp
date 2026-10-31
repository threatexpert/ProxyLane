#include "stdafx.h"
#include "ProxyLane.h"
#include "LaunchPanel.h"
#include "ModernUI.h"

namespace
{
	const int kPadding = 16;
	const int kHeaderHeight = 88;
	const int kIconBox = 44;
	const int kTileWidth = 156;
	const int kTileHeight = 46;
	const int kTileGap = 8;
	const int kTileIcon = 24;
	const int kRecentLabelTop = 98;
	const int kTileTop = 120;
}

namespace
{
	// Store apps ship white glyphs meant for a coloured tile; detect icons whose
	// visible pixels are almost all very light so they can get a backing plate.
	BOOL IsLightIcon(HICON icon)
	{
		ICONINFO info = { 0 };
		if (!icon || !::GetIconInfo(icon, &info)) return FALSE;
		BOOL light = FALSE;
		if (info.hbmColor)
		{
			BITMAP bitmap = { 0 };
			::GetObject(info.hbmColor, sizeof(bitmap), &bitmap);
			const int width = bitmap.bmWidth, height = bitmap.bmHeight;
			if (width > 0 && height > 0 && width <= 256 && height <= 256)
			{
				BITMAPINFO bmi = { 0 };
				bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
				bmi.bmiHeader.biWidth = width;
				bmi.bmiHeader.biHeight = -height;
				bmi.bmiHeader.biPlanes = 1;
				bmi.bmiHeader.biBitCount = 32;
				bmi.bmiHeader.biCompression = BI_RGB;
				std::vector<DWORD> pixels(width * height);
				HDC screen = ::GetDC(NULL);
				if (::GetDIBits(screen, info.hbmColor, 0, height, &pixels[0], &bmi, DIB_RGB_COLORS) == height)
				{
					int visible = 0, bright = 0;
					for (size_t i = 0; i < pixels.size(); ++i)
					{
						const DWORD p = pixels[i];
						if ((p >> 24) < 64) continue; // transparent (icons without alpha are never "light" here)
						++visible;
						const int lum = (GetBValue(p) * 299 + GetGValue(p) * 587 + GetRValue(p) * 114) / 1000;
						if (lum > 225) ++bright;
					}
					light = visible > 0 && bright * 100 >= visible * 85;
				}
				::ReleaseDC(NULL, screen);
			}
		}
		if (info.hbmColor) ::DeleteObject(info.hbmColor);
		if (info.hbmMask) ::DeleteObject(info.hbmMask);
		return light;
	}
}

IMPLEMENT_DYNAMIC(CLaunchPanel, CWnd)

BEGIN_MESSAGE_MAP(CLaunchPanel, CWnd)
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_SIZE()
	ON_WM_MOUSEMOVE()
	ON_MESSAGE(WM_MOUSELEAVE, OnMouseLeave)
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONUP()
	ON_WM_KEYDOWN()
	ON_WM_SETFOCUS()
	ON_WM_KILLFOCUS()
	ON_WM_GETDLGCODE()
	ON_WM_DESTROY()
END_MESSAGE_MAP()

CLaunchPanel::CLaunchPanel()
	: m_enabled(FALSE)
	, m_hot(-1)
	, m_pressed(-1)
	, m_focusTile(0)
	, m_tracking(FALSE)
	, m_fontDpi(0)
	, m_actionWidth(0)
{
}

CLaunchPanel::~CLaunchPanel()
{
}

BOOL CLaunchPanel::Create(CWnd* parent, UINT id)
{
	CString className = AfxRegisterWndClass(CS_HREDRAW | CS_VREDRAW,
		::LoadCursor(NULL, IDC_ARROW), NULL, NULL);
	if (!CWnd::Create(className, _T(""),
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS,
		CRect(0, 0, 0, 0), parent, id))
		return FALSE;
	if (m_tooltip.Create(this, TTS_ALWAYSTIP | TTS_NOPREFIX))
	{
		m_tooltip.AddTool(this, LPSTR_TEXTCALLBACK);
		m_tooltip.SetMaxTipWidth(Scale(480));
		m_tooltip.SetDelayTime(TTDT_AUTOPOP, 30000);
	}
	return TRUE;
}

void CLaunchPanel::OnDestroy()
{
	CWnd::OnDestroy();
}

int CLaunchPanel::Scale(int value) const
{
	return UiTheme::ScaleForWindow(m_hWnd, value);
}

void CLaunchPanel::EnsureFonts()
{
	HDC dc = ::GetDC(m_hWnd);
	const int dpi = dc ? ::GetDeviceCaps(dc, LOGPIXELSY) : 96;
	if (dc) ::ReleaseDC(m_hWnd, dc);
	if (m_fontDpi == dpi && m_titleFont.GetSafeHandle()) return;
	m_fontDpi = dpi;
	UiTheme::CreateUiFont(m_titleFont, m_hWnd, 11, FW_SEMIBOLD);
	UiTheme::CreateUiFont(m_bodyFont, m_hWnd, 9, FW_NORMAL);
	UiTheme::CreateUiFont(m_labelFont, m_hWnd, 9, FW_SEMIBOLD);
}

void CLaunchPanel::SetText(const CString& title, const CString& body,
	const CString& recentTitle, const CString& emptyText)
{
	if (m_title == title && m_body == body && m_recentTitle == recentTitle && m_emptyText == emptyText)
		return;
	m_title = title;
	m_body = body;
	m_recentTitle = recentTitle;
	m_emptyText = emptyText;
	if (GetSafeHwnd()) Invalidate(FALSE);
}

void CLaunchPanel::SetActionWidth(int width)
{
	if (m_actionWidth == width) return;
	m_actionWidth = width;
	if (GetSafeHwnd()) Invalidate(FALSE);
}

void CLaunchPanel::SetEnabledState(BOOL enabled)
{
	if (m_enabled == enabled) return;
	m_enabled = enabled;
	SetHotTile(-1);
	if (GetSafeHwnd()) Invalidate(FALSE);
}

void CLaunchPanel::SetTiles(const std::vector<Tile>& tiles)
{
	m_tiles = tiles;
	for (size_t i = 0; i < m_tiles.size(); ++i)
		m_tiles[i].lightIcon = IsLightIcon(m_tiles[i].icon);
	if (m_focusTile >= static_cast<int>(m_tiles.size())) m_focusTile = 0;
	m_hot = -1;
	m_pressed = -1;
	m_tipText.Empty();
	if (m_tooltip.GetSafeHwnd()) m_tooltip.Pop();
	if (GetSafeHwnd()) Invalidate(FALSE);
}

int CLaunchPanel::PreferredHeight() const
{
	return Scale(kTileTop + kTileHeight + kPadding);
}

CRect CLaunchPanel::ActionSlot(int buttonWidth, int buttonHeight) const
{
	CRect client;
	GetClientRect(&client);
	const int top = (Scale(kHeaderHeight) - buttonHeight) / 2;
	return CRect(client.right - Scale(kPadding) - buttonWidth, top,
		client.right - Scale(kPadding), top + buttonHeight);
}

CRect CLaunchPanel::HeaderTextRect() const
{
	CRect client;
	GetClientRect(&client);
	const int left = Scale(kPadding + kIconBox + 14);
	return CRect(left, Scale(20),
		max(left, client.right - Scale(kPadding) - m_actionWidth - Scale(20)),
		Scale(kHeaderHeight - 8));
}

int CLaunchPanel::VisibleTileCount() const
{
	CRect client;
	GetClientRect(&client);
	const int slot = Scale(kTileWidth + kTileGap);
	const int fit = max(1, (client.Width() - Scale(kPadding) * 2 + Scale(kTileGap)) / max(1, slot));
	return min(static_cast<int>(m_tiles.size()), fit);
}

CRect CLaunchPanel::TileRect(int index) const
{
	const int left = Scale(kPadding) + index * Scale(kTileWidth + kTileGap);
	return CRect(left, Scale(kTileTop), left + Scale(kTileWidth), Scale(kTileTop + kTileHeight));
}

int CLaunchPanel::HitTestTile(CPoint point) const
{
	const int count = VisibleTileCount();
	for (int i = 0; i < count; ++i)
		if (TileRect(i).PtInRect(point)) return i;
	return -1;
}

void CLaunchPanel::SetHotTile(int index)
{
	if (m_hot == index) return;
	m_hot = index;
	if (GetSafeHwnd()) Invalidate(FALSE);
}

void CLaunchPanel::ActivateTile(int index)
{
	if (!m_enabled || index < 0 || index >= VisibleTileCount()) return;
	if (CWnd* parent = GetParent())
		parent->SendMessage(WM_LAUNCH_PANEL_TILE, static_cast<WPARAM>(index), 0);
}

BOOL CLaunchPanel::OnEraseBkgnd(CDC*)
{
	return TRUE;
}

void CLaunchPanel::OnSize(UINT type, int cx, int cy)
{
	CWnd::OnSize(type, cx, cy);
	Invalidate(FALSE);
}

void CLaunchPanel::OnPaint()
{
	EnsureFonts();
	CPaintDC paint(this);
	CRect client;
	GetClientRect(&client);
	if (client.IsRectEmpty()) return;

	CDC dc;
	CBitmap bitmap;
	dc.CreateCompatibleDC(&paint);
	bitmap.CreateCompatibleBitmap(&paint, client.Width(), client.Height());
	CBitmap* oldBitmap = dc.SelectObject(&bitmap);

	// Page background first so the rounded corners blend into the page.
	dc.FillSolidRect(client, UiTheme::PageBackground());
	UiTheme::FillRoundRect(dc.m_hDC, client, Scale(14), UiTheme::Surface(), UiTheme::BorderSoft());

	dc.SetBkMode(TRANSPARENT);
	const COLORREF primary = m_enabled ? UiTheme::TextPrimary() : UiTheme::TextSecondary();

	// Header glyph: a tray with a downward arrow.
	{
		CRect box(Scale(kPadding), Scale(20), Scale(kPadding + kIconBox), Scale(20 + kIconBox));
		UiTheme::FillRoundRect(dc.m_hDC, box, Scale(12), m_enabled ? UiTheme::AccentSoft() : RGB(238, 241, 245), CLR_NONE);
		CRect glyph = box;
		glyph.DeflateRect(Scale(8), Scale(8));
		UiTheme::DrawGlyph(dc.m_hDC, UiTheme::GLYPH_PROXY_TOOL, glyph,
			m_enabled ? UiTheme::Accent() : RGB(160, 166, 177), max(1.6f, Scale(2) * 0.9f));
	}

	// Header title and body.
	{
		CRect text = HeaderTextRect();
		CFont* oldFont = dc.SelectObject(&m_titleFont);
		dc.SetTextColor(primary);
		CRect titleRect(text.left, text.top, text.right, text.top + Scale(24));
		dc.DrawText(m_title, titleRect, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
		dc.SelectObject(&m_bodyFont);
		dc.SetTextColor(UiTheme::TextSecondary());
		CRect bodyRect(text.left, titleRect.bottom + Scale(2), text.right, text.bottom);
		dc.DrawText(m_body, bodyRect, DT_LEFT | DT_WORDBREAK | DT_END_ELLIPSIS | DT_NOPREFIX);
		dc.SelectObject(oldFont);
	}

	// Divider between the header and the recent apps.
	dc.FillSolidRect(Scale(kPadding), Scale(kHeaderHeight), client.Width() - Scale(kPadding) * 2, 1, UiTheme::BorderSoft());

	// Recent apps.
	{
		CFont* oldFont = dc.SelectObject(&m_labelFont);
		dc.SetTextColor(UiTheme::TextSecondary());
		CRect label(Scale(kPadding), Scale(kRecentLabelTop), client.right - Scale(kPadding), Scale(kRecentLabelTop + 20));
		dc.DrawText(m_recentTitle, label, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);

		const int count = VisibleTileCount();
		if (count == 0)
		{
			dc.SelectObject(&m_bodyFont);
			CRect empty(Scale(kPadding), Scale(kTileTop), client.right - Scale(kPadding), Scale(kTileTop + kTileHeight));
			dc.DrawText(m_emptyText, empty, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
		}
		dc.SelectObject(&m_bodyFont);
		for (int i = 0; i < count; ++i)
		{
			CRect tile = TileRect(i);
			const BOOL hot = m_enabled && i == m_hot;
			const BOOL down = hot && i == m_pressed;
			UiTheme::FillRoundRect(dc.m_hDC, tile, Scale(10),
				down ? UiTheme::AccentSoft() : (hot ? RGB(243, 247, 254) : RGB(255, 255, 255)),
				hot ? UiTheme::AccentSoftBorder() : UiTheme::BorderSoft());

			// Draw the shell's large icon at its own size; scaling makes it blurry.
			const int iconSize = max(Scale(kTileIcon), min(::GetSystemMetrics(SM_CXICON), Scale(32)));
			const int iconLeft = tile.left + Scale(10);
			const int iconTop = tile.top + (tile.Height() - iconSize) / 2;
			if (m_tiles[i].icon && m_tiles[i].lightIcon)
			{
				CRect plate(iconLeft - Scale(2), iconTop - Scale(2), iconLeft + iconSize + Scale(2), iconTop + iconSize + Scale(2));
				UiTheme::FillRoundRect(dc.m_hDC, plate, Scale(7), RGB(47, 52, 61), CLR_NONE);
			}
			if (m_tiles[i].icon)
				::DrawIconEx(dc.m_hDC, iconLeft, iconTop, m_tiles[i].icon, iconSize, iconSize, 0, NULL, DI_NORMAL);
			dc.SetTextColor(m_enabled ? UiTheme::TextPrimary() : UiTheme::TextSecondary());
			CRect name(iconLeft + iconSize + Scale(8), tile.top, tile.right - Scale(10), tile.bottom);
			dc.DrawText(m_tiles[i].name, name, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

			const BOOL cuesHidden = (SendMessage(WM_QUERYUISTATE) & UISF_HIDEFOCUS) != 0;
			if (m_enabled && !cuesHidden && ::GetFocus() == m_hWnd && i == m_focusTile)
				UiTheme::FillRoundRect(dc.m_hDC, tile, Scale(10), CLR_NONE, UiTheme::Accent());
		}
		dc.SelectObject(oldFont);
	}

	paint.BitBlt(0, 0, client.Width(), client.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBitmap);
}

void CLaunchPanel::OnMouseMove(UINT flags, CPoint point)
{
	if (!m_tracking)
	{
		TRACKMOUSEEVENT track = { sizeof(track), TME_LEAVE, m_hWnd, 0 };
		m_tracking = _TrackMouseEvent(&track);
	}
	const int hit = HitTestTile(point);
	SetHotTile(hit);
	CString tip = (hit >= 0 && hit < static_cast<int>(m_tiles.size())) ? m_tiles[hit].tip : CString();
	if (tip != m_tipText)
	{
		if (m_tooltip.GetSafeHwnd()) m_tooltip.Pop();
		m_tipText = tip;
	}
	::SetCursor(::LoadCursor(NULL, m_enabled && hit >= 0 ? IDC_HAND : IDC_ARROW));
	CWnd::OnMouseMove(flags, point);
}

LRESULT CLaunchPanel::OnMouseLeave(WPARAM, LPARAM)
{
	m_tracking = FALSE;
	SetHotTile(-1);
	return 0;
}

void CLaunchPanel::OnLButtonDown(UINT flags, CPoint point)
{
	SetFocus();
	const int hit = HitTestTile(point);
	if (m_enabled && hit >= 0)
	{
		m_pressed = hit;
		m_focusTile = hit;
		SetCapture();
		Invalidate(FALSE);
	}
	CWnd::OnLButtonDown(flags, point);
}

void CLaunchPanel::OnLButtonUp(UINT flags, CPoint point)
{
	const int pressed = m_pressed;
	if (GetCapture() == this) ReleaseCapture();
	m_pressed = -1;
	Invalidate(FALSE);
	if (pressed >= 0 && HitTestTile(point) == pressed)
		ActivateTile(pressed);
	CWnd::OnLButtonUp(flags, point);
}

void CLaunchPanel::OnKeyDown(UINT character, UINT repeatCount, UINT flags)
{
	const int count = VisibleTileCount();
	if (count > 0)
	{
		switch (character)
		{
		case VK_LEFT: m_focusTile = max(0, m_focusTile - 1); Invalidate(FALSE); return;
		case VK_RIGHT: m_focusTile = min(count - 1, m_focusTile + 1); Invalidate(FALSE); return;
		case VK_HOME: m_focusTile = 0; Invalidate(FALSE); return;
		case VK_END: m_focusTile = count - 1; Invalidate(FALSE); return;
		case VK_RETURN:
		case VK_SPACE: ActivateTile(m_focusTile); return;
		}
	}
	CWnd::OnKeyDown(character, repeatCount, flags);
}

void CLaunchPanel::OnSetFocus(CWnd* oldWindow)
{
	CWnd::OnSetFocus(oldWindow);
	Invalidate(FALSE);
}

void CLaunchPanel::OnKillFocus(CWnd* newWindow)
{
	CWnd::OnKillFocus(newWindow);
	Invalidate(FALSE);
}

UINT CLaunchPanel::OnGetDlgCode()
{
	return DLGC_WANTARROWS | DLGC_WANTCHARS;
}

BOOL CLaunchPanel::PreTranslateMessage(MSG* message)
{
	if (m_tooltip.GetSafeHwnd())
	{
		m_tooltip.Activate(!m_tipText.IsEmpty());
		m_tooltip.RelayEvent(message);
	}
	return CWnd::PreTranslateMessage(message);
}

BOOL CLaunchPanel::OnNotify(WPARAM wParam, LPARAM lParam, LRESULT* result)
{
	NMHDR* header = reinterpret_cast<NMHDR*>(lParam);
	if (header && m_tooltip.GetSafeHwnd() && header->hwndFrom == m_tooltip.GetSafeHwnd() &&
		header->code == TTN_NEEDTEXT)
	{
		reinterpret_cast<NMTTDISPINFO*>(header)->lpszText = const_cast<LPTSTR>(static_cast<LPCTSTR>(m_tipText));
		*result = 0;
		return TRUE;
	}
	return CWnd::OnNotify(wParam, lParam, result);
}
