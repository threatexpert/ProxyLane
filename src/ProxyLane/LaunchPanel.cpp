#include "stdafx.h"
#include "ProxyLane.h"
#include "LaunchPanel.h"
#include "ModernUI.h"
#include "Localization.h"
#include "LaunchPanelPaging.h"

namespace
{
	const int kPadding = 16;
	const int kHeaderHeight = 88;
	const int kActionsHeight = 88;
	const UINT_PTR kSnapTimer = 1;
	const UINT_PTR kEdgeTimer = 3;
	// Win7 gestures are resolved dynamically to preserve the XP build target.
	struct PanInfo {
		UINT cbSize; DWORD flags; DWORD id; HWND target; POINTS point;
		DWORD instance; DWORD sequence; ULONGLONG arguments; UINT extraBytes;
	};
	struct PanConfig { DWORD id; DWORD want; DWORD block; };
	typedef BOOL (WINAPI* ReadPan)(HANDLE, PanInfo*);
	typedef BOOL (WINAPI* ClosePan)(HANDLE);
	typedef BOOL (WINAPI* ConfigurePan)(HWND, DWORD, UINT, PanConfig*, UINT);
	const int kIconBox = 44;
	const int kTileWidth = 96;
	const int kTileHeight = 74;
	const int kTileGap = 8;
	const int kTileIcon = 24;
	const int kRecentLabelTop = 98;
	const int kTileTop = 124;
	const int kCompactHeaderHeight = 52;
	const int kCompactTileTop = 60;
	const int kCompactTileSize = 36;
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

BEGIN_MESSAGE_MAP(CLaunchProfileLink, CButton)
	ON_WM_MOUSEMOVE()
	ON_MESSAGE(WM_MOUSELEAVE, OnMouseLeave)
	ON_WM_SETCURSOR()
	ON_CONTROL_REFLECT(BN_CLICKED, OnClicked)
END_MESSAGE_MAP()

void CLaunchProfileLink::SetTip(const CString& text)
{
	if (!m_tooltip.GetSafeHwnd())
	{
		if (!m_tooltip.Create(this, TTS_ALWAYSTIP | TTS_NOPREFIX)) return;
		m_tooltip.SetMaxTipWidth(UiTheme::ScaleForWindow(m_hWnd, 480));
		m_tooltip.SetDelayTime(TTDT_AUTOPOP, 30000);
	}
	m_tooltip.Pop();
	m_tooltip.DelTool(this);
	if (!text.IsEmpty()) m_tooltip.AddTool(this, text);
	m_tooltip.Activate(!text.IsEmpty());
}

void CLaunchProfileLink::OnClicked()
{
	m_tooltip.Pop();
	GetParent()->SendMessage(WM_LAUNCH_PANEL_PROFILE);
}

void CLaunchProfileLink::DrawItem(LPDRAWITEMSTRUCT item)
{
	CDC dc; dc.Attach(item->hDC);
	CRect rect(item->rcItem);
	dc.FillSolidRect(rect, UiTheme::Surface());
	dc.SetBkMode(TRANSPARENT);
	const BOOL focused = (item->itemState & ODS_FOCUS) && !(item->itemState & ODS_NOFOCUSRECT);
	dc.SetTextColor(m_hot || focused ? UiTheme::Accent() : UiTheme::TextSecondary());
	CFont* oldFont = GetFont() ? dc.SelectObject(GetFont()) : NULL;
	CString text; GetWindowText(text);
	dc.DrawText(text, rect, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
	if (m_hot || focused)
	{
		TEXTMETRIC metrics = { 0 }; dc.GetTextMetrics(&metrics);
		const int y = rect.CenterPoint().y + metrics.tmHeight / 2;
		dc.FillSolidRect(rect.left, min(y, rect.bottom - 1), rect.Width(), 1, UiTheme::Accent());
	}
	if (oldFont) dc.SelectObject(oldFont);
	dc.Detach();
}

BOOL CLaunchProfileLink::PreTranslateMessage(MSG* message)
{
	if (m_tooltip.GetSafeHwnd()) m_tooltip.RelayEvent(message);
	if (message->message == WM_KEYDOWN && message->wParam == VK_RETURN)
	{
		if (!(message->lParam & (1L << 30))) SendMessage(BM_CLICK);
		return TRUE;
	}
	return CButton::PreTranslateMessage(message);
}

void CLaunchProfileLink::OnMouseMove(UINT flags, CPoint point)
{
	if (!m_hot)
	{
		TRACKMOUSEEVENT track = { sizeof(track), TME_LEAVE, m_hWnd, 0 };
		_TrackMouseEvent(&track);
		m_hot = TRUE;
		Invalidate(FALSE);
	}
	CButton::OnMouseMove(flags, point);
}

LRESULT CLaunchProfileLink::OnMouseLeave(WPARAM, LPARAM)
{
	m_hot = FALSE;
	Invalidate(FALSE);
	return 0;
}

BOOL CLaunchProfileLink::OnSetCursor(CWnd*, UINT, UINT)
{
	::SetCursor(::LoadCursor(NULL, IDC_HAND));
	return TRUE;
}

BEGIN_MESSAGE_MAP(CLaunchPanel, CWnd)
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_SIZE()
	ON_WM_MOUSEMOVE()
	ON_MESSAGE(WM_MOUSELEAVE, OnMouseLeave)
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONUP()
	ON_WM_RBUTTONDOWN()
	ON_WM_CONTEXTMENU()
	ON_WM_KEYDOWN()
	ON_WM_MOUSEWHEEL()
	ON_WM_TIMER()
	ON_WM_CAPTURECHANGED()
	ON_MESSAGE(0x020E, OnHorizontalWheel) // WM_MOUSEHWHEEL
	ON_MESSAGE(0x0119, OnGesture) // WM_GESTURE
	ON_WM_SETFOCUS()
	ON_WM_KILLFOCUS()
	ON_WM_GETDLGCODE()
	ON_WM_DESTROY()
END_MESSAGE_MAP()

CLaunchPanel::CLaunchPanel()
	: m_enabled(FALSE)
	, m_compact(FALSE)
	, m_hot(-1)
	, m_pressed(-1)
	, m_focusTile(0)
	, m_firstTile(0)
	, m_wheelDelta(0)
	, m_tracking(FALSE)
	, m_fontDpi(0)
	, m_recentTitleWidth(0)
	, m_actionWidth(0)
	, m_tipCount(0)
	, m_busyTile(-1)
	, m_pointerDown(FALSE)
	, m_dragging(FALSE)
	, m_touchPanning(FALSE)
	, m_animating(FALSE)
	, m_dragPage(0)
	, m_scrollOffset(0)
	, m_animationFrom(0)
	, m_animationTo(0)
	, m_animationStart(0)
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
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
		CRect(0, 0, 0, 0), parent, id))
		return FALSE;
	EnsureFonts();
	// Like the primary action, this is a sibling on the page. Keeping native
	// dialog controls out of the painted panel preserves normal focus traversal.
	if (!m_profileLink.Create(L"", WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
		CRect(0, 0, 0, 0), parent, IDC_LAUNCH_PROFILE)) return FALSE;
	m_profileLink.SetFont(&m_bodyFont);
	ConfigureTouch();
	if (m_tooltip.Create(this, TTS_ALWAYSTIP | TTS_NOPREFIX))
	{
		m_tooltip.SetMaxTipWidth(Scale(480));
		m_tooltip.SetDelayTime(TTDT_AUTOPOP, 30000);
		m_tooltip.Activate(TRUE);
	}
	return TRUE;
}

void CLaunchPanel::OnDestroy()
{
	StopMotion();
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
	if (m_profileLink.GetSafeHwnd()) m_profileLink.SetFont(&m_bodyFont);
	MeasureHeaderText();
	MeasureRecentTitle();
}

void CLaunchPanel::MeasureHeaderText()
{
	if (!GetSafeHwnd() || !m_titleFont.GetSafeHandle()) return;
	CClientDC dc(this);
	CFont* old = dc.SelectObject(&m_titleFont);
	m_titleWidth = dc.GetTextExtent(m_title).cx;
	dc.SelectObject(&m_bodyFont);
	m_profileWidth = dc.GetTextExtent(m_profileSummary).cx;
	dc.SelectObject(old);
	UpdateProfileLayout();
}

void CLaunchPanel::SetProfileSummary(const CString& summary)
{
	const CString tip = summary.IsEmpty() ? CString() : summary + L"\r\n" + Localization::Get(L"launch.edit_profile");
	if (summary == m_profileSummary && tip == m_profileTip) return;
	m_profileSummary = summary;
	m_profileTip = tip;
	m_profileLink.SetWindowText(summary);
	m_profileLink.SetTip(m_profileTip);
	MeasureHeaderText();
	UpdateTileLayout();
	Invalidate(FALSE);
}

void CLaunchPanel::MeasureRecentTitle()
{
	if (!GetSafeHwnd() || !m_labelFont.GetSafeHandle()) return;
	CClientDC dc(this);
	CFont* oldFont = dc.SelectObject(&m_labelFont);
	m_recentTitleWidth = dc.GetTextExtent(m_recentTitle).cx;
	dc.SelectObject(oldFont);
	UpdateTileLayout();
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
	MeasureHeaderText();
	MeasureRecentTitle();
	if (GetSafeHwnd()) Invalidate(FALSE);
}

void CLaunchPanel::SetActionWidth(int width)
{
	if (m_actionWidth == width) return;
	m_actionWidth = width;
	UpdateProfileLayout();
	RebuildTooltips();
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
	CancelTileMove();
	CString anchor, focus;
	if (m_firstTile < static_cast<int>(m_tiles.size())) anchor = m_tiles[m_firstTile].id;
	if (m_focusTile < static_cast<int>(m_tiles.size())) focus = m_tiles[m_focusTile].id;
	if (m_organizing && !focus.IsEmpty()) anchor = focus;
	StopMotion();
	ClearTooltips();
	m_tiles = tiles;
	if (m_tiles.empty()) { m_organizing = FALSE; ConfigureTouch(); }
	m_firstTile = min(m_firstTile, max(0, static_cast<int>(m_tiles.size()) - 1));
	m_focusTile = min(m_focusTile, max(0, static_cast<int>(m_tiles.size()) - 1));
	for (size_t i = 0; i < m_tiles.size(); ++i)
	{
		m_tiles[i].lightIcon = IsLightIcon(m_tiles[i].icon);
		if (m_tiles[i].id == anchor) m_firstTile = static_cast<int>(i);
		if (m_tiles[i].id == focus) m_focusTile = static_cast<int>(i);
	}
	UpdateTileLayout();
	if (GetSafeHwnd()) Invalidate(FALSE);
}

void CLaunchPanel::SetBusyTile(int index)
{
	m_busyTile = index;
	if (index >= 0) ClearTooltips(); else RebuildTooltips();
	if (GetSafeHwnd()) { Invalidate(FALSE); UpdateWindow(); }
}

int CLaunchPanel::PreferredHeight(int width) const
{
	return Scale(TileTop(width) + TileHeight() + kPadding);
}

int CLaunchPanel::TileWidth() const { return m_compact ? kCompactTileSize : kTileWidth; }
int CLaunchPanel::TileHeight() const { return m_tiles.empty() ? 24 : (m_compact ? kCompactTileSize : kTileHeight); }
int CLaunchPanel::TileTop(int width) const { return (m_compact ? kCompactTileTop : (m_tiles.empty() ? kHeaderHeight + 12 : kTileTop)) + HeaderExtraHeight(width); }

int CLaunchPanel::HeaderExtraHeight(int width) const
{
	if (m_profileSummary.IsEmpty()) return 0;
	CRect client; GetClientRect(&client);
	if (width < 0) width = client.Width();
	const int available = width - Scale(kPadding * 2 + (m_compact ? 40 : kIconBox + 14) + 20) - m_actionWidth;
	return available - m_titleWidth - Scale(12) < min(m_profileWidth, Scale(180)) ? 24 : 0;
}

void CLaunchPanel::HeaderRects(CRect& title, CRect& summary, CRect& body) const
{
	const CRect text = HeaderTextRect();
	const BOOL wrapped = HeaderExtraHeight() != 0;
	title = CRect(text.left, m_compact && wrapped ? Scale(10) : text.top, text.right,
		m_compact ? (wrapped ? Scale(34) : text.bottom) : text.top + Scale(24));
	summary.SetRectEmpty();
	if (!m_profileSummary.IsEmpty())
	{
		if (wrapped)
			summary = CRect(text.left, title.bottom + Scale(2), text.right, title.bottom + Scale(26));
		else
		{
			title.right = min(text.right, title.left + m_titleWidth);
			summary = CRect(min(text.right, title.right + Scale(12)), title.top, text.right, title.bottom);
		}
		summary.right = min(summary.right, summary.left + m_profileWidth);
	}
	body = CRect(text.left, title.bottom + Scale(2 + HeaderExtraHeight()), text.right, text.bottom);
}

void CLaunchPanel::UpdateProfileLayout()
{
	if (!m_profileLink.GetSafeHwnd()) return;
	CRect title, summary, body;
	HeaderRects(title, summary, body);
	if (summary.IsRectEmpty())
	{
		if (::GetFocus() == m_profileLink.m_hWnd) SetFocus();
		m_profileLink.ShowWindow(SW_HIDE);
	}
	else
	{
		MapWindowPoints(GetParent(), &summary);
		m_profileLink.SetWindowPos(&wndTop, summary.left, summary.top, summary.Width(), summary.Height(),
			SWP_NOACTIVATE | SWP_SHOWWINDOW);
	}
}

void CLaunchPanel::SetCompact(BOOL compact)
{
	if (m_compact == compact) return;
	m_compact = compact;
	UpdateProfileLayout();
	UpdateTileLayout();
	if (GetSafeHwnd()) Invalidate(FALSE);
}

CRect CLaunchPanel::ActionSlot(int buttonWidth, int buttonHeight) const
{
	CRect client;
	GetClientRect(&client);
	const int top = (Scale((m_compact ? kCompactHeaderHeight : kActionsHeight) + HeaderExtraHeight()) - buttonHeight) / 2;
	return CRect(client.right - Scale(kPadding) - buttonWidth, top,
		client.right - Scale(kPadding), top + buttonHeight);
}

CRect CLaunchPanel::HeaderTextRect() const
{
	CRect client;
	GetClientRect(&client);
	const int left = Scale(kPadding + (m_compact ? 28 + 12 : kIconBox + 14));
	return CRect(left, m_compact ? 0 : Scale(20),
		max(left, client.right - Scale(kPadding) - m_actionWidth - Scale(20)),
		Scale((m_compact ? kCompactHeaderHeight : kActionsHeight - 8) + HeaderExtraHeight()));
}

int CLaunchPanel::TileCapacity() const
{
	const int slot = Scale(TileWidth() + kTileGap);
	const int fit = max(1, (TileViewport().Width() + Scale(kTileGap)) / max(1, slot));
	return fit;
}

int CLaunchPanel::VisibleTileCount() const
{
	return min(TileCapacity(), max(0, static_cast<int>(m_tiles.size()) - m_firstTile));
}

int CLaunchPanel::PageWidth() const
{
	return max(1, TileViewport().Width());
}

int CLaunchPanel::PageCount() const
{
	return LaunchPanelPaging::PageCount(static_cast<int>(m_tiles.size()), TileCapacity());
}

CRect CLaunchPanel::TileViewport() const
{
	CRect client; GetClientRect(&client);
	int left = Scale(kPadding), right = max(left, client.right - Scale(kPadding));
	if (m_compact || m_tiles.empty())
	{
		// Reserve title and paging space outside the icon viewport so neither
		// gets covered while swiping. Compute capacity here without recursion.
		const int dotsWidth = Scale(5 * 12 + 8);
		const int titleWidth = min(m_recentTitleWidth, max(0, right - left - Scale(12 + kCompactTileSize) - dotsWidth));
		left = min(right, left + titleWidth + Scale(12));
		const int capacityWithoutDots = max(1, (right - left + Scale(kTileGap)) / max(1, Scale(TileWidth() + kTileGap)));
		if (static_cast<int>(m_tiles.size()) > capacityWithoutDots)
			right = max(left, right - dotsWidth);
	}
	return CRect(left, Scale(TileTop()), right, Scale(TileTop() + TileHeight()));
}

CRect CLaunchPanel::TileRect(int index) const
{
	const int capacity = TileCapacity();
	const int left = TileViewport().left + index / capacity * PageWidth() +
		index % capacity * Scale(TileWidth() + kTileGap) - static_cast<int>(m_scrollOffset);
	return CRect(left, Scale(TileTop()), left + min(Scale(TileWidth()), PageWidth()), Scale(TileTop() + TileHeight()));
}

int CLaunchPanel::HitTestTile(CPoint point) const
{
	if (m_animating || m_dragging || !TileViewport().PtInRect(point)) return -1;
	const int count = VisibleTileCount();
	for (int i = m_firstTile; i < m_firstTile + count; ++i)
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
	if (m_organizing || m_busyTile >= 0 || m_animating || m_dragging || index < m_firstTile || index >= m_firstTile + VisibleTileCount()) return;
	if (CWnd* parent = GetParent())
		parent->SendMessage(WM_LAUNCH_PANEL_TILE, static_cast<WPARAM>(index), LAUNCH_DEFAULT);
}

BOOL CLaunchPanel::OnEraseBkgnd(CDC*)
{
	return TRUE;
}

void CLaunchPanel::OnSize(UINT type, int cx, int cy)
{
	CWnd::OnSize(type, cx, cy);
	UpdateProfileLayout();
	UpdateTileLayout();
	Invalidate(FALSE);
}

void CLaunchPanel::ClearTooltips()
{
	if (!m_tooltip.GetSafeHwnd()) return;
	m_tooltip.Pop();
	for (int i = 0; i < m_tipCount; ++i) m_tooltip.DelTool(this, i + 1);
	m_tipCount = 0;
}

void CLaunchPanel::RebuildTooltips()
{
	ClearTooltips();
	if (!m_tooltip.GetSafeHwnd() || IsInteracting() || m_animating || m_dragging || m_busyTile >= 0) return;
	// Each visible tile is a distinct tool, with its own text and current bounds.
	// No mouse-move activation race or zero-size creation rectangle is involved.
	const int count = VisibleTileCount();
	for (int i = 0; i < count; ++i)
	{
		const int index = m_firstTile + i;
		CRect rect = TileRect(index);
		if (m_organizing)
		{
			CRect remove = RemoveRect(index);
			m_tooltip.AddTool(this, Localization::Get(L"recent.remove"), &remove, ++m_tipCount);
		}
		m_tooltip.AddTool(this, m_tiles[index].tip + L"\r\n" + Localization::Get(m_organizing ? L"launch.organize_active" : L"launch.organize_hint"), &rect, ++m_tipCount);
	}
}

void CLaunchPanel::StopMotion()
{
	CancelTileMove();
	m_removePressed = -1;
	m_pointerDown = m_dragging = m_touchPanning = m_animating = FALSE;
	m_hot = m_pressed = -1;
	if (GetSafeHwnd())
	{
		KillTimer(kSnapTimer);
		if (GetCapture() == this) ReleaseCapture();
	}
}

void CLaunchPanel::UpdateTileLayout()
{
	if (!GetSafeHwnd()) return;
	StopMotion();
	const int capacity = TileCapacity();
	m_firstTile = LaunchPanelPaging::ClampPage(m_firstTile / capacity, PageCount()) * capacity;
	m_focusTile = max(m_firstTile, min(m_focusTile, m_firstTile + VisibleTileCount() - 1));
	m_scrollOffset = static_cast<double>(m_firstTile / capacity * PageWidth());
	RebuildTooltips();
}

void CLaunchPanel::AnimateToPage(int page)
{
	page = LaunchPanelPaging::ClampPage(page, PageCount());
	m_firstTile = page * TileCapacity();
	m_hot = m_pressed = -1;
	m_animationFrom = m_scrollOffset;
	m_animationTo = static_cast<double>(page * PageWidth());
	m_animationStart = GetTickCount();
	BOOL animationAllowed = TRUE;
	::SystemParametersInfo(0x1042, 0, &animationAllowed, 0); // SPI_GETCLIENTAREAANIMATION (Vista+)
	m_animating = animationAllowed && m_animationFrom != m_animationTo;
	ClearTooltips();
	if (m_animating && !SetTimer(kSnapTimer, 16, NULL)) m_animating = FALSE;
	if (!m_animating)
	{
		KillTimer(kSnapTimer);
		m_scrollOffset = m_animationTo;
		RebuildTooltips();
	}
	Invalidate(FALSE);
}

void CLaunchPanel::OnTimer(UINT_PTR eventId)
{
	if (eventId == kEdgeTimer) {
		if (m_reordering && m_edgeDirection && GetTickCount() - m_edgeSince >= 650) {
			const int page = LaunchPanelPaging::ClampPage(m_firstTile / TileCapacity() + m_edgeDirection, PageCount());
			m_firstTile = page * TileCapacity();
			m_scrollOffset = static_cast<double>(page * PageWidth());
			m_edgeSince = GetTickCount();
			MoveOrganizedTile(m_editPoint);
			Invalidate(FALSE);
		}
		return;
	}
	if (eventId != kSnapTimer) { CWnd::OnTimer(eventId); return; }
	const double progress = (GetTickCount() - m_animationStart) / 180.0;
	m_scrollOffset = m_animationFrom + (m_animationTo - m_animationFrom) * LaunchPanelPaging::Ease(progress);
	if (progress >= 1)
	{
		KillTimer(kSnapTimer);
		m_animating = FALSE;
		RebuildTooltips();
	}
	Invalidate(FALSE);
}

void CLaunchPanel::ChangePage(int direction)
{
	if (m_busyTile >= 0 || m_pointerDown) return;
	const int page = LaunchPanelPaging::ClampPage(m_firstTile / TileCapacity() + direction, PageCount());
	m_focusTile = page * TileCapacity();
	AnimateToPage(page);
}

void CLaunchPanel::EnsureFocusVisible()
{
	if (m_pointerDown) return;
	AnimateToPage(m_focusTile / TileCapacity());
}

LRESULT CLaunchPanel::OnHorizontalWheel(WPARAM wParam, LPARAM lParam)
{
	CPoint point(static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam)));
	return OnMouseWheel(LOWORD(wParam), -static_cast<short>(HIWORD(wParam)), point);
}

void CLaunchPanel::BeginDrag(CPoint point)
{
	if (m_busyTile >= 0 || !TileViewport().PtInRect(point)) return;
	const BOOL wasAnimating = m_animating;
	UpdateTileLayout();
	m_pointerDown = TRUE;
	m_dragOrigin = point;
	m_dragPage = m_firstTile / TileCapacity();
	m_pressed = wasAnimating ? -1 : HitTestTile(point);
	if (m_pressed >= 0) m_focusTile = m_pressed;
	if (m_pressed >= 0 && m_organizing) { m_editIndex = m_pressed; m_beforeMove = m_tiles; }
}

void CLaunchPanel::MoveDrag(CPoint point)
{
	if (!m_pointerDown) return;
	const int dx = point.x - m_dragOrigin.x, dy = point.y - m_dragOrigin.y;
	if (m_organizing && m_editIndex >= 0) {
		if (!m_reordering && (abs(dx) >= Scale(6) || abs(dy) >= Scale(6))) {
			m_reordering = TRUE; ClearTooltips(); SetTimer(kEdgeTimer, 50, NULL);
		}
		if (m_reordering) MoveOrganizedTile(point);
		return;
	}
	const int panSlop = Scale(10);
	if (!m_dragging && abs(dy) >= panSlop) m_pressed = -1;
	if (!m_dragging && abs(dx) >= panSlop && abs(dx) > abs(dy))
	{
		m_dragging = TRUE;
		m_pressed = m_hot = -1;
		ClearTooltips();
	}
	if (m_dragging)
	{
		m_scrollOffset = LaunchPanelPaging::DragOffset(static_cast<double>(m_dragPage * PageWidth() - dx),
			static_cast<double>((PageCount() - 1) * PageWidth()));
		Invalidate(FALSE);
	}
}

void CLaunchPanel::EndDrag(CPoint point, BOOL allowClick)
{
	if (!m_pointerDown) return;
	MoveDrag(point);
	if (m_organizing && m_editIndex >= 0) {
		Edit edit;
		edit.remove = FALSE;
		const BOOL save = m_reordering && TileViewport().PtInRect(point);
		edit.id = m_tiles[m_editIndex].id;
		edit.targetId = m_beforeMove[m_editIndex].id;
		m_pointerDown = m_touchPanning = FALSE;
		CancelTileMove();
		for (size_t i = 0; i < m_tiles.size(); ++i)
			if (m_tiles[i].id == edit.id) m_focusTile = static_cast<int>(i);
		m_pressed = -1;
		if (GetCapture() == this) ReleaseCapture();
		if (save && edit.id != edit.targetId)
			if (CWnd* parent = GetParent()) parent->SendMessage(WM_LAUNCH_PANEL_EDIT, 0, reinterpret_cast<LPARAM>(&edit));
		RebuildTooltips();
		Invalidate(FALSE);
		return;
	}
	const int pressed = m_pressed;
	const BOOL dragged = m_dragging;
	m_pointerDown = m_dragging = m_touchPanning = FALSE;
	m_pressed = -1;
	if (GetCapture() == this) ReleaseCapture();
	if (dragged)
	{
		const int page = LaunchPanelPaging::ReleasePage(m_dragPage, point.x - m_dragOrigin.x,
			PageWidth(), max(Scale(24), PageWidth() / 6), PageCount());
		m_focusTile = page * TileCapacity();
		AnimateToPage(page);
	}
	else if (allowClick && pressed >= 0 && HitTestTile(point) == pressed) ActivateTile(pressed);
	Invalidate(FALSE);
}

void CLaunchPanel::OnCaptureChanged(CWnd* window)
{
	m_removePressed = -1;
	if (m_pointerDown)
	{
		CancelTileMove();
		m_pointerDown = m_dragging = m_touchPanning = FALSE;
		AnimateToPage(m_firstTile / TileCapacity());
	}
	CWnd::OnCaptureChanged(window);
}

CRect CLaunchPanel::RemoveRect(int index) const
{
	const CRect tile = TileRect(index);
	// Painted at 20px over the corner; the hit target is 28px, which helps over RDP.
	const CPoint centre(tile.right - Scale(4), tile.top + Scale(4));
	return CRect(centre.x - Scale(14), centre.y - Scale(14), centre.x + Scale(14), centre.y + Scale(14));
}

int CLaunchPanel::HitTestRemove(CPoint point) const
{
	if (!m_organizing || m_reordering || m_pointerDown || m_animating || m_busyTile >= 0) return -1;
	for (int i = m_firstTile; i < m_firstTile + VisibleTileCount(); ++i)
		if (RemoveRect(i).PtInRect(point)) return i;
	return -1;
}

void CLaunchPanel::StartOrganizing()
{
	const int pressed = m_pressed;
	StopMotion();
	m_organizing = TRUE;
	ConfigureTouch();
	m_focusTile = pressed;
	RebuildTooltips();
	Invalidate(FALSE);
}

void CLaunchPanel::CancelTileMove()
{
	if (!m_beforeMove.empty()) m_tiles.swap(m_beforeMove);
	m_beforeMove.clear();
	m_editIndex = -1; m_reordering = FALSE; m_edgeDirection = 0;
	if (GetSafeHwnd()) KillTimer(kEdgeTimer);
}

void CLaunchPanel::FinishOrganizing()
{
	if (!m_organizing) return;
	StopMotion(); m_organizing = FALSE;
	ConfigureTouch();
	RebuildTooltips(); Invalidate(FALSE);
}

void CLaunchPanel::ConfigureTouch()
{
	ConfigurePan configure = reinterpret_cast<ConfigurePan>(::GetProcAddress(::GetModuleHandle(L"user32.dll"), "SetGestureConfig"));
	if (!configure) return;
	// Browsing uses a horizontal gutter; arranging lets the icon follow both
	// axes without inertia or Windows locking a diagonal drag to one direction.
	const DWORD want = m_organizing ? 0x1 | 0x2 | 0x4 : 0x1 | 0x4 | 0x8;
	const DWORD block = m_organizing ? 0x8 | 0x10 : 0x2 | 0x10;
	PanConfig pan = { 4, want, block };
	configure(m_hWnd, 0, 1, &pan, sizeof(pan));
}

void CLaunchPanel::MoveOrganizedTile(CPoint point)
{
	m_editPoint = point;
	const CRect viewport = TileViewport();
	int edge = 0;
	if (point.y >= viewport.top && point.y < viewport.bottom &&
		point.x >= viewport.left - Scale(12) && point.x <= viewport.right + Scale(12)) {
		if (point.x < viewport.left + Scale(18)) edge = -1;
		else if (point.x >= viewport.right - Scale(18)) edge = 1;
	}
	if (edge != m_edgeDirection) { m_edgeDirection = edge; m_edgeSince = GetTickCount(); }
	if (viewport.PtInRect(point)) {
		int target = min(static_cast<int>(m_tiles.size()) - 1,
			m_firstTile + min(TileCapacity() - 1, max(0, (point.x - viewport.left) / Scale(TileWidth() + kTileGap))));
		// Preserve the picker's existing pinned/ordinary groups.
		while (target != m_editIndex && m_tiles[target].pinned != m_tiles[m_editIndex].pinned)
			target += target < m_editIndex ? 1 : -1;
		if (target != m_editIndex) {
			const Tile moving = m_tiles[m_editIndex];
			m_tiles.erase(m_tiles.begin() + m_editIndex);
			m_tiles.insert(m_tiles.begin() + target, moving);
			m_editIndex = target;
		}
	}
	Invalidate(FALSE);
}

LRESULT CLaunchPanel::OnGesture(WPARAM wParam, LPARAM lParam)
{
	HMODULE user = ::GetModuleHandle(L"user32.dll");
	ReadPan read = reinterpret_cast<ReadPan>(::GetProcAddress(user, "GetGestureInfo"));
	ClosePan close = reinterpret_cast<ClosePan>(::GetProcAddress(user, "CloseGestureInfoHandle"));
	PanInfo info = { sizeof(info) };
	if (!read || !close || !read(reinterpret_cast<HANDLE>(lParam), &info)) return DefWindowProc(0x0119, wParam, lParam);
	if (info.id == 4) // GID_PAN
	{
		CPoint point(info.point.x, info.point.y); ScreenToClient(&point);
		if (info.flags & 1) { if (!m_pointerDown) BeginDrag(point); m_touchPanning = m_pointerDown; }
		if (m_touchPanning)
		{
			MoveDrag(point);
			if (info.flags & 4) EndDrag(point, FALSE);
		}
		close(reinterpret_cast<HANDLE>(lParam));
		return 0;
	}
	if (info.id == 2 && m_touchPanning) // GID_END also covers an interrupted pan.
	{
		CancelTileMove();
		m_pointerDown = m_dragging = m_touchPanning = FALSE;
		AnimateToPage(m_firstTile / TileCapacity());
	}
	return DefWindowProc(0x0119, wParam, lParam);
}

BOOL CLaunchPanel::OnMouseWheel(UINT flags, short delta, CPoint point)
{
	CPoint local = point;
	ScreenToClient(&local);
	if (local.y < Scale(m_compact ? TileTop() : kRecentLabelTop + HeaderExtraHeight()) || static_cast<int>(m_tiles.size()) <= TileCapacity())
		return CWnd::OnMouseWheel(flags, delta, point);
	m_wheelDelta += delta;
	while (m_wheelDelta >= WHEEL_DELTA) { ChangePage(-1); m_wheelDelta -= WHEEL_DELTA; }
	while (m_wheelDelta <= -WHEEL_DELTA) { ChangePage(1); m_wheelDelta += WHEEL_DELTA; }
	return TRUE;
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
		const int boxSize = m_compact ? 28 : kIconBox;
		const int boxTop = m_compact ? (kCompactHeaderHeight - boxSize) / 2 : 20;
		CRect box(Scale(kPadding), Scale(boxTop), Scale(kPadding + boxSize), Scale(boxTop + boxSize));
		UiTheme::FillRoundRect(dc.m_hDC, box, Scale(12), m_enabled ? UiTheme::AccentSoft() : RGB(238, 241, 245), CLR_NONE);
		CRect glyph = box;
		glyph.DeflateRect(Scale(m_compact ? 5 : 8), Scale(m_compact ? 5 : 8));
		UiTheme::DrawGlyph(dc.m_hDC, UiTheme::GLYPH_PROXY_TOOL, glyph,
			m_enabled ? UiTheme::Accent() : RGB(160, 166, 177), max(1.6f, Scale(2) * 0.9f));
	}

	// Header title and body.
	{
		CRect titleRect, summaryRect, bodyRect;
		HeaderRects(titleRect, summaryRect, bodyRect);
		CFont* oldFont = dc.SelectObject(&m_titleFont);
		dc.SetTextColor(primary);
		dc.DrawText(m_title, titleRect, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
		if (!m_compact)
		{
			dc.SelectObject(&m_bodyFont);
			dc.SetTextColor(m_bodyColor == CLR_NONE ? UiTheme::TextSecondary() : m_bodyColor);
			dc.DrawText(m_body, bodyRect, DT_LEFT | DT_WORDBREAK | DT_END_ELLIPSIS | DT_NOPREFIX);
		}
		dc.SelectObject(oldFont);
	}

	// Divider between the header and the recent apps.
	dc.FillSolidRect(Scale(kPadding), Scale((m_compact ? kCompactHeaderHeight : kHeaderHeight) + HeaderExtraHeight()), client.Width() - Scale(kPadding) * 2, 1, UiTheme::BorderSoft());

	// Recent apps.
	{
		CFont* oldFont = dc.SelectObject(&m_labelFont);
		dc.SetTextColor(UiTheme::TextSecondary());
		// An empty history needs only one quiet line, not a vacant tile row.
		const BOOL inlineRecent = m_compact || m_tiles.empty();
		const int labelTop = inlineRecent ? TileTop() : kRecentLabelTop + HeaderExtraHeight();
		CRect label(Scale(kPadding), Scale(labelTop), client.right - Scale(kPadding), Scale(labelTop + (inlineRecent ? TileHeight() : 20)));
		if (inlineRecent) label.right = max(label.left, TileViewport().left - Scale(12));
		if (PageCount() > 1)
		{
			const int dots = min(m_compact ? 5 : 7, PageCount());
			const int page = m_firstTile / TileCapacity();
			const int firstDot = max(0, min(page - dots / 2, PageCount() - dots));
			const int dotLeft = client.right - Scale(kPadding + dots * 12);
			if (!m_compact) label.right = dotLeft - Scale(8);
			for (int d = 0; d < dots; ++d)
			{
				const BOOL active = firstDot + d == page;
				const BOOL clipped = (d == 0 && firstDot > 0) || (d == dots - 1 && firstDot + dots < PageCount());
				const int size = Scale(clipped && !active ? 3 : 5);
				const int x = dotLeft + Scale(d * 12 + 6), y = label.CenterPoint().y;
				CRect dot(x - size / 2, y - size / 2, x - size / 2 + size, y - size / 2 + size);
				UiTheme::FillRoundRect(dc.m_hDC, dot, size / 2, active ? UiTheme::TextSecondary() : UiTheme::Border(), CLR_NONE);
			}
		}
		dc.DrawText(m_recentTitle, label, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);

		const int count = VisibleTileCount();
		if (count == 0)
		{
			dc.SelectObject(&m_bodyFont);
			CRect empty = TileViewport();
			dc.DrawText(m_emptyText, empty, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
		}
		dc.SelectObject(&m_bodyFont);
		TEXTMETRIC captionMetrics = { 0 };
		dc.GetTextMetrics(&captionMetrics);
		const int savedDc = dc.SaveDC();
		CRect viewport = TileViewport();
		dc.IntersectClipRect(viewport);
		for (int i = 0; i < static_cast<int>(m_tiles.size()); ++i)
		{
			CRect tile = TileRect(i);
			if (tile.right <= viewport.left || tile.left >= viewport.right) continue;
			if (m_organizing) tile.DeflateRect(Scale(2), Scale(2));
			if (m_reordering && i == m_editIndex) {
				UiTheme::FillRoundRect(dc.m_hDC, tile, Scale(10), UiTheme::AccentSoft(), UiTheme::AccentSoftBorder());
				continue;
			}
			const BOOL hot = m_busyTile < 0 && i == m_hot;
			const BOOL down = hot && i == m_pressed;
			UiTheme::FillRoundRect(dc.m_hDC, tile, Scale(10),
				down ? UiTheme::AccentSoft() : (hot ? RGB(243, 247, 254) : RGB(255, 255, 255)),
				(hot || m_organizing) ? UiTheme::AccentSoftBorder() : UiTheme::BorderSoft());

			// Draw the shell's large icon at its own size; scaling makes it blurry.
			const int iconSize = m_compact ? Scale(20) : max(Scale(kTileIcon), min(::GetSystemMetrics(SM_CXICON), Scale(32)));
			const int iconLeft = tile.left + (tile.Width() - iconSize) / 2;
			const int contentHeight = m_compact ? iconSize : iconSize + Scale(6) + captionMetrics.tmHeight;
			const int iconTop = tile.top + (tile.Height() - contentHeight) / 2;
			if (m_tiles[i].icon && m_tiles[i].lightIcon)
			{
				CRect plate(iconLeft - Scale(2), iconTop - Scale(2), iconLeft + iconSize + Scale(2), iconTop + iconSize + Scale(2));
				UiTheme::FillRoundRect(dc.m_hDC, plate, Scale(7), RGB(47, 52, 61), CLR_NONE);
			}
			if (m_compact && (i == m_busyTile || !m_tiles[i].icon))
			{
				dc.SetTextColor(UiTheme::TextPrimary());
				dc.DrawText(i == m_busyTile ? CString(L"\x2026") : m_tiles[i].name.Left(1), tile,
					DT_CENTER | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
			}
			else if (m_tiles[i].icon)
				::DrawIconEx(dc.m_hDC, iconLeft, iconTop, m_tiles[i].icon, iconSize, iconSize, 0, NULL, DI_NORMAL);
			if (m_tiles[i].elevated)
			{
				const int right = iconLeft + iconSize + Scale(2), bottom = iconTop + iconSize + Scale(2);
				const int badgeSize = Scale(m_compact ? 11 : 14);
				UiTheme::DrawElevationBadge(dc.m_hDC, CRect(right - badgeSize, bottom - badgeSize, right, bottom));
			}
			dc.SetTextColor(UiTheme::TextPrimary());
			// Center the icon and single-line caption as one group, with equal
			// space above and below. The tooltip retains the complete name.
			const int captionTop = iconTop + iconSize + Scale(6);
			CRect name(tile.left + Scale(6), captionTop, tile.right - Scale(6), captionTop + captionMetrics.tmHeight);
			if (!m_compact)
				dc.DrawText(i == m_busyTile ? Localization::Get(L"launch.opening") : m_tiles[i].name, name,
					DT_CENTER | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);

			const BOOL cuesHidden = (SendMessage(WM_QUERYUISTATE) & UISF_HIDEFOCUS) != 0;
			if (!m_animating && !m_dragging && !cuesHidden && ::GetFocus() == m_hWnd && i == m_focusTile)
				UiTheme::FillRoundRect(dc.m_hDC, tile, Scale(10), CLR_NONE, UiTheme::Accent());
		}
		dc.RestoreDC(savedDc);
		dc.SelectObject(oldFont);
	}
	if (m_organizing && !m_reordering && !m_animating && !m_dragging) {
		for (int i = m_firstTile; i < m_firstTile + VisibleTileCount(); ++i) {
			const CRect hit = RemoveRect(i);
			CRect badge(hit.CenterPoint().x - Scale(10), hit.CenterPoint().y - Scale(10),
				hit.CenterPoint().x + Scale(10), hit.CenterPoint().y + Scale(10));
			UiTheme::DrawRemoveBadge(dc.m_hDC, badge, m_removePressed == i && hit.PtInRect(m_editPoint));
		}
	}
	if (m_reordering && m_editIndex >= 0) {
		// A small floating copy stays above the pointer so the destination is visible.
		const Tile& moving = m_tiles[m_editIndex];
		const int size = Scale(m_compact ? 24 : 32), padding = Scale(6);
		CRect ghost(m_editPoint.x - size / 2 - padding, m_editPoint.y - size - padding * 3,
			m_editPoint.x + size / 2 + padding, m_editPoint.y - padding);
		UiTheme::FillRoundRect(dc.m_hDC, ghost, Scale(8), moving.lightIcon ? RGB(47, 52, 61) : RGB(255, 255, 255), UiTheme::Accent());
		if (moving.icon) ::DrawIconEx(dc.m_hDC, ghost.left + padding, ghost.top + padding, moving.icon, size, size, 0, NULL, DI_NORMAL);
		if (moving.elevated) UiTheme::DrawElevationBadge(dc.m_hDC, CRect(ghost.right - Scale(14), ghost.bottom - Scale(14), ghost.right, ghost.bottom));
	}

	paint.BitBlt(0, 0, client.Width(), client.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBitmap);
}

void CLaunchPanel::OnMouseMove(UINT flags, CPoint point)
{
	if (m_removePressed >= 0) { m_editPoint = point; Invalidate(FALSE); }
	if (!m_tracking)
	{
		TRACKMOUSEEVENT track = { sizeof(track), TME_LEAVE, m_hWnd, 0 };
		m_tracking = _TrackMouseEvent(&track);
	}
	MoveDrag(point);
	const int hit = m_busyTile < 0 ? HitTestTile(point) : -1;
	SetHotTile(hit);
	::SetCursor(::LoadCursor(NULL, hit >= 0 || HitTestRemove(point) >= 0 ? IDC_HAND : IDC_ARROW));
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
	const int remove = HitTestRemove(point);
	if (remove >= 0) {
		SetFocus(); m_removePressed = remove; m_editPoint = point;
		ClearTooltips(); SetCapture(); Invalidate(FALSE); return;
	}
	if (m_organizing && !TileViewport().PtInRect(point)) { FinishOrganizing(); return; }
	if (!m_touchPanning && m_busyTile < 0)
	{
		SetFocus();
		BeginDrag(point);
		if (m_pointerDown) SetCapture();
		Invalidate(FALSE);
	}
	CWnd::OnLButtonDown(flags, point);
}

void CLaunchPanel::OnLButtonUp(UINT flags, CPoint point)
{
	if (m_removePressed >= 0) {
		const int index = m_removePressed;
		const BOOL remove = HitTestRemove(point) == index;
		Edit edit;
		edit.id = m_tiles[index].id; edit.remove = TRUE;
		m_removePressed = -1;
		if (GetCapture() == this) ReleaseCapture();
		if (remove) if (CWnd* parent = GetParent()) parent->SendMessage(WM_LAUNCH_PANEL_EDIT, 0, reinterpret_cast<LPARAM>(&edit));
		RebuildTooltips(); Invalidate(FALSE); return;
	}
	if (!m_touchPanning) EndDrag(point, TRUE);
	CWnd::OnLButtonUp(flags, point);
}

void CLaunchPanel::OnRButtonDown(UINT flags, CPoint point)
{
	// A remote press-and-hold may be promoted to a right click after an
	// initial left down. Cancel that pending launch before the context event.
	UpdateTileLayout();
	CWnd::OnRButtonDown(flags, point);
}

void CLaunchPanel::OnContextMenu(CWnd*, CPoint point)
{
	if (m_busyTile >= 0) return;
	const BOOL keyboard = point == CPoint(-1, -1);
	if (!keyboard) ScreenToClient(&point);
	UpdateTileLayout();
	const int index = keyboard ? m_focusTile : HitTestTile(point);
	if (index < 0 || index >= static_cast<int>(m_tiles.size())) return;
	SetFocus();
	CPoint screen = point;
	if (keyboard) { const CRect tile = TileRect(index); screen = CPoint(tile.left + Scale(8), tile.bottom); }
	ClientToScreen(&screen);
	ShowTileMenu(index, screen);
}

void CLaunchPanel::ShowTileMenu(int index, CPoint screenPoint)
{
	enum { CMD_OPEN = 1, CMD_OPEN_ADMIN, CMD_SHORTCUT, CMD_REORDER, CMD_REMOVE };
	const Tile tile = m_tiles[index];
	FinishOrganizing();
	CModernPopupMenu menu;
	if (!menu.CreatePopupMenu()) return;
	const UINT unavailable = tile.available ? 0 : MF_GRAYED;
	menu.AppendMenu(MF_STRING | unavailable, CMD_OPEN, Localization::Get(L"launch.menu_open"));
	// Both choices remain available regardless of the saved default.
	if (!tile.packaged)
		menu.AppendMenu(MF_STRING | unavailable, CMD_OPEN_ADMIN, Localization::Get(L"launch.menu_open_admin"));
	menu.AppendMenu(MF_SEPARATOR);
	menu.AppendMenu(MF_STRING | unavailable, CMD_SHORTCUT, Localization::Get(L"shortcut.create"));
	menu.AppendMenu(MF_STRING | (m_tiles.size() > 1 ? 0 : MF_GRAYED), CMD_REORDER, Localization::Get(L"launch.menu_reorder"));
	menu.AppendMenu(MF_SEPARATOR);
	menu.AppendMenu(MF_STRING, CMD_REMOVE, Localization::Get(L"recent.remove"));
	menu.SetItemIcon(CMD_OPEN, CModernPopupMenu::LAUNCH);
	menu.SetItemIcon(CMD_OPEN_ADMIN, CModernPopupMenu::SHIELD);
	menu.SetItemIcon(CMD_SHORTCUT, CModernPopupMenu::LINK);
	menu.SetItemIcon(CMD_REORDER, CModernPopupMenu::REORDER);
	menu.SetItemIcon(CMD_REMOVE, CModernPopupMenu::REMOVE);
	if (tile.available) menu.SetDefaultItem(tile.elevated && !tile.packaged ? CMD_OPEN_ADMIN : CMD_OPEN);
	const UINT command = menu.TrackPopupMenu(TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD,
		screenPoint.x, screenPoint.y, this);
	// The menu pumps messages: find the tile again by id before acting on it.
	int current = -1;
	for (size_t i = 0; i < m_tiles.size(); ++i)
		if (m_tiles[i].id == tile.id) current = static_cast<int>(i);
	CWnd* parent = GetParent();
	if (current < 0 || !parent || m_busyTile >= 0) return;
	switch (command)
	{
	case CMD_OPEN:
	case CMD_OPEN_ADMIN:
		m_focusTile = current;
		if (m_tiles[current].available && current >= m_firstTile && current < m_firstTile + VisibleTileCount())
			parent->SendMessage(WM_LAUNCH_PANEL_TILE, static_cast<WPARAM>(current),
				command == CMD_OPEN_ADMIN ? LAUNCH_ADMIN : LAUNCH_NORMAL);
		break;
	case CMD_SHORTCUT:
		parent->SendMessage(WM_LAUNCH_PANEL_SHORTCUT, 0, reinterpret_cast<LPARAM>(&tile.id));
		break;
	case CMD_REORDER:
		m_pressed = current;
		StartOrganizing();
		break;
	case CMD_REMOVE:
	{
		Edit edit;
		edit.id = tile.id; edit.remove = TRUE;
		parent->SendMessage(WM_LAUNCH_PANEL_EDIT, 0, reinterpret_cast<LPARAM>(&edit));
		break;
	}
	}
}

void CLaunchPanel::SetBodyColor(COLORREF color)
{
	if (m_bodyColor == color) return;
	m_bodyColor = color;
	if (GetSafeHwnd()) Invalidate(FALSE);
}

void CLaunchPanel::OnKeyDown(UINT character, UINT repeatCount, UINT flags)
{
	if (m_busyTile >= 0 || m_pointerDown) return;
	const int count = static_cast<int>(m_tiles.size());
	if (count > 0)
	{
		switch (character)
		{
		case VK_LEFT: m_focusTile = max(0, m_focusTile - 1); EnsureFocusVisible(); return;
		case VK_RIGHT: m_focusTile = min(count - 1, m_focusTile + 1); EnsureFocusVisible(); return;
		case VK_HOME: m_focusTile = 0; EnsureFocusVisible(); return;
		case VK_END: m_focusTile = count - 1; EnsureFocusVisible(); return;
		case VK_RETURN:
		case VK_SPACE:
			if (!(flags & KF_REPEAT)) ActivateTile(m_focusTile);
			return;
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
	FinishOrganizing();
	Invalidate(FALSE);
}

UINT CLaunchPanel::OnGetDlgCode()
{
	return DLGC_WANTARROWS | DLGC_WANTCHARS;
}

BOOL CLaunchPanel::PreTranslateMessage(MSG* message)
{
	if (message->hwnd == m_hWnd && message->message == WM_KEYDOWN && message->wParam == VK_ESCAPE && (m_pointerDown || m_organizing))
	{
		if (m_organizing) FinishOrganizing(); else UpdateTileLayout();
		Invalidate(FALSE);
		return TRUE;
	}
	if (message->hwnd == m_hWnd && message->message == WM_KEYDOWN && message->wParam == VK_RETURN)
	{
		// Enter normally goes to the enclosing dialog's default button.
		if (!(message->lParam & (1L << 30))) ActivateTile(m_focusTile);
		return TRUE;
	}
	if (m_tooltip.GetSafeHwnd() && !m_pointerDown && !m_animating && m_busyTile < 0)
	{
		m_tooltip.RelayEvent(message);
	}
	return CWnd::PreTranslateMessage(message);
}
