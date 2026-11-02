#pragma once

#include <afxwin.h>
#include <vector>

namespace UiTheme
{
	COLORREF WindowBackground();
	COLORREF PageBackground();
	COLORREF SidebarBackground();
	COLORREF TextPrimary();
	COLORREF TextSecondary();
	COLORREF Border();
	COLORREF Accent();
	COLORREF AccentHover();
	COLORREF AccentSoft();
	COLORREF AccentSoftBorder();
	COLORREF Surface();
	COLORREF BorderSoft();
	// Fields, inactive pills and other shapes that sit on a card.
	COLORREF Inner();
	COLORREF Hover();
	COLORREF TextDisabled();
	// Accent used for text and icons; Accent() itself is meant for fills.
	COLORREF AccentText();
	COLORREF Warning();
	COLORREF WarningSoft();

	// Fonts, DPI awareness and the saved theme. Call once before any window exists.
	void Initialize();
	BOOL IsDark();
	void SetDark(BOOL dark);
	// Dark caption bar on Windows versions that support it.
	void ApplyWindowChrome(HWND hWnd);
	// Dark scroll bars and headers for native lists and multi-line edits.
	void ApplyControlTheme(HWND hWnd);
	void ApplyListColors(HWND hWnd);
	// Shared brush for a theme colour; owned by the theme, never delete it.
	HBRUSH BrushFor(COLORREF color);
	// What a control sits on: the card under it, otherwise the page.
	COLORREF BackdropFor(CWnd* control);
	COLORREF BackdropAmongCards(CWnd* parent, CWnd* control);

	// Anti-aliased drawing (GDI+, available on Windows XP and later).
	// fill/border may be CLR_NONE to skip that part. `radius` is in pixels.
	void FillRoundRect(HDC dc, const CRect& rect, int radius, COLORREF fill, COLORREF border);
	void DrawElevationBadge(HDC dc, const CRect& rect);
	// Transparent image-list overlay; caller owns the returned icon.
	HICON CreateElevationOverlay(int iconSize);

	enum Glyph
	{
		GLYPH_APPS,
		GLYPH_PROXY,
		GLYPH_LOG,
		GLYPH_MONITOR,
		GLYPH_ABOUT,
		GLYPH_DROP,
		GLYPH_PROXY_TOOL,
		GLYPH_CHEVRON_DOWN,
		GLYPH_CHEVRON_UP,
		GLYPH_GLOBE,
		GLYPH_TABLE,
		GLYPH_MOON,
		GLYPH_SIDEBAR,
		GLYPH_ARROW_UP,
		GLYPH_ARROW_DOWN,
		GLYPH_CHECK,
		GLYPH_MINUS,
		GLYPH_PLAY
	};
	// Draws a line glyph centred in `box`; `strokePx` is the pen width in pixels.
	void DrawGlyph(HDC dc, Glyph glyph, const CRect& box, COLORREF color, float strokePx);
	void DrawFilledGlyph(HDC dc, Glyph glyph, const CRect& box, COLORREF color);
	COLORREF Success();
	COLORREF SuccessSoft();
	COLORREF Danger();
	COLORREF DangerSoft();

	int ScaleForWindow(HWND hWnd, int value);
	// A NULL face means the bundled UI font.
	BOOL CreateUiFont(CFont& font, HWND hWnd, int pointSize,
		int weight = FW_NORMAL, LPCTSTR faceName = NULL);
	void ApplyFontToChildren(CWnd* parent, CFont* font);
}

class CModernDialog : public CDialog
{
	DECLARE_DYNAMIC(CModernDialog)

public:
	CModernDialog(UINT templateId, CWnd* parent = NULL);
	virtual ~CModernDialog();
	void AdoptNativeControls();
	// What a child sits on; pages that paint their own cards override this.
	virtual COLORREF BackdropForChild(CWnd* child);
	// Card frames on this page, found once instead of on every paint.
	std::vector<HWND> m_cards;

protected:
	virtual BOOL OnInitDialog();
	virtual void OnOK();
	virtual void OnCancel();
	afx_msg void OnSize(UINT type, int cx, int cy);
	afx_msg BOOL OnEraseBkgnd(CDC* dc);
	afx_msg HBRUSH OnCtlColor(CDC* dc, CWnd* wnd, UINT ctlColor);
	void LayoutPageHeader();
	// Static texts that should be drawn in the secondary (muted) colour.
	virtual BOOL UsesSecondaryText(UINT controlId) const;

	CBrush m_backgroundBrush;
	CFont m_uiFont;
	CFont m_titleFont;
	UINT m_templateId;

	DECLARE_MESSAGE_MAP()
};

class CModernButton : public CButton
{
	DECLARE_DYNAMIC(CModernButton)

public:
	enum VisualStyle
	{
		STYLE_SECONDARY,
		STYLE_PRIMARY,
		STYLE_DANGER,
		STYLE_PILL,
		STYLE_PILL_ACTIVE,
		STYLE_GHOST
	};

	CModernButton();
	void SetVisualStyle(VisualStyle style);
	// Colour behind the rounded corners; follows the card or page by default.
	void SetBackdropColor(COLORREF color);

protected:
	virtual void PreSubclassWindow();
	virtual void DrawItem(LPDRAWITEMSTRUCT drawItemStruct);
	afx_msg void OnMouseMove(UINT flags, CPoint point);
	afx_msg LRESULT OnMouseLeave(WPARAM, LPARAM);

	VisualStyle m_visualStyle;
	COLORREF m_backdrop;
	BOOL m_hot;

	DECLARE_MESSAGE_MAP()
};

// Check boxes draw as switches and radio buttons as segmented pills. The check
// state stays behind BM_GETCHECK/BM_SETCHECK, so callers keep using CButton's API.
class CToggleButton : public CButton
{
	DECLARE_DYNAMIC(CToggleButton)

public:
	CToggleButton();

protected:
	virtual void PreSubclassWindow();
	virtual void PostNcDestroy();
	virtual void DrawItem(LPDRAWITEMSTRUCT drawItemStruct);
	afx_msg LRESULT OnGetCheck(WPARAM, LPARAM);
	afx_msg LRESULT OnSetCheck(WPARAM state, LPARAM);
	afx_msg UINT OnGetDlgCode();
	afx_msg BOOL OnClicked();
	afx_msg void OnLButtonDblClk(UINT flags, CPoint point);
	afx_msg void OnMouseMove(UINT flags, CPoint point);
	afx_msg LRESULT OnMouseLeave(WPARAM, LPARAM);
	afx_msg void OnTimer(UINT_PTR timer);

	BOOL m_radio;
	float m_knob;      // 0 = off, 1 = on; slides between the two.
	DWORD m_animStart;
	BOOL m_automatic;
	BOOL m_autoDelete;
	int m_check;
	BOOL m_hot;

	friend class CModernDialog;

	DECLARE_MESSAGE_MAP()
};

class CStatusLabel : public CStatic
{
	DECLARE_DYNAMIC(CStatusLabel)

public:
	enum Tone
	{
		TONE_NEUTRAL,
		TONE_INFO,
		TONE_WARNING,
		TONE_SUCCESS,
		TONE_DANGER
	};

	CStatusLabel();
	void SetStatus(LPCTSTR text, Tone tone);
	void SetTwoLineStatus(LPCTSTR primaryText, LPCTSTR secondaryText, Tone tone, BOOL compact = FALSE);
	void SetDetailText(const CString& text);
	void SetTrafficRates(LPCTSTR uploadText, LPCTSTR downloadText);
	void SetBackdropColor(COLORREF color);

protected:
	virtual void PreSubclassWindow();
	virtual BOOL PreTranslateMessage(MSG* message);
	virtual void DrawItem(LPDRAWITEMSTRUCT drawItemStruct);
	afx_msg void OnSize(UINT type, int cx, int cy);
	afx_msg LRESULT OnInitializeTooltip(WPARAM wParam, LPARAM lParam);
	void UpdateOverflowTooltip();

	Tone m_tone;
	COLORREF m_backdrop;
	BOOL m_twoLine;
	BOOL m_compact;
	CString m_detailText;
	CFont m_detailFont;
	CString m_primaryText;
	CString m_secondaryText;
	CString m_uploadText;
	CString m_downloadText;
	CString m_tooltipText;
	CToolTipCtrl m_tooltip;

	DECLARE_MESSAGE_MAP()
};

// Replaces a group box with a flat, rounded section card. Only the border and
// the title are painted, so controls placed over it keep their own background.
class CCardFrame : public CButton
{
	DECLARE_DYNAMIC(CCardFrame)

protected:
	virtual void PreSubclassWindow();
	virtual void PostNcDestroy();
	virtual void DrawItem(LPDRAWITEMSTRUCT drawItemStruct);
	afx_msg BOOL OnEraseBkgnd(CDC* dc);
	afx_msg LRESULT OnNcHitTest(CPoint point);
	afx_msg LRESULT OnSendToBack(WPARAM, LPARAM);

	BOOL m_autoDelete = FALSE;
	friend class CModernDialog;

	DECLARE_MESSAGE_MAP()
};

// Tab strip drawn as pills. Selection and hit testing stay native.
class CSoftTab : public CTabCtrl
{
	DECLARE_DYNAMIC(CSoftTab)

protected:
	virtual void PreSubclassWindow();
	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC* dc);
	afx_msg void OnSize(UINT type, int cx, int cy);

	DECLARE_MESSAGE_MAP()
};

// List header painted to match the theme; sizing and clicks stay native.
class CSoftHeader : public CHeaderCtrl
{
	DECLARE_DYNAMIC(CSoftHeader)

protected:
	virtual void PostNcDestroy();
	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC* dc);

	DECLARE_MESSAGE_MAP()
};

// Single/multi-line edit with a soft rounded border and inner padding; the
// border turns to the accent colour while the control has focus.
class CSoftEdit : public CEdit
{
	DECLARE_DYNAMIC(CSoftEdit)

protected:
	virtual void PreSubclassWindow();
	virtual void PostNcDestroy();
	BOOL m_autoDelete = FALSE;
	friend class CModernDialog;
	afx_msg void OnNcCalcSize(BOOL calcValidRects, NCCALCSIZE_PARAMS* params);
	afx_msg void OnNcPaint();
	afx_msg void OnSetFocus(CWnd* oldWindow);
	afx_msg void OnKillFocus(CWnd* newWindow);
	afx_msg void OnEnable(BOOL enable);
	afx_msg LRESULT OnNcHitTest(CPoint point);

	DECLARE_MESSAGE_MAP()
};

// Combo box drawn with the same rounded field look as CSoftEdit. The drop-down
// list itself stays native; only the closed field and its arrow are painted.
class CSoftCombo : public CComboBox
{
	DECLARE_DYNAMIC(CSoftCombo)

public:
	CSoftCombo();

protected:
	virtual void PreSubclassWindow();
	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC* dc);
	afx_msg void OnMouseMove(UINT flags, CPoint point);
	afx_msg LRESULT OnMouseLeave(WPARAM, LPARAM);
	afx_msg void OnEnable(BOOL enable);
	afx_msg BOOL OnStateChanged();

	BOOL m_hot;

	DECLARE_MESSAGE_MAP()
};
