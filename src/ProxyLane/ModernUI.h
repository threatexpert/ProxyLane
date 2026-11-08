#pragma once

#include <afxwin.h>

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

	// Anti-aliased drawing (GDI+, available on Windows XP and later).
	// fill/border may be CLR_NONE to skip that part. `radius` is in pixels.
	void FillRoundRect(HDC dc, const CRect& rect, int radius, COLORREF fill, COLORREF border);
	void DrawElevationBadge(HDC dc, const CRect& rect);
	// Round "remove" badge: a red disc with a white ring and cross, drawn over a
	// tile corner. `pressed` darkens it while the pointer is held on it.
	void DrawRemoveBadge(HDC dc, const CRect& rect, BOOL pressed);
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
		GLYPH_CHEVRON_UP
	};
	// Draws a line glyph centred in `box`; `strokePx` is the pen width in pixels.
	void DrawGlyph(HDC dc, Glyph glyph, const CRect& box, COLORREF color, float strokePx);
	COLORREF Success();
	COLORREF SuccessSoft();
	COLORREF Danger();
	COLORREF DangerSoft();

	// Per-monitor DPI where the OS provides it (Windows 10 1607+), otherwise system DPI.
	int WindowDpi(HWND hWnd);
	int ScaleForWindow(HWND hWnd, int value);
	// faceName NULL picks the UI face for the current language. The font is
	// remembered so RescaleUiFonts can recreate it after a DPI change.
	BOOL CreateUiFont(CFont& font, HWND hWnd, int pointSize,
		int weight = FW_NORMAL, LPCTSTR faceName = NULL);
	void ApplyFontToChildren(CWnd* parent, CFont* font);
	// Recreates the CreateUiFont fonts owned by `root` or its descendants at their
	// current DPI and hands the new fonts to every window under `root` that used them.
	void RescaleUiFonts(HWND root);
	// Drops remembered fonts owned by `root` or its descendants (call before they go away).
	void ForgetUiFonts(HWND root);
}

class CModernDialog : public CDialog
{
	DECLARE_DYNAMIC(CModernDialog)

public:
	CModernDialog(UINT templateId, CWnd* parent = NULL);
	virtual ~CModernDialog();

protected:
	virtual BOOL OnInitDialog();
	virtual void OnOK();
	virtual void OnCancel();
	afx_msg void OnSize(UINT type, int cx, int cy);
	afx_msg BOOL OnEraseBkgnd(CDC* dc);
	afx_msg HBRUSH OnCtlColor(CDC* dc, CWnd* wnd, UINT ctlColor);
	afx_msg void OnDestroy();
	afx_msg LRESULT OnDpiChanged(WPARAM wParam, LPARAM lParam);
	void LayoutPageHeader();
	// Static texts that should be drawn in the secondary (muted) colour.
	virtual BOOL UsesSecondaryText(UINT controlId) const;

	CBrush m_backgroundBrush;
	CBrush m_fieldBrush, m_disabledFieldBrush;
	CFont m_uiFont;
	CFont m_titleFont;
	UINT m_templateId;
	int m_dpi;

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
		STYLE_GHOST,
		// Accent-tinted secondary action: as visible as a primary button beside it.
		STYLE_SOFT
	};
	enum Icon
	{
		ICON_NONE,
		ICON_POWER, // enable / start
		ICON_GAUGE  // test a connection (speedometer)
	};

	CModernButton();
	void SetVisualStyle(VisualStyle style);
	// Line icon drawn before the caption; callers add IconWidth() to the width.
	void SetIcon(Icon icon);
	int IconWidth() const;
	// Colour behind the rounded corners; defaults to the page background.
	void SetBackdropColor(COLORREF color);

protected:
	virtual void PreSubclassWindow();
	virtual void DrawItem(LPDRAWITEMSTRUCT drawItemStruct);
	afx_msg void OnMouseMove(UINT flags, CPoint point);
	afx_msg LRESULT OnMouseLeave(WPARAM, LPARAM);

	VisualStyle m_visualStyle;
	Icon m_icon;
	COLORREF m_backdrop;
	BOOL m_hot;

	DECLARE_MESSAGE_MAP()
};

// Switch control adapted from lijing6006/ProxyLane PR #3.
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
	// Inline: a single-line status draws as a tone dot plus text instead of a
	// boxed badge, so it does not read as a (disabled) button next to buttons.
	void SetInlineStyle(BOOL inlineStyle);
	void SetStatus(LPCTSTR text, Tone tone);
	Tone GetTone() const { return m_tone; }
	void SetTwoLineStatus(LPCTSTR primaryText, LPCTSTR secondaryText, Tone tone, BOOL compact = FALSE);
	void SetDetailText(const CString& text);
	// Two-line status only: rates as values (for example "1.2 KB/s"); the card
	// draws the arrows and the localized Upload/Download labels itself.
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
	BOOL m_inline;
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
	virtual void DrawItem(LPDRAWITEMSTRUCT drawItemStruct);
	afx_msg BOOL OnEraseBkgnd(CDC* dc);
	afx_msg LRESULT OnNcHitTest(CPoint point);

	DECLARE_MESSAGE_MAP()
};

// Single/multi-line edit with a soft rounded border and inner padding; the
// border turns to the accent colour while the control has focus.
class CSoftEdit : public CEdit
{
	DECLARE_DYNAMIC(CSoftEdit)

protected:
	bool m_autoDelete = false;
	friend class CModernDialog;
	virtual void PostNcDestroy();
	virtual void PreSubclassWindow();
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
