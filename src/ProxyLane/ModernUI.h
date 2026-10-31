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

	int ScaleForWindow(HWND hWnd, int value);
	BOOL CreateUiFont(CFont& font, HWND hWnd, int pointSize,
		int weight = FW_NORMAL, LPCTSTR faceName = _T("Segoe UI"));
	void ApplyFontToChildren(CWnd* parent, CFont* font);
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
		STYLE_DANGER
	};

	CModernButton();
	void SetVisualStyle(VisualStyle style);
	// Colour behind the rounded corners; defaults to the page background.
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
	void SetTwoLineStatus(LPCTSTR primaryText, LPCTSTR secondaryText, Tone tone);
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
