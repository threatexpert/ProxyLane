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
	afx_msg BOOL OnEraseBkgnd(CDC* dc);
	afx_msg HBRUSH OnCtlColor(CDC* dc, CWnd* wnd, UINT ctlColor);

	CBrush m_backgroundBrush;
	CFont m_uiFont;
	CFont m_titleFont;

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

protected:
	virtual void PreSubclassWindow();
	virtual void DrawItem(LPDRAWITEMSTRUCT drawItemStruct);
	afx_msg void OnMouseMove(UINT flags, CPoint point);
	afx_msg LRESULT OnMouseLeave(WPARAM, LPARAM);

	VisualStyle m_visualStyle;
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
		TONE_SUCCESS,
		TONE_DANGER
	};

	CStatusLabel();
	void SetStatus(LPCTSTR text, Tone tone);
	void SetTwoLineStatus(LPCTSTR primaryText, LPCTSTR secondaryText, Tone tone);

protected:
	virtual void PreSubclassWindow();
	virtual void DrawItem(LPDRAWITEMSTRUCT drawItemStruct);

	Tone m_tone;
	BOOL m_twoLine;
	CString m_primaryText;
	CString m_secondaryText;
};
