#pragma once

#include <afxwin.h>
#include <afxcmn.h>
#include <vector>

#define WM_LAUNCH_PANEL_TILE (WM_APP + 321)

// Launch area at the top of the applications page: a short explanation of
// what dropping/choosing an app does, followed by one-click recent apps.
// The action button is a real child of the page and is positioned into
// ActionSlot(); this window only paints the card and the recent-app tiles.
class CLaunchPanel : public CWnd
{
	DECLARE_DYNAMIC(CLaunchPanel)

public:
	struct Tile
	{
		HICON icon;
		CString name;
		CString tip;
		BOOL lightIcon; // white-on-transparent icon (Store apps); drawn on a dark plate
		Tile() : icon(NULL), lightIcon(FALSE) {}
	};

	CLaunchPanel();
	virtual ~CLaunchPanel();

	BOOL Create(CWnd* parent, UINT id);
	void SetText(const CString& title, const CString& body,
		const CString& recentTitle, const CString& emptyText);
	void SetActionWidth(int width);
	void SetEnabledState(BOOL enabled);
	void SetTiles(const std::vector<Tile>& tiles);

	int PreferredHeight() const;
	// Rectangle, in this window's client coordinates, reserved for the action button.
	CRect ActionSlot(int buttonWidth, int buttonHeight) const;

protected:
	virtual BOOL PreTranslateMessage(MSG* message);
	virtual BOOL OnNotify(WPARAM wParam, LPARAM lParam, LRESULT* result);
	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC* dc);
	afx_msg void OnSize(UINT type, int cx, int cy);
	afx_msg void OnMouseMove(UINT flags, CPoint point);
	afx_msg LRESULT OnMouseLeave(WPARAM, LPARAM);
	afx_msg void OnLButtonDown(UINT flags, CPoint point);
	afx_msg void OnLButtonUp(UINT flags, CPoint point);
	afx_msg void OnKeyDown(UINT character, UINT repeatCount, UINT flags);
	afx_msg void OnSetFocus(CWnd* oldWindow);
	afx_msg void OnKillFocus(CWnd* newWindow);
	afx_msg UINT OnGetDlgCode();
	afx_msg void OnDestroy();

private:
	int Scale(int value) const;
	void EnsureFonts();
	int VisibleTileCount() const;
	CRect TileRect(int index) const;
	CRect HeaderTextRect() const;
	int HitTestTile(CPoint point) const;
	void SetHotTile(int index);
	void ActivateTile(int index);

	std::vector<Tile> m_tiles;
	CString m_title;
	CString m_body;
	CString m_recentTitle;
	CString m_emptyText;
	BOOL m_enabled;
	int m_hot;
	int m_pressed;
	int m_focusTile;
	BOOL m_tracking;
	CFont m_titleFont;
	CFont m_bodyFont;
	CFont m_labelFont;
	int m_fontDpi;
	int m_actionWidth;
	CToolTipCtrl m_tooltip;
	CString m_tipText;

	DECLARE_MESSAGE_MAP()
};
