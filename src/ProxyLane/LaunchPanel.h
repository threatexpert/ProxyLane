#pragma once

#include <afxwin.h>
#include <afxcmn.h>
#include <vector>
#include "ModernUI.h"

#define WM_LAUNCH_PANEL_TILE (WM_APP + 321)
#define WM_LAUNCH_PANEL_PROFILE (WM_APP + 322)
#define WM_LAUNCH_PANEL_EDIT (WM_APP + 323)
#define WM_LAUNCH_PANEL_SHORTCUT (WM_APP + 324)

// A native, keyboard-accessible button painted as a quiet text link.
class CLaunchProfileLink : public CButton
{
public:
	void SetTip(const CString& text);
protected:
	virtual void DrawItem(LPDRAWITEMSTRUCT item);
	virtual BOOL PreTranslateMessage(MSG* message);
	afx_msg void OnMouseMove(UINT flags, CPoint point);
	afx_msg LRESULT OnMouseLeave(WPARAM, LPARAM);
	afx_msg BOOL OnSetCursor(CWnd* window, UINT hitTest, UINT message);
	afx_msg void OnClicked();
	BOOL m_hot = FALSE;
	CToolTipCtrl m_tooltip;
	DECLARE_MESSAGE_MAP()
};

// Launch area at the top of the applications page: a short explanation of
// what dropping/choosing an app does, followed by one-click recent apps.
// The action button is a real child of the page and is positioned into
// ActionSlot(); this window only paints the card and the recent-app tiles.
class CLaunchPanel : public CWnd
{
	DECLARE_DYNAMIC(CLaunchPanel)

public:
	// WM_LAUNCH_PANEL_TILE lParam: clicks retain the saved preference;
	// context-menu actions explicitly choose the next successful default.
	enum LaunchMode { LAUNCH_DEFAULT = 0, LAUNCH_ADMIN, LAUNCH_NORMAL };
	struct Tile
	{
		CString id;
		HICON icon;
		CString name;
		CString tip;
		BOOL lightIcon; // white-on-transparent icon (Store apps); drawn on a dark plate
		BOOL elevated;
		BOOL pinned;
		BOOL available = TRUE;
		BOOL packaged = FALSE; // Store app: cannot be started elevated
		Tile() : icon(NULL), lightIcon(FALSE), elevated(FALSE), pinned(FALSE) {}
	};
	struct Edit { CString id, targetId; BOOL remove; };

	CLaunchPanel();
	virtual ~CLaunchPanel();

	BOOL Create(CWnd* parent, UINT id);
	void SetText(const CString& title, const CString& body,
		const CString& recentTitle, const CString& emptyText);
	void SetActionWidth(int width);
	void SetEnabledState(BOOL enabled);
	void SetTiles(const std::vector<Tile>& tiles);
	void SetBusyTile(int index);
	void SetCompact(BOOL compact);
	void SetProfileSummary(const CString& summary);
	// Colour of the header's second line; CLR_NONE restores the secondary text colour.
	void SetBodyColor(COLORREF color);
	BOOL IsInteracting() const { return m_pointerDown || m_removePressed >= 0; }
	void FinishOrganizing();

	int PreferredHeight(int width = -1) const;
	// Rectangle, in this window's client coordinates, reserved for the action button.
	CRect ActionSlot(int buttonWidth, int buttonHeight) const;

protected:
	virtual BOOL PreTranslateMessage(MSG* message);
	afx_msg void OnPaint();
	afx_msg BOOL OnEraseBkgnd(CDC* dc);
	afx_msg void OnSize(UINT type, int cx, int cy);
	afx_msg void OnMouseMove(UINT flags, CPoint point);
	afx_msg LRESULT OnMouseLeave(WPARAM, LPARAM);
	afx_msg void OnLButtonDown(UINT flags, CPoint point);
	afx_msg void OnLButtonUp(UINT flags, CPoint point);
	afx_msg void OnRButtonDown(UINT flags, CPoint point);
	afx_msg void OnContextMenu(CWnd* window, CPoint point);
	afx_msg void OnKeyDown(UINT character, UINT repeatCount, UINT flags);
	afx_msg BOOL OnMouseWheel(UINT flags, short delta, CPoint point);
	afx_msg void OnTimer(UINT_PTR eventId);
	afx_msg void OnCaptureChanged(CWnd* window);
	afx_msg LRESULT OnHorizontalWheel(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnGesture(WPARAM wParam, LPARAM lParam);
	afx_msg void OnSetFocus(CWnd* oldWindow);
	afx_msg void OnKillFocus(CWnd* newWindow);
	afx_msg UINT OnGetDlgCode();
	afx_msg void OnDestroy();

private:
	int Scale(int value) const;
	int TileWidth() const;
	int TileHeight() const;
	int TileTop(int width = -1) const;
	int HeaderExtraHeight(int width = -1) const;
	void HeaderRects(CRect& title, CRect& summary, CRect& body) const;
	void UpdateProfileLayout();
	void MeasureHeaderText();
	void EnsureFonts();
	void MeasureRecentTitle();
	int VisibleTileCount() const;
	int TileCapacity() const;
	void UpdateTileLayout();
	void RebuildTooltips();
	void ClearTooltips();
	void ChangePage(int direction);
	void EnsureFocusVisible();
	int PageWidth() const;
	int PageCount() const;
	CRect TileViewport() const;
	void AnimateToPage(int page);
	void StopMotion();
	void BeginDrag(CPoint point);
	void MoveDrag(CPoint point);
	void EndDrag(CPoint point, BOOL allowClick);
	CRect TileRect(int index) const;
	CRect HeaderTextRect() const;
	int HitTestTile(CPoint point) const;
	void SetHotTile(int index);
	void ActivateTile(int index);
	void StartOrganizing();
	void MoveOrganizedTile(CPoint point);
	void CancelTileMove();
	void ConfigureTouch();
	CRect RemoveRect(int index) const;
	int HitTestRemove(CPoint point) const;
	void ShowTileMenu(int index, CPoint screenPoint);

	std::vector<Tile> m_tiles;
	CString m_title;
	CString m_body;
	CString m_recentTitle;
	CString m_emptyText;
	CString m_profileSummary;
	CString m_profileTip;
	CLaunchProfileLink m_profileLink;
	int m_titleWidth = 0;
	int m_profileWidth = 0;
	BOOL m_enabled;
	BOOL m_compact;
	int m_hot;
	int m_pressed;
	int m_focusTile;
	int m_firstTile;
	int m_wheelDelta;
	BOOL m_tracking;
	CFont m_titleFont;
	CFont m_bodyFont;
	CFont m_labelFont;
	int m_fontDpi;
	int m_recentTitleWidth;
	int m_actionWidth;
	CToolTipCtrl m_tooltip;
	int m_tipCount;
	int m_busyTile;
	BOOL m_pointerDown;
	BOOL m_dragging;
	BOOL m_touchPanning;
	BOOL m_animating;
	CPoint m_dragOrigin;
	int m_dragPage;
	double m_scrollOffset;
	double m_animationFrom;
	double m_animationTo;
	DWORD m_animationStart;
	BOOL m_organizing = FALSE, m_reordering = FALSE;
	int m_removePressed = -1;
	COLORREF m_bodyColor = CLR_NONE;
	int m_editIndex = -1, m_edgeDirection = 0;
	DWORD m_edgeSince = 0;
	CPoint m_editPoint;
	std::vector<Tile> m_beforeMove;

	DECLARE_MESSAGE_MAP()
};
