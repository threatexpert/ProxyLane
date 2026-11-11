#pragma once
#include <afxwin.h>
#include <afxcmn.h>
#include <functional>
#include <vector>

// Presentation only. The owner retains the ordered profile references and
// commits edits; a cancelled drag never changes that model.
class CChainRouteView : public CWnd
{
public:
    enum State { Idle, Running, Passed, Failed };
    enum Action { Selection, Edit, Remove, Move };
    struct Node {
        CString name, host, protocol, tip;
        State state = Idle;
        CString elapsed;
    };
    std::function<void(Action, int, int)> onAction;
    bool followProgress = true;
    BOOL Create(CWnd* parent, UINT id);
    void SetNodes(const std::vector<Node>& nodes, int selected = -1);
    void UpdateNode(int index, const Node& node);
    void SetProgress(int index, State state, const CString& elapsed, const CString& tip);
    void ClearProgress();
    void SetEditable(bool editable);
    bool Editable() const { return m_editable; }
    int Count() const { return (int)m_nodes.size(); }
    int Selected() const { return m_selected; }
    const Node& At(int index) const { return m_nodes.at(index); }
    void Select(int index, bool reveal = true);
    void Follow(int index);
    int CurrentPage() const { return m_page; }
    int Capacity() const;
    int PageCount() const;
    CRect NodeRect(int index) const;
    int PreferredHeight(); // Compact content height, independent of common-control metrics.

protected:
    BOOL PreTranslateMessage(MSG* message) override;
    LRESULT WindowProc(UINT message, WPARAM wp, LPARAM lp) override;
    HRESULT get_accChildCount(long* count) override;
    HRESULT get_accName(VARIANT child, BSTR* name) override;
    HRESULT get_accDescription(VARIANT child, BSTR* description) override;
    HRESULT get_accRole(VARIANT child, VARIANT* role) override;
    HRESULT get_accState(VARIANT child, VARIANT* state) override;
    HRESULT get_accFocus(VARIANT* focus) override;
    HRESULT get_accSelection(VARIANT* selection) override;
    HRESULT get_accDefaultAction(VARIANT child, BSTR* action) override;
    HRESULT accSelect(long flags, VARIANT child) override;
    HRESULT accLocation(long* x, long* y, long* width, long* height, VARIANT child) override;
    HRESULT accHitTest(long x, long y, VARIANT* child) override;
    HRESULT accDoDefaultAction(VARIANT child) override;
    HRESULT accNavigate(long direction, VARIANT start, VARIANT* end) override;

private:
    enum { SnapTimer = 1, EdgeTimer = 2, SpinnerTimer = 3 };
    int S(int n) const;
    CRect Viewport() const;
    int PageWidth() const;
    CRect GripRect(int index) const;
    CRect DeleteRect(int index) const;
    CRect ArrowRect(bool next) const;
    CRect DotRect(int page) const;
    int HitNode(CPoint point) const;
    int HitDot(CPoint point) const;
    void Paint();
    void EnsureSmallFont();
    int ResultHeight() const;
    void UpdateSpinner();
    void StopSpinner();
    void InvalidateRunningIndicators();
    void ChangePage(int page, bool animate = true);
    void CancelInteraction();
    void Down(CPoint point);
    void Motion(CPoint point);
    void Up(CPoint point);
    void Key(UINT key);
    void Invoke(Action action, int index, int to = -1);
    void UpdateTip(CPoint point);
    void ClearTip();
    void ContextMenu(CPoint screen);
    int AccIndex(VARIANT child) const;
    std::vector<Node> m_nodes;
    int m_selected = -1, m_page = 0, m_pressed = -1, m_deletePressed = -1;
    int m_originPage = 0, m_drop = -1, m_edge = 0;
    bool m_editable = true, m_down = false, m_panning = false, m_grip = false, m_reordering = false;
    bool m_animating = false;
    bool m_spinning = false;
    DWORD m_spinnerStarted = 0;
    CPoint m_origin, m_point;
    double m_offset = 0, m_from = 0, m_to = 0;
    DWORD m_animationStart = 0, m_edgeSince = 0;
    int m_wheel = 0;
    CToolTipCtrl m_tip;
    CString m_tipText;
    CFont m_smallFont;
    int m_fontDpi = 0, m_smallLineHeight = 0;
    HFONT m_font = NULL; // Borrowed from the page; custom CWnd has no native font storage.
};
