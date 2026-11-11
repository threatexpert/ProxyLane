#include "stdafx.h"
#include "ChainRouteView.h"
#include "LaunchPanelPaging.h"
#include "ModernUI.h"
#include "Localization.h"
#include <oleacc.h>

namespace {
COLORREF RunningColor() { return RGB(175, 122, 0); }
void Line(CDC& dc, CPoint a, CPoint b, COLORREF color, int width) {
    CPen pen(PS_SOLID, width, color); CPen* old = dc.SelectObject(&pen);
    dc.MoveTo(a); dc.LineTo(b); dc.SelectObject(old);
}
HRESULT StringResult(const CString& value, BSTR* out) {
    if (!out) return E_POINTER;
    *out = value.AllocSysString(); return *out ? S_OK : E_OUTOFMEMORY;
}
}

BOOL CChainRouteView::Create(CWnd* parent, UINT id) {
    BOOL ok = CreateEx(0, AfxRegisterWndClass(CS_DBLCLKS, LoadCursor(NULL, IDC_ARROW)),
        Localization::Get(L"chain.view.name"), WS_CHILD | WS_TABSTOP, CRect(), parent, id);
    if (!ok) return FALSE;
    EnableActiveAccessibility();
    if (m_tip.Create(this, TTS_ALWAYSTIP | TTS_NOPREFIX)) {
        m_tip.SetMaxTipWidth(S(460)); m_tip.SetDelayTime(TTDT_AUTOPOP, 20000);
    }
    return TRUE;
}
int CChainRouteView::S(int n) const { return UiTheme::ScaleForWindow(m_hWnd, n); }
CRect CChainRouteView::Viewport() const {
    CRect r; GetClientRect(r); r.DeflateRect(S(24), 0, S(24), S(22));
    r.right = max(r.left + 1, r.right); r.bottom = max(r.top + 1, r.bottom); return r;
}
int CChainRouteView::PageWidth() const { return Viewport().Width(); }
int CChainRouteView::Capacity() const { return max(1, (PageWidth() + S(8)) / S(188)); }
int CChainRouteView::PageCount() const { return LaunchPanelPaging::PageCount(Count(), Capacity()); }
CRect CChainRouteView::NodeRect(int index) const {
    const CRect view = Viewport(); const int cap = Capacity();
    const int width = max(1, (view.Width() - S(8) * (cap - 1) - 2) / cap);
    const int left = view.left + 1 + index / cap * PageWidth() + index % cap * (width + S(8)) - (int)m_offset;
    return CRect(left, view.top + 1, left + width, view.bottom - 1);
}
CRect CChainRouteView::GripRect(int i) const { CRect r = NodeRect(i); return CRect(r.left + S(2), r.top, r.left + S(26), r.top + S(24)); }
CRect CChainRouteView::DeleteRect(int i) const { CRect r = NodeRect(i); return CRect(r.right - S(26), r.top, r.right - S(2), r.top + S(24)); }
CRect CChainRouteView::ArrowRect(bool next) const {
    CRect r; GetClientRect(r); const int y = Viewport().CenterPoint().y;
    return CRect(next ? r.right - S(22) : 0, y - S(20), next ? r.right : S(22), y + S(20));
}
CRect CChainRouteView::DotRect(int page) const {
    const int count = min(7, PageCount()), first = max(0, min(m_page - 3, PageCount() - count));
    if (page < first || page >= first + count) return CRect();
    CRect r; GetClientRect(r); const int left = (r.Width() - count * S(22)) / 2 + (page - first) * S(22);
    return CRect(left, r.bottom - S(22), left + S(22), r.bottom);
}
int CChainRouteView::HitNode(CPoint point) const {
    if (!Viewport().PtInRect(point) || m_animating) return -1;
    for (int i = m_page * Capacity(); i < min(Count(), (m_page + 1) * Capacity()); ++i)
        if (NodeRect(i).PtInRect(point)) return i;
    return -1;
}
int CChainRouteView::HitDot(CPoint point) const {
    const int first = max(0, m_page - 6), last = min(PageCount(), m_page + 7);
    for (int p = first; p < last; ++p) if (DotRect(p).PtInRect(point)) return p;
    return -1;
}
void CChainRouteView::EnsureSmallFont() {
    const int dpi = UiTheme::WindowDpi(m_hWnd);
    if (m_fontDpi == dpi) return;
    m_smallFont.DeleteObject(); UiTheme::CreateUiFont(m_smallFont, m_hWnd, 8);
    CClientDC dc(this); CFont* old = dc.SelectObject(&m_smallFont);
    TEXTMETRIC metrics = {}; dc.GetTextMetrics(&metrics); dc.SelectObject(old);
    m_smallLineHeight = metrics.tmHeight; m_fontDpi = dpi;
}
int CChainRouteView::ResultHeight() const { return max(S(17), m_smallLineHeight + S(4)); }
int CChainRouteView::PreferredHeight() {
    EnsureSmallFont();
    CClientDC dc(this);
    CFont* old = dc.SelectObject(GetFont() ? GetFont() : CFont::FromHandle((HFONT)GetStockObject(DEFAULT_GUI_FONT)));
    TEXTMETRIC metrics = {}; dc.GetTextMetrics(&metrics); dc.SelectObject(old);
    // Grip/protocol row, name, Host, result row, card borders and page dots.
    // Hidden ListCtrl row/header measurements are not reliable on older hosts.
    return S(23) + metrics.tmHeight + S(1) + m_smallLineHeight + ResultHeight() + 2 + S(22);
}
void CChainRouteView::SetNodes(const std::vector<Node>& nodes, int selected) {
    CancelInteraction(); m_nodes = nodes; m_selected = selected >= 0 && selected < Count() ? selected : -1;
    UpdateSpinner();
    ChangePage(m_selected >= 0 ? m_selected / Capacity() : min(m_page, PageCount() - 1), false);
    ::NotifyWinEvent(EVENT_OBJECT_REORDER, m_hWnd, OBJID_CLIENT, CHILDID_SELF); Invalidate(FALSE);
}
void CChainRouteView::UpdateNode(int index, const Node& node) {
    if (index < 0 || index >= Count()) return;
    m_nodes[index] = node; UpdateSpinner(); ClearTip(); Invalidate(FALSE);
    ::NotifyWinEvent(EVENT_OBJECT_NAMECHANGE, m_hWnd, OBJID_CLIENT, index + 1);
}
void CChainRouteView::SetProgress(int index, State state, const CString& elapsed, const CString& tip) {
    if (index < 0 || index >= Count()) return;
    Node& n = m_nodes[index]; const bool changed = n.state != state;
    if (changed || n.elapsed != elapsed) { n.state = state; n.elapsed = elapsed; Invalidate(FALSE); }
    n.tip = tip;
    if (changed) UpdateSpinner();
    if (changed) ::NotifyWinEvent(EVENT_OBJECT_STATECHANGE, m_hWnd, OBJID_CLIENT, index + 1);
}
void CChainRouteView::ClearProgress() {
    for (auto& n : m_nodes) { n.state = Idle; n.elapsed.Empty(); n.tip.Empty(); }
    StopSpinner();
    ClearTip(); Invalidate(FALSE);
}
void CChainRouteView::SetEditable(bool editable) {
    if (m_editable == editable) return;
    CancelInteraction(); m_editable = editable; Invalidate(FALSE);
}
void CChainRouteView::StopSpinner() {
    if (m_spinning) KillTimer(SpinnerTimer);
    m_spinning = false;
}
void CChainRouteView::UpdateSpinner() {
    bool running = false;
    for (const auto& node : m_nodes) if (node.state == Running) { running = true; break; }
    BOOL animations = TRUE;
    SystemParametersInfo(SPI_GETCLIENTAREAANIMATION, 0, &animations, 0);
    if (!running || !IsWindowVisible() || !animations) { StopSpinner(); return; }
    if (!m_spinning) {
        m_spinnerStarted = GetTickCount();
        m_spinning = SetTimer(SpinnerTimer, 40, NULL) != 0;
    }
}
void CChainRouteView::InvalidateRunningIndicators() {
    const CRect viewport = Viewport();
    for (int i = 0; i < Count(); ++i) if (m_nodes[i].state == Running) {
        const CRect card = NodeRect(i);
        CRect dot(card.right - S(25), card.bottom - ResultHeight(), card.right - S(11), card.bottom), clipped;
        if (clipped.IntersectRect(dot, viewport)) InvalidateRect(clipped, FALSE);
    }
}
void CChainRouteView::Select(int index, bool reveal) {
    if (index < -1 || index >= Count()) return;
    m_selected = index;
    if (reveal && index >= 0) ChangePage(index / Capacity());
    Invalidate(FALSE);
    ::NotifyWinEvent(EVENT_OBJECT_SELECTION, m_hWnd, OBJID_CLIENT, index >= 0 ? index + 1 : CHILDID_SELF);
}
void CChainRouteView::Follow(int index) {
    if (followProgress && !m_down && index >= 0 && index < Count() && index / Capacity() != m_page)
        ChangePage(index / Capacity());
}
void CChainRouteView::ChangePage(int page, bool animate) {
    m_page = LaunchPanelPaging::ClampPage(page, PageCount()); ClearTip();
    m_from = m_offset; m_to = (double)m_page * PageWidth(); m_animationStart = GetTickCount();
    BOOL animations = TRUE; SystemParametersInfo(SPI_GETCLIENTAREAANIMATION, 0, &animations, 0);
    m_animating = animate && animations && m_from != m_to;
    if (m_animating && !SetTimer(SnapTimer, 15, NULL)) m_animating = false;
    if (!m_animating) { KillTimer(SnapTimer); m_offset = m_to; }
    Invalidate(FALSE);
}
void CChainRouteView::CancelInteraction() {
    m_down = m_panning = m_grip = m_reordering = m_animating = false;
    m_pressed = m_deletePressed = m_drop = -1; m_edge = 0;
    KillTimer(SnapTimer); KillTimer(EdgeTimer); ClearTip();
    if (GetCapture() == this) ReleaseCapture();
    m_offset = (double)m_page * PageWidth();
}
void CChainRouteView::Invoke(Action action, int index, int to) {
    if (index < 0 || index >= Count() || (action != Selection && !m_editable)) return;
    Select(index, false);
    if (onAction) onAction(action, index, to);
}
void CChainRouteView::Down(CPoint point) {
    SetFocus(); ClearTip();
    if (ArrowRect(false).PtInRect(point) || ArrowRect(true).PtInRect(point)) {
        followProgress = false; ChangePage(m_page + (ArrowRect(true).PtInRect(point) ? 1 : -1)); return;
    }
    const int dot = HitDot(point); if (dot >= 0) { followProgress = false; ChangePage(dot); return; }
    const int hit = HitNode(point); if (hit < 0) return;
    m_origin = m_point = point; m_originPage = m_page; m_pressed = hit; m_down = true;
    m_grip = m_editable && GripRect(hit).PtInRect(point);
    m_deletePressed = m_editable && DeleteRect(hit).PtInRect(point) ? hit : -1;
    SetCapture(); Select(hit, false);
}
void CChainRouteView::Motion(CPoint point) {
    m_point = point;
    if (!m_down) { UpdateTip(point); return; }
    const int dx = point.x - m_origin.x, dy = point.y - m_origin.y;
    if (m_deletePressed >= 0) return;
    if (m_grip) {
        if (!m_reordering && (abs(dx) >= S(6) || abs(dy) >= S(6))) { m_reordering = true; ClearTip(); }
        if (!m_reordering) return;
        const CRect view = Viewport(); CRect client; GetClientRect(client);
        int edge = point.x < view.left + S(10) ? -1 : point.x >= view.right - S(10) ? 1 : 0;
        if (point.y < view.top || point.y >= view.bottom) edge = 0;
        if ((edge < 0 && m_page == 0) || (edge > 0 && m_page == PageCount() - 1)) edge = 0;
        if (edge != m_edge) { m_edge = edge; m_edgeSince = GetTickCount(); KillTimer(EdgeTimer); if (edge) SetTimer(EdgeTimer, 650, NULL); }
        m_drop = -1;
        if (point.y >= view.top && point.y < view.bottom && point.x >= client.left && point.x < client.right) {
            const int first = m_page * Capacity(), last = min(Count(), (m_page + 1) * Capacity()) - 1;
            int target = last;
            // The whole target card accepts the move. Split only the gaps,
            // so adjacent moves do not require crossing a card's midpoint.
            // The arrow gutters also accept the first/last visible position.
            for (int i = first; i < last; ++i)
                if (point.x < (NodeRect(i).right + NodeRect(i + 1).left) / 2) { target = i; break; }
            m_drop = target + (target > m_pressed ? 1 : 0);
        }
    } else {
        if (!m_panning && abs(dx) >= S(10) && abs(dx) > abs(dy)) { m_panning = true; followProgress = false; ClearTip(); }
        if (m_panning) m_offset = LaunchPanelPaging::DragOffset((double)m_originPage * PageWidth() - dx, (double)(PageCount() - 1) * PageWidth());
    }
    Invalidate(FALSE);
}
void CChainRouteView::Up(CPoint point) {
    if (!m_down) return;
    Motion(point); const int pressed = m_pressed, drop = m_drop, deleted = m_deletePressed;
    const bool pan = m_panning, reorder = m_reordering;
    const int target = LaunchPanelPaging::ReleasePage(m_originPage, point.x - m_origin.x, PageWidth(), max(S(24), PageWidth() / 6), PageCount());
    const double offset = m_offset;
    CancelInteraction(); m_offset = offset;
    if (reorder) {
        ChangePage(m_page, false);
        const int to = drop > pressed ? drop - 1 : drop;
        if (drop >= 0 && to >= 0 && to < Count() && to != pressed) Invoke(Move, pressed, to);
    } else if (pan) ChangePage(target);
    else if (deleted >= 0 && DeleteRect(deleted).PtInRect(point)) Invoke(Remove, deleted);
    else if (HitNode(point) == pressed && abs(point.y - m_origin.y) < S(10)) Invoke(Selection, pressed);
    Invalidate(FALSE);
}
void CChainRouteView::Key(UINT key) {
    if (key == VK_ESCAPE) { CancelInteraction(); Invalidate(FALSE); return; }
    if (m_down) return;
    if (key == VK_NEXT || key == VK_PRIOR) { followProgress = false; ChangePage(m_page + (key == VK_NEXT ? 1 : -1)); return; }
    if (key == VK_LEFT || key == VK_RIGHT || key == VK_HOME || key == VK_END) {
        const int next = key == VK_HOME ? 0 : key == VK_END ? Count() - 1 : m_selected < 0 ? 0 : m_selected + (key == VK_RIGHT ? 1 : -1);
        if (next < 0 || next >= Count()) return;
        if ((GetKeyState(VK_MENU) & 0x8000) && (key == VK_LEFT || key == VK_RIGHT)) Invoke(Move, m_selected, next);
        else { followProgress = false; Select(next); Invoke(Selection, next); }
    } else if (key == VK_DELETE) Invoke(Remove, m_selected);
    else if (key == VK_RETURN || key == VK_F2) Invoke(Edit, m_selected);
}
void CChainRouteView::ClearTip() {
    if (m_tip.GetSafeHwnd()) { m_tip.Pop(); if (m_tip.GetToolCount()) m_tip.DelTool(this, 1); }
    m_tipText.Empty();
}
void CChainRouteView::UpdateTip(CPoint point) {
    if (!m_tip.GetSafeHwnd() || m_down || m_animating) return;
    const int i = HitNode(point); CString text; CRect rect;
    if (i >= 0) {
        rect = NodeRect(i);
        if (DeleteRect(i).PtInRect(point)) { text = Localization::Get(L"page1.chain_remove"); rect = DeleteRect(i); }
        else if (GripRect(i).PtInRect(point)) { text = Localization::Get(L"chain.view.drag"); rect = GripRect(i); }
        else text = m_nodes[i].name + L"\r\n" + m_nodes[i].protocol + L" · " + m_nodes[i].host +
            (m_nodes[i].tip.IsEmpty() ? CString() : L"\r\n" + m_nodes[i].tip);
    } else if (ArrowRect(false).PtInRect(point) || ArrowRect(true).PtInRect(point)) {
        const bool next = ArrowRect(true).PtInRect(point); rect = ArrowRect(next);
        text = Localization::Get(next ? L"chain.view.next" : L"chain.view.previous");
    } else { const int p = HitDot(point); if (p >= 0) { rect = DotRect(p); text.Format(L"%d / %d", p + 1, PageCount()); } }
    if (text == m_tipText) return;
    ClearTip(); if (text.IsEmpty()) return;
    m_tipText = text; m_tip.AddTool(this, m_tipText, rect, 1);
}
void CChainRouteView::ContextMenu(CPoint screen) {
    if (m_down) return;
    if (screen.x != -1) { CPoint pt = screen; ScreenToClient(&pt); const int i = HitNode(pt); if (i < 0) return; Select(i, false); }
    if (m_selected < 0) return;
    if (screen.x == -1) { screen = NodeRect(m_selected).CenterPoint(); ClientToScreen(&screen); }
    CModernPopupMenu menu; menu.CreatePopupMenu();
    const UINT disabled = m_editable ? 0 : MF_GRAYED;
    menu.AppendMenu(MF_STRING | disabled, 1, Localization::Get(L"chain.edit.button"));
    menu.AppendMenu(MF_STRING | disabled | (m_selected == 0 ? MF_GRAYED : 0), 2, Localization::Get(L"page1.chain_up"));
    menu.AppendMenu(MF_STRING | disabled | (m_selected == Count() - 1 ? MF_GRAYED : 0), 3, Localization::Get(L"page1.chain_down"));
    menu.AppendMenu(MF_STRING | disabled, 4, Localization::Get(L"page1.chain_remove"));
    const UINT cmd = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_RIGHTBUTTON, screen.x, screen.y, this);
    if (cmd == 1) Invoke(Edit, m_selected);
    if (cmd == 2 || cmd == 3) Invoke(Move, m_selected, m_selected + (cmd == 2 ? -1 : 1));
    if (cmd == 4) Invoke(Remove, m_selected);
}
BOOL CChainRouteView::PreTranslateMessage(MSG* message) {
    if (message && message->hwnd == m_hWnd) {
        if (m_tip.GetSafeHwnd()) m_tip.RelayEvent(message);
        if ((message->message == WM_KEYDOWN || message->message == WM_SYSKEYDOWN) &&
            (message->wParam == VK_RETURN || message->wParam == VK_ESCAPE || message->wParam == VK_LEFT || message->wParam == VK_RIGHT ||
             message->wParam == VK_DELETE || message->wParam == VK_F2 || message->wParam == VK_HOME || message->wParam == VK_END ||
             message->wParam == VK_NEXT || message->wParam == VK_PRIOR)) { Key((UINT)message->wParam); return TRUE; }
    }
    return CWnd::PreTranslateMessage(message);
}
LRESULT CChainRouteView::WindowProc(UINT message, WPARAM wp, LPARAM lp) {
    const CPoint point((short)LOWORD(lp), (short)HIWORD(lp));
    switch (message) {
    case WM_PAINT: Paint(); return 0;
    case WM_ERASEBKGND: return TRUE;
    case WM_LBUTTONDOWN: Down(point); return 0;
    case WM_MOUSEMOVE: Motion(point); return 0;
    case WM_LBUTTONUP: Up(point); return 0;
    case WM_LBUTTONDBLCLK: { const int i = HitNode(point); if (i >= 0 && !GripRect(i).PtInRect(point) && !DeleteRect(i).PtInRect(point)) Invoke(Edit, i); return 0; }
    case WM_CONTEXTMENU: ContextMenu(point); return 0;
    case WM_KEYDOWN: Key((UINT)wp); return 0;
    case WM_SYSKEYDOWN:
        if (wp == VK_LEFT || wp == VK_RIGHT) { Key((UINT)wp); return 0; }
        break; // Leave system shortcuts such as Alt+F4 to Windows.
    case WM_GETDLGCODE: return DLGC_WANTARROWS;
    case WM_SETFOCUS: case WM_KILLFOCUS: Invalidate(FALSE); break;
    case WM_CAPTURECHANGED: if (m_down) { CancelInteraction(); ChangePage(m_page); } break;
    case WM_CANCELMODE: CancelInteraction(); Invalidate(FALSE); break;
    case WM_SHOWWINDOW: if (!wp) { CancelInteraction(); StopSpinner(); } break;
    case WM_SETTINGCHANGE: UpdateSpinner(); InvalidateRunningIndicators(); break;
    case WM_SIZE: CancelInteraction(); ChangePage(m_page, false); break;
    case WM_SETFONT: m_font = (HFONT)wp; m_fontDpi = 0; if (lp) Invalidate(FALSE); return 0;
    case WM_GETFONT: return (LRESULT)m_font;
    case WM_MOUSEWHEEL: case WM_MOUSEHWHEEL:
        if (!m_down) { followProgress = false; m_wheel += (message == WM_MOUSEHWHEEL ? -1 : 1) * (short)HIWORD(wp);
            if (abs(m_wheel) >= WHEEL_DELTA) { ChangePage(m_page + (m_wheel < 0 ? 1 : -1)); m_wheel = 0; } } return TRUE;
    case WM_TIMER:
        if (wp == SpinnerTimer) {
            if (!m_spinning) return 0; // Ignore notifications queued before stop/cancel.
            if (!IsWindowVisible()) { StopSpinner(); return 0; }
            InvalidateRunningIndicators(); return 0; // Paint only; never advances a proxy test.
        }
        if (wp == SnapTimer) {
            if (!m_animating) return 0; // A killed timer may already be queued.
            const double p = (GetTickCount() - m_animationStart) / 180.0;
            m_offset = m_from + (m_to - m_from) * LaunchPanelPaging::Ease(p);
            if (p >= 1) { m_animating = false; KillTimer(SnapTimer); }
            Invalidate(FALSE); return 0;
        }
        if (wp == EdgeTimer) {
            if (m_reordering && m_edge && GetTickCount() - m_edgeSince >= 650) {
                const int direction = m_edge; ChangePage(m_page + direction, false); m_edgeSince = GetTickCount(); Motion(m_point);
            } return 0;
        } break;
    case WM_DESTROY: StopSpinner(); CancelInteraction(); UiTheme::ForgetUiFonts(m_hWnd); break;
    }
    return CWnd::WindowProc(message, wp, lp);
}

void CChainRouteView::Paint() {
    UpdateSpinner(); // Resume after this control or its parent becomes visible.
    CPaintDC target(this); CRect client; GetClientRect(client); if (client.IsRectEmpty()) return;
    CDC dc; dc.CreateCompatibleDC(&target); CBitmap bitmap; bitmap.CreateCompatibleBitmap(&target, client.Width(), client.Height());
    CBitmap* oldBitmap = dc.SelectObject(&bitmap); dc.FillSolidRect(client, UiTheme::PageBackground()); dc.SetBkMode(TRANSPARENT);
    CFont* oldFont = dc.SelectObject(GetFont() ? GetFont() : CFont::FromHandle((HFONT)GetStockObject(DEFAULT_GUI_FONT)));
    EnsureSmallFont();
    const CRect view = Viewport(); const int saved = dc.SaveDC(); dc.IntersectClipRect(view);
    const int first = max(0, (int)(m_offset / PageWidth()) - 1) * Capacity();
    const int last = min(Count(), first + 3 * Capacity());
    for (int i = first; i < last; ++i) {
        const Node& n = m_nodes[i]; CRect r = NodeRect(i), clipped; if (!clipped.IntersectRect(r, view)) continue;
        COLORREF border = i == m_selected ? UiTheme::Accent() : UiTheme::Border(), fill = UiTheme::Surface(), result = UiTheme::TextSecondary();
        if (n.state == Running) result = RunningColor();
        if (n.state == Passed) result = UiTheme::Success();
        if (n.state == Failed) result = UiTheme::Danger();
        UiTheme::FillRoundRect(dc, r, S(7), fill, border);
        const CRect grip = GripRect(i), del = DeleteRect(i); const COLORREF action = m_editable ? UiTheme::TextSecondary() : UiTheme::Border();
        for (int x = -1; x <= 1; x += 2) for (int y = -1; y <= 1; ++y)
            dc.FillSolidRect(grip.CenterPoint().x + S(x * 2), grip.CenterPoint().y + S(y * 4), max(1, S(2)), max(1, S(2)), action);
        Line(dc, del.CenterPoint() + CPoint(-S(3), -S(3)), del.CenterPoint() + CPoint(S(3), S(3)), action, max(1, S(1)));
        Line(dc, del.CenterPoint() + CPoint(S(3), -S(3)), del.CenterPoint() + CPoint(-S(3), S(3)), action, max(1, S(1)));
        CFont* normal = dc.SelectObject(&m_smallFont); dc.SetTextColor(UiTheme::TextSecondary());
        CRect protocol(grip.right, r.top + S(2), del.left, r.top + S(23)); dc.DrawText(n.protocol, protocol, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        dc.SelectObject(normal); dc.SetTextColor(UiTheme::TextPrimary());
        TEXTMETRIC metrics = {}; dc.GetTextMetrics(&metrics);
        const int nameY = r.top + S(23), lineH = metrics.tmHeight;
        CRect name(r.left + S(9), nameY, r.right - S(9), nameY + lineH); dc.DrawText(n.name, name, DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        dc.SelectObject(&m_smallFont); dc.SetTextColor(UiTheme::TextSecondary());
        CRect host(r.left + S(9), name.bottom + S(1), r.right - S(9), r.bottom - ResultHeight());
        dc.DrawText(n.host, host, DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        if (n.state != Idle) {
            dc.SetTextColor(result); const int textW = n.elapsed.IsEmpty() ? 0 : dc.GetTextExtent(n.elapsed).cx;
            CRect elapsed(r.right - S(9) - textW, r.bottom - ResultHeight(), r.right - S(9), r.bottom - S(2));
            dc.DrawText(n.elapsed, elapsed, DT_RIGHT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
            const CPoint c(elapsed.left - S(9), elapsed.CenterPoint().y);
            if (n.state == Passed) { Line(dc, c + CPoint(-S(4), 0), c + CPoint(-S(1), S(3)), result, S(2)); Line(dc, c + CPoint(-S(1), S(3)), c + CPoint(S(5), -S(4)), result, S(2)); }
            else if (n.state == Failed) { Line(dc, c + CPoint(-S(3), -S(3)), c + CPoint(S(3), S(3)), result, S(2)); Line(dc, c + CPoint(S(3), -S(3)), c + CPoint(-S(3), S(3)), result, S(2)); }
            else {
                const float angle = m_spinning ? ((GetTickCount() - m_spinnerStarted) % 1000) * 0.36f : 0.0f;
                UiTheme::DrawSpinner(dc, CRect(c.x - S(5), c.y - S(5), c.x + S(5), c.y + S(5)),
                    RunningColor(), angle, (float)max(1, S(2)));
            }
        }
        dc.SelectObject(normal);
        if (i == m_selected && GetFocus() == this) { CRect focus = r; focus.DeflateRect(S(3), S(3)); dc.DrawFocusRect(focus); }
    }
    if (!Count()) { dc.SetTextColor(UiTheme::TextSecondary()); CRect text = view; dc.DrawText(Localization::Get(L"chain.view.empty"), text, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS); }
    dc.RestoreDC(saved);
    // Boundary gaps lie just outside the card viewport. Draw the insertion
    // marker after restoring its clip, so first/last positions remain visible.
    if (m_reordering && m_drop >= 0) {
        const int end = min(Count(), (m_page + 1) * Capacity());
        const int x = m_drop >= end ? NodeRect(end - 1).right + S(3) : NodeRect(m_drop).left - S(3);
        dc.FillSolidRect(x, view.top + S(4), max(2, S(2)), view.Height() - S(8), UiTheme::Accent());
    }
    for (int side = 0; side < 2; ++side) {
        const CPoint c = ArrowRect(side != 0).CenterPoint(); const int dir = side ? 1 : -1;
        const COLORREF color = (side ? m_page < PageCount() - 1 : m_page > 0) ? UiTheme::TextSecondary() : UiTheme::Border();
        Line(dc, c + CPoint(-dir * S(3), -S(5)), c + CPoint(dir * S(2), 0), color, max(1, S(1)));
        Line(dc, c + CPoint(dir * S(2), 0), c + CPoint(-dir * S(3), S(5)), color, max(1, S(1)));
    }
    for (int p = max(0, m_page - 6); p < min(PageCount(), m_page + 7); ++p) {
        CRect r = DotRect(p); if (r.IsRectEmpty()) continue;
        const CPoint c = r.CenterPoint(); const int radius = S(3);
        UiTheme::FillRoundRect(dc, CRect(c.x - radius, c.y - radius, c.x + radius, c.y + radius), radius,
            p == m_page ? UiTheme::Accent() : UiTheme::PageBackground(), p == m_page ? UiTheme::Accent() : UiTheme::TextSecondary());
    }
    if (m_reordering && m_pressed >= 0 && m_pressed < Count()) {
        CString text = m_nodes[m_pressed].name; const int w = min(S(180), dc.GetTextExtent(text).cx + S(18));
        int x = max(0, min(client.right - w, m_point.x + S(8))), y = max(0, min(client.bottom - S(26), m_point.y + S(8)));
        CRect r(x, y, x + w, y + S(26)); UiTheme::FillRoundRect(dc, r, S(5), UiTheme::Accent(), CLR_NONE);
        r.DeflateRect(S(8), 0); dc.SetTextColor(RGB(255,255,255)); dc.DrawText(text, r, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
    dc.SelectObject(oldFont); target.BitBlt(0, 0, client.Width(), client.Height(), &dc, 0, 0, SRCCOPY); dc.SelectObject(oldBitmap);
}

// Simple MSAA children expose every node, including off-page nodes. Native
// keyboard actions and the context menu provide edit/remove/reorder access.
int CChainRouteView::AccIndex(VARIANT child) const { return child.vt == VT_I4 && child.lVal > 0 && child.lVal <= Count() ? child.lVal - 1 : -1; }
HRESULT CChainRouteView::get_accChildCount(long* count) { if (!count) return E_POINTER; *count = Count(); return S_OK; }
HRESULT CChainRouteView::get_accName(VARIANT child, BSTR* name) { const int i = AccIndex(child); return i >= 0 ? StringResult(m_nodes[i].name, name) : CWnd::get_accName(child, name); }
HRESULT CChainRouteView::get_accDescription(VARIANT child, BSTR* description) {
    const int i = AccIndex(child); if (i < 0) return CWnd::get_accDescription(child, description);
    const Node& n = m_nodes[i]; return StringResult(n.protocol + L" · " + n.host + L"\r\n" + n.tip + L"\r\n" + Localization::Get(L"chain.view.keys"), description);
}
HRESULT CChainRouteView::get_accRole(VARIANT child, VARIANT* role) { if (!role) return E_POINTER; if (child.vt != VT_I4 || child.lVal < 0 || child.lVal > Count()) return E_INVALIDARG; VariantInit(role); role->vt = VT_I4; role->lVal = child.lVal ? ROLE_SYSTEM_LISTITEM : ROLE_SYSTEM_LIST; return S_OK; }
HRESULT CChainRouteView::get_accState(VARIANT child, VARIANT* state) {
    const int i = AccIndex(child); if (i < 0) return CWnd::get_accState(child, state); if (!state) return E_POINTER;
    VariantInit(state); state->vt = VT_I4; state->lVal = STATE_SYSTEM_FOCUSABLE | STATE_SYSTEM_SELECTABLE;
    if (i == m_selected) state->lVal |= STATE_SYSTEM_SELECTED | (GetFocus() == this ? STATE_SYSTEM_FOCUSED : 0);
    if (i / Capacity() != m_page) state->lVal |= STATE_SYSTEM_OFFSCREEN;
    if (!m_editable) state->lVal |= STATE_SYSTEM_READONLY; return S_OK;
}
HRESULT CChainRouteView::get_accFocus(VARIANT* focus) { if (!focus) return E_POINTER; VariantInit(focus); if (GetFocus() == this) { focus->vt = VT_I4; focus->lVal = m_selected + 1; } return S_OK; }
HRESULT CChainRouteView::get_accSelection(VARIANT* selection) { if (!selection) return E_POINTER; VariantInit(selection); if (m_selected >= 0) { selection->vt = VT_I4; selection->lVal = m_selected + 1; } return S_OK; }
HRESULT CChainRouteView::get_accDefaultAction(VARIANT child, BSTR* action) { if (AccIndex(child) < 0) return CWnd::get_accDefaultAction(child, action); return StringResult(Localization::Get(L"chain.edit.button"), action); }
HRESULT CChainRouteView::accSelect(long flags, VARIANT child) { const int i = AccIndex(child); if (i < 0) return E_INVALIDARG; if (flags & SELFLAG_TAKEFOCUS) SetFocus(); if (flags & (SELFLAG_TAKESELECTION | SELFLAG_TAKEFOCUS)) { Select(i); Invoke(Selection, i); return S_OK; } return E_INVALIDARG; }
HRESULT CChainRouteView::accLocation(long* x, long* y, long* width, long* height, VARIANT child) {
    const int i = AccIndex(child); if (i < 0) return CWnd::accLocation(x,y,width,height,child); if (!x || !y || !width || !height) return E_POINTER;
    CRect r = NodeRect(i); ClientToScreen(r); *x=r.left; *y=r.top; *width=r.Width(); *height=r.Height(); return S_OK;
}
HRESULT CChainRouteView::accHitTest(long x, long y, VARIANT* child) { if (!child) return E_POINTER; CPoint p(x,y); ScreenToClient(&p); VariantInit(child); CRect r; GetClientRect(r); if (!r.PtInRect(p)) return S_FALSE; child->vt=VT_I4; child->lVal=HitNode(p)+1; return S_OK; }
HRESULT CChainRouteView::accDoDefaultAction(VARIANT child) { const int i=AccIndex(child); if(i<0 || !m_editable) return S_FALSE; Select(i); Invoke(Edit,i); return S_OK; }
HRESULT CChainRouteView::accNavigate(long direction, VARIANT start, VARIANT* end) {
    if (!end) return E_POINTER; VariantInit(end); int i=AccIndex(start);
    if(direction==NAVDIR_FIRSTCHILD && start.vt==VT_I4 && start.lVal==CHILDID_SELF) i=0;
    else if(direction==NAVDIR_LASTCHILD && start.vt==VT_I4 && start.lVal==CHILDID_SELF) i=Count()-1;
    else if(i>=0 && (direction==NAVDIR_NEXT || direction==NAVDIR_RIGHT)) ++i;
    else if(i>=0 && (direction==NAVDIR_PREVIOUS || direction==NAVDIR_LEFT)) --i;
    else return S_FALSE;
    if(i<0 || i>=Count()) return S_FALSE; end->vt=VT_I4; end->lVal=i+1; return S_OK;
}
