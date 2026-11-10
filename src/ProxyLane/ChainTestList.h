#pragma once
#include <afxcmn.h>
#include <vector>
#include "ModernUI.h"

// Keep the compact native list. Tooltips cover every column; user navigation
// suspends following the active hop until the next test.
class CChainTestList : public CListCtrl
{
public:
    bool followProgress = true;
    std::vector<CString> tips;
    void Initialize()
    {
        if (m_tip.Create(this, TTS_ALWAYSTIP | TTS_NOPREFIX))
        {
            m_tip.SetMaxTipWidth(UiTheme::ScaleForWindow(m_hWnd, 460));
            m_tip.SetDelayTime(TTDT_AUTOPOP, 20000);
        }
    }
    void Follow(int row)
    {
        if (!followProgress || row < 0) return;
        m_following = true;
        EnsureVisible(row, FALSE);
        m_following = false;
    }
    void ClearTips()
    {
        tips.clear(); m_text.Empty(); m_row = -1;
        if (m_tip.GetSafeHwnd() && m_tip.GetToolCount()) { m_tip.Pop(); m_tip.DelTool(this, 1); }
    }
    void RefreshTip() { UpdateTip(m_row); }
protected:
    BOOL PreTranslateMessage(MSG* message) override
    {
        if (message && m_tip.GetSafeHwnd())
        {
            if (message->message == WM_MOUSEMOVE && message->hwnd == m_hWnd)
            {
                const CPoint point((short)LOWORD(message->lParam), (short)HIWORD(message->lParam));
                LVHITTESTINFO hit = {}; hit.pt = point;
                const int row = SubItemHitTest(&hit);
                UpdateTip(row);
            }
            m_tip.RelayEvent(message);
        }
        return CListCtrl::PreTranslateMessage(message);
    }
    LRESULT WindowProc(UINT message, WPARAM wParam, LPARAM lParam) override
    {
        if (!m_following && (message == WM_MOUSEWHEEL || message == WM_VSCROLL ||
            message == WM_KEYDOWN || message == WM_LBUTTONDOWN)) followProgress = false;
        return CListCtrl::WindowProc(message, wParam, lParam);
    }
private:
    void UpdateTip(int row)
    {
        if (!m_tip.GetSafeHwnd()) return;
        CString text = row >= 0 && row < (int)tips.size() ? tips[row] : CString();
        if (row != m_row || text.IsEmpty())
        {
            m_tip.Pop();
            if (m_tip.GetToolCount()) m_tip.DelTool(this, 1);
            m_row = row;
        }
        if (text.IsEmpty()) { m_text.Empty(); return; }
        CRect rect; GetItemRect(row, &rect, LVIR_BOUNDS);
        if (!m_tip.GetToolCount()) { m_text = text; m_tip.AddTool(this, m_text, rect, 1); }
        else if (m_text != text) { m_text = text; m_tip.UpdateTipText(m_text, this, 1); }
        m_tip.SetToolRect(this, 1, rect);
    }
    int m_row = -1;
    bool m_following = false;
    CString m_text;
    CToolTipCtrl m_tip;
};
