#pragma once
#include <vector>
#include <algorithm>

// Read-only native byte control. Holds bytes, paints visible rows only, and
// shares one byte selection between hexadecimal and character columns.
class CByteHexView : public CWnd {
    friend class ProtocolPageHarness;
public:
    bool Create(CWnd* parent, UINT id) {
        return CreateEx(WS_EX_CLIENTEDGE, AfxRegisterWndClass(CS_DBLCLKS, LoadCursor(NULL, IDC_IBEAM)),
            L"", WS_CHILD | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL, CRect(), parent, id) != FALSE;
    }
    void SetBytes(std::vector<unsigned char> bytes, bool preserve=false) {
        std::vector<Line> lines;
        for(size_t i=0;i<bytes.size();i+=16) lines.push_back({i,min(size_t(16),bytes.size()-i),0,i});
        SetData(std::move(bytes),std::move(lines),false,preserve);
    }
    void SetPackets(const std::vector<std::vector<unsigned char>>& packets, bool preserve) {
        std::vector<unsigned char> bytes;std::vector<Line> lines;
        for(size_t packet=0;packet<packets.size();++packet) {
            const auto& data=packets[packet];const size_t start=bytes.size();
            bytes.insert(bytes.end(),data.begin(),data.end());
            if(data.empty()) lines.push_back({start,0,packet,0});
            for(size_t i=0;i<data.size();i+=16) lines.push_back({start+i,min(size_t(16),data.size()-i),packet,i});
        }
        SetData(std::move(bytes),std::move(lines),true,preserve);
    }
    bool LocatePacket(size_t packet) {
        if(!m_packets) return false;
        auto found=std::lower_bound(m_lines.begin(),m_lines.end(),packet,
            [](const Line& line,size_t value){return line.packet<value;});
        if(found==m_lines.end() || found->packet!=packet) return false;
        StopDrag();m_selectedRow=(int)(found-m_lines.begin());
        m_first=m_last=found->first;m_hasSelection=found->count>0;
        m_top=m_selectedRow;m_left=0;UpdateScroll();Invalidate(FALSE);return true;
    }
    const std::vector<unsigned char>& Bytes() const { return m_bytes; }
    size_t SelectedPacket() const { return m_lines.empty() ? 0 : m_lines[m_selectedRow].packet; }
    size_t SelectedOffset() const {
        if(m_lines.empty() || !m_lines[m_selectedRow].count) return 0;
        const auto& line=m_lines[m_selectedRow];return line.offset+m_last-line.first;
    }
private:
    struct Line {
        size_t first,count,packet,offset;
        bool operator==(const Line& other) const {return first==other.first && count==other.count && packet==other.packet && offset==other.offset;}
    };
    std::vector<unsigned char> m_bytes;
    std::vector<Line> m_lines;
    bool m_packets=false,m_hasSelection=false;
    int m_selectedRow=0;
    void SetData(std::vector<unsigned char> bytes,std::vector<Line> lines,bool packets,bool preserve) {
        if(preserve && bytes==m_bytes && lines==m_lines && packets==m_packets) return;
        StopDrag();m_bytes=std::move(bytes);m_lines=std::move(lines);m_packets=packets;
        if(!preserve) {m_first=m_last=0;m_top=m_left=m_selectedRow=0;m_hasSelection=!m_lines.empty() && m_lines[0].count>0;}
        else {
            m_first=min(m_first,m_bytes.empty() ? size_t(0) : m_bytes.size()-1);
            m_last=min(m_last,m_bytes.empty() ? size_t(0) : m_bytes.size()-1);
            m_selectedRow=min(m_selectedRow,max(0,Rows()-1));
            if(m_bytes.empty()) m_hasSelection=false;
        }
        UpdateScroll();Invalidate(FALSE);
    }
    int RowOfByte(size_t index) const {
        auto found=std::lower_bound(m_lines.begin(),m_lines.end(),index,
            [](const Line& line,size_t byte){return line.first+line.count<=byte;});
        return found==m_lines.end() ? max(0,Rows()-1) : (int)(found-m_lines.begin());
    }
    int HitRow(CPoint point) const {return max(0,min(Rows()-1,m_top+max(0,point.y)/m_ch));}
    void NotifySelection() {
        if(m_packets && GetParent()) {NMHDR header={m_hWnd,(UINT_PTR)GetDlgCtrlID(),NM_CLICK};GetParent()->SendMessage(WM_NOTIFY,header.idFrom,(LPARAM)&header);}
    }
    int m_top = 0, m_left = 0, m_cw = 8, m_ch = 16;
    size_t m_first = 0, m_last = 0;
    bool m_drag = false;
    CPoint m_dragPoint;
    static const UINT_PTR DragTimer = 1;
    HFONT m_displayFont = NULL;
    void StopDrag() {
        const bool selecting = m_drag;
        m_drag = false;
        if (m_hWnd) {
            KillTimer(DragTimer);
            if (selecting && GetCapture() == this) ReleaseCapture();
        }
    }
    void ExtendSelection(CPoint point) {
        CRect r; GetClientRect(r);
        point.y = max(0, min(max(0, r.bottom - 1), point.y));
        size_t next=Hit(point);const int row=HitRow(point);
        if(!m_lines.empty() && !m_lines[row].count && m_first<next) --next;
        if(next!=m_last || row!=m_selectedRow) {
            const size_t oldLast=m_last;m_last=next;m_selectedRow=row;
            InvalidateSelection(m_first,oldLast);NotifySelection();
        }
    }
    void ScrollDrag() {
        if (!m_drag || GetCapture() != this || m_bytes.empty()) return;
        CRect r; GetClientRect(r);
        if (r.IsRectEmpty()) return;
        const int edge = max(1, min(m_ch / 2, r.Height() / 4));
        int step = 0;
        if (m_dragPoint.y < edge) step = -min(8, 1 + (edge - m_dragPoint.y) / m_ch);
        else if (m_dragPoint.y >= r.bottom - edge) step = min(8, 1 + (m_dragPoint.y - r.bottom + edge) / m_ch);
        if (!step) return;
        const int oldTop = m_top;
        m_top += step; UpdateScroll();
        // Keep the anchor fixed and extend to the newly exposed row. Painting
        // remains buffered; a stationary pointer inside the view does no work.
        ExtendSelection(CPoint(m_dragPoint.x, max(0, min(r.bottom - 1, m_dragPoint.y))));
        if (m_top != oldTop) Invalidate(FALSE);
    }
    int Rows() const { return (int)m_lines.size(); }
    void UpdateScroll() {
        if (!m_hWnd) return;
        CClientDC dc(this); CFont* font = GetFont(); CFont* old = font ? dc.SelectObject(font) : nullptr;
        TEXTMETRIC tm; dc.GetTextMetrics(&tm); m_cw = max(1, (int)tm.tmAveCharWidth); m_ch = max(1, (int)tm.tmHeight + 2);
        if (old) dc.SelectObject(old);
        CRect r; GetClientRect(r);
        m_top = max(0, min(m_top, max(0, Rows() - max(1, r.Height() / m_ch))));
        m_left = max(0, min(m_left, max(0, 77 * m_cw - r.Width())));
        SCROLLINFO si = {sizeof(si), SIF_RANGE | SIF_PAGE | SIF_POS};
        si.nMax = max(0, Rows() - 1); si.nPage = max(1, r.Height() / m_ch); si.nPos = m_top; SetScrollInfo(SB_VERT, &si);
        si.nMax = 77 * m_cw; si.nPage = max(1, r.Width()); si.nPos = m_left; SetScrollInfo(SB_HORZ, &si);
    }
    size_t Hit(CPoint point) const {
        int col = (point.x + m_left) / m_cw;
        int byte = col >= 60 ? col - 60 : (col - 10) / 3;
        if(m_lines.empty()) return 0;
        const auto& line=m_lines[HitRow(point)];
        return line.first+(line.count ? min(line.count-1,(size_t)max(0,min(15,byte))) : 0);
    }
    void InvalidateBytes(size_t first, size_t last) {
        if (m_bytes.empty() || first > last) return;
        CRect r; GetClientRect(r);
        const int top = max(0, (RowOfByte(first) - m_top) * m_ch);
        const int bottom = min(r.bottom, (RowOfByte(last) - m_top + 1) * m_ch);
        if (top < bottom) InvalidateRect(CRect(0, top, r.right, bottom), FALSE);
    }
    void InvalidateSelection(size_t oldFirst, size_t oldLast) {
        const size_t a = min(oldFirst, oldLast), b = max(oldFirst, oldLast);
        const size_t c = min(m_first, m_last), d = max(m_first, m_last);
        // Repaint only the symmetric difference of the old/new selection.
        if (b < c || d < a) { InvalidateBytes(a, b); InvalidateBytes(c, d); return; }
        if (a != c) InvalidateBytes(min(a, c), max(a, c) - 1);
        if (b != d) InvalidateBytes(min(b, d) + 1, max(b, d));
    }
    void DrawBytes(CDC& dc, const CRect& dirty) {
        dc.FillSolidRect(dirty, RGB(255,255,255));
        CFont* font = GetFont(); CFont* old = font ? dc.SelectObject(font) : nullptr;
        dc.SetBkMode(TRANSPARENT);
        const size_t first = min(m_first, m_last), last = max(m_first, m_last);
        for (int row = m_top + max(0, dirty.top) / m_ch;
            row < Rows() && (row - m_top) * m_ch < dirty.bottom; ++row) {
            const auto& line=m_lines[row];
            int y = (row - m_top) * m_ch;
            if(m_packets) {
                dc.FillSolidRect(dirty.left,y,dirty.Width(),m_ch,line.packet%2 ? RGB(218,232,248) : RGB(255,255,255));
                if(line.offset==0 && row>0) dc.FillSolidRect(dirty.left,y,dirty.Width(),1,RGB(166,190,216));
            }
            CString address; address.Format(L"%08X",(unsigned)line.offset);
            dc.SetTextColor(RGB(105,105,105)); dc.TextOut(0 - m_left, y, address);
            for (int b = 0; b < (int)line.count; ++b) {
                size_t index = line.first + b;
                bool selected = m_hasSelection && index >= first && index <= last;
                const int hx = (10 + b * 3) * m_cw - m_left, ax = (60 + b) * m_cw - m_left;
                if (selected) { dc.FillSolidRect(hx, y, m_cw * 2, m_ch, RGB(0,100,200)); dc.FillSolidRect(ax, y, m_cw, m_ch, RGB(0,100,200)); }
                dc.SetTextColor(selected ? RGB(255,255,255) : RGB(20,20,20));
                CString hex; hex.Format(L"%02X", m_bytes[index]); dc.TextOut(hx, y, hex);
                wchar_t c = m_bytes[index] >= 32 && m_bytes[index] < 127 ? m_bytes[index] : L'.'; dc.TextOut(ax, y, &c, 1);
            }
        }
        if (old) dc.SelectObject(old);
    }
    CString SelectionText() const {
        CString text;
        if(!m_hasSelection) return text;
        for (size_t i = min(m_first, m_last); i <= max(m_first, m_last) && i < m_bytes.size(); ++i) {
            CString byte; byte.Format(L"%02X%s", m_bytes[i], i == max(m_first, m_last) ? L"" : L" "); text += byte;
        }
        return text;
    }
    void CopySelection() {
        CString text=SelectionText();
        if(text.IsEmpty() || !OpenClipboard()) return;
        HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, (text.GetLength() + 1) * sizeof(wchar_t));
        if (memory) {
            void* data = GlobalLock(memory);
            if (data) { memcpy(data, (LPCWSTR)text, (text.GetLength() + 1) * sizeof(wchar_t)); GlobalUnlock(memory);
                EmptyClipboard(); if (!SetClipboardData(CF_UNICODETEXT, memory)) GlobalFree(memory); }
            else GlobalFree(memory);
        }
        CloseClipboard();
    }
protected:
    LRESULT WindowProc(UINT message, WPARAM wp, LPARAM lp) override {
        switch (message) {
        case WM_ERASEBKGND: return 1;
        case WM_GETDLGCODE: return DLGC_WANTARROWS | DLGC_WANTCHARS;
        case WM_PAINT: {
            CPaintDC dc(this); CRect dirty; dc.GetClipBox(dirty);
            if (dirty.IsRectEmpty()) return 0;
            CDC buffer; CBitmap bitmap;
            if (!buffer.CreateCompatibleDC(&dc) || !bitmap.CreateCompatibleBitmap(&dc, dirty.Width(), dirty.Height())) {
                DrawBytes(dc, dirty); return 0;
            }
            CBitmap* old = buffer.SelectObject(&bitmap);
            buffer.SetWindowOrg(dirty.left, dirty.top);
            DrawBytes(buffer, dirty);
            buffer.SetWindowOrg(0, 0);
            dc.BitBlt(dirty.left, dirty.top, dirty.Width(), dirty.Height(), &buffer, 0, 0, SRCCOPY);
            buffer.SelectObject(old); return 0;
        }
        case WM_SIZE: UpdateScroll(); Invalidate(FALSE); break;
        case WM_GETFONT: return (LRESULT)m_displayFont;
        case WM_SETFONT: m_displayFont = (HFONT)wp; UpdateScroll(); if (lp) Invalidate(FALSE); return 0;
        case WM_VSCROLL: case WM_HSCROLL: {
            const bool vertical = message == WM_VSCROLL; int& value = vertical ? m_top : m_left;
            CRect r; GetClientRect(r); int page = vertical ? max(1, r.Height() / m_ch) : r.Width();
            SCROLLINFO si = {sizeof(si), SIF_TRACKPOS}; GetScrollInfo(vertical ? SB_VERT : SB_HORZ, &si);
            switch (LOWORD(wp)) {
            case SB_LINEUP: value -= vertical ? 1 : m_cw; break;
            case SB_LINEDOWN: value += vertical ? 1 : m_cw; break;
            case SB_PAGEUP: value -= page; break; case SB_PAGEDOWN: value += page; break;
            case SB_THUMBTRACK: case SB_THUMBPOSITION: value = si.nTrackPos; break;
            case SB_TOP: value = 0; break; case SB_BOTTOM: value = vertical ? Rows() : 77 * m_cw; break;
            }
            UpdateScroll(); Invalidate(FALSE); return 0;
        }
        case WM_MOUSEWHEEL: m_top -= GET_WHEEL_DELTA_WPARAM(wp) / WHEEL_DELTA * 3; UpdateScroll(); Invalidate(FALSE); return 0;
        case WM_TIMER: if (wp == DragTimer) { ScrollDrag(); return 0; } break;
        case WM_LBUTTONDOWN: {
            const size_t oldFirst = m_first, oldLast = m_last;
            SetFocus(); m_dragPoint = CPoint((short)LOWORD(lp), (short)HIWORD(lp)); m_last = Hit(m_dragPoint);
            m_selectedRow=HitRow(m_dragPoint);
            const bool wasSelected=m_hasSelection;
            m_hasSelection=!m_lines.empty() && m_lines[m_selectedRow].count>0;
            if (!(GetKeyState(VK_SHIFT) & 0x8000) || !wasSelected) m_first = m_last;
            if(wasSelected!=m_hasSelection) InvalidateBytes(min(oldFirst,oldLast),max(oldFirst,oldLast));
            if(!m_hasSelection) {Invalidate(FALSE);NotifySelection();return 0;}
            m_drag = true; SetCapture(); SetTimer(DragTimer, 50, nullptr); InvalidateSelection(oldFirst, oldLast); NotifySelection(); return 0;
        }
        case WM_MOUSEMOVE: if (m_drag) {
            m_dragPoint = CPoint((short)LOWORD(lp), (short)HIWORD(lp));
            ExtendSelection(m_dragPoint);
            return 0;
        } break; // Native scrollbar tracking also delivers captured client mouse messages.
        case WM_LBUTTONUP: if (m_drag) { ExtendSelection(CPoint((short)LOWORD(lp), (short)HIWORD(lp))); StopDrag(); NotifySelection();return 0; } break;
        case WM_CAPTURECHANGED: case WM_CANCELMODE: case WM_KILLFOCUS: case WM_DESTROY: StopDrag(); break;
        case WM_SHOWWINDOW: if (!wp) StopDrag(); break;
        case WM_KEYDOWN: {
            if ((GetKeyState(VK_CONTROL) & 0x8000) && wp == 'C') { CopySelection(); return 0; }
            if ((GetKeyState(VK_CONTROL) & 0x8000) && wp == 'A') {
                m_first=0;m_last=m_bytes.empty() ? 0 : m_bytes.size()-1;m_hasSelection=!m_bytes.empty();
                m_selectedRow=RowOfByte(m_last);Invalidate(FALSE);NotifySelection();return 0;
            }
            if(m_lines.empty()) break;
            CRect r;GetClientRect(r);
            int row=m_selectedRow;size_t column=m_last>=m_lines[row].first ? m_last-m_lines[row].first : 0;
            bool vertical=true;
            switch(wp) {
            case VK_UP: --row;break;case VK_DOWN: ++row;break;
            case VK_PRIOR: row-=max(1,r.Height()/m_ch);break;case VK_NEXT:row+=max(1,r.Height()/m_ch);break;
            case VK_HOME:row=0;column=0;break;
            case VK_END:row=Rows()-1;column=15;break;
            case VK_LEFT:
                if(!m_lines[row].count) {--row;column=15;}
                else {if(m_last) --m_last;vertical=false;}break;
            case VK_RIGHT:
                if(!m_lines[row].count) {++row;column=0;}
                else {if(m_last+1<m_bytes.size()) ++m_last;vertical=false;}break;
            default:return CWnd::WindowProc(message,wp,lp);
            }
            if(vertical) {
                row=max(0,min(Rows()-1,row));const auto& line=m_lines[row];
                m_last=line.first+(line.count ? min(column,line.count-1) : 0);
            } else row=RowOfByte(m_last);
            m_selectedRow=row;m_hasSelection=m_lines[row].count>0;
            if (!(GetKeyState(VK_SHIFT) & 0x8000)) m_first=m_last;
            if(row<m_top) m_top=row;
            if(row>=m_top+max(1,r.Height()/m_ch)) m_top=row-max(1,r.Height()/m_ch)+1;
            UpdateScroll(); Invalidate(FALSE); NotifySelection();return 0;
        }
        }
        return CWnd::WindowProc(message, wp, lp);
    }
};
