#pragma once
#include <afxcmn.h>
#include <vector>

// Read-only payload text. Formatting never becomes part of copied content.
class CProtocolRawView : public CRichEditCtrl {
public:
    struct Range { LONG first, last; };
    bool Updating() const { return m_updating; }
    const std::vector<Range>& Ranges() const { return m_ranges; }
    static CString Normalize(CString text) {
        // RichEdit character positions count each paragraph as one CR.
        text.Replace(L"\r\n", L"\r"); text.Replace(L"\n", L"\r"); return text;
    }
    void GetSel(int& first, int& last) const {
        CHARRANGE range; const_cast<CProtocolRawView*>(this)->SendMessage(EM_EXGETSEL,0,(LPARAM)&range);
        first=range.cpMin; last=range.cpMax;
    }
    void SetSel(int first, int last, BOOL noScroll=FALSE) {
        CHARRANGE range={first,last}; SendMessage(EM_EXSETSEL,0,(LPARAM)&range);
        if (!noScroll) SendMessage(EM_SCROLLCARET);
    }
    bool LocatePacket(size_t packet) {
        if(packet>=m_ranges.size()) return false;
        m_updating=true;SetFocus();
        SetSel(m_ranges[packet].first,m_ranges[packet].first,TRUE);
        LineScroll(LineFromChar(m_ranges[packet].first)-GetFirstVisibleLine());
        SendMessage(EM_SCROLLCARET);
        // RichEdit may ignore horizontal caret scrolling while unfocused.
        POINT position={},scroll={};CRect bounds;
        SendMessage(EM_POSFROMCHAR,(WPARAM)&position,m_ranges[packet].first);
        SendMessage(EM_GETRECT,0,(LPARAM)&bounds);
        SendMessage(EM_GETSCROLLPOS,0,(LPARAM)&scroll);
        SCROLLINFO info={sizeof(info),SIF_POS};
        if(GetScrollInfo(SB_HORZ,&info)) scroll.x=info.nPos;
        if(GetScrollInfo(SB_VERT,&info)) scroll.y=info.nPos;
        if(position.x<bounds.left) scroll.x=max(0L,scroll.x+position.x-bounds.left);
        else if(position.x>=bounds.right) scroll.x+=position.x-bounds.right+max(1,bounds.Width()/4);
        SendMessage(EM_SETSCROLLPOS,0,(LPARAM)&scroll);
        m_updating=false;return true;
    }
    void SetLimitText(UINT limit) { LimitText(limit); }
    void Render(const CString& text, const std::vector<Range>& ranges, bool preserve) {
        bool sameRanges=ranges.size()==m_ranges.size();
        for(size_t i=0;sameRanges && i<ranges.size();++i)
            sameRanges=ranges[i].first==m_ranges[i].first && ranges[i].last==m_ranges[i].last;
        if(preserve && text==m_text && sameRanges) return;
        const int top=GetFirstVisibleLine();
        POINT scroll={}; SendMessage(EM_GETSCROLLPOS,0,(LPARAM)&scroll);
        SCROLLINFO info={sizeof(info),SIF_POS};
        if(GetScrollInfo(SB_HORZ,&info)) scroll.x=info.nPos;
        if(GetScrollInfo(SB_VERT,&info)) scroll.y=info.nPos;
        int first,last;GetSel(first,last);
        // WM_SETREDRAW(TRUE) adds WS_VISIBLE. A hidden Raw view must never
        // receive that pair while HexView owns the same screen rectangle.
        const bool redraw=(GetStyle()&WS_VISIBLE)!=0;
        m_updating=true;if(redraw) SetRedraw(FALSE);SetReadOnly(FALSE);
        const bool append=preserve && ranges.size()>=m_ranges.size() && text.GetLength()>=m_text.GetLength() && text.Left(m_text.GetLength())==m_text;
        const int from=append ? m_text.GetLength() : 0;
        if(append) {SetSel(from,from,TRUE);ReplaceSel(text.Mid(from),FALSE);}
        else {SETTEXTEX settings={ST_DEFAULT,1200};SendMessage(EM_SETTEXTEX,(WPARAM)&settings,(LPARAM)(LPCTSTR)text);}
        CHARFORMAT2 format={};format.cbSize=sizeof(format);format.dwMask=CFM_BACKCOLOR|CFM_COLOR;
        format.crTextColor=UiTheme::TextPrimary();format.crBackColor=UiTheme::PageBackground();
        SetSel(from,text.GetLength(),TRUE);SendMessage(EM_SETCHARFORMAT,SCF_SELECTION,(LPARAM)&format);
        size_t visiblePacket=0;
        for(size_t i=0;i<ranges.size();++i) {
            const auto& range=ranges[i];
            const bool unchanged=append && i<m_ranges.size() && range.first==m_ranges[i].first && range.last==m_ranges[i].last;
            if(range.first==range.last) continue;
            format.crBackColor=(visiblePacket++%2) ? RGB(218,232,248) : UiTheme::PageBackground();
            if(unchanged) continue;
            SetSel(range.first,range.last,TRUE);SendMessage(EM_SETCHARFORMAT,SCF_SELECTION,(LPARAM)&format);
        }
        m_text=text;m_ranges=ranges;EmptyUndoBuffer();SetReadOnly(TRUE);
        SetSel(preserve ? min(first,text.GetLength()) : 0,preserve ? min(last,text.GetLength()) : 0,TRUE);
        if(preserve) {
            SendMessage(EM_SETSCROLLPOS,0,(LPARAM)&scroll);
            // Older RichEdit implementations may truncate scroll coordinates.
            if(GetFirstVisibleLine()!=top) LineScroll(top-GetFirstVisibleLine());
        } else {POINT origin={};SendMessage(EM_SETSCROLLPOS,0,(LPARAM)&origin);}
        if(redraw) SetRedraw(TRUE);Invalidate(FALSE);m_updating=false;
    }
protected:
    LRESULT WindowProc(UINT message, WPARAM wp, LPARAM lp) override {
        if(message==WM_COPY || (message==WM_KEYDOWN && (GetKeyState(VK_CONTROL)&0x8000) && (wp=='C' || wp==VK_INSERT))) {
            int first,last;GetSel(first,last);
            CString text=m_text.Mid(first,max(0,last-first));text.Replace(L"\r",L"\r\n");
            if(!text.IsEmpty() && OpenClipboard()) {
                HGLOBAL data=GlobalAlloc(GMEM_MOVEABLE,(text.GetLength()+1)*sizeof(wchar_t));
                if(data) {
                    void* memory=GlobalLock(data);
                    if(memory) {
                        memcpy(memory,(LPCTSTR)text,(text.GetLength()+1)*sizeof(wchar_t));GlobalUnlock(data);
                        if(!EmptyClipboard() || !SetClipboardData(CF_UNICODETEXT,data)) GlobalFree(data);
                    } else GlobalFree(data);
                }
                CloseClipboard();
            }
            return 0;
        }
        return CRichEditCtrl::WindowProc(message,wp,lp);
    }
private:
    CString m_text;
    std::vector<Range> m_ranges;
    bool m_updating=false;
};
