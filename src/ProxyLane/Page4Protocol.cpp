#include "stdafx.h"
#include "ProxyLane.h"
#include "Page4.h"
#include "Localization.h"
#include "ProtocolViewModel.h"
#include "MitmSettings.h"
#include "RecordingSettings.h"
#include "ProcessIconCache.h"
#include <atomic>
#include <thread>
#include <map>
#include <shlobj.h>

namespace {
int CALLBACK RecordingBrowseCallback(HWND window,UINT message,LPARAM,LPARAM initial) {
    if(message==BFFM_INITIALIZED && initial)SendMessage(window,BFFM_SETSELECTION,TRUE,initial);
    return 0;
}
CString Text(const std::string& value) {
    if (value.empty()) return CString();
    int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), (int)value.size(), nullptr, 0);
    CString text; auto buffer = text.GetBuffer(size);
    MultiByteToWideChar(CP_UTF8, 0, value.data(), (int)value.size(), buffer, size);
    for (int i = 0; i < size; ++i)
        if (buffer[i] < 32 && buffer[i] != '\r' && buffer[i] != '\n' && buffer[i] != '\t') buffer[i] = L'.';
    text.ReleaseBuffer(size); return text;
}
ProtocolView::Query QueryFor(IProxyTlsControl* tls) {
    return [tls](const ProtocolView::Json& command) {
        auto request=command;
        request["live_preview"]=true;
        const auto input = request.dump();
        std::vector<char> output(65536);
        for (int retry = 0; retry < 4; ++retry) {
            int size = tls->QueryProtocol(input.c_str(), output.data(), output.size());
            if (size < 0) throw std::runtime_error(output.data());
            if (size <= 0 || size > 8 * 1024 * 1024) throw std::runtime_error("Invalid protocol reply size");
            if ((size_t)size <= output.size()) return ProtocolView::Json::parse(output.data());
            output.resize(size);
        }
        throw std::runtime_error("Protocol reply changed too quickly; retry");
    };
}
struct Job {
    std::atomic<bool> done{false};
    int archiveAction = 0;
    ProtocolView::Json archive;
    bool detail = false;
    bool updated = true;
    bool baseline = false;
    uint64_t epoch = 0;
    std::string key, error, archivePath;
    ProtocolView::Batch batch;
    ProtocolView::Detail result;
};

}
struct ProtocolPageData {
    ProtocolView::History history;
    bool offline=false, archiveRefresh=false;
    uint64_t archiveOffset=0, archiveTotal=0, archiveCount=0;
    uint64_t archiveGeneration=0;
    int archiveSelected=-1, archiveFailedAt=-1;
    std::map<int,std::string> archiveKeys;
    CString archiveCaption, archiveDirectory;
    size_t previewLimit=ProtocolView::BodyPreviewLimit;
    std::shared_ptr<Job> job;
    std::string run, selected, displayed, firstRow;
    std::vector<std::string> shownKeys;
    ProcessIconCache icons;
    std::vector<std::wstring> shownIconKeys;
    std::vector<std::string> shownIconPaths;
    std::vector<int> shownIcons;
    ProtocolView::Detail detail;
    uint64_t next = 0, epoch = 0, lost = 0;
    DWORD lastPoll = 0, lastStatus = 0;
    bool baseline = false, rebuilding = false, haveDetail = false;
    bool wasRecording = false;
    bool finalPoll = false;
    bool columnsInitialized = false;
    CString error;
    std::string rawContext, hexContext, locateContext;
    bool pendingDisplay = false;
};
LRESULT CPage4::OnMonitorSettings(WPARAM,LPARAM) {ApplyMonitorSettings();SetMonitorControls(m_job || m_stopJob);return 0;}
void CPage4::ApplyMonitorSettings() {
    if(!m_protocol || IsViewingRecording()) return;
    auto settings=MitmSettings::Load();auto& state=*m_protocol;
    const size_t preview=settings[3]*1024;
    if(state.previewLimit==preview && state.history.rowLimit==settings[2]) return;
    state.previewLimit=preview;state.history.SetLimit(settings[2]);
    ++state.epoch;state.haveDetail=false;state.displayed.clear();
    RebuildRequests();ShowProtocolDetail();
}
void CPage4::InitProtocolView() {
    m_protocol = std::make_shared<ProtocolPageData>();
    const DWORD child = WS_CHILD | WS_VISIBLE | WS_TABSTOP;
    CRect empty;
    m_openRecording.Create(Localization::Get(L"recording.view_close"),(child&~WS_VISIBLE)|BS_PUSHBUTTON,empty,this,IDC_ARCHIVE_OPEN);
    m_recordingViewStatus.Create(L"",WS_CHILD|WS_VISIBLE|SS_LEFTNOWORDWRAP|SS_ENDELLIPSIS,empty,this,IDC_ARCHIVE_STATUS);
    m_requests.Create(child | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_SHAREIMAGELISTS, empty, this, IDC_PROTOCOL_REQUESTS);
    m_requests.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_INFOTIP | LVS_EX_SUBITEMIMAGES);
    const int iconSize=UiTheme::ScaleForWindow(m_hWnd,16);
    if(m_processIcons.Create(iconSize,iconSize,ILC_COLOR32|ILC_MASK,1,8)) {
        if(m_processIcons.Add(LoadIcon(nullptr,IDI_APPLICATION))>=0)
            m_requests.SetImageList(&m_processIcons,LVSIL_SMALL);
        else m_processIcons.DeleteImageList();
    }
    UiTheme::ApplyListColors(m_requests.m_hWnd);
    const LPCTSTR columns[] = {L"#", L"protocol.process", L"PID", L"protocol.version", L"protocol.method", L"protocol.address", L"protocol.status", L"protocol.size"};
    for (int i = 0; i < _countof(columns); ++i)
        m_requests.InsertColumn(i, i == 0 || i == 2 ? columns[i] : Localization::Get(columns[i]), LVCFMT_LEFT, 80);
    m_requests.EnableGroupView(FALSE);
    m_filter.Create(child | WS_BORDER | ES_AUTOHSCROLL, empty, this, IDC_PROTOCOL_FILTER);
    m_filter.SetLimitText(256);
    m_follow.Create(Localization::Get(L"protocol.follow"), child | BS_AUTOCHECKBOX, empty, this, IDC_PROTOCOL_FOLLOW);
    m_follow.SetCheck(BST_CHECKED);
    m_filter.SendMessage(EM_SETCUEBANNER, TRUE, (LPARAM)(LPCTSTR)Localization::Get(L"protocol.filter"));
    m_protocolFilter.Create(child | CBS_DROPDOWNLIST | WS_VSCROLL, empty, this, IDC_PROTOCOL_KIND);
    for (LPCTSTR key : {L"protocol.all", L"HTTP", L"TCP", L"UDP", L"TLS", L"DNS", L"QUIC"})
        m_protocolFilter.AddString(key == CString(L"protocol.all") ? Localization::Get(key) : key);
    m_protocolFilter.SetCurSel(0);
    m_detailTabs.Create(child | TCS_FOCUSNEVER, empty, this, IDC_PROTOCOL_DETAIL_TABS);
    m_detailTabs.InsertItem(0, Localization::Get(L"protocol.request"));
    m_detailTabs.InsertItem(1, Localization::Get(L"protocol.response"));
    m_viewTabs.Create(child | TCS_FOCUSNEVER, empty, this, IDC_PROTOCOL_VIEW_TABS);
    m_viewTabs.InsertItem(0, L"Raw"); m_viewTabs.InsertItem(1, L"HexView");
    m_detailStatus.Create(L"", WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_LEFTNOWORDWRAP | SS_ENDELLIPSIS, empty, this, IDC_PROTOCOL_STATUS);
    if(m_detailTooltip.Create(this,TTS_ALWAYSTIP | TTS_NOPREFIX)) {
        m_detailTooltip.AddTool(&m_detailStatus,L" ");
        m_detailTooltip.AddTool(&m_recordingViewStatus,L" ");
        m_detailTooltip.AddTool(&m_recordStatus,L" ");
        m_detailTooltip.SetMaxTipWidth(UiTheme::ScaleForWindow(m_hWnd,640));
        m_detailTooltip.Activate(FALSE);
    }
    AfxInitRichEdit2();
    m_detail.Create(child | ES_MULTILINE | ES_READONLY | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL,
        empty, this, IDC_PROTOCOL_DETAIL);
    m_detail.SetBackgroundColor(FALSE,UiTheme::Surface());
    m_detail.SetEventMask(m_detail.GetEventMask() | ENM_SELCHANGE);
    m_detail.SendMessage(EM_SETUNDOLIMIT,0);
    m_hexView.Create(this, IDC_PROTOCOL_HEX); m_hexView.SetFont(&m_font);
    CWnd* controls[] = {&m_openRecording,&m_recordingViewStatus,&m_requests, &m_detailTabs, &m_viewTabs, &m_detailStatus, &m_filter, &m_follow, &m_protocolFilter};
    for (auto control : controls) control->SetFont(&m_uiFont);
    m_detail.SetFont(&m_font); m_detail.SetLimitText(2 * 1024 * 1024);
    ShowProtocolDetail();
}
void CPage4::InitProtocolColumns() {
    if (!m_protocol || m_protocol->columnsInitialized || !m_requests.GetSafeHwnd()) return;
    CRect client; m_requests.GetClientRect(client);
    if (client.Width() <= 0) return;
    auto s = [this](int v) { return UiTheme::ScaleForWindow(m_hWnd, v); };
    const int widths[] = {38, 118, 62, 105, 50, 0, 90, 115};
    int remaining = client.Width() - s(20);
    for (int col = 0; col < 8; ++col) if (col != 5) {
        m_requests.SetColumnWidth(col, s(widths[col])); remaining -= s(widths[col]);
    }
    m_requests.SetColumnWidth(5, max(s(150), remaining));
    m_protocol->columnsInitialized = true;
}
void CPage4::LayoutProtocolView(int x, int y, int width, int height) {
    if (!m_protocol || !m_detail.GetSafeHwnd()) return;
    auto s = [this](int v) { return UiTheme::ScaleForWindow(m_hWnd, v); };
    const bool offline=IsViewingRecording();
    m_follow.ShowWindow(offline?SW_HIDE:SW_SHOW);
    m_filter.MoveWindow(x, y, max(0,width-s(offline?120:232)), s(24));
    m_follow.MoveWindow(x+max(0,width-s(224)), y, s(104), s(24));
    m_protocolFilter.MoveWindow(x+max(0,width-s(112)), y, s(112), s(200));
    y += s(30); height = max(0, height - s(30));
    m_protocolRect.SetRect(x,y,x+width,y+height);
    int available = max(0, height - s(88));
    int minimum = min(s(70), available / 2);
    int listHeight = max(minimum, min(available-minimum, (int)(available*m_splitRatio)));
    m_requests.MoveWindow(x, y, width, listHeight);
    y += listHeight;
    m_splitRect.SetRect(x,y,x+width,y+s(8)); y += s(8);
    int viewWidth=s(152),tabsWidth=max(s(100),width-viewWidth-s(8));
    m_detailTabs.MoveWindow(x,y,tabsWidth,s(26));
    m_viewTabs.MoveWindow(x+width-viewWidth,y,viewWidth,s(26)); y += s(29);
    m_detailStatus.MoveWindow(x,y,width,s(18)); y += s(21);
    UpdateDetailTooltip();
    CRect body(x,y,x+width,max(y,m_protocolRect.bottom));
    m_detail.MoveWindow(body); m_hexView.MoveWindow(body);
}
void CPage4::OnLButtonDown(UINT flags, CPoint point) {
    if (m_splitRect.PtInRect(point)) { m_dragging = true; SetCapture(); return; }
    CModernDialog::OnLButtonDown(flags, point);
}
void CPage4::OnLButtonUp(UINT flags, CPoint point) {
    if (m_dragging) { m_dragging = false; ReleaseCapture(); }
    CModernDialog::OnLButtonUp(flags, point);
}
void CPage4::OnMouseMove(UINT flags, CPoint point) {
    if (m_dragging) {
        int available = max(1, m_protocolRect.Height()-UiTheme::ScaleForWindow(m_hWnd,88));
        m_splitRatio = max(0.0, min(1.0, (double)(point.y-m_protocolRect.top)/available));
        CRect r; GetClientRect(r); LayoutControls(r.Width(),r.Height());
    }
    CModernDialog::OnMouseMove(flags, point);
}
BOOL CPage4::OnSetCursor(CWnd* window, UINT hit, UINT message) {
    CPoint point; GetCursorPos(&point); ScreenToClient(&point);
    if (m_dragging || m_splitRect.PtInRect(point)) { SetCursor(LoadCursor(NULL,IDC_SIZENS)); return TRUE; }
    return CModernDialog::OnSetCursor(window,hit,message);
}
void CPage4::OnCaptureChanged(CWnd* window) { m_dragging = false; CModernDialog::OnCaptureChanged(window); }
void CPage4::OnFilter() { if (m_protocol && m_requests.GetSafeHwnd()) {
    if(IsViewingRecording()) {
        auto& state=*m_protocol;
        ++state.archiveGeneration; ++state.epoch;
        state.archiveRefresh=true;state.archiveFailedAt=-1;state.archiveSelected=-1;
        state.selected.clear();state.displayed.clear();state.haveDetail=false;
        state.shownKeys.clear();state.archiveKeys.clear();state.history.Clear();
        state.rebuilding=true;m_requests.DeleteAllItems();state.rebuilding=false;
        ShowProtocolDetail();return;
    }
    RebuildRequests(); ShowProtocolDetail(); } }
bool CPage4::CanFollowLatest() {
    if (IsViewingRecording() || m_follow.GetCheck() != BST_CHECKED) return false;
    SCROLLINFO scroll = {}; scroll.cbSize = sizeof(scroll); scroll.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    const bool aboveBottom = m_requests.GetScrollInfo(SB_VERT, &scroll) &&
        scroll.nPage > 0 && scroll.nPos + (int)scroll.nPage <= scroll.nMax;
    if (!m_protocol->selected.empty() || aboveBottom) {
        m_follow.SetCheck(BST_UNCHECKED); return false;
    }
    return true;
}
void CPage4::OnListScrolled(NMHDR*, LRESULT* result) {
    *result = 0;
    if (m_protocol && !m_protocol->rebuilding) CanFollowLatest();
}
void CPage4::OnFollowLatest() {
    if (!m_protocol || m_follow.GetCheck() != BST_CHECKED) return;
    auto& state = *m_protocol;
    ++state.epoch; state.selected.clear(); state.displayed.clear(); state.haveDetail = false;
    state.rebuilding = true;
    m_requests.SetItemState(-1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (m_requests.GetItemCount()) m_requests.EnsureVisible(m_requests.GetItemCount()-1, FALSE);
    state.rebuilding = false;
    ShowProtocolDetail();
    CRect r; GetClientRect(r); LayoutControls(r.Width(),r.Height());
}
void CPage4::OnRequestSelected(NMHDR*, LRESULT* result) {
    *result = 0; auto& state = *m_protocol; if (state.rebuilding) return;
    int item = m_requests.GetNextItem(-1, LVNI_SELECTED);
    const auto* row=RequestRow(item);
    std::string key=row?row->key:"";
    if(state.offline) state.archiveSelected=item;
    if (!key.empty()) m_follow.SetCheck(BST_UNCHECKED);
    if (key == state.selected) return;
    for(const auto& row:state.history.rows) if(row.key==key && row.websocket) {
        const auto& exchange=row.record.at("exchange");m_detailTabs.SetCurSel(exchange["request"].is_null()?1:0);break;
    }
    state.selected = key; state.locateContext.clear(); state.haveDetail = false; state.displayed.clear(); ShowProtocolDetail();
    CRect r; GetClientRect(r); LayoutControls(r.Width(),r.Height());
}
void CPage4::OnDetailTab(NMHDR*, LRESULT* result) { *result = 0; m_protocol->locateContext.clear(); ShowProtocolDetail(); }
void CPage4::OnView(NMHDR*, LRESULT* result) {
    *result = 0; if (!m_protocol) return;
    for(auto& row:m_protocol->history.rows) if(row.key==m_protocol->selected) {
        const bool hex=m_viewTabs.GetCurSel()==1;
        if(row.hex!=hex && row.udp && !row.dns)
            m_protocol->locateContext=row.key+":"+std::to_string(m_detailTabs.GetCurSel());
        row.hex=hex;break;
    }
    ShowProtocolDetail();
}
void CPage4::OnHexSelection(NMHDR*,LRESULT* result) {
    *result=0;
    if(!m_protocol || m_protocol->rebuilding || m_viewTabs.GetCurSel()!=1) return;
    for(auto& row:m_protocol->history.rows) if(row.key==m_protocol->selected && row.udp && !row.dns) {
        row.datagram[m_detailTabs.GetCurSel()==0 ? 0 : 1]=m_hexView.SelectedPacket();
        ShowProtocolDetail();return;
    }
}
void CPage4::OnRawSelection(NMHDR*, LRESULT* result) {
    *result=0;
    if(!m_protocol || m_protocol->rebuilding || m_detail.Updating() || m_viewTabs.GetCurSel()!=0) return;
    int first,last;m_detail.GetSel(first,last);
    const auto& ranges=m_detail.Ranges();
    for(auto& row:m_protocol->history.rows) if(row.key==m_protocol->selected && row.udp && !row.dns && !row.quic) {
        auto& packet=row.datagram[m_detailTabs.GetCurSel()==0 ? 0 : 1];
        if(first==last && packet<ranges.size() && ranges[packet].first==ranges[packet].last && first==ranges[packet].first) return;
        for(size_t i=0;i<ranges.size();++i) if(first>=ranges[i].first && first<ranges[i].last) {
            if(packet!=i) {packet=i;ShowProtocolDetail();}return;
        }
    }
}
void CPage4::ShowProtocolDetail() {
    if (!m_protocol) return;
    auto& state = *m_protocol; bool hex = false, stream = false, udp = false;
    // A timer must not replace text while the user is dragging a selection
    // or a scrollbar. Refresh once the native control releases capture.
    if (::GetCapture() == m_detail.GetSafeHwnd() || ::GetCapture() == m_hexView.GetSafeHwnd()) { state.pendingDisplay = true; return; }
    state.pendingDisplay = false;
    size_t packet = 0; const ProtocolView::Row* selected = nullptr;
    for (const auto& row : state.history.rows) if (row.key == state.selected) {
        selected = &row; hex = row.hex; stream = row.stream; udp = row.udp && !row.dns;
        packet = row.datagram[m_detailTabs.GetCurSel() == 0 ? 0 : 1]; break;
    }
    for (int i=0;i<2;++i) {
        CString label = Localization::Get(stream ? (i == 0 ? L"protocol.sent" : L"protocol.received") : (i == 0 ? L"protocol.request" : L"protocol.response"));
        TCHAR current[64] = {}; TCITEM item = {}; item.mask = TCIF_TEXT;
        item.pszText = current; item.cchTextMax = _countof(current);
        m_detailTabs.GetItem(i,&item);
        if (label != current) {
            item.pszText = label.GetBuffer(); m_detailTabs.SetItem(i,&item); label.ReleaseBuffer();
            m_detailTabs.Invalidate();
        }
    }
    m_viewTabs.SetCurSel(hex ? 1 : 0); m_viewTabs.EnableWindow(selected != nullptr);
    std::vector<unsigned char> bytes; CString status;
    if (!m_mitmSupported) status = Localization::Get(ProxyIsLegacyWindows() ? L"mitm.legacy_unavailable" : L"mitm.x64_required");
    else if (state.selected.empty()) status = Localization::Get(L"protocol.select");
    else if (!state.haveDetail) status = Localization::Get(L"protocol.loading");
    else {
        const auto& side = m_detailTabs.GetCurSel() == 0 ? state.detail.request : state.detail.response;
        bytes = ProtocolView::DisplayBytes(side);
        if (state.detail.state == ProtocolView::Detail::Truncated || state.detail.state == ProtocolView::Detail::Evicted || state.detail.state == ProtocolView::Detail::Unavailable) {
            status = Text(state.detail.note); if (status.IsEmpty()) status = Text(side.note);
            status.Trim(); status.Replace(L"\r\n",L"  ");
        }
        if (side.previewLimited || ((hex || !udp) && side.note.find("Display limited") != std::string::npos) || (!udp && stream && selected &&
            (m_detailTabs.GetCurSel() == 0 ? selected->requestBytes : selected->responseBytes) > state.previewLimit)) {
            if (!status.IsEmpty()) status += L" | "; status += Localization::Format(L"protocol.preview",(unsigned)(state.previewLimit/1024));
        }
        if (udp) {
            if (state.detail.note.find("Datagram index limited") != std::string::npos) status += Text(" | Datagram index limited to " + std::to_string(side.datagrams.size()) + " packets in this direction.");
        }
    }
    std::vector<CProtocolRawView::Range> ranges;
    CString raw = bytes.empty() ? CString() : Text(std::string(bytes.begin(),bytes.end()));
    if (state.haveDetail) {
        const auto& side=m_detailTabs.GetCurSel()==0 ? state.detail.request : state.detail.response;
        if (!side.text.empty()) raw=Text(side.text);
        if(udp && selected && !selected->quic) {
            raw.Empty();
            for(const auto& data:side.packets) {
                const LONG first=raw.GetLength();
                raw+=CProtocolRawView::Normalize(Text(std::string(data.begin(),data.end())));
                ranges.push_back({first,raw.GetLength()});
            }
        }
        if (selected && selected->record.contains("connection") && selected->record["connection"].is_object() && selected->record["connection"].value("decrypted",false) && selected->record["connection"].value("upstream_verification_skipped",false) && !selected->connectionRow) {
            if (!status.IsEmpty()) status += L" | "; status += L"Target certificate verification skipped.";
        }
        if (selected && (selected->dns || selected->connectionRow)) {
            CString prefix = selected->dns ? Text("DNS server: " + selected->endpoint + " | " + selected->protocol) : Text(state.detail.note);
            if (!prefix.IsEmpty()) { if (!status.IsEmpty()) prefix += L" | " + status; status = prefix; }
        }
        if(state.detail.targetCertificateRejected) {
            // Keep the actionable hint first so the option path survives a narrow preview.
            CString hint=Localization::Format(L"protocol.target_certificate_help",
                (LPCWSTR)Localization::Get(L"mitm.ca"),(LPCWSTR)Localization::Get(L"mitm.skip_verify"));
            status=hint+(status.IsEmpty() ? CString() : L" | "+status);
        }
    }
    raw = CProtocolRawView::Normalize(raw);
    const std::string context = state.selected + ":" + std::to_string(m_detailTabs.GetCurSel());
    m_detail.ShowWindow(hex ? SW_HIDE : SW_SHOW); m_hexView.ShowWindow(hex ? SW_SHOW : SW_HIDE);
    m_detail.Render(raw, ranges, state.rawContext == context);
    state.rawContext = context;
    if(udp && state.haveDetail) {
        const auto& side=m_detailTabs.GetCurSel()==0 ? state.detail.request : state.detail.response;
        m_hexView.SetPackets(side.packets,state.hexContext==context);
        // Synchronize only on an explicit view change. Incoming data must not
        // repeatedly recenter either view or replace the user's selection.
        if(state.locateContext==context) {
            state.locateContext.clear();
            if(hex) m_hexView.LocatePacket(packet);
            else if(selected && !selected->quic) m_detail.LocatePacket(packet);
        }
        if(packet<side.datagrams.size()) {
            CString prefix=Localization::Format(selected && selected->protocol=="QUIC/DATAGRAM" ? L"protocol.quic_datagram" : L"protocol.datagram",(unsigned)packet+1,(uint64_t)side.datagrams[packet].second);
            if(hex && packet<side.packets.size()) {
                CString offset;offset.Format(L" | Offset 0x%X",(unsigned)m_hexView.SelectedOffset());prefix+=offset;
            }
            if(packet>=side.packets.size()) prefix+=L" | Packet payload is outside the preview or unavailable.";
            if(!status.IsEmpty()) prefix+=L" | "+status;
            status=prefix;
        }
    } else m_hexView.SetBytes(std::move(bytes),state.hexContext==context);
    state.hexContext=context;
    if (state.history.discarded || state.lost) status += Localization::Format(L"protocol.dropped", state.history.discarded + state.lost);
    if (!state.error.IsEmpty()) status += L" | " + state.error;
    if(m_detailStatusText!=status) {
        m_detailStatusText=status;
        m_detailStatus.SetWindowText(status);
        if(m_detailTooltip.GetSafeHwnd()) {
            m_detailTooltip.Pop();
            m_detailTooltip.UpdateTipText(m_detailStatusText,&m_detailStatus);
        }
    }
    UpdateDetailTooltip();
}
void CPage4::UpdateDetailTooltip() {
    if(!m_detailTooltip.GetSafeHwnd() || !m_detailStatus.GetSafeHwnd()) return;
    CRect rect;m_detailStatus.GetClientRect(rect);
    CClientDC dc(&m_detailStatus);
    auto font=m_detailStatus.GetFont();auto old=font ? dc.SelectObject(font) : nullptr;
    const bool overflow=!m_detailStatusText.IsEmpty() && rect.Width()>0 &&
        (dc.GetTextExtent(m_detailStatusText).cx>rect.Width() || m_detailStatusText.Find(L'\n')>=0);
    if(old) dc.SelectObject(old);
    if(!overflow) m_detailTooltip.Pop();
    m_detailTooltip.Activate(TRUE);
}
BOOL CPage4::PreTranslateMessage(MSG* message) {
    if(message && m_detailTooltip.GetSafeHwnd()) {
        if(message->message==WM_MOUSEMOVE) UpdateDetailTooltip();
        m_detailTooltip.RelayEvent(message);
    }
    return CModernDialog::PreTranslateMessage(message);
}
void CPage4::RebuildRequests() {
    auto& state = *m_protocol;
    if(state.offline) {
        // The native virtual list owns only the row count, never all summaries.
        // Keeping that count stable preserves selection and both scrollbars.
        state.rebuilding=true;
        if(m_requests.GetItemCount()!=(int)state.archiveTotal)
            m_requests.SetItemCountEx((int)state.archiveTotal,LVSICF_NOSCROLL|LVSICF_NOINVALIDATEALL);
        m_requests.Invalidate(FALSE);state.rebuilding=false;
        return;
    }
    const bool follow = CanFollowLatest();
    CString filterText; m_filter.GetWindowText(filterText); filterText.Trim();
    CStringA utf8(CW2A(filterText, CP_UTF8)); std::string filter(utf8);
    std::vector<const ProtocolView::Row*> visible;
    std::vector<std::string> keys;
    for (const auto& row : state.history.rows) if (state.offline || ProtocolView::Matches(row,filter,m_protocolFilter.GetCurSel())) { visible.push_back(&row); keys.push_back(row.key); }
    const bool rebuild = keys.size() < state.shownKeys.size() || !std::equal(state.shownKeys.begin(), state.shownKeys.end(), keys.begin());
    const int existing = rebuild ? 0 : m_requests.GetItemCount();
    int top = m_requests.GetTopIndex(); CRect topRect;
    bool restoreTop = rebuild && top >= 0 && m_requests.GetItemRect(top,topRect,LVIR_BOUNDS);
    std::string topKey = restoreTop && (size_t)top < state.shownKeys.size() ? state.shownKeys[top] : "";
    state.rebuilding = true; m_requests.SetRedraw(FALSE);
    if (rebuild) m_requests.DeleteAllItems();
    int selected = -1;
    state.shownIconKeys.resize(visible.size());state.shownIconPaths.resize(visible.size());state.shownIcons.resize(visible.size());
    for (size_t index=0;index<visible.size();++index) {
        const auto& row = *visible[index]; CString number; number.Format(L"%I64u",row.number);
        if ((int)index >= existing) m_requests.InsertItem((int)index, number,I_IMAGENONE); else m_requests.SetItemText((int)index,0,number);
        m_requests.SetItemText((int)index,1,Text(row.process)); CString pid; pid.Format(L"%u",row.pid); m_requests.SetItemText((int)index,2,pid);
        if(rebuild || (int)index>=existing || state.shownIconPaths[index]!=row.processPath) {
            state.shownIconPaths[index]=row.processPath;
            state.shownIconKeys[index]=ProcessIconCache::Key(Text(row.processPath));
        }
        int icon=m_processIcons.GetSafeHandle()?state.icons.Request(state.shownIconKeys[index]):I_IMAGENONE;
        if(rebuild || (int)index>=existing || state.shownIcons[index]!=icon) {
            LVITEM item={};item.mask=LVIF_IMAGE;item.iItem=(int)index;item.iSubItem=1;item.iImage=icon;m_requests.SetItem(&item);
        }
        state.shownIcons[index]=icon;
        m_requests.SetItemText((int)index,3,Text(row.protocol)); m_requests.SetItemText((int)index,4,Text(row.method));
        m_requests.SetItemText((int)index,5,Text(row.destination+" "+row.target)); m_requests.SetItemText((int)index,6,Text(row.status));
        CString size; size.Format(L"%I64u / %I64u",row.requestBytes,row.responseBytes); m_requests.SetItemText((int)index,7,size);
        if (row.key == state.selected) selected = (int)index;
    }
    state.shownKeys = std::move(keys);
    if (selected >= 0) m_requests.SetItemState(selected,LVIS_SELECTED|LVIS_FOCUSED,LVIS_SELECTED|LVIS_FOCUSED);
    else if (!state.selected.empty()) { state.selected.clear(); state.displayed.clear(); state.haveDetail=false; ShowProtocolDetail(); }
    // Re-enable layout before restoring scroll: image-list row height and newly
    // visible scrollbars can change the page size while redraw is disabled.
    m_requests.SetRedraw(TRUE);
    if (follow && !state.shownKeys.empty()) m_requests.EnsureVisible((int)state.shownKeys.size()-1,FALSE);
    else if (restoreTop) for (size_t i=0;i<state.shownKeys.size();++i) if (state.shownKeys[i] == topKey) {
        m_requests.EnsureVisible((int)i,FALSE); CRect r;
        if (m_requests.GetItemRect((int)i,r,LVIR_BOUNDS)) m_requests.Scroll(CSize(0,r.top-topRect.top)); break;
    }
    m_requests.Invalidate(FALSE); state.rebuilding=false;
}
void CPage4::ClearProtocolView() {
    auto& state = *m_protocol;
    ++state.epoch; state.baseline = true; state.history.Clear(); state.lost = 0;
    state.selected.clear(); state.displayed.clear(); state.haveDetail = false; state.error.Empty();
    RebuildRequests(); ShowProtocolDetail();
    m_follow.SetCheck(BST_CHECKED);
}
void CPage4::TickProtocolView() {
    if (!m_protocol || !m_mitmSupported) return;
    if(m_processIcons.GetSafeHandle() && m_protocol->icons.Apply(m_processIcons)) {
        // Update only image cells. No list rebuild, selection change or scroll.
        if(m_protocol->offline) m_requests.Invalidate(FALSE);
        else for(size_t i=0;i<m_protocol->shownIconKeys.size();++i) {
            int icon=m_protocol->icons.Lookup(m_protocol->shownIconKeys[i]);
            if(icon!=m_protocol->shownIcons[i]) {
                LVITEM item={};item.mask=LVIF_IMAGE;item.iItem=(int)i;item.iSubItem=1;item.iImage=icon;
                m_requests.SetItem(&item);m_protocol->shownIcons[i]=icon;
            }
        }
    }
    if (m_protocol->pendingDisplay && (::GetCapture() != m_detail.GetSafeHwnd() && ::GetCapture() != m_hexView.GetSafeHwnd())) ShowProtocolDetail();
    CanFollowLatest();
    auto& state = *m_protocol;
    if(state.job && state.job->archiveAction) {
        if(!state.job->done.load()) return;
        auto job=state.job;state.job.reset();
        if(job->archiveAction==2 && job->epoch!=state.archiveGeneration) {UpdateRecordingControls();return;}
        if(!job->error.empty()) {
            state.archiveFailedAt=(int)state.archiveOffset;
            if(job->archiveAction==1 && job->error.find("INDEX_REBUILD_REQUIRED: ")!=std::string::npos) {
                CString prompt=Localization::Get(L"recording.index_rebuild_prompt");
                prompt+=L"\r\n\r\n"+Text(job->archivePath)+L"\r\n\r\n"+Text(job->error);
                // MessageBox pumps WM_TIMER. Keep the archive job reserved so
                // a timer cannot start another reader while the user decides.
                job->done.store(false);state.job=job;
                const int answer=MessageBox(prompt,Localization::Get(L"recording.view_open"),MB_YESNO|MB_DEFBUTTON2|MB_ICONQUESTION);
                state.job.reset();
                if(answer==IDYES) {
                    QueueRecordingPage(4,job->archivePath);return;
                }
            } else MessageBox(Text(job->error),Localization::Get(L"recording.view_open"),MB_OK|MB_ICONERROR);
        }
        else {
            const bool switching=job->archiveAction!=2;
            if(switching) {
                ++state.epoch;state.selected.clear();state.displayed.clear();state.haveDetail=false;state.archiveSelected=-1;
                state.offline=job->archiveAction!=3;
                SetRecordingListMode(state.offline);
            }
            // Retain the selected summary/detail even when it scrolls out of the
            // bounded list window. Reading another window must not disturb it.
            if(switching) {state.history.Clear();state.shownKeys.clear();state.archiveKeys.clear();}
            state.error.Empty();state.finalPoll=false;
            state.archiveFailedAt=-1;
            if(state.offline) {
                state.run=job->batch.run;state.archiveOffset=job->archive.value("offset",uint64_t(0));
                state.archiveTotal=job->archive.value("total",uint64_t(0));state.archiveCount=job->batch.rows.size();
                state.history.rowLimit=512;state.history.metadataLimit=16*1024*1024;
                int index=(int)state.archiveOffset;
                for(auto& row:job->batch.rows) {
                    row.number=row.record.value("recording_number",uint64_t(0));
                    state.archiveKeys[index++]=row.key;
                    bool found=false;
                    for(const auto& old:state.history.rows) if(old.key==row.key) {found=true;break;}
                    if(!found) {
                        state.history.bytes+=row.bytes;state.history.rows.push_back(std::move(row));
                    }
                }
                // Bounded FIFO summary cache; keep the current selection. Its
                // body is separately bounded by the normal detail preview cap.
                while(state.history.rows.size()>state.history.rowLimit || state.history.bytes>state.history.metadataLimit) {
                    auto old=state.history.rows.begin();
                    if(old!=state.history.rows.end() && old->key==state.selected) ++old;
                    if(old==state.history.rows.end()) break;
                    for(auto it=state.archiveKeys.begin();it!=state.archiveKeys.end();) {
                        if(it->second==old->key) it=state.archiveKeys.erase(it);else ++it;
                    }
                    state.history.bytes-=old->bytes;state.history.rows.erase(old);
                }
                CString caption;caption.Format(Localization::Get(L"recording.view_count"),state.archiveTotal);
                if(job->archive["manifest"].value("status",std::string())=="recording")caption+=Localization::Get(L"recording.view_interrupted");
                if(job->archive.value("warnings",0u))caption+=Localization::Get(L"recording.view_damaged");
                state.archiveDirectory=Text(job->archive.value("directory",std::string()));
                state.archiveCaption=caption;
                if(!state.archiveDirectory.IsEmpty()) {
                    auto directory=state.archiveDirectory;int slash=max(directory.ReverseFind(L'\\'),directory.ReverseFind(L'/'));
                    state.archiveCaption+=L" · "+directory.Mid(slash+1);
                }
            } else {
                state.run.clear();state.next=0;state.baseline=true;state.archiveRefresh=false;
                state.history.SetLimit(MitmSettings::Load()[2]);ApplyMonitorSettings();
            }
            RebuildRequests();
            if(state.offline) {LRESULT ignored=0;OnRequestSelected(nullptr,&ignored);}
            ShowProtocolDetail();
        }
        SetMonitorControls(false);
        return;
    }
    if(state.offline && state.archiveRefresh && !state.job) {state.archiveRefresh=false;state.archiveOffset=0;QueueRecordingPage(2);return;}
    if (state.wasRecording != m_recording) {
        state.finalPoll = !m_recording;
        ++state.epoch; state.wasRecording = m_recording;
    }
    if (state.job && state.job->done.load()) {
        auto job = state.job; state.job.reset();
        UpdateRecordingControls();
        if (job->epoch == state.epoch) {
            state.error = Text(job->error);
            if (!job->detail && job->baseline && !job->error.empty()) state.baseline = true;
            if (job->detail && job->key == state.selected) {
                if (job->updated) {
                    state.detail = std::move(job->result); state.haveDetail = true; state.displayed = job->key;
                    ShowProtocolDetail();
                }
            } else if (!job->detail && job->error.empty()) {
                state.run = job->batch.run; state.next = job->batch.next; state.lost += job->batch.lost;
                const auto discarded = state.history.discarded;
                for (auto& row : job->batch.rows) {
                    if (!row.connectionRow) for (const auto& old : state.history.rows) {
                        if (old.connectionRow && old.key == state.selected && old.run == row.run && old.record["connection"]["id"] == row.record["connection"]["id"]) {
                            state.selected = row.key; state.haveDetail = false; state.displayed.clear(); break;
                        }
                    }
                    if (row.key == state.selected) { state.detail.cacheStamp.clear(); state.lastStatus = 0; }
                    state.history.Add(std::move(row));
                }
                if (!job->batch.rows.empty()) RebuildRequests();
                if (job->batch.lost || (discarded != state.history.discarded && state.selected.empty())) ShowProtocolDetail();
                if(!m_recording && !state.selected.empty()) {
                    state.haveDetail=false;state.displayed.clear();
                }
            }
            if (!job->error.empty()) {
                if(job->detail && job->key==state.selected) {
                    state.detail=std::move(job->result);state.haveDetail=true;state.displayed=job->key;
                }
                ShowProtocolDetail();
            }
        }
    }
    if (state.job || m_stopJob) return;
    if(state.offline && m_requests.IsWindowVisible() && state.archiveTotal) {
        int wanted=-1;
        // A keyboard/click selection can arrive before that window is loaded.
        if(state.archiveSelected>=0 && !RequestRow(state.archiveSelected)) wanted=state.archiveSelected;
        const int top=m_requests.GetTopIndex();
        const int end=min((int)state.archiveTotal,top+m_requests.GetCountPerPage()+2);
        if(wanted<0) for(int i=top;i<end;++i) if(!RequestRow(i)) {wanted=i;break;}
        if(wanted>=0 && wanted!=state.archiveFailedAt) {
            state.archiveOffset=(uint64_t)wanted;QueueRecordingPage(2);return;
        }
    }
    const DWORD now = GetTickCount();
    bool statusOnly = state.haveDetail && state.selected == state.displayed;
    bool detail = !state.finalPoll && !state.selected.empty() && m_requests.IsWindowVisible() &&
        (!statusOnly || (m_recording && now - state.lastStatus >= 2000));
    // Stopped history remains readable on demand. Drain the final results once
    // after stop completes, but never poll an idle page or repeatedly re-read
    // an unchanged historical selection (including while the page is hidden).
    if (!m_recording && !detail && !state.finalPoll) return;
    if (!detail && !state.baseline && now - state.lastPoll < 500) return;
    auto job = std::make_shared<Job>(); job->epoch = state.epoch; job->detail = detail; job->key = state.selected;
    ProtocolView::Row selected;
    if (detail) {
        for (const auto& row : state.history.rows) if (row.key == state.selected) { selected = row; break; }
    }
    auto query = QueryFor(m_tls);
    const auto run = state.run; const auto after = state.next;
    const bool baseline = state.baseline;
    const bool finalPoll = !m_recording && state.finalPoll && !detail;
    job->baseline = baseline;
    const auto cacheStamp = state.detail.cacheStamp;
    const auto previewLimit=state.previewLimit;
    const bool offline=state.offline;
    if (detail) state.lastStatus = now;
    else { state.baseline = false; state.finalPoll = false; state.lastPoll = now; }
    state.job = job;
    UpdateRecordingControls();
    try {
        std::thread([job, query, run, after, baseline, finalPoll, selected, statusOnly, cacheStamp, previewLimit, offline]() {
            try {
                if (job->detail) {
                    if (statusOnly && ProtocolView::CacheStamp(query, selected) == cacheStamp) job->updated = false;
                    else {
                        auto row=selected;
                        if(offline) row.record=query(ProtocolView::Json{{"type","recording_detail"},{"run_id",row.run},{"cache_id",row.cacheId},{"connection_id",row.record["connection"]["id"]},{"preview_bytes",previewLimit}});
                        job->result = ProtocolView::ReadDetail(query, row, previewLimit);
                    }
                }
                else {
                    job->batch = ProtocolView::Poll(query, run, after, baseline);
                    // The stopped backend retains at most 256 records. Drain
                    // bounded pages in this one job, then stop polling entirely.
                    if(finalPoll && !baseline) for(unsigned i=0;i<16;++i) {
                        auto next=ProtocolView::Poll(query,job->batch.run,job->batch.next,false);
                        if(next.next<=job->batch.next)break;
                        job->batch.next=next.next;job->batch.lost+=next.lost;
                        for(auto& row:next.rows)job->batch.rows.push_back(std::move(row));
                    }
                }
            } catch (const std::exception& e) {
                job->error = e.what(); job->result.state = ProtocolView::Detail::Unavailable; job->result.note = e.what();
            } catch (...) {
                job->error = "Protocol query failed"; job->result.state = ProtocolView::Detail::Unavailable;
            }
            job->done.store(true);
        }).detach();
    } catch (...) { job->error = "Unable to start protocol worker"; job->done.store(true); }
}

void CPage4::OnRequestInfoTip(NMHDR* header, LRESULT* result) {
    *result = 0;
    auto info = reinterpret_cast<NMLVGETINFOTIP*>(header);
    if (!m_protocol || info->iItem < 0 || !info->pszText || info->cchTextMax <= 0) return;
    CPoint point; GetCursorPos(&point); m_requests.ScreenToClient(&point);
    LVHITTESTINFO hit = {}; hit.pt = point;
    if (m_requests.SubItemHitTest(&hit) != info->iItem || hit.iSubItem != 0) return;
    const auto* row=RequestRow(info->iItem);
    if (row && row->firstSeenSeconds > 0) {
        CString time = CTime((__time64_t)row->firstSeenSeconds).Format(L"%Y-%m-%d %H:%M:%S");
        _tcsncpy_s(info->pszText, info->cchTextMax, time, _TRUNCATE);
        return;
    }
}

const ProtocolView::Row* CPage4::RequestRow(int item) const {
    if(!m_protocol || item<0) return nullptr;
    auto& state=*m_protocol;std::string key;
    if(state.offline) {
        auto found=state.archiveKeys.find(item);
        if(found!=state.archiveKeys.end()) key=found->second;
    } else if((size_t)item<state.shownKeys.size()) key=state.shownKeys[item];
    if(!key.empty()) for(const auto& row:state.history.rows) if(row.key==key) return &row;
    return nullptr;
}
void CPage4::OnRequestDisplay(NMHDR* header,LRESULT* result) {
    *result=0;
    auto& item=reinterpret_cast<NMLVDISPINFO*>(header)->item;
    if(!m_protocol || !m_protocol->offline) return;
    const auto* row=RequestRow(item.iItem);CString value;
    if(row) switch(item.iSubItem) {
        case 0:value.Format(L"%I64u",row->number);break;
        case 1:value=Text(row->process);break;
        case 2:value.Format(L"%u",row->pid);break;
        case 3:value=Text(row->protocol);break;
        case 4:value=Text(row->method);break;
        case 5:value=Text(row->destination+" "+row->target);break;
        case 6:value=Text(row->status);break;
        case 7:value.Format(L"%I64u / %I64u",row->requestBytes,row->responseBytes);break;
    }
    else if(item.iSubItem==1) value=Localization::Get(L"protocol.loading");
    if((item.mask&LVIF_TEXT) && item.pszText && item.cchTextMax>0)
        _tcsncpy_s(item.pszText,item.cchTextMax,value,_TRUNCATE);
    if(item.mask&LVIF_IMAGE) item.iImage=row && item.iSubItem==1 && m_processIcons.GetSafeHandle()
        ?m_protocol->icons.Request(ProcessIconCache::Key(Text(row->processPath))):I_IMAGENONE;
}
void CPage4::SetRecordingListMode(bool offline) {
    // LVS_OWNERDATA cannot be toggled on an existing HWND. Recreate only when
    // entering/leaving the archive; keep live monitoring's list unchanged.
    if(((m_requests.GetStyle()&LVS_OWNERDATA)!=0)==offline) return;
    auto& state=*m_protocol;state.rebuilding=true;
    CRect bounds;m_requests.GetWindowRect(bounds);ScreenToClient(bounds);
    DWORD style=m_requests.GetStyle(),extended=m_requests.GetExtendedStyle();
    int widths[8],order[8];CString titles[8];
    m_requests.GetColumnOrderArray(order,8);
    for(int i=0;i<8;++i) {
        TCHAR text[128]={};LVCOLUMN column={};column.mask=LVCF_TEXT;column.pszText=text;column.cchTextMax=128;
        m_requests.GetColumn(i,&column);titles[i]=text;widths[i]=m_requests.GetColumnWidth(i);
    }
    const bool focus=GetFocus()==&m_requests;
    m_requests.DestroyWindow();
    m_requests.Create(offline?style|LVS_OWNERDATA:style&~LVS_OWNERDATA,bounds,this,IDC_PROTOCOL_REQUESTS);
    m_requests.SetExtendedStyle(extended);m_requests.SetFont(&m_uiFont);
    UiTheme::ApplyListColors(m_requests.m_hWnd);
    if(m_processIcons.GetSafeHandle()) m_requests.SetImageList(&m_processIcons,LVSIL_SMALL);
    for(int i=0;i<8;++i) m_requests.InsertColumn(i,titles[i],LVCFMT_LEFT,widths[i]);
    m_requests.SetColumnOrderArray(8,order);
    // Restore the list's tab position immediately after the protocol filter.
    m_requests.SetWindowPos(&m_protocolFilter,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE);
    if(focus) m_requests.SetFocus();
    state.rebuilding=false;
}

bool CPage4::IsViewingRecording() const {
    return m_protocol && (m_protocol->offline || (m_protocol->job && m_protocol->job->archiveAction));
}
void CPage4::UpdateRecordingControls() {
    if(!m_protocol || !m_openRecording.GetSafeHwnd())return;
    const auto& state=*m_protocol;bool busy=state.job!=nullptr;
    m_openRecording.SetWindowText(Localization::Get(L"recording.view_close"));
    m_openRecording.EnableWindow(m_mitmSupported && !m_recording && !m_job && !m_stopJob && !busy);
    if(!m_stopJob)m_recordingViewStatus.SetWindowText(state.job && state.job->archiveAction ? Localization::Get(state.job->archiveAction==4?L"recording.index_rebuilding":L"recording.view_loading") : state.offline ? state.archiveCaption : L"");
    m_follow.EnableWindow(!IsViewingRecording());
    if(!m_stopJob && m_detailTooltip.GetSafeHwnd())m_detailTooltip.UpdateTipText(state.archiveCaption+L"\r\n"+state.archiveDirectory,&m_recordingViewStatus);
}
void CPage4::OnOpenRecording() {
    if(!m_protocol || m_recording || m_job || m_stopJob || m_protocol->job)return;
    if(m_protocol->offline){QueueRecordingPage(3);return;}
    BROWSEINFO info={};info.hwndOwner=m_hWnd;CString title=Localization::Get(L"recording.view_choose");info.lpszTitle=title;
    info.ulFlags=BIF_RETURNONLYFSDIRS|BIF_NEWDIALOGSTYLE;
    CString initial=RecordingSettings::BrowseDirectory();info.lpfn=RecordingBrowseCallback;info.lParam=(LPARAM)initial.GetString();
    auto item=SHBrowseForFolder(&info);if(!item)return;
    wchar_t path[MAX_PATH]={};bool ok=SHGetPathFromIDList(item,path)!=FALSE;CoTaskMemFree(item);
    if(ok) {m_protocol->archiveOffset=0;QueueRecordingPage(1,std::string(CW2A(path,CP_UTF8)));}
}
void CPage4::QueueRecordingPage(int action,const std::string& path) {
    auto& state=*m_protocol;if(state.job)return;
    auto job=std::make_shared<Job>();job->archiveAction=action;job->archivePath=path;job->epoch=state.archiveGeneration;state.job=job;
    auto query=QueryFor(m_tls);auto offset=state.archiveOffset;
    CString text;m_filter.GetWindowText(text);text.Trim();std::string filter(CW2A(text,CP_UTF8));int protocol=m_protocolFilter.GetCurSel();
    SetMonitorControls(false);
    try {std::thread([job,query,action,path,offset,filter,protocol]() {
        try {
            if(action==3){query(ProtocolView::Json{{"type","recording_close"}});}
            else {
                if(action==1 || action==4) query(ProtocolView::Json{{"type","recording_open"},{"path",path},{"rebuild_index",action==4}});
                job->archive=query(ProtocolView::Json{{"type","recording_page"},{"offset",offset},{"filter",filter},{"protocol",protocol},{"limit",128}});
                job->batch=ProtocolView::Poll([job](const ProtocolView::Json&){return job->archive;},"",0,false);
            }
        }catch(const std::exception& e){job->error=e.what();if(action==1 || action==4)try{query(ProtocolView::Json{{"type","recording_close"}});}catch(...) {}}
        catch(...){job->error="Cannot open recording";}
        job->done.store(true);
    }).detach();}catch(...){job->error="Unable to start recording reader";job->done.store(true);}
}
