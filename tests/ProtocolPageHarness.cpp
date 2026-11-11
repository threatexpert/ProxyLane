// Tests the actual page/controls in an owned test window. Uses a fake query
// service only; never installs a CA, starts a proxy or touches another app.
#include "../src/ProxyLane/stdafx.h"
#include "../src/ProxyLane/ProxyLane.h"
#include "../src/ProxyLane/Page4.cpp"
#include "../src/ProxyLane/Page4Protocol.cpp"
#include <atlimage.h>
#include <mutex>
#include <fstream>
#include <iostream>

IGlobalProxy* g_GlobalProxy = nullptr;
class FakeTls : public IProxyTlsControl {
public:
    std::atomic<bool> evicted{false};
    bool caOk=false, skipVerify=false, enabled=false, moduleOk=true, prepareOk=true;
    bool activeRecording=false,missingRecording=false;
    unsigned stops=0;
    int caFlags=3;
    std::atomic<unsigned> starts{0}, caQueries{0};
    bool lastDecrypt=false, injectionQuic=false;
    nlohmann::json settings;
    nlohmann::json recordingQuality=nlohmann::json::object();
    std::atomic<unsigned> count{2};
    std::atomic<unsigned> delay{0};
    std::atomic<bool> packetPayload{false};
    std::atomic<unsigned> queries{0};
    std::atomic<unsigned> polls{0};
    std::atomic<bool> livePreviewRequested{false};
    std::atomic<bool> indexMissing{false};
    std::atomic<unsigned> indexRebuilds{0};
    std::string processPath;
    FakeTls() {
        wchar_t path[MAX_PATH]={};GetModuleFileNameW(nullptr,path,_countof(path));
        processPath=CW2A(path,CP_UTF8);
    }
    int ManageCA(CaAction, char* output, size_t capacity) override {
        ++caQueries;
        if(caOk) {if(output&&capacity) strcpy_s(output,capacity,"Test CA status");return caFlags;}
        if (output && capacity) strcpy_s(output,capacity,"Test CA load failure");
        return -1;
    }
    BOOL SetEnabled(BOOL value, char*, size_t) override {enabled=value!=FALSE;return TRUE;}
    BOOL IsEnabled() override { return enabled; }
    int QueryProtocol(const char* request, char* output, size_t capacity) override {
        ++queries;
        using J = ProtocolView::Json;
        auto command = J::parse(request); J reply;
        if(command.value("live_preview",false)) livePreviewRequested=true;
        std::string type = command.at("type");
        // recording_status is an atomic snapshot; unlike cache reads it never waits for disk.
        if (delay.load() && type!="recording_status" && type!="monitor_stop_status") Sleep(delay.load());
        if(type=="recording_open" || type=="recording_close") {
            if(type=="recording_open" && command.value("rebuild_index",false)){++indexRebuilds;indexMissing=false;}
            if(type=="recording_open" && indexMissing){strcpy_s(output,capacity,"INDEX_REBUILD_REQUIRED: missing test index");return -1;}
            reply={{"run_id","recording:fake"}};
        }
        else if(type=="recording_page" || type=="recording_detail") {
            const bool detail=type=="recording_detail";
            auto offset=detail?command.value("cache_id",uint64_t(1))-1:command.value("offset",uint64_t(0));
            std::vector<char> buffer(65536);J rows=J::array();
            const bool filter=!command.value("filter",std::string()).empty();
            if(filter)offset=529;
            for(int page=0;page<(detail||filter?1:4);++page) {
                auto input=J{{"type","poll"},{"after",offset+rows.size()}}.dump();
                int required=QueryProtocol(input.c_str(),buffer.data(),buffer.size());if(required<=0 || required>(int)buffer.size())throw std::runtime_error("fake archive page reply");
                auto parsed=J::parse(buffer.data());
                for(auto row:parsed["records"]) {
                    row["recording_number"]=row["sequence"];
                    rows.push_back(row);if(detail||filter)break;
                }
            }
            if(detail)reply=rows.at(0);
            else reply={{"type","records"},{"run_id","recording:fake"},{"records",rows},{"next",0},{"offset",filter?0:offset},{"total",filter?1:count.load()},{"warnings",0},{"manifest",{{"status","completed"}}}};
        }
        else if(type=="monitor_stop_status") reply={{"active",true},{"phase","writing"}};
        else if(type=="recording_status") reply={{"enabled",activeRecording},{"ended",false},{"stopped",false},{"directory",activeRecording?"D:/test-recording":""},{"quality",recordingQuality}};
        else if(type=="quic_injection_policy") {injectionQuic=command.value("enabled",injectionQuic);reply={{"enabled",injectionQuic}};}
        else if (type == "monitor_start") {
            ++starts;lastDecrypt=command.value("decrypt",false);
            if(!moduleOk || (lastDecrypt && !prepareOk)) {strcpy_s(output,capacity,"Injected dependency failure");return -1;}
            enabled=lastDecrypt;activeRecording=!missingRecording && settings["recording"].value("enabled",false);reply={{"type","monitor"}};
        } else if(type=="monitor_stop") {++stops;activeRecording=false;enabled=false;reply={{"type","monitor"}};}
        else if (type == "mitm_options") {
            if(command.contains("settings") && !command.value("validate_only",false)) settings=command["settings"];
            if(command.contains("skip_upstream_verify") && !command.value("validate_only",false)) skipVerify=command["skip_upstream_verify"].get<bool>();
            reply={{"settings",settings},{"skip_upstream_verify",skipVerify}};
        } else if (type == "poll") {
            ++polls;
            J records = J::array(); uint64_t next = command.value("after", uint64_t(0));
            for (uint64_t id = next + 1; id <= count && records.size() < 32; ++id) {
                J request = {{"method", "GET"}, {"target", "/ip"}, {"status", nullptr},
                    {"headers", J::array({J::array({"host", "ifconfig.test"})})}, {"trailers", J::array()},
                    {"body_bytes", 0}, {"complete", true}, {"text", nullptr}, {"body_base64", ""}};
                J response = request; response["method"] = nullptr; response["target"] = nullptr; response["status"] = 200;
                response["body_bytes"] = 5;
                response["headers"] = J::array({J::array({"content-type", "application/json"}), J::array({"content-encoding", "gzip"})});
                records.push_back({{"type", "exchange"}, {"sequence", id}, {"protocol", id % 2 ? "http1" : "h2"},
                    {"connection", {{"id", std::to_string(id)}, {"pid", id % 2 ? 1234 : 5678}, {"process_start", id % 2 + 1},
                        {"socket", id + 99}, {"generation", 1}, {"destination", "ifconfig.test:443"},
                        {"process_name", "curl.exe"}, {"process_path",processPath}, {"server_name", "ifconfig.test"}, {"server_port", 443}}},
                    {"exchange", {{"id", id}, {"cache", {{"id", id}}}, {"problem", nullptr}, {"request", request},
                        {"response", response}, {"informational", J::array()}}}});
                next = id;
            }
            reply = {{"type", "records"}, {"run_id", "test"}, {"records", records}, {"next", next}, {"lost_before", 0}};
        } else if (type == "stats") reply = {{"type", "stats"}, {"run_id", "test"}, {"last_sequence", count.load()}};
        else if (type == "cache_status") reply = {{"cache", {{"id", command["cache_id"]}, {"finished", true},
            {"evicted", evicted.load()}, {"pending_chunks", 0}, {"reason", nullptr}}}};
        else if (type == "cache_read" && packetPayload) reply = {{"payload",{{"data_base64",command.value("offset",0u)!=0 ? "AwQF" : command.value("length",0u)>3 ? "AAECAwQF" : "AAEC"}}}};
        else if (type == "dns_read") reply = {{"payload",{{"data_base64","AAEBAAABAAAAAAAAAWEAAAEAAQ=="}}},{"text","ID: 0x0001\r\n[Question]\r\na. IN A"}};
        else reply = {{"payload", {{"data_base64", "eyJpcCI6IjIwMy4wLjExMy4xMCJ9"}}}};
        auto text = reply.dump();
        if (capacity > text.size()) memcpy(output, text.c_str(), text.size() + 1);
        return (int)text.size() + 1;
    }
};
static void Require(bool good, const char* message) { if (!good) throw std::runtime_error(message); }
static void CheckFreshRecordingProcess() {
    wchar_t exe[32768]={};Require(GetModuleFileNameW(nullptr,exe,_countof(exe))!=0,"test executable path");
    std::wstring command=L"\""+std::wstring(exe)+L"\" --recording-fresh";
    STARTUPINFOW startup={sizeof(startup)};PROCESS_INFORMATION child={};
    Require(CreateProcessW(exe,&command[0],nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&child)!=FALSE,"fresh recording process");
    DWORD waited=WaitForSingleObject(child.hProcess,30000),code=1;
    if(waited!=WAIT_OBJECT_0) {TerminateProcess(child.hProcess,1);WaitForSingleObject(child.hProcess,5000);}
    else GetExitCodeProcess(child.hProcess,&code);
    CloseHandle(child.hThread);CloseHandle(child.hProcess);
    Require(waited==WAIT_OBJECT_0 && code==0,"new instance defaults to no recording and retains directory/limits, even with legacy Enabled=1");
}
class ProtocolPageHarness {
public:
    static void DragThumb(CByteHexView& hex, int bar) {
        SCROLLBARINFO info = {}; info.cbSize=sizeof(info);
        Require(::GetScrollBarInfo(hex.m_hWnd,bar==SB_VERT ? OBJID_VSCROLL : OBJID_HSCROLL,&info)!=FALSE,"native scrollbar geometry");
        const bool vertical=bar==SB_VERT;
        CPoint start = vertical ? CPoint((info.rcScrollBar.left+info.rcScrollBar.right)/2,info.rcScrollBar.top+(info.xyThumbTop+info.xyThumbBottom)/2) :
            CPoint(info.rcScrollBar.left+(info.xyThumbTop+info.xyThumbBottom)/2,(info.rcScrollBar.top+info.rcScrollBar.bottom)/2);
        CPoint end = vertical ? CPoint(start.x,info.rcScrollBar.bottom-info.dxyLineButton-12) : CPoint(info.rcScrollBar.right-info.dxyLineButton-12,start.y);
        HWND owner=::GetAncestor(hex.m_hWnd,GA_ROOT);
        ::SetForegroundWindow(owner); ::UpdateWindow(owner);
        POINT previousCursor;::GetCursorPos(&previousCursor);
        std::atomic<bool> injected{false};
        // A real non-client scrollbar loop requires the mouse-button state;
        // posting WM_MOUSEMOVE alone causes Windows to cancel tracking.
        std::thread input([=,&injected] {
            Sleep(250); if(::GetForegroundWindow()!=owner || (GetAsyncKeyState(VK_LBUTTON)&0x8000)) return;
            INPUT event={};event.type=INPUT_MOUSE;
            ::SetCursorPos(start.x,start.y);event.mi.dwFlags=MOUSEEVENTF_LEFTDOWN;::SendInput(1,&event,sizeof(event));
            Sleep(100);::SetCursorPos(end.x,end.y);Sleep(150);
            event.mi.dwFlags=MOUSEEVENTF_LEFTUP;::SendInput(1,&event,sizeof(event));
            injected=true;
        });
        DWORD started=GetTickCount();
        while(GetTickCount()-started<800) {
            MSG msg;while(PeekMessage(&msg,nullptr,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessage(&msg);}Sleep(10);
        }
        input.join();
        if(::GetForegroundWindow()==owner) ::SetCursorPos(previousCursor.x,previousCursor.y);
        Require(injected,"owned thumb test requires foreground window and released mouse");
        Require(hex.GetScrollPos(bar)>0,vertical ? "native vertical thumb drag" : "native horizontal thumb drag");
        Require(::GetCapture()!=hex.m_hWnd,"thumb releases capture");
    }
    static void Pump(CPage4& page, const std::function<bool()>& done, DWORD timeout = 10000) {
        DWORD start = GetTickCount();
        do {
            MSG message;
            while (PeekMessage(&message, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&message); DispatchMessage(&message);
            }
            page.OnTimer(1);
            if (done()) return;
            Sleep(10);
        } while (GetTickCount() - start < timeout);
        std::cerr << "Timeout: offline=" << page.m_protocol->offline << " selected=" << page.m_protocol->selected << " next=" << page.m_protocol->next << " final=" << page.m_protocol->finalPoll << " rows=" << page.m_requests.GetItemCount() << " job=" << (page.m_protocol->job?1:0) << "\n";
        throw std::runtime_error("page worker timeout");
    }
    static void Screenshot(CPage4& page,LPCWSTR path) {
        CRect rect;page.GetClientRect(rect);CImage image;image.Create(rect.Width(),rect.Height(),32);
        HDC dc=image.GetDC();page.SendMessage(WM_PRINT,(WPARAM)dc,PRF_CLIENT|PRF_CHILDREN|PRF_ERASEBKGND);image.ReleaseDC();
        Require(SUCCEEDED(image.Save(path)),"toolbar screenshot");
    }
    static void Run(bool nativeScroll) {
        FakeTls fake;
        QueryFor(&fake)(ProtocolView::Json{{"type","stats"}});
        Require(fake.livePreviewRequested,"live page queries opt into independent recording previews");
        CWnd parent;
        Require(parent.CreateEx(0, AfxRegisterWndClass(0), L"Protocol page regression", WS_OVERLAPPEDWINDOW,
            CRect(0, 0, 980, 720), nullptr, 0) != FALSE, "create parent");
        CPage4 page(&parent);
        Require(page.Create(IDD_Page4, &parent) != FALSE, "create page");
#ifndef _WIN64
        Require(!page.m_mitmSupported && !page.m_monitor.IsWindowEnabled() && !page.m_options.IsWindowEnabled(),"32-bit host disables MITM and monitoring controls");
        char unsupported[512]={};
        Require(page.m_tls->QueryProtocol("{\"type\":\"mitm_options\",\"skip_upstream_verify\":true}",unsupported,sizeof(unsupported))<0,"32-bit backend rejects persisted options");
        SetEnvironmentVariable(L"PROXYLANE_MITM",L"1");
        Require(!page.m_tls->IsEnabled(),"32-bit host ignores MITM environment setting");
        Require(!page.m_tls->SetEnabled(TRUE,unsupported,sizeof(unsupported)),"32-bit backend refuses enabling MITM");
        SetEnvironmentVariable(L"PROXYLANE_MITM",nullptr);
        page.OnCA();page.OnMonitor();page.OnTimer(1);
        Require(!GetModuleHandle(L"ProxyLaneMitm32.dll") && !GetModuleHandle(L"ProxyLaneMitm64.dll"),"32-bit host never loads MITM DLL");
        // Remaining view tests use an in-memory fake service, not a 32-bit Rust module.
        page.m_mitmSupported=true;
#endif
        Require(!page.GetDlgItem(IDC_MITM_ENABLE),"page exposes only one monitoring switch");
        page.m_tls = &fake;
        auto idleFor=[&](DWORD duration) {
            DWORD began=GetTickCount();
            Pump(page,[&] {return GetTickCount()-began>=duration;},duration+3000);
        };
        const auto coldQueries=fake.queries.load();
        idleFor(1200);
        Require(fake.queries==coldQueries && !page.m_protocol->job,"cold idle page never queries optional module");
        auto waitJob=[](std::shared_ptr<MitmJob> job) {for(int i=0;i<200 && !job->done.load();++i) Sleep(10);Require(job->done.load(),"start worker completed");return job;};
        fake.caOk=true;fake.caFlags=0;
        auto start=waitJob(StartMonitorJob(&fake,true));
        Require(start->needsCA && fake.starts==0 && !fake.enabled,"missing CA guides installation without starting plain monitoring");
        fake.caOk=false;start=waitJob(StartMonitorJob(&fake,true));
        Require(start->result<0 && !start->needsCA && fake.starts==0,"CA/module failure blocks requested decryption");
        fake.caOk=true;fake.caFlags=3;fake.prepareOk=false;
        start=waitJob(StartMonitorJob(&fake,true));
        Require(start->result<0 && fake.lastDecrypt && !fake.enabled,"failed TLS preparation never falls back to plaintext monitoring");
        fake.prepareOk=true;start=waitJob(StartMonitorJob(&fake,true));
        Require(start->result>=0 && fake.enabled && fake.lastDecrypt,"valid decryption starts monitoring in the requested mode");
        fake.enabled=false;fake.caOk=false;const auto caBefore=fake.caQueries.load();
        start=waitJob(StartMonitorJob(&fake,false));
        Require(start->result>=0 && !fake.enabled && !fake.lastDecrypt && fake.caQueries==caBefore,"plain monitoring needs no CA");
        fake.moduleOk=false;start=waitJob(StartMonitorJob(&fake,false));
        Require(start->result<0,"missing analysis module also blocks plain monitoring");fake.moduleOk=true;
        {
            const CString path=Localization::SettingsPath();wchar_t original[32768]={};
            const bool originalEnabled=RecordingSettings::Load().enabled;
            GetPrivateProfileSectionW(L"recording",original,_countof(original),path);WritePrivateProfileSectionW(L"recording",nullptr,path);
            auto values=RecordingSettings::Load();Require(values.capacityMiB==8192,"new default recording capacity is 8 GiB");
            const CString defaultDirectory=values.directory;
            wchar_t folder[MAX_PATH]={};GetFullPathNameW(L"build\\qa\\recording-picker",_countof(folder),folder,nullptr);
            CreateDirectoryW(folder,nullptr);CString recent=CString(folder)+L"\\recording-test";CreateDirectoryW(recent,nullptr);
            values.directory=folder;Require(RecordingSettings::Save(values),"save picker root");
            WritePrivateProfileStringW(L"recording",L"LastDirectory",recent,path);
            Require(RecordingSettings::BrowseDirectory()==recent,"picker preselects recent recording inside configured root");
            CString other=CString(folder)+L"\\other-root";CreateDirectoryW(other,nullptr);
            values.directory=other;Require(RecordingSettings::Save(values),"change picker root");
            Require(RecordingSettings::BrowseDirectory()==other,"picker follows changed root instead of stale last directory");
            values.directory=CString(folder)+L"\\missing";Require(RecordingSettings::Save(values),"missing picker root");
            Require(RecordingSettings::BrowseDirectory()==defaultDirectory,"picker falls back to default recording root");
            values.directory=defaultDirectory;
            values.enabled=true;Require(RecordingSettings::Save(values),"enable recording before first start");
            const auto idleQueries=fake.queries.load();CString idleCaption;
            page.SetMonitorControls(false);page.OnTimer(1);page.m_recordStatus.GetWindowText(idleCaption);
            Require(idleCaption==Localization::Get(L"recording.enabled") && fake.queries==idleQueries,"session recording opt-in is visible before monitoring without loading the optional backend");
            values.enabled=false;Require(RecordingSettings::Save(values),"disable idle recording");
            page.SetMonitorControls(false);page.OnTimer(1);page.m_recordStatus.GetWindowText(idleCaption);
            Require(idleCaption==Localization::Get(L"recording.disabled") && fake.queries==idleQueries,"idle recording disabled state stays visible across refresh");
            values.enabled=true;Require(RecordingSettings::Save(values),"restore enabled recording for start");
            page.SetMonitorControls(false);
            start=waitJob(StartMonitorJob(&fake,false));Require(start->result>=0 && fake.activeRecording,"first start includes the saved recording settings");
            fake.missingRecording=true;const auto stops=fake.stops;
            start=waitJob(StartMonitorJob(&fake,false));Require(start->result<0 && fake.stops==stops+1,"requested recording may never silently fall back to ordinary monitoring");
            fake.missingRecording=false;fake.activeRecording=false;
            WritePrivateProfileSectionW(L"recording",original[0]?original:nullptr,path);
            RecordingSettings::SessionEnabled().store(originalEnabled);
            page.SetMonitorControls(false);
        }

        page.MoveWindow(0, 0, 960, 660); page.ShowWindow(SW_SHOW);
        parent.ShowWindow(SW_SHOWNOACTIVATE);
        Require(!page.m_openRecording.IsWindowVisible() && !page.m_recordingViewStatus.IsWindowVisible(),"live toolbar has no extra recording row");
        Require(page.m_recordStatus.IsWindowVisible() && page.m_options.IsWindowVisible(),"recording state remains visible beside single options menu");
        {
            CRect status,options;page.m_recordStatus.GetWindowRect(status);page.m_options.GetWindowRect(options);
            CClientDC dc(&page.m_recordStatus);auto old=dc.SelectObject(page.m_recordStatus.GetFont());CString label;page.m_recordStatus.GetWindowText(label);
            Require(status.Width()==dc.GetTextExtent(label).cx,"recording status click area exactly fits its text");dc.SelectObject(old);
            Require(options.left-status.right>20,"toolbar has noninteractive whitespace after status");
            CPoint blank(status.right+10,status.CenterPoint().y);page.ScreenToClient(&blank);
            Require(page.ChildWindowFromPoint(blank,CWP_SKIPINVISIBLE|CWP_SKIPDISABLED)!=&page.m_recordStatus,"blank area does not hit recording options status");
        }
        Screenshot(page,L"build\\qa\\monitor-toolbar-live.png");
        page.m_recording = true;
        {
            Require(MitmSettings::Defaults()[5]==128,"default concurrent analysis limit is 128");
            fake.activeRecording=true;fake.recordingQuality={{"analysis_deferred_count",1}};
            page.OnTimer(1);CString caption;page.m_recordStatus.GetWindowText(caption);
            Require(caption==Localization::Get(L"recording.active_deferred"),"raw fallback is visible without stopping recording");
            fake.recordingQuality={{"capture_incomplete",true},{"gap_count",1}};page.m_recordingGapNotified=true;
            page.OnTimer(1);page.m_recordStatus.GetWindowText(caption);
            Require(caption==Localization::Get(L"recording.active_incomplete") && page.m_recording,"recording gap has a persistent warning caption and keeps monitoring");
            fake.activeRecording=false;fake.recordingQuality=nlohmann::json::object();page.m_recordingGapNotified=false;
        }
        Pump(page, [&] { return page.m_requests.GetItemCount() == 2; });
        Require(page.m_follow.GetCheck() == BST_CHECKED, "follow latest enabled initially");
        Require(page.m_requests.GetGroupCount() == 0, "process groups");
        Require(page.m_requests.GetItemText(0, 1).Find(L"curl.exe") >= 0, "saved process name");
        auto itemImage=[&](int row,int col) {
            LVITEM item={};item.mask=LVIF_IMAGE;item.iItem=row;item.iSubItem=col;
            Require(page.m_requests.GetItem(&item)!=FALSE,"read process subitem icon");return item.iImage;
        };
        Pump(page,[&]{return itemImage(0,1)>0;});
        Require(itemImage(0,0)==I_IMAGENONE,"no application icon in sequence column");
        Require(itemImage(0,1)==itemImage(1,1) && page.m_processIcons.GetImageCount()==2,"same executable shares one cached icon across PIDs");
        Require(page.m_protocol->icons.Size()==1,"process executable queried only once");
        const auto iconCount=page.m_processIcons.GetImageCount();
        const auto cachedCount=page.m_protocol->icons.Size();
        for(int n=0;n<20;++n) page.RebuildRequests();
        Require(page.m_processIcons.GetImageCount()==iconCount && page.m_protocol->icons.Size()==cachedCount,"refresh does not allocate or enqueue duplicate icons");
        Require(ProcessIconCache::Key(L"\\\\server\\share\\app.exe").empty(),"remote executable uses fallback without extraction");
        Require(ProcessIconCache::Key(L"\\\\?\\C:\\Tools\\APP.EXE")==ProcessIconCache::Key(L"c:\\tools\\app.exe"),"path spellings share the icon cache");
        Require(page.m_requests.GetItemText(0, 5) == L"ifconfig.test:443 /ip", "domain without mapped IP");
        Require(!page.GetDlgItem(IDC_PROTOCOL_TABS) && !page.GetDlgItem(IDC_EDIT1), "raw log controls removed");
        Require(!page.m_viewTabs.IsWindowEnabled(), "HEX disabled without selection");
        Require(page.m_requests.GetItemText(0, 3) == L"HTTP/1.1" && page.m_requests.GetItemText(1, 3) == L"HTTP/2", "protocol follows PID");
        Require(page.m_requests.GetItemText(0,4)==L"GET" && page.m_requests.GetItemText(0,6)==L"200", "method and status columns");
        Require(page.m_requests.GetColumnWidth(0) == UiTheme::ScaleForWindow(page.m_hWnd,38), "initial column sizing");
        Pump(page,[&] {return !page.m_protocol->job;});
        const auto pollsBeforeStop=fake.polls.load();
        page.m_recording=false;
        // The asynchronous stop must finish before requesting final records.
        page.m_stopJob=std::make_shared<MitmJob>();
        idleFor(650);
        Require(fake.polls==pollsBeforeStop,"no polling while stop drains capture");
        page.m_stopJob->result=1;page.m_stopJob->done=true;
        Pump(page,[&] {return !page.m_stopJob && !page.m_protocol->finalPoll && !page.m_protocol->job;});
        Require(fake.polls==pollsBeforeStop+2,"one final drain job after stopping");
        const auto stoppedQueries=fake.queries.load();
        idleFor(1200);
        Require(fake.queries==stoppedQueries,"stopped page does not poll history");
        page.m_requests.SetItemState(0,LVIS_SELECTED,LVIS_SELECTED);
        Pump(page,[&] {return page.m_protocol->haveDetail && !page.m_protocol->job;});
        const auto detailQueries=fake.queries.load();
        idleFor(2300);
        Require(fake.queries==detailQueries,"stopped selection is read once on demand");
        page.m_follow.SetCheck(BST_CHECKED);page.OnFollowLatest();
        page.m_recording=true;
        const int customWidths[] = {45,170,70,55,310,88,115,130};
        for (int col=0; col<8; ++col) page.m_requests.SetColumnWidth(col,customWidths[col]);
        auto checkWidths = [&] {
            for (int col=0; col<8; ++col)
                Require(page.m_requests.GetColumnWidth(col)==customWidths[col], "manual column widths preserved");
        };
        page.m_requests.SetItemState(0, LVIS_SELECTED, LVIS_SELECTED);
        Require(page.m_follow.GetCheck() == BST_UNCHECKED, "selection pauses follow latest");
        Pump(page, [&] { return page.m_protocol->haveDetail; });
        checkWidths();
        CString text; page.m_detail.GetWindowText(text);
        Require(text.Find(L"GET /ip HTTP/1.1") >= 0 && text.Find(L"host: ifconfig.test") >= 0, "request headers");
        Require(page.m_viewTabs.IsWindowEnabled(), "headers available with empty request body");
        Require(!page.m_hexView.Bytes().empty() && page.m_hexView.Bytes()[0] == 'G', "HEX contains request headers");
        LRESULT ignored;
        page.m_detailTabs.SetCurSel(1); page.OnDetailTab(nullptr, &ignored);
        page.m_detail.GetWindowText(text);
        Require(text.Find(L"content-encoding: gzip") >= 0 && text.Find(L"203.0.113.10") >= 0, "decoded response body");
        page.m_viewTabs.SetCurSel(1); page.OnView(nullptr, &ignored); page.m_detail.GetWindowText(text);
        Require(page.m_hexView.IsWindowVisible() && !page.m_hexView.Bytes().empty(), "native HEX control");
        Require(page.m_hexView.SendMessage(WM_GETFONT) == (LRESULT)page.m_font.GetSafeHandle(), "HEX uses the configured monospaced font");
        // A slow result for B must not replace A after changing selection back.
        fake.delay = 120;
        page.m_requests.SetItemState(1, LVIS_SELECTED, LVIS_SELECTED);
        Require(page.m_viewTabs.GetCurSel() == 0, "HEX does not affect another request");
        Pump(page, [&] { return page.m_protocol->job && page.m_protocol->job->detail; });
        page.m_requests.SetItemState(0, LVIS_SELECTED, LVIS_SELECTED);
        Pump(page, [&] { return page.m_protocol->haveDetail; });
        Require(page.m_protocol->detail.context.find("Request/stream 1") != std::string::npos, "stale selection result");
        Require(page.m_viewTabs.GetCurSel() == 1, "request remembers its HEX preference");
        page.m_viewTabs.SetCurSel(0); page.OnView(nullptr, &ignored);
        fake.delay = 0;
        // Save the real page's rendering, not a mockup.
        CImage image; image.Create(960, 660, 32);
        HDC dc = image.GetDC(); page.PrintWindow(CDC::FromHandle(dc), 0); image.ReleaseDC();
        Require(SUCCEEDED(image.Save(L"build\\qa\\protocol-page.png")), "save page image");
        fake.evicted = true;
        Pump(page, [&] { return page.m_protocol->detail.state == ProtocolView::Detail::Evicted; }, 6000);
        page.m_detail.GetWindowText(text);
        Require(text.Find(L"203.0.113.10") < 0 && text.Find(L"evicted") < 0, "eviction removes displayed body");
        for (int width : {600, 960, 1200}) {
            page.MoveWindow(0, 0, width, 660);
            CRect list, detail; page.m_requests.GetWindowRect(list); page.m_detail.GetWindowRect(detail);
            Require(list.bottom < detail.top && detail.Height() > 100, "layout bounds");
            checkWidths();
        }
        // Filtering keeps the selection tied to record identity, not visible index.
        page.m_filter.SetWindowText(L"5678");
        Require(page.m_requests.GetItemCount() == 1 && page.m_requests.GetItemText(0,2) == L"5678", "exact PID filter");
        page.m_filter.SetWindowText(L"CURL"); Require(page.m_requests.GetItemCount() == 2, "case insensitive process filter");
        page.m_filter.SetWindowText(L"absent"); Require(page.m_requests.GetItemCount() == 0, "filter empty result");
        page.m_filter.SetWindowText(L"");
        CRect before; page.m_requests.GetWindowRect(before);
        CPoint split = page.m_splitRect.CenterPoint(); page.OnLButtonDown(0,split);
        page.OnMouseMove(MK_LBUTTON,CPoint(split.x,split.y+70)); page.OnLButtonUp(0,split);
        CRect after; page.m_requests.GetWindowRect(after); Require(after.Height() > before.Height(), "draggable splitter");
        page.m_follow.SetCheck(BST_CHECKED); page.OnFollowLatest();
        Require(page.m_protocol->selected.empty() && page.m_detail.GetWindowTextLength()==0, "resume clears inspected session");
        fake.count = 700;
        Pump(page, [&] { return page.m_protocol->next == 700; }, 20000);
        Require(page.m_requests.GetItemCount() == 512 && page.m_protocol->history.discarded == 188, "bounded visible history");
        if(!page.CanFollowLatest() || page.m_requests.GetTopIndex()<=450) {
            SCROLLINFO si={sizeof(si),SIF_ALL};page.m_requests.GetScrollInfo(SB_VERT,&si);
            std::cerr<<"follow diagnostic: top="<<page.m_requests.GetTopIndex()<<" pos="<<si.nPos<<" page="<<si.nPage
                <<" max="<<si.nMax<<" checked="<<page.m_follow.GetCheck()<<'\n';
            Require(false,"follow stays at latest through history eviction");
        }
        page.m_requests.SendMessage(WM_VSCROLL, SB_PAGEUP);
        page.TickProtocolView();
        Require(page.m_follow.GetCheck()==BST_UNCHECKED, "scrolling up pauses follow");
        const auto anchor = page.m_protocol->shownKeys[page.m_requests.GetTopIndex()];
        fake.count = 701;
        Pump(page, [&] { return page.m_protocol->next==701; });
        Require(page.m_protocol->shownKeys[page.m_requests.GetTopIndex()]==anchor, "new records preserve scrolled anchor");
        page.m_requests.SetItemState(page.m_requests.GetTopIndex()+1, LVIS_SELECTED, LVIS_SELECTED);
        const auto inspected = page.m_protocol->selected;
        fake.count = 702;
        Pump(page, [&] { return page.m_protocol->next==702; });
        Require(page.m_protocol->selected==inspected && page.m_follow.GetCheck()==BST_UNCHECKED, "new records preserve inspected session");
        page.m_follow.SetCheck(BST_CHECKED); page.OnFollowLatest();
        Require(page.CanFollowLatest() && page.m_requests.GetNextItem(-1,LVNI_SELECTED)==-1, "explicit resume jumps to latest");
        fake.delay = 120;
        page.m_requests.SetItemState(1, LVIS_SELECTED, LVIS_SELECTED);
        Pump(page, [&] { return page.m_protocol->job && page.m_protocol->job->detail; });
        page.OnClear(); // Clear while a detail query is in flight.
        Pump(page, [&] { return !page.m_protocol->baseline && !page.m_protocol->job; });
        Require(page.m_requests.GetItemCount() == 0 && page.m_detail.GetWindowTextLength() == 0, "clear suppresses backend history");
        Require(!page.m_viewTabs.IsWindowEnabled() && page.m_viewTabs.GetCurSel() == 0, "clear resets HEX");
        Require(page.m_follow.GetCheck()==BST_CHECKED, "clear restores follow latest");
        // Progress updates replace the same connection row and keep its selection/HEX preference.
        ProtocolView::Row flow; flow.run = "test"; flow.key = "test:stream:99"; flow.sequence = 701;
        flow.stream = true; flow.protocol = "TCP"; flow.pid = 1234; flow.cacheId = 99; flow.bytes = 512;
        flow.record = {{"type", "stream"}, {"connection", {{"id", "99"},{"upstream_verification_skipped",true},{"decrypted",false}}},
            {"stream", {{"sent_bytes", 10}, {"received_bytes", 20}, {"finished", false}}}};
        page.m_protocol->history.Add(flow); page.RebuildRequests();
        page.m_requests.SetItemState(0, LVIS_SELECTED, LVIS_SELECTED);
        fake.evicted = false; fake.delay = 0;
        Pump(page, [&] { return page.m_protocol->haveDetail; });
        page.m_viewTabs.SetCurSel(1); page.OnView(nullptr, &ignored);
        page.m_detailStatus.GetWindowText(text);
        Require(text.Find(L"certificate verification skipped")==-1,"plain TCP must not show target TLS verification warning");
        const auto firstSeen = page.m_protocol->history.rows.front().firstSeenSeconds;
        Require(firstSeen > 0, "row records its first appearance time");
        if(nativeScroll) {
        POINT savedCursor; GetCursorPos(&savedCursor);
        page.m_requests.SendMessage(WM_HSCROLL,SB_LEFT);page.m_requests.EnsureVisible(0,FALSE);
        CRect numberRect; page.m_requests.GetSubItemRect(0,0,LVIR_BOUNDS,numberRect);
        CPoint tipPoint(8,numberRect.CenterPoint().y);page.m_requests.ClientToScreen(&tipPoint);
        SetCursorPos(tipPoint.x,tipPoint.y);
        wchar_t tipText[128] = {};
        NMLVGETINFOTIP tip = {};tip.iItem=0;tip.pszText=tipText;tip.cchTextMax=_countof(tipText);
        page.OnRequestInfoTip((NMHDR*)&tip,&ignored);
        if(!tipText[0]) {POINT actual;GetCursorPos(&actual);std::cerr<<"tooltip cursor "<<actual.x<<","<<actual.y<<" wanted "<<tipPoint.x<<","<<tipPoint.y<<"\n";}
        Require(CString(tipText)==CTime((__time64_t)firstSeen).Format(L"%Y-%m-%d %H:%M:%S"),"number tooltip shows full local date and time");
        page.m_requests.GetSubItemRect(0,1,LVIR_BOUNDS,numberRect);
        tipPoint=numberRect.CenterPoint();page.m_requests.ClientToScreen(&tipPoint);SetCursorPos(tipPoint.x,tipPoint.y);
        tipText[0]=0;page.OnRequestInfoTip((NMHDR*)&tip,&ignored);
        Require(!tipText[0],"time tooltip is restricted to the number column");
        SetCursorPos(savedCursor.x,savedCursor.y);
        }
        flow.sequence = 702; flow.responseBytes = 100; page.m_protocol->history.Add(flow); page.RebuildRequests();
        Require(page.m_protocol->history.rows.front().firstSeenSeconds==firstSeen,"row updates preserve the timestamp");
        Require(page.m_requests.GetItemCount() == 1 && page.m_requests.GetItemText(0,7) == L"0 / 100", "stream updates same row");
        Require(page.m_protocol->selected == flow.key && page.m_protocol->history.rows.front().hex, "stream selection/HEX preserved");
        page.m_detail.GetWindowText(text);
        Require(page.m_hexView.Bytes().size() > 2 && page.m_hexView.Bytes()[0] == 0x7b && text.Find(L"Connection") < 0, "stream HEX detail");
        page.m_hexView.SetBytes(std::vector<unsigned char>(65536,0xab));
        CRect hexRect;page.m_hexView.GetWindowRect(hexRect);page.ScreenToClient(hexRect);
        page.m_hexView.MoveWindow(hexRect.left,hexRect.top,300,220);
        page.m_hexView.SetCapture();
        page.m_hexView.StopDrag();
        Require(::GetCapture()==page.m_hexView.m_hWnd,"selection cleanup preserves native scrollbar capture");
        ::ReleaseCapture();
        if (nativeScroll) {
            DragThumb(page.m_hexView,SB_VERT); DragThumb(page.m_hexView,SB_HORZ);
        }
        page.m_hexView.SendMessage(WM_HSCROLL,SB_TOP);
        page.m_hexView.MoveWindow(hexRect);
        page.m_hexView.SendMessage(WM_KEYDOWN,VK_END);
        Require(page.m_hexView.GetScrollPos(SB_VERT) > 0, "native byte view keyboard scroll");
        page.m_hexView.SendMessage(WM_KEYDOWN,VK_HOME);
        Require(page.m_hexView.GetScrollPos(SB_VERT) == 0, "native byte view home");
        // Dragging within one byte produces no paint; crossing a byte updates
        // only affected visible rows. Repeated buffered paints release GDI objects.
        {
            CClientDC dc(&page.m_hexView); CFont* old=dc.SelectObject(page.m_hexView.GetFont());
            TEXTMETRIC tm;dc.GetTextMetrics(&tm);dc.SelectObject(old);
            const int cw=tm.tmAveCharWidth,ch=tm.tmHeight+2;
            page.m_hexView.UpdateWindow();
            page.m_hexView.SendMessage(WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(10*cw+1,1));
            page.m_hexView.UpdateWindow();
            page.m_hexView.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(11*cw,1));
            Require(!page.m_hexView.GetUpdateRect(nullptr,FALSE),"same-byte drag must not repaint");
            page.m_hexView.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(13*cw+1,1));
            CRect dirty;Require(page.m_hexView.GetUpdateRect(dirty,FALSE) && dirty.top==0 && dirty.bottom<=ch,"single-row selection damage");
            page.m_hexView.UpdateWindow();
            const DWORD objects=GetGuiResources(GetCurrentProcess(),GR_GDIOBJECTS);
            for (int i=0;i<250;++i) {
                page.m_hexView.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM((13+i%10*3)*cw+1,(i%3)*ch+1));
                page.m_hexView.UpdateWindow();
            }
            Require(GetGuiResources(GetCurrentProcess(),GR_GDIOBJECTS)<=objects+2,"buffered selection painting leaks GDI objects");
            page.m_hexView.SendMessage(WM_LBUTTONUP,0,0);
            // Holding a captured drag at/beyond the edge keeps scrolling even
            // without more mouse moves, while keeping the selection anchor.
            auto& hex = page.m_hexView;
            CRect client; hex.GetClientRect(client);
            hex.SendMessage(WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(10*cw+1,ch+1));
            const size_t anchor = hex.m_first;
            hex.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(13*cw+1,client.bottom+20));
            const size_t before = hex.m_last;
            for (int i=0;i<10;++i) hex.SendMessage(WM_TIMER,CByteHexView::DragTimer);
            Require(hex.GetScrollPos(SB_VERT)>0 && hex.m_last>before && hex.m_first==anchor,"drag scroll down extends selection with fixed anchor");
            const int down = hex.GetScrollPos(SB_VERT);
            hex.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(13*cw+1,-20));
            for (int i=0;i<3;++i) hex.SendMessage(WM_TIMER,CByteHexView::DragTimer);
            Require(hex.GetScrollPos(SB_VERT)<down && hex.m_first==anchor,"drag scroll up");
            hex.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(13*cw+1,client.Height()/2));
            const int middle = hex.GetScrollPos(SB_VERT);
            hex.UpdateWindow(); hex.SendMessage(WM_TIMER,CByteHexView::DragTimer);
            Require(hex.GetScrollPos(SB_VERT)==middle && !hex.GetUpdateRect(nullptr,FALSE),"inside drag does not scroll or repaint");
            hex.SendMessage(WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(13*cw+1,client.bottom+20));
            hex.SendMessage(WM_LBUTTONUP,0,MAKELPARAM(13*cw+1,client.bottom+20));
            hex.SendMessage(WM_TIMER,CByteHexView::DragTimer);
            Require(!hex.m_drag && hex.GetScrollPos(SB_VERT)==middle,"release stops drag scrolling");
            hex.SendMessage(WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(13*cw+1,client.bottom+20));
            parent.SetCapture(); hex.SendMessage(WM_TIMER,CByteHexView::DragTimer);
            Require(!hex.m_drag && hex.GetScrollPos(SB_VERT)==middle,"capture loss stops drag scrolling");
            ReleaseCapture();
            hex.SendMessage(WM_VSCROLL,SB_BOTTOM);
            hex.SendMessage(WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(13*cw+1,client.bottom+20));
            hex.SendMessage(WM_TIMER,CByteHexView::DragTimer);
            Require(hex.m_last<hex.Bytes().size(),"drag at end remains within bytes");
            hex.SetBytes(std::vector<unsigned char>{1,2,3});
            Require(!hex.m_drag,"replacing payload stops drag scrolling");
        }
        // Packet rows preserve wire boundaries, independently of byte alignment.
        {
            auto& hex=page.m_hexView;
            std::vector<std::vector<unsigned char>> packets={{0,1,2},std::vector<unsigned char>(18,0xab),{}, {0xff}};
            hex.SetPackets(packets,false);
            Require(hex.Rows()==5 && hex.Bytes().size()==22,"packet padding and empty rows add no bytes");
            Require(hex.m_lines[1].offset==0 && hex.m_lines[2].offset==16 && hex.m_lines[4].offset==0,"offset restarts at each packet");
            Require(hex.Hit(CPoint(10*hex.m_cw+1,hex.m_ch+1))==3 && hex.Hit(CPoint(60*hex.m_cw+1,2*hex.m_ch+1))==19,"hex and text hit mapping across unaligned packets");
            hex.SendMessage(WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(10*hex.m_cw+1,3*hex.m_ch+1));
            Require(hex.SelectedPacket()==2 && !hex.m_hasSelection && hex.SelectionText().IsEmpty(),"empty packet is clickable without synthetic bytes");
            hex.SendMessage(WM_KEYDOWN,VK_RIGHT);
            Require(hex.SelectedPacket()==3 && hex.SelectedOffset()==0 && hex.m_last==21,"keyboard exits empty packet at next payload start");
            hex.m_first=1;hex.m_last=4;hex.m_hasSelection=true;
            Require(hex.SelectionText()==L"01 02 AB AB","cross-packet copy excludes row padding and labels");
            std::vector<std::vector<unsigned char>> many(120,std::vector<unsigned char>(17,0x42));
            hex.SetPackets(many,false);hex.m_first=35;hex.m_last=49;hex.m_selectedRow=hex.RowOfByte(49);hex.m_top=30;hex.UpdateScroll();
            const int top=hex.m_top,left=hex.m_left;
            many.push_back({3,4,5});hex.SetPackets(many,true);
            Require(hex.m_top==top && hex.m_left==left && hex.m_first==35 && hex.m_last==49,"packet append retains selection and scroll");
            hex.SetPackets(many,false);
            Require(hex.m_top==0 && hex.m_first==0 && hex.m_last==0,"different session resets view even with identical payload");
        }
        // QUIC uses the same cumulative UDP HexView while Raw retains its summary.
        Pump(page,[&]{return !page.m_protocol->job;});
        fake.packetPayload=true; ++flow.sequence; flow.udp=true; flow.quic=true; flow.protocol="QUIC v1";
        flow.record["quic"]={{"sni","example.test"}};
        flow.record["stream"]["datagrams"]=ProtocolView::Json::array({
            ProtocolView::Json::array({ProtocolView::Json::array({0,3}),ProtocolView::Json::array({3,3})}),
            ProtocolView::Json::array({ProtocolView::Json::array({0,3})})});
        page.m_protocol->history.Add(flow); page.RebuildRequests();
        page.m_protocol->haveDetail=false; page.m_protocol->displayed.clear();
        page.m_detailTabs.SetCurSel(0); page.m_viewTabs.SetCurSel(0); page.OnView(nullptr,&ignored);
        Pump(page,[&]{return page.m_protocol->haveDetail;});
        Require(!page.GetDlgItem(1106) && !page.GetDlgItem(1110),"packet navigation controls removed");
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        Require(page.m_hexView.Bytes()==std::vector<unsigned char>({0,1,2,3,4,5}) && page.m_hexView.Rows()==2,"all UDP packets appear together");
        page.m_hexView.SendMessage(WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(10*page.m_hexView.m_cw+1,page.m_hexView.m_ch+1));
        page.m_hexView.SendMessage(WM_LBUTTONUP,0,MAKELPARAM(10*page.m_hexView.m_cw+1,page.m_hexView.m_ch+1));
        page.ShowProtocolDetail();page.m_detailStatus.GetWindowText(text);
        Require(text.Find(L"#2")>=0 && text.Find(L"Offset 0x0")>=0,"Hex click reports packet and local offset");
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);page.m_detail.GetWindowText(text);
        Require(text.Find(L"Protocol: QUIC v1")>=0,"Raw summary remains available");
        // Plain UDP accumulates all packets, independent of the Hex selection.
        ++flow.sequence;flow.quic=false;flow.protocol="UDP";
        page.m_protocol->history.Add(flow);
        page.m_protocol->detail=ProtocolView::ReadDetail(QueryFor(&fake),flow);
        page.ShowProtocolDetail();page.m_detail.GetWindowText(text);
        Require(text==L"......","UDP Raw has only payload characters");
        auto& rawSide=page.m_protocol->detail.request;
        auto packetBytes=[](const std::string& text){return std::vector<unsigned char>(text.begin(),text.end());};
        rawSide.packets={packetBytes("\xe4\xb8\xad\r\n"),packetBytes("\xf0\x9f\x99\x82"),{},packetBytes("\xffX")};
        rawSide.datagrams={{0,5},{5,4},{9,0},{9,2},{11,10}};
        page.ShowProtocolDetail();
        auto spans=page.m_detail.Ranges();
        Require(spans.size()==4 && spans[0].first==0 && spans[0].last==2 && spans[1].first==2 && spans[1].last==4 && spans[2].first==4 && spans[2].last==4 && spans[3].last==6,"Unicode, CRLF, empty and invalid UTF-8 character mapping");
        auto colorAt=[&](int pos){
            page.m_protocol->rebuilding=true;page.m_detail.SetSel(pos,pos+1,TRUE);
            CHARFORMAT2 format={};format.cbSize=sizeof(format);
            page.m_detail.SendMessage(EM_GETCHARFORMAT,SCF_SELECTION,(LPARAM)&format);
            page.m_protocol->rebuilding=false;return format.crBackColor;
        };
        Require(colorAt(0)==UiTheme::PageBackground() && colorAt(2)==RGB(218,232,248) && colorAt(4)==UiTheme::PageBackground(),"alternating packet background colors");
        page.m_detail.SetSel(2,2,TRUE);
        int first,last;page.m_detail.GetSel(first,last);
        CString notice;page.m_detailStatus.GetWindowText(notice);
        Require(first==2 && last==2 && notice.Find(L"#2")>=0 && page.m_viewTabs.GetCurSel()==0,"Raw click identifies packet without changing view");
        page.m_detail.SetSel(4,5,TRUE);page.m_detailStatus.GetWindowText(notice);
        Require(notice.Find(L"#4")>=0,"Raw selection identifies containing datagram after empty packet");
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        Require(page.m_hexView.SelectedPacket()==3 && page.m_hexView.SelectedOffset()==0,"Raw Unicode packet selection transfers to Hex byte position");
        page.m_hexView.SendMessage(WM_KEYDOWN,VK_UP); // Empty third datagram.
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);
        page.m_detail.GetSel(first,last);page.m_detailStatus.GetWindowText(notice);
        Require(first==4 && last==4 && notice.Find(L"#3")>=0,"empty Hex packet transfers to Raw insertion point");
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        Require(page.m_hexView.SelectedPacket()==2 && !page.m_hexView.m_hasSelection,"empty packet survives a round trip");
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);
        std::string block;for(int i=0;i<50;++i) block+="packet text line\r\n";
        rawSide.packets.assign(8,packetBytes(block));rawSide.datagrams.clear();
        for(size_t i=0;i<8;++i) rawSide.datagrams.push_back({i*block.size(),block.size()});
        page.ShowProtocolDetail();
        const int fifth=page.m_detail.Ranges()[4].first;
        page.m_detail.SetSel(fifth+3,fifth+3);
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        Require(page.m_hexView.SelectedPacket()==4 && page.m_hexView.SelectedOffset()==0 && page.m_hexView.m_top>0,"view switch reveals fifth packet beyond first screen");
        page.m_hexView.m_first+=2;page.m_hexView.m_last+=4;page.m_hexView.m_top+=2;page.m_hexView.UpdateScroll();
        const auto hexFirst=page.m_hexView.m_first,hexLast=page.m_hexView.m_last;const auto hexTop=page.m_hexView.m_top;
        rawSide.packets.push_back(packetBytes("later"));page.ShowProtocolDetail();
        Require(page.m_hexView.m_first==hexFirst && page.m_hexView.m_last==hexLast && page.m_hexView.m_top==hexTop,"refresh after synchronization does not relocate or replace selection");
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);page.m_detail.GetSel(first,last);
        Require(first==fifth && last==fifth && page.m_detail.GetFirstVisibleLine()>0,"Hex to Raw reveals same packet start");
        GUITHREADINFO caretInfo={sizeof(caretInfo)};
        Require(GetGUIThreadInfo(GetCurrentThreadId(),&caretInfo) && caretInfo.hwndFocus==page.m_detail.m_hWnd && caretInfo.hwndCaret==page.m_detail.m_hWnd,"Raw synchronization transfers actual focus and creates caret");
        CRect caretClient;page.m_detail.GetClientRect(caretClient);
        Require(caretInfo.rcCaret.top>=0 && caretInfo.rcCaret.bottom<=caretClient.bottom && caretInfo.rcCaret.left>=0 && caretInfo.rcCaret.right<=caretClient.right,"Raw caret is inside the viewport");
        rawSide.packets.assign(8,packetBytes(std::string(3000,'x')));page.ShowProtocolDetail();
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);page.m_detail.GetSel(first,last);
        POINT location={};page.m_detail.SendMessage(EM_POSFROMCHAR,(WPARAM)&location,first);
        CRect rawClient;page.m_detail.GetClientRect(rawClient);
        Require(first==12000 && location.x>=0 && location.x<rawClient.right,"single-line packet synchronization scrolls horizontally into view");
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);page.m_detail.GetSel(first,last);
        page.m_detail.SendMessage(EM_POSFROMCHAR,(WPARAM)&location,first);
        Require(first==12000 && location.x>=0 && location.x<rawClient.right,"long horizontal position survives repeated view switching");
        rawSide.packets.resize(2);page.ShowProtocolDetail();
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);page.m_detailStatus.GetWindowText(notice);
        Require(notice.Find(L"outside the preview")>=0,"unavailable synchronized packet is reported instead of silently selecting another");
        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);
        std::string lines;for(int i=0;i<120;++i) lines+="packet line\r\n";
        rawSide.packets={packetBytes(lines)};rawSide.datagrams={{0,lines.size()}};
        page.ShowProtocolDetail();page.m_detail.LineScroll(-page.m_detail.GetFirstVisibleLine());page.m_detail.SetSel(100,120,TRUE);page.m_detail.LineScroll(25);
        const int top=page.m_detail.GetFirstVisibleLine();
        rawSide.packets.push_back(packetBytes("next packet\r\n"));page.ShowProtocolDetail();
        page.m_detail.GetSel(first,last);
        Require(first==100 && last==120 && page.m_detail.GetFirstVisibleLine()==top,"Raw refresh preserves selection and scroll");
        page.m_detail.SetCapture();rawSide.packets.push_back(packetBytes("deferred packet\r\n"));page.ShowProtocolDetail();
        page.m_detail.GetWindowText(text);
        Require(text.Find(L"deferred packet")==-1 && page.m_protocol->pendingDisplay,"Raw drag defers replacement");
        ReleaseCapture();page.TickProtocolView();page.m_detail.GetWindowText(text);
        Require(text.Find(L"deferred packet")>=0 && !page.m_protocol->pendingDisplay,"Raw refresh resumes after drag");
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        auto priorHex=page.m_hexView.Bytes();page.m_hexView.SetCapture();
        rawSide.packets.push_back(packetBytes("hex deferred"));page.ShowProtocolDetail();
        Require(page.m_hexView.Bytes()==priorHex && page.m_protocol->pendingDisplay,"Hex drag defers refresh");
        ReleaseCapture();page.TickProtocolView();
        Require(page.m_hexView.Bytes().size()>priorHex.size(),"Hex refresh resumes after capture release");
        Require((page.m_detail.GetStyle()&WS_VISIBLE)==0 && page.m_hexView.IsWindowVisible(),"background Raw refresh must not uncover Raw over HexView");
        CRect afterRefresh;page.m_hexView.GetWindowRect(afterRefresh);page.ScreenToClient(afterRefresh);
        page.m_hexView.MoveWindow(afterRefresh.left,afterRefresh.top,300,220);
        if(nativeScroll) {
            DragThumb(page.m_hexView,SB_VERT);DragThumb(page.m_hexView,SB_HORZ);
        }
        for(int refresh=0;refresh<3;++refresh) {
            rawSide.packets.push_back(packetBytes("more UDP payload"));page.ShowProtocolDetail();
            Require((page.m_detail.GetStyle()&WS_VISIBLE)==0 && page.m_hexView.IsWindowVisible(),"repeated UDP updates keep Raw hidden");
        }
        page.m_hexView.MoveWindow(afterRefresh);

        page.m_viewTabs.SetCurSel(0);page.OnView(nullptr,&ignored);
        ++flow.sequence;flow.quic=true;flow.protocol="QUIC v1";
        page.m_protocol->history.Add(flow);
        fake.packetPayload=false;
        ProtocolView::Row dns;dns.key="test:dns:100:1";dns.run="test";dns.dns=true;dns.udp=true;dns.protocol="DNS/UDP";
        dns.cacheId=100;dns.requestBytes=19;dns.bytes=512;dns.sequence=703;
        dns.record={{"type","dns"},{"exchange",{{"id",1},{"cache",{{"id",100}}}}}};
        page.m_protocol->history.Add(dns);page.RebuildRequests();page.m_requests.SetItemState(1,LVIS_SELECTED,LVIS_SELECTED);
        page.m_detailTabs.SetCurSel(0);page.OnDetailTab(nullptr,&ignored);
        Pump(page,[&]{return page.m_protocol->haveDetail;});page.m_detail.GetWindowText(text);
        Require(text.Find(L"[Question]")>=0 && !page.GetDlgItem(1106),"DNS Raw fields without packet selector");
        page.m_viewTabs.SetCurSel(1);page.OnView(nullptr,&ignored);
        Require(page.m_hexView.Bytes().size()==19 && page.m_hexView.Bytes()[0]==0,"DNS HexView original wire bytes");
        page.m_protocolFilter.SetCurSel(5);page.OnFilter();Require(page.m_requests.GetItemCount()==1,"DNS filter");
        page.m_protocolFilter.SetCurSel(6);page.OnFilter();Require(page.m_requests.GetItemCount()==1 && page.m_requests.GetItemText(0,3)==L"QUIC v1","QUIC filter excludes DNS");
        Pump(page,[&]{return !page.m_protocol->job;});
        Require(!page.m_protocol->job, "worker completed before harness destruction");
        page.ShowWindow(SW_HIDE); page.ShowWindow(SW_SHOW);
        checkWidths(); // Also covers selection, refresh, filtering, splitter drag and clear above.
        page.KillTimer(1); page.ShowWindow(SW_HIDE);
        {
            CPage4 legacy(&parent); legacy.m_mitmSupported=false;
            Require(legacy.Create(IDD_Page4,&parent)!=FALSE,"create legacy page");
            legacy.m_tls=&fake; legacy.ShowWindow(SW_SHOW);
            Require(!legacy.m_monitor.IsWindowEnabled() && !legacy.m_options.IsWindowEnabled(),"legacy entry points disabled");
            const unsigned queries=fake.queries;
            legacy.OnCA();
            legacy.m_monitor.SetCheck(BST_CHECKED); legacy.OnMonitor(); legacy.UpdateMonitorStatus();
            for (int i=0;i<5;++i) legacy.OnTimer(1);
            Require(fake.queries==queries && !legacy.m_protocol->job && !legacy.m_job,"legacy actions and background timer never query module");
            Require(legacy.m_monitor.GetCheck()==BST_UNCHECKED,"legacy forced commands remain disabled");
            legacy.m_detailStatus.GetWindowText(text);
            Require(text==Localization::Get(ProxyIsLegacyWindows() ? L"mitm.legacy_unavailable" : L"mitm.x64_required"),"unsupported host explanation");
            legacy.KillTimer(1); legacy.DestroyWindow();
        }
        {
            // Leave a failing CA MessageBox open across several dialog timer
            // ticks. The completed job must be consumed before its modal loop.
            CMitmCaDialog ca(&parent,&fake);
            Require(ca.Create(IDD_MITM_CA,&parent)!=FALSE,"create failing CA dialog");
            ca.ShowWindow(SW_SHOW);
            std::atomic<bool> stop{false}; std::atomic<unsigned> prompts{0};
            const DWORD uiThread=GetCurrentThreadId();
            std::thread dismiss([&] {
                struct State { std::vector<HWND> seen; DWORD first=0; } state;
                while (!stop.load()) {
                    EnumThreadWindows(uiThread,[](HWND h,LPARAM value)->BOOL {
                        if (!::IsWindowVisible(h)) return TRUE;
                        wchar_t body[256]={};DWORD_PTR result=0;
                        HWND label=::GetDlgItem(h,0xffff);
                        if(!label || !::SendMessageTimeout(label,WM_GETTEXT,_countof(body),(LPARAM)body,SMTO_ABORTIFHUNG|SMTO_BLOCK,100,&result)) return TRUE;
                        if (wcscmp(body,L"Test CA load failure")!=0) return TRUE;
                        auto& state=*reinterpret_cast<State*>(value);
                        if (std::find(state.seen.begin(),state.seen.end(),h)==state.seen.end()) state.seen.push_back(h);
                        if (!state.first) state.first=GetTickCount();
                        if (GetTickCount()-state.first>500) ::PostMessage(h,WM_CLOSE,0,0);
                        return TRUE;
                    },reinterpret_cast<LPARAM>(&state));
                    prompts.store((unsigned)state.seen.size()); Sleep(10);
                }
            });
            const DWORD start=GetTickCount();
            while (GetTickCount()-start<1000) {
                MSG msg;while(PeekMessage(&msg,nullptr,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessage(&msg);}
                Sleep(10);
            }
            stop=true; dismiss.join();
            Require(prompts==1,"CA failure reported once across nested timer messages");
            ca.KillTimer(1);ca.DestroyWindow();
        }
        {
            const CString path=Localization::SettingsPath();
            const auto original=MitmSettings::Load();
            wchar_t originalSkip[32]={};GetPrivateProfileString(L"options",L"MitmSkipUpstreamVerify",L"",originalSkip,32,path);
            wchar_t originalDecrypt[32]={};GetPrivateProfileString(L"options",L"DecryptHTTPS",L"",originalDecrypt,32,path);
            wchar_t originalRaw[8192]={};GetPrivateProfileSectionW(L"quic_raw",originalRaw,_countof(originalRaw),path);
            WritePrivateProfileStringW(L"quic_raw",L"Enabled",L"0",path); // Legacy preferences must not gate automatic QUIC.
            wchar_t originalQuic[32]={};GetPrivateProfileString(L"options",L"DecryptQUIC",L"",originalQuic,32,path);
            Require(MitmSettings::SaveDecryptQUIC(false),"start QUIC options test off");
            const bool hadIni=GetFileAttributes(path)!=INVALID_FILE_ATTRIBUTES;
            fake.caOk=true;
            for(auto key:{L"mitm.quic_udp_blocked",L"mitm.quic_udp_unsupported",L"mitm.quic_udp_not_captured"}) {
                const CString warning=Localization::Get(key);
                CMitmCaDialog options(&parent,&fake,false,warning);
                Require(options.Create(IDD_MITM_CA,&parent),"UDP warning options");options.ShowWindow(SW_SHOW);
                for(int n=0;n<40;++n){Sleep(10);options.OnTimer(1);}
                CWnd* label=nullptr;
                for(CWnd* child=options.GetWindow(GW_CHILD);child;child=child->GetNextWindow()) {
                    CString text;child->GetWindowText(text);if(text==warning){label=child;break;}
                }
                Require(label && !(label->GetStyle()&WS_VISIBLE),"unchecked QUIC hides UDP warning");
                options.CheckDlgButton(1303,BST_CHECKED);options.SendMessage(WM_COMMAND,MAKEWPARAM(1303,BN_CLICKED));
                for(int n=0;n<40;++n){Sleep(10);options.OnTimer(1);}
                Require((label->GetStyle()&WS_VISIBLE)!=0,"checked QUIC shows UDP warning");
                CRect textRect,heading;label->GetWindowRect(textRect);options.GetDlgItem(IDC_CA_HINT)->GetWindowRect(heading);
                Require(textRect.Height()>0 && textRect.bottom<=heading.top,"UDP warning does not overlap CA section");
                options.CheckDlgButton(1303,BST_UNCHECKED);options.SendMessage(WM_COMMAND,MAKEWPARAM(1303,BN_CLICKED));
                Require(!(label->GetStyle()&WS_VISIBLE),"unchecking QUIC removes UDP warning");
                options.KillTimer(1);options.DestroyWindow();
            }
            // Hint follows an actual new decryption choice, never simply opening
            // options during monitoring (including an already decrypted run).
            auto hintVisible=[](CMitmCaDialog& dialog) {
                for(CWnd* child=dialog.GetWindow(GW_CHILD);child;child=child->GetNextWindow()) {
                    CString text;child->GetWindowText(text);
                    if(text==Localization::Get(L"mitm.next_monitor")) return (child->GetStyle()&WS_VISIBLE)!=0;
                }
                throw std::runtime_error("missing restart hint control");
            };
            for(int state=0;state<4;++state) {
                const bool monitoring=state!=0, active=state==2, saved=state>=2;
                fake.enabled=active;Require(MitmSettings::SaveDecryptHTTPS(saved),"hint test preference");
                CMitmCaDialog hint(&parent,&fake,monitoring);
                Require(hint.Create(IDD_MITM_CA,&parent)!=FALSE,"hint options");hint.ShowWindow(SW_SHOW);
                for(int n=0;n<40;++n){Sleep(10);hint.OnTimer(1);}
                Require(!hintVisible(hint),"opening options never requests restart");
                hint.CheckDlgButton(IDC_MITM_ENABLE,BST_UNCHECKED);
                hint.SendMessage(WM_COMMAND,MAKEWPARAM(IDC_MITM_ENABLE,BN_CLICKED));
                Require(!hintVisible(hint),"unchecked decryption hides hint");
                hint.CheckDlgButton(IDC_MITM_ENABLE,BST_CHECKED);
                hint.SendMessage(WM_COMMAND,MAKEWPARAM(IDC_MITM_ENABLE,BN_CLICKED));
                for(int n=0;n<40;++n){Sleep(10);hint.OnTimer(1);}
                Require(hintVisible(hint)==(monitoring&&!active),"only enabling decryption during plaintext monitoring requests restart");
                hint.SendMessage(WM_COMMAND,MAKEWPARAM(1302,BN_CLICKED));
                Require(!hintVisible(hint),"defaults hide restart hint");
                hint.KillTimer(1);hint.DestroyWindow();
            }
            fake.enabled=false;Require(MitmSettings::SaveDecryptHTTPS(false),"restore off before options tests");
            CMitmCaDialog options(&parent,&fake);
            Require(options.Create(IDD_MITM_CA,&parent)!=FALSE,"create options dialog");options.ShowWindow(SW_SHOW);
            for(int n=0;n<40;++n){Sleep(10);options.OnTimer(1);}
            Require(options.IsDlgButtonChecked(IDC_MITM_ENABLE)==BST_UNCHECKED,"HTTPS decryption defaults off");
            options.CheckDlgButton(IDC_MITM_ENABLE,BST_CHECKED);
            options.SendMessage(WM_COMMAND,MAKEWPARAM(IDC_MITM_ENABLE,BN_CLICKED));
            for(int n=0;n<40;++n){Sleep(10);options.OnTimer(1);}
            Require(!MitmSettings::DecryptHTTPS() && !fake.enabled,"changing the draft never enables MITM or saves it");
            Require(!options.GetDlgItem(1314)->IsWindowVisible(),"advanced settings initially collapsed");
            CRect collapsed;options.GetWindowRect(collapsed);
            options.SendMessage(WM_COMMAND,MAKEWPARAM(1300,BN_CLICKED));
            CRect expanded;options.GetWindowRect(expanded);
            Require(expanded.Height()>collapsed.Height() && options.GetDlgItem(1318)->IsWindowVisible(),"advanced settings expand");
            const MitmSettings::Values changed={{48,768,1024,128,8,64,16,512,30}};
            for(int i=0;i<9;++i) options.SetDlgItemInt(1310+i,changed[i]);
            options.CheckDlgButton(IDC_MITM_SKIP_VERIFY,BST_CHECKED);
            options.SendMessage(WM_COMMAND,MAKEWPARAM(IDC_MITM_SKIP_VERIFY,BN_CLICKED));
            Require(!fake.skipVerify && GetPrivateProfileInt(L"options",L"MitmSkipUpstreamVerify",0,path)==0,"verification checkbox stays draft until save");
            options.CheckDlgButton(1303,BST_CHECKED);
            options.SendMessage(WM_COMMAND,MAKEWPARAM(1303,BN_CLICKED));
            for(int n=0;n<40;++n){Sleep(10);options.OnTimer(1);}
            Require(!fake.injectionQuic && !MitmSettings::DecryptQUIC(),"QUIC draft does not change injection policy");
            Require(!options.GetDlgItem(1304) && !options.GetDlgItem(1305),"no raw QUIC checkbox or ALPN input");
            CRect rawRect;options.GetWindowRect(&rawRect);CImage rawImage;rawImage.Create(rawRect.Width(),rawRect.Height(),32);
            HDC rawDc=rawImage.GetDC();options.PrintWindow(CDC::FromHandle(rawDc),0);rawImage.ReleaseDC();
            Require(SUCCEEDED(rawImage.Save(L"build\\qa\\quic-raw-options.png")),"raw options screenshot");
            options.SendMessage(WM_COMMAND,MAKEWPARAM(1301,BN_CLICKED));
            Require(fake.injectionQuic && MitmSettings::DecryptQUIC(),"save publishes QUIC policy for future injections");
            Require(!fake.settings.contains("quic_raw_enabled") && !fake.settings.contains("quic_raw_alpns"),"automatic QUIC has no manual ALPN settings");
            Require(!options.IsWindowVisible(),"successful save closes options");
            Require(MitmSettings::Load()==changed,"all nine settings persisted to ini");
            Require(MitmSettings::DecryptHTTPS() && !fake.enabled,"Save persists decryption preference without starting interception");
            Require(fake.settings==MitmSettings::Json(changed),"all nine settings applied to service");
            options.KillTimer(1);options.DestroyWindow();
            Require(options.Create(IDD_MITM_CA,&parent),"reopen after save");options.ShowWindow(SW_SHOW);
            for(int n=0;n<40;++n){Sleep(10);options.OnTimer(1);}
            const unsigned beforeReset=fake.queries.load();
            options.SendMessage(WM_COMMAND,MAKEWPARAM(1302,BN_CLICKED));
            const auto defaults=MitmSettings::Defaults();
            for(int i=0;i<9;++i) Require(options.GetDlgItemInt(1310+i)==defaults[i],"restore drafts all nine defaults");
            Require(options.IsDlgButtonChecked(IDC_MITM_SKIP_VERIFY)==BST_UNCHECKED,"restore drafts strict verification");
            Require(options.IsDlgButtonChecked(IDC_MITM_ENABLE)==BST_UNCHECKED && MitmSettings::DecryptHTTPS(),"restore drafts decryption off until Save");
            Require(fake.injectionQuic && MitmSettings::DecryptQUIC(),"restore defaults remains a draft for QUIC policy");
            Require(fake.queries==beforeReset && fake.skipVerify && fake.settings==MitmSettings::Json(changed),"restore makes no service call");
            Require(MitmSettings::Load()==changed && GetPrivateProfileInt(L"options",L"MitmSkipUpstreamVerify",0,path)==1,"restore makes no ini changes");
            page.ApplyMonitorSettings();
            Require(page.m_protocol->history.rowLimit==1024 && page.m_protocol->history.metadataLimit==16*1024*1024 && page.m_protocol->previewLimit==128*1024,"display limits applied immediately");
            options.SendMessage(WM_COMMAND,IDOK);
            Require(!options.IsWindowVisible(),"cancel closes draft without applying defaults");
            options.KillTimer(1);options.DestroyWindow();
            CMitmCaDialog reopened(&parent,&fake);Require(reopened.Create(IDD_MITM_CA,&parent),"reopen saved options");
            for(int i=0;i<9;++i) Require(reopened.GetDlgItemInt(1310+i)==changed[i],"restore saved option values");
            Require(reopened.IsDlgButtonChecked(IDC_MITM_SKIP_VERIFY)==BST_CHECKED,"discard draft verification change on close");
            for(int n=0;n<40;++n){Sleep(10);reopened.OnTimer(1);}
            reopened.SetDlgItemInt(1310,99);
            reopened.CheckDlgButton(IDC_MITM_SKIP_VERIFY,BST_UNCHECKED);
            reopened.SendMessage(WM_COMMAND,MAKEWPARAM(IDC_MITM_SKIP_VERIFY,BN_CLICKED));
            reopened.CheckDlgButton(1303,BST_UNCHECKED);
            reopened.SendMessage(WM_CLOSE);
            Require(fake.injectionQuic && MitmSettings::DecryptQUIC(),"X does not publish QUIC draft");
            Require(fake.skipVerify && GetPrivateProfileInt(L"options",L"MitmSkipUpstreamVerify",0,path)==1,"X discards verification draft");
            reopened.KillTimer(1);reopened.DestroyWindow();
            Require(MitmSettings::Load()==changed,"closing without save preserves settings");
            CMitmCaDialog reset(&parent,&fake);Require(reset.Create(IDD_MITM_CA,&parent),"open options for saved reset");
            for(int n=0;n<40;++n){Sleep(10);reset.OnTimer(1);}
            reset.SendMessage(WM_COMMAND,MAKEWPARAM(1302,BN_CLICKED));
            reset.SendMessage(WM_COMMAND,MAKEWPARAM(1301,BN_CLICKED));
            Require(MitmSettings::Load()==defaults && fake.settings==MitmSettings::Json(defaults),"save applies and persists defaults");
            Require(!MitmSettings::DecryptHTTPS(),"saved defaults disable decryption preference");
            Require(!fake.skipVerify && GetPrivateProfileInt(L"options",L"MitmSkipUpstreamVerify",1,path)==0,"save applies and persists strict verification");
            reset.KillTimer(1);reset.DestroyWindow();
            Require(MitmSettings::Save(original),"restore harness ini values");
            WritePrivateProfileString(L"options",L"MitmSkipUpstreamVerify",originalSkip[0] ? originalSkip : nullptr,path);
            WritePrivateProfileString(L"options",L"DecryptHTTPS",originalDecrypt[0] ? originalDecrypt : nullptr,path);
            WritePrivateProfileString(L"options",L"DecryptQUIC",originalQuic[0] ? originalQuic : nullptr,path);
            WritePrivateProfileSectionW(L"quic_raw",originalRaw[0]?originalRaw:nullptr,path);
            if(!hadIni) Require(DeleteFile(path)!=FALSE,"remove owned harness ini");
            page.ApplyMonitorSettings();fake.caOk=false;
        }
        {
            const CString path=Localization::SettingsPath();
            wchar_t original[32768]={};GetPrivateProfileSectionW(L"recording",original,_countof(original),path);
            const bool originalEnabled=RecordingSettings::Load().enabled;
            auto values=RecordingSettings::Load();values.enabled=false;values.directory=L"D:\\capture-test";values.capacityMiB=128;values.reserveMiB=32;
            Require(RecordingSettings::Save(values),"recording initial preferences");
            CRecordingDialog running(&parent,true,false);Require(running.Create(IDD_RECORDING_OPTIONS,&parent),"running recording options create");
            running.CheckDlgButton(IDC_RECORDING_ENABLE,BST_CHECKED);running.SendMessage(WM_COMMAND,MAKEWPARAM(IDC_RECORDING_ENABLE,BN_CLICKED));
            CString hint;running.GetDlgItemText(IDC_RECORDING_HINT,hint);
            Require(hint==Localization::Get(L"recording.restart_hint"),"enabling recording mid-monitor explains restart is required");
            running.SendMessage(WM_COMMAND,IDCANCEL);running.DestroyWindow();
            Require(!RecordingSettings::Load().enabled,"cancel discards mid-monitor recording draft");
            CRecordingDialog dialog(&parent,false);Require(dialog.Create(IDD_RECORDING_OPTIONS,&parent),"recording options create");dialog.ShowWindow(SW_SHOW);
            Require(dialog.IsDlgButtonChecked(IDC_RECORDING_ENABLE)==BST_UNCHECKED,"recording initially off");
            CRect r;dialog.GetWindowRect(&r);CImage image;image.Create(r.Width(),r.Height(),32);
            HDC dc=image.GetDC();dialog.PrintWindow(CDC::FromHandle(dc),0);image.ReleaseDC();
            Require(SUCCEEDED(image.Save(L"build\\qa\\recording-options.png")),"recording options render");
            dialog.CheckDlgButton(IDC_RECORDING_ENABLE,BST_CHECKED);dialog.SetDlgItemInt(IDC_RECORDING_CAPACITY,256);
            dialog.SendMessage(WM_CLOSE);dialog.DestroyWindow();
            Require(!RecordingSettings::Load().enabled && RecordingSettings::Load().capacityMiB==128,"X discards recording draft");
            Require(dialog.Create(IDD_RECORDING_OPTIONS,&parent),"recording options reopen");
            dialog.CheckDlgButton(IDC_RECORDING_ENABLE,BST_CHECKED);dialog.SetDlgItemInt(IDC_RECORDING_CAPACITY,256);
            dialog.SendMessage(WM_COMMAND,IDOK);dialog.DestroyWindow();
            auto saved=RecordingSettings::Load();Require(saved.enabled && saved.capacityMiB==256 && saved.reserveMiB==32 && saved.directory==values.directory,"recording save retains session opt-in and persists other values");
            Require(MitmSettings::Json(MitmSettings::Load())["recording"]==RecordingSettings::Json(saved),"recording config reaches monitoring start");
            Require(RecordingSettings::ReadPath(L"Enabled",L"missing")==L"missing","recording opt-in is not written to INI");
            CheckFreshRecordingProcess();
            Require(WritePrivateProfileStringW(L"recording",L"Enabled",L"1",path)!=FALSE,"simulate legacy enabled INI");
            CheckFreshRecordingProcess();
            Require(RecordingSettings::Load().enabled,"another instance does not reset this instance's opt-in");
            WritePrivateProfileSectionW(L"recording",original[0]?original:nullptr,path);
            RecordingSettings::SessionEnabled().store(originalEnabled);
        }
        page.ShowWindow(SW_SHOW);
        fake.delay=300;page.m_recording=true;page.m_retainedRecording=true;page.m_monitor.SetCheck(BST_UNCHECKED);
        const auto finalSequence=fake.count.load()+70;fake.count=finalSequence;
        const DWORD stopStarted=GetTickCount();page.UpdateMonitorStatus();
        Require(GetTickCount()-stopStarted<200,"monitor stop does not wait for disk work on the UI thread");
        Require(!page.IsMonitoring() && page.m_stopJob && !page.m_monitor.IsWindowEnabled(),"stop blocks rapid restart until drained");
        CString stopText;page.m_recordingViewStatus.GetWindowText(stopText);
        Require(page.m_recordingViewStatus.IsWindowVisible() && stopText.Find(Localization::Get(L"monitor.stop_writing"))>=0,"stop visibly reports payload/decode stage");
        page.m_monitor.GetWindowText(stopText);Require(stopText==Localization::Get(L"monitor.stopping"),"stop control has explicit busy caption");
        page.m_recordStatus.GetWindowText(stopText);Require(stopText==Localization::Get(L"recording.finishing"),"retained recording shows finalization independently of next-run preferences");
        Require(!page.m_clear.IsWindowEnabled() && !page.m_options.IsWindowEnabled(),"stop excludes conflicting actions");
        Screenshot(page,L"build\\qa\\monitor-toolbar-stopping.png");
        Pump(page,[&] {return !page.m_stopJob;});
        Require(page.m_monitor.IsWindowEnabled() && page.m_monitor.GetCheck()==BST_UNCHECKED,"stop completion restores controls without restarting capture");
        Require(!page.m_recordingViewStatus.IsWindowVisible(),"temporary stop status row is removed after draining");
        fake.delay=0;
        Pump(page,[&] {return page.m_protocol->next==finalSequence && !page.m_protocol->finalPoll && !page.m_protocol->job;});
        const auto finalQueries=fake.queries.load();idleFor(1200);
        Require(fake.queries==finalQueries,"final multi-page drain leaves no recurring queries");
        // HTTP/3 progress updates must preserve the selected list item and view.
        using J=ProtocolView::Json;
        auto h3=page.m_protocol->history.rows.back().record;
        h3["protocol"]="h3";h3["connection"]["decrypted"]=true;h3["connection"]["id"]="h3-test";
        h3["exchange"]["id"]=0;h3["sequence"]=1;
        page.m_protocol->history.Clear();page.m_protocol->selected.clear();
        auto pushH3=[&] {
            auto batch=ProtocolView::Poll([&](const J&){return J{{"run_id","h3-page"},{"next",h3["sequence"]},
                {"records",J::array({h3})}};},"",0,false);
            page.m_protocol->history.Add(std::move(batch.rows.front()));page.RebuildRequests();
        };
        pushH3();page.m_requests.SetItemState(0,LVIS_SELECTED|LVIS_FOCUSED,LVIS_SELECTED|LVIS_FOCUSED);
        const auto selectedH3=page.m_protocol->selected;
        Require(!selectedH3.empty(),"HTTP/3 row selected");
        page.m_protocol->history.rows.front().hex=true;
        for(unsigned n=2;n<7;++n) {
            h3["sequence"]=n;h3["exchange"]["response"]["body_bytes"]=n*112;pushH3();
            Require(page.m_requests.GetItemCount()==1 && page.m_requests.GetItemText(0,0)==L"1","HTTP/3 progress updates original row");
            Require(page.m_protocol->selected==selectedH3 && page.m_requests.GetNextItem(-1,LVNI_SELECTED)==0,"HTTP/3 selection preserved");
            Require(page.m_protocol->history.rows.front().hex,"HTTP/3 HexView preference preserved");
            Require(page.m_protocol->history.rows.front().responseBytes==n*112,"HTTP/3 body counter refreshed");
        }
        h3["sequence"]=7;h3["exchange"]["id"]=4;pushH3();
        Require(page.m_requests.GetItemCount()==2 && page.m_protocol->selected==selectedH3,"another HTTP/3 stream gets its own row");
        std::cout << "Testing recording viewer\n" << std::flush;
        page.ShowWindow(SW_SHOW);
        page.m_protocol->selected.clear();page.m_protocol->haveDetail=false;
        Pump(page,[&] {return !page.m_protocol->job;});fake.count=4096;
        fake.indexMissing=true;
        for(int answer:{IDNO,IDYES}) {
            std::atomic<bool> answered{false};
            CString caption=Localization::Get(L"recording.view_open");
            std::thread responder([&,caption,answer] {
                for(int retry=0;retry<500;++retry) {
                    HWND dialog=FindWindowW(L"#32770",caption);DWORD pid=0;if(dialog)GetWindowThreadProcessId(dialog,&pid);
                    if(dialog && pid==GetCurrentProcessId()) {Sleep(300);answered=true;PostMessage(dialog,WM_COMMAND,answer,0);return;}Sleep(10);
                }
            });
            page.QueueRecordingPage(1,"D:/fake-recording");
            Pump(page,[&] {return !page.m_protocol->job;});responder.join();
            Require(answered,"missing index asks before scanning");
            if(answer==IDNO)Require(!page.m_protocol->offline && fake.indexRebuilds==0,"declining leaves recording unopened and never rebuilds");
            else Require(page.m_protocol->offline && fake.indexRebuilds==1,"explicit approval performs one rebuild and opens the recording");
        }
        Require(!page.m_monitor.IsWindowEnabled(),"archive open excludes monitor start");
        Pump(page,[&] {return page.m_protocol->offline && !page.m_protocol->job;});
        Require(page.m_requests.GetItemCount()==4096 && page.m_protocol->history.rows.size()==128,"virtual list exposes entire recording with bounded summaries");
        Require(!page.m_clear.IsWindowEnabled() && !page.m_follow.IsWindowEnabled(),"read-only view disables destructive/live controls");
        Require(!page.m_monitor.IsWindowVisible() && !page.m_options.IsWindowVisible() && !page.m_clear.IsWindowVisible() && page.m_openRecording.IsWindowVisible(),"archive toolbar shows return and caption without live actions");
        Require((page.m_requests.GetStyle()&LVS_OWNERDATA)!=0,"offline list is virtual");
        page.m_requests.SetColumnWidth(1,211);
        page.m_requests.SetItemState(0,LVIS_SELECTED|LVIS_FOCUSED,LVIS_SELECTED|LVIS_FOCUSED);
        Pump(page,[&] {return page.m_protocol->haveDetail && !page.m_protocol->job;});
        const auto keptSelection=page.m_protocol->selected;
        const auto keptHeaders=page.m_protocol->detail.request.headers;
        for(int index:{600,1200,1800,2400,3000,4095}) {
            page.m_requests.EnsureVisible(index,FALSE);
            Pump(page,[&] {return page.RequestRow(index)!=nullptr && !page.m_protocol->job;});
            CString expected;expected.Format(L"%d",index+1);
            Require(page.m_requests.GetItemText(index,0)==expected,"scroll loads requested global row");
            Require(page.m_protocol->history.rows.size()<=512 && page.m_protocol->history.bytes<=16*1024*1024,"scrolling does not grow summary cache without bound");
            Require(page.m_protocol->selected==keptSelection && page.m_protocol->detail.request.headers==keptHeaders,"scrolling preserves selected detail");
            Require(page.m_requests.GetColumnWidth(1)==211,"scrolling preserves column width");
        }
        page.m_requests.EnsureVisible(0,FALSE);
        Pump(page,[&] {return page.RequestRow(10)!=nullptr && !page.m_protocol->job;});
        Require(page.m_requests.GetTopIndex()==0 && page.m_requests.GetItemText(10,0)==L"11","scroll backward reloads evicted summaries without moving viewport");
        page.m_requests.EnsureVisible(2200,FALSE);
        page.m_requests.SetItemState(2200,LVIS_SELECTED|LVIS_FOCUSED,LVIS_SELECTED|LVIS_FOCUSED);
        Pump(page,[&] {return page.RequestRow(2200)!=nullptr && page.m_protocol->haveDetail && !page.m_protocol->job;});
        Require(page.m_protocol->selected==page.RequestRow(2200)->key,"selecting an unloaded row loads its detail");
        fake.delay=30;
        page.m_requests.EnsureVisible(3500,FALSE);page.TickProtocolView();
        Require(page.m_protocol->job && page.m_protocol->job->archiveAction==2,"scroll read starts asynchronously");
        page.m_filter.SetWindowText(L"old filter");
        page.m_filter.SetWindowText(L"item-529");
        fake.delay=0;
        page.m_filter.SetWindowText(L"item-529");Pump(page,[&] {return !page.m_protocol->archiveRefresh && !page.m_protocol->job;});
        Require(page.m_requests.GetItemCount()==1 && page.m_requests.GetItemText(0,0)==L"530","filter searches entire recording");
        page.m_requests.SetItemState(0,LVIS_SELECTED|LVIS_FOCUSED,LVIS_SELECTED|LVIS_FOCUSED);
        Pump(page,[&] {return page.m_protocol->haveDetail && !page.m_protocol->job;});
        Require(page.m_protocol->detail.request.headers.find("GET /ip")!=std::string::npos,"offline detail hydrates headers on demand");
        CRect archiveRect;page.GetClientRect(archiveRect);CImage archiveImage;archiveImage.Create(archiveRect.Width(),archiveRect.Height(),32);
        HDC archiveDc=archiveImage.GetDC();page.SendMessage(WM_PRINT,(WPARAM)archiveDc,PRF_CLIENT|PRF_CHILDREN|PRF_ERASEBKGND);archiveImage.ReleaseDC();
        Require(SUCCEEDED(archiveImage.Save(L"build\\qa\\recording-view.png")),"offline screenshot");
        page.OnOpenRecording();Pump(page,[&] {return !page.m_protocol->job;});
        Require(!page.m_protocol->offline && page.m_monitor.IsWindowEnabled(),"return live releases archive without starting monitoring");
        Require((page.m_requests.GetStyle()&LVS_OWNERDATA)==0 && page.m_requests.GetColumnWidth(1)==211,"live list and user column width restored");
        page.DestroyWindow();parent.DestroyWindow();
        std::cout << "PASS actual page controls: saved process names, clean address, no raw log, per-request HEX, selection races, headers, decoded body, eviction, resize, bounds, clear\n";
    }
};
CWinApp testApplication;
int main(int argc, char** argv) {
    try {
        Require(AfxWinInit(GetModuleHandle(nullptr), nullptr, GetCommandLine(), 0) != FALSE, "MFC init");
        INITCOMMONCONTROLSEX controls = {sizeof(controls), ICC_WIN95_CLASSES}; InitCommonControlsEx(&controls);
        Require(Localization::Initialize() != FALSE, "locale init");
        if(argc>1 && std::string(argv[1])=="--recording-fresh") {
            const auto v=RecordingSettings::Load();
            Require(!v.enabled && v.capacityMiB==256 && v.reserveMiB==32 && v.directory==L"D:\\capture-test","fresh recording preferences");
            FakeTls fake;fake.caOk=true;fake.caFlags=3;auto job=StartMonitorJob(&fake,false);
            for(int i=0;i<200 && !job->done.load();++i)Sleep(10);
            Require(job->done.load() && job->result>=0 && fake.starts==1 && !fake.activeRecording,"fresh monitor start never retains files without opt-in");
            return 0;
        }
        // Opt in only on an idle desktop: this check moves the real cursor.
        const bool nativeScroll=argc>1 && std::string(argv[1])=="--native-scroll";
        ProtocolPageHarness::Run(nativeScroll); return 0;
    } catch (const std::exception& e) { std::cerr << "FAIL " << e.what() << "\n"; return 1; }
}
