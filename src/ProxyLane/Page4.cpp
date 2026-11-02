#include "stdafx.h"
#include "ProxyLane.h"
#include "Page4.h"
#include "Localization.h"
#include "MitmSettings.h"
#include "RecordingDialog.h"
#include "../../third_party/nlohmann/json.hpp"
#include <thread>
#include <atomic>
#include <algorithm>

// Workers own their result, never a window pointer. Closing a dialog cannot
// leave a callback targeting a destroyed HWND. Release/acquire publishes text.
struct MitmJob {
    std::atomic<bool> done;
    int result;
    bool needsCA;
    bool failureReported;
    std::string recordingDirectory;
    char text[8192];
    MitmJob() : done(false), result(-1), needsCA(false), failureReported(false) { text[0] = 0; }
};
static std::shared_ptr<MitmJob> StartMitmJob(IProxyTlsControl* tls, unsigned action)
{
    auto job = std::make_shared<MitmJob>();
    try {
        std::thread([job, tls, action]() {
            job->result = tls->ManageCA(static_cast<IProxyTlsControl::CaAction>(action), job->text, sizeof(job->text));
            job->done.store(true);
        }).detach();
    } catch (...) { strcpy_s(job->text, "Unable to start CA worker."); job->done.store(true); }
    return job;
}
static std::shared_ptr<MitmJob> StartMonitorJob(IProxyTlsControl* tls, bool decrypt)
{
    auto job = std::make_shared<MitmJob>();
    const auto settings=MitmSettings::Json(MitmSettings::Load()); // Snapshot ALL options on the UI thread.
    const bool quic=MitmSettings::DecryptQUIC();
    const bool skip=GetPrivateProfileInt(L"options",L"MitmSkipUpstreamVerify",0,Localization::SettingsPath())==1;
    try {
        std::thread([job,tls,decrypt,quic,settings,skip]() {
            try {
                if(decrypt || quic) {
                    job->result=tls->ManageCA(IProxyTlsControl::QueryCA,job->text,sizeof(job->text));
                    if(job->result>=0) job->needsCA=(job->result&2)==0;
                    if(job->result<0 || job->needsCA) {job->done.store(true);return;}
                }
                auto options=nlohmann::json{{"type","mitm_options"},{"settings",settings},{"skip_upstream_verify",skip}}.dump();
                job->result=tls->QueryProtocol(options.c_str(),job->text,sizeof(job->text));
                if(job->result>=0) {
                    auto applied=nlohmann::json::parse(job->text,nullptr,false);
                    if(job->result>sizeof(job->text) || !applied.is_object() || applied["settings"]["recording"]!=settings["recording"])
                        throw std::runtime_error("Recording options were not accepted by the monitoring module.");
                    auto request=nlohmann::json{{"type","monitor_start"},{"decrypt",decrypt},{"quic",quic}}.dump();
                    job->result=tls->QueryProtocol(request.c_str(),job->text,sizeof(job->text));
                    if(job->result>=0 && settings["recording"].value("enabled",false)) {
                        char status[8192]={};int n=tls->QueryProtocol("{\"type\":\"recording_status\"}",status,sizeof(status));
                        auto value=nlohmann::json::parse(status,nullptr,false);
                        if(n<=0 || n>sizeof(status) || !value.is_object() || !value.value("enabled",false) ||
                            value.value("ended",false) || value.value("stopped",false) || value.value("directory",std::string()).empty()) {
                            tls->QueryProtocol("{\"type\":\"monitor_stop\"}",status,sizeof(status));
                            throw std::runtime_error("Recording was requested but did not start. Monitoring has been stopped; check the recording directory and settings.");
                        }
                    }
                }
            } catch (const std::exception& e) {job->result=-1;strncpy_s(job->text,e.what(),_TRUNCATE);}
              catch (...) { job->result=-1;strcpy_s(job->text,"Unable to prepare monitoring."); }
            job->done.store(true);
        }).detach();
    } catch (...) {strcpy_s(job->text,"Unable to start monitor worker.");job->done.store(true);}
    return job;
}
static CString Utf8(const BYTE* bytes, size_t length)
{
    CString result;
    if (!length) return result;
    int count = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)bytes, (int)length, NULL, 0);
    LPWSTR out = result.GetBuffer(count);
    MultiByteToWideChar(CP_UTF8, 0, (LPCCH)bytes, (int)length, out, count);
    // The edit control cannot show embedded NULs. Keep payload length explicit.
    for (int i = 0; i < count; ++i)
        if (out[i] < 32 && out[i] != '\r' && out[i] != '\n' && out[i] != '\t') out[i] = L'\x00b7';
    result.ReleaseBuffer(count);
    return result;
}
static CString Utf8(const char* text) { return Utf8((const BYTE*)text, strlen(text)); }
static CString MonitorStartError(const char* text)
{
    const auto error=nlohmann::json::parse(text,nullptr,false);
    if(error.is_object() && error.contains("error") && error["error"].is_string() &&
        error.contains("path") && error["path"].is_string() && error.contains("detail") && error["detail"].is_string()) {
        const auto code=error["error"].get<std::string>();
        if(code=="recording_directory_error" || code=="recording_initialize_error") {
            CString message;
            message.Format(Localization::Get(code=="recording_directory_error"?L"recording.path_error":L"recording.initialize_error"),
                Utf8(error["path"].get<std::string>().c_str()).GetString(),
                Utf8(error["detail"].get<std::string>().c_str()).GetString());
            return message;
        }
    }
    return Localization::Get(L"monitor.start_failed")+L"\r\n\r\n"+Utf8(text);
}
// Section headers provide a visible boundary without adding group-box padding.
class CMitmSectionHeader : public CStatic {
    void DrawItem(LPDRAWITEMSTRUCT item) override {
        CDC dc;dc.Attach(item->hDC);CRect rect=item->rcItem;
        dc.FillSolidRect(rect,UiTheme::AccentSoft());
        dc.FillSolidRect(rect.left,rect.top,UiTheme::ScaleForWindow(m_hWnd,3),rect.Height(),UiTheme::AccentText());
        dc.FillSolidRect(rect.left,rect.bottom-1,rect.Width(),1,UiTheme::AccentSoftBorder());
        CFont* old=dc.SelectObject(GetFont());dc.SetBkMode(TRANSPARENT);dc.SetTextColor(UiTheme::TextPrimary());
        rect.DeflateRect(UiTheme::ScaleForWindow(m_hWnd,9),0);
        CString caption;GetWindowText(caption);dc.DrawText(caption,rect,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
        dc.SelectObject(old);dc.Detach();
    }
};
class CMitmCaDialog : public CModernDialog {
    std::shared_ptr<MitmJob> m_job;
    CModernButton m_buttons[4], m_advanced, m_save, m_defaults;
    CStatic m_labels[9],m_effective,m_enableHint,m_quicHint,m_quicUdpHint;
    CString m_quicUdpWarning;
    CButton m_quic; bool m_savedQuic=false; UINT m_pendingEnableId=IDC_MITM_ENABLE;
    CMitmSectionHeader m_caTitle,m_settingsTitle;
    CFont m_sectionFont;
    CEdit m_values[9];
    bool m_expanded=false, m_defaultsPending=false, m_savedSkip=false;
    bool m_savedDecrypt=false, m_enablePending=false, m_saveAfterTrust=false, m_monitoring=false;
    bool m_enableHintRequested=false;
    MitmSettings::Values m_saved;
    enum { AdvancedId=1300,SaveId=1301,DefaultsId=1302,QuicId=1303,EditBase=1310 };
    void Place(CWnd& control,int x,int y,int w,int h) {
        CRect r(x,y,x+w,y+h);MapDialogRect(r);control.MoveWindow(r);
    }
    void LayoutOptions() {
        auto scale=[&](int value){return UiTheme::ScaleForWindow(m_hWnd,value);};
        CClientDC dc(this);auto old=dc.SelectObject(&m_uiFont);
        TEXTMETRIC metrics={};dc.GetTextMetrics(&metrics);
        const int line=metrics.tmHeight, margin=scale(12), gap=scale(6);
        CRect client;GetClientRect(client);
        const int width=client.Width()-2*margin;
        const int editHeight=line+scale(4), buttonHeight=line+scale(8), rowHeight=editHeight+gap;
        auto measureText=[&](CString text) {
            CRect bounds(0,0,width,0);
            dc.DrawText(text,bounds,DT_CALCRECT|DT_WORDBREAK|DT_NOPREFIX);return bounds.Height();
        };
        auto textHeight=[&](LPCTSTR key){return measureText(Localization::Get(key));};
        auto buttonWidth=[&](CWnd& button) {
            CString text;button.GetWindowText(text);return dc.GetTextExtent(text).cx+scale(20);
        };
        int y=margin;
        GetDlgItem(IDC_MITM_ENABLE)->MoveWindow(margin,y,scale(150),line);
        m_enableHint.MoveWindow(margin+scale(160),y,max(0,width-scale(160)),line);
        y+=line+gap;
        m_quic.MoveWindow(margin,y,width,line);y+=line+gap;
        const int quicHintHeight=textHeight(L"mitm.quic_hint");
        m_quicHint.MoveWindow(margin,y,width,quicHintHeight);y+=quicHintHeight+gap;
        const bool udpWarning=m_quic.GetCheck()==BST_CHECKED && !m_quicUdpWarning.IsEmpty();
        m_quicUdpHint.ShowWindow(udpWarning ? SW_SHOW:SW_HIDE);
        if(udpWarning) {
            const int height=max(line,measureText(m_quicUdpWarning));
            m_quicUdpHint.MoveWindow(margin,y,width,height);y+=height+gap;
        }
        const int headingHeight=line+scale(8);
        m_caTitle.MoveWindow(margin,y,width,headingHeight);y+=headingHeight+gap;
        CString status;GetDlgItemText(IDC_MITM_STATUS,status);
        const int statusHeight=max(line,measureText(status));
        GetDlgItem(IDC_MITM_STATUS)->MoveWindow(margin,y,width,statusHeight);y+=statusHeight+gap;
        int x=margin;
        for(int i=0;i<3;++i) {
            int w=buttonWidth(m_buttons[i]);m_buttons[i].MoveWindow(x,y,w,buttonHeight);x+=w+gap;
        }
        y+=buttonHeight+scale(8);
        GetDlgItem(IDC_MITM_SKIP_VERIFY)->MoveWindow(margin,y,width,line);y+=line+gap;
        const int hintHeight=textHeight(L"mitm.skip_hint");
        GetDlgItem(IDC_MITM_SKIP_HINT)->MoveWindow(margin,y,width,hintHeight);y+=hintHeight+scale(8);
        m_settingsTitle.MoveWindow(margin,y,width,headingHeight);y+=headingHeight+gap;
        const int columnGap=scale(20),column=(width-columnGap)/2,editWidth=scale(60);
        auto field=[&](int i,int n,int top) {
            int left=margin+(n%2)*(column+columnGap),row=top+(n/2)*rowHeight;
            m_labels[i].MoveWindow(left,row+(editHeight-line)/2,column-editWidth-gap,line);
            m_values[i].MoveWindow(left+column-editWidth,row,editWidth,editHeight);
            m_labels[i].ShowWindow(i<4||m_expanded ? SW_SHOW:SW_HIDE);
            m_values[i].ShowWindow(i<4||m_expanded ? SW_SHOW:SW_HIDE);
        };
        for(int i=0;i<4;++i) field(i,i,y);
        y+=2*rowHeight;
        m_advanced.SetWindowText(Localization::Get(m_expanded ? L"mitm.advanced_hide":L"mitm.advanced"));
        m_advanced.MoveWindow(margin,y,buttonWidth(m_advanced),buttonHeight);y+=buttonHeight+gap;
        for(int i=4;i<9;++i) field(i,i-4,y);
        if(m_expanded) y+=3*rowHeight;
        int effectiveHeight=line;
        for(auto key:{L"mitm.settings_effective",L"mitm.settings_saved",L"mitm.defaults_pending"})
            effectiveHeight=max(effectiveHeight,textHeight(key));
        m_effective.MoveWindow(margin,y,width,effectiveHeight);y+=effectiveHeight+scale(10);
        m_defaults.MoveWindow(margin,y,buttonWidth(m_defaults),buttonHeight);
        int closeWidth=buttonWidth(m_buttons[3]),saveWidth=buttonWidth(m_save);
        m_buttons[3].MoveWindow(margin+width-closeWidth,y,closeWidth,buttonHeight);
        m_save.MoveWindow(margin+width-closeWidth-gap-saveWidth,y,saveWidth,buttonHeight);
        dc.SelectObject(old);
        CRect window;GetWindowRect(window);
        const int height=window.Height()-client.Height()+y+buttonHeight+margin;
        MONITORINFO monitor={sizeof(monitor)};int top=window.top;
        if(GetMonitorInfo(MonitorFromWindow(m_hWnd,MONITOR_DEFAULTTONEAREST),&monitor))
            top=max(monitor.rcWork.top,min(top,monitor.rcWork.bottom-height));
        SetWindowPos(nullptr,window.left,top,window.Width(),height,SWP_NOZORDER);
        RedrawWindow(nullptr,nullptr,RDW_INVALIDATE|RDW_ALLCHILDREN|RDW_UPDATENOW);
    }
    void RestoreDefaults() {
        const auto values=MitmSettings::Defaults();
        for(int i=0;i<9;++i) SetDlgItemInt(EditBase+i,values[i]);
        CheckDlgButton(IDC_MITM_SKIP_VERIFY,BST_UNCHECKED);
        CheckDlgButton(IDC_MITM_ENABLE,BST_UNCHECKED);m_quic.SetCheck(BST_UNCHECKED);
        m_defaultsPending=true;
        m_effective.SetWindowText(Localization::Get(L"mitm.defaults_pending"));
        LayoutOptions();
    }
    void UpdateEnableHint() {
        // Opening options is not a mode change. Only a new unchecked->checked
        // choice during plaintext monitoring needs a restart; active MITM does not.
        char status[256]={};bool activeQuic=false;
        if(m_monitoring && m_tls->QueryProtocol("{\"type\":\"monitor_status\"}",status,sizeof(status))>0) {
            auto value=nlohmann::json::parse(status,nullptr,false);
            if(value.is_object())activeQuic=value.value("quic",false);
        }
        const bool show=m_monitoring && m_enableHintRequested &&
            ((IsDlgButtonChecked(IDC_MITM_ENABLE)==BST_CHECKED && !m_tls->IsEnabled()) ||
             (m_quic.GetCheck()==BST_CHECKED && !activeQuic));
        m_enableHint.ShowWindow(show ? SW_SHOW : SW_HIDE);
    }
    void SaveOptions() {
        if(m_job) return;
        const bool decrypt=IsDlgButtonChecked(IDC_MITM_ENABLE)==BST_CHECKED;
        const bool quic=m_quic.GetCheck()==BST_CHECKED;
        if((decrypt || quic) && !IsTrusted()) {m_enablePending=true;m_saveAfterTrust=true;Start(IProxyTlsControl::TrustCA);return;}
        auto values=m_saved;
        for(int i=0;i<9;++i) {
            CString text;m_values[i].GetWindowText(text);
            const auto& f=MitmSettings::Fields()[i];
            wchar_t* end=nullptr;unsigned long value=wcstoul(text,&end,10);
            if(text.IsEmpty() || text.SpanIncluding(L"0123456789")!=text || !end || *end || value<f.minimum || value>f.maximum) {
                if(i>=4 && !m_expanded){m_expanded=true;LayoutOptions();}
                MessageBox(Localization::Format(L"mitm.range",(LPCWSTR)Localization::Get(f.label),f.minimum,f.maximum),Localization::Get(L"mitm.ca"),MB_ICONWARNING);
                m_values[i].SetFocus();m_values[i].SetSel(0,-1);return;
            }
            values[i]=value;
        }
        if(values[0]>values[1]) {MessageBox(Localization::Get(L"mitm.quota_error"),Localization::Get(L"mitm.ca"),MB_ICONWARNING);return;}
        char response[4096]={};
        nlohmann::json request={{"type","mitm_options"},{"settings",MitmSettings::Json(values)},{"validate_only",true}};
        const bool skip=IsDlgButtonChecked(IDC_MITM_SKIP_VERIFY)==BST_CHECKED;
        request["skip_upstream_verify"]=skip;
        if(m_tls->QueryProtocol(request.dump().c_str(),response,sizeof(response))<0) {MessageBox(Utf8(response),Localization::Get(L"mitm.ca"),MB_ICONERROR);return;}
        if(!MitmSettings::Save(values)) {MessageBox(Localization::Get(L"mitm.save_failed"),Localization::Get(L"mitm.ca"),MB_ICONERROR);return;}
        if(!WritePrivateProfileString(L"options",L"MitmSkipUpstreamVerify",skip ? L"1":L"0",Localization::SettingsPath())) {
            MitmSettings::Save(m_saved);
            MessageBox(Localization::Get(L"mitm.save_failed"),Localization::Get(L"mitm.ca"),MB_ICONERROR);return;
        }
        if(!MitmSettings::SaveDecryptHTTPS(decrypt) || !MitmSettings::SaveDecryptQUIC(quic)) {
            MitmSettings::SaveDecryptHTTPS(m_savedDecrypt);MitmSettings::SaveDecryptQUIC(m_savedQuic);
            MitmSettings::Save(m_saved);
            WritePrivateProfileString(L"options",L"MitmSkipUpstreamVerify",m_savedSkip ? L"1":L"0",Localization::SettingsPath());
            MessageBox(Localization::Get(L"mitm.save_failed"),Localization::Get(L"mitm.ca"),MB_ICONERROR);return;
        }
        request["validate_only"]=false;
        if(m_tls->QueryProtocol(request.dump().c_str(),response,sizeof(response))<0) {
            bool restored=MitmSettings::Save(m_saved);
            restored=MitmSettings::SaveDecryptHTTPS(m_savedDecrypt) && restored;
            restored=MitmSettings::SaveDecryptQUIC(m_savedQuic) && restored;
            restored=WritePrivateProfileString(L"options",L"MitmSkipUpstreamVerify",m_savedSkip ? L"1":L"0",Localization::SettingsPath()) && restored;
            CString error=Utf8(response);if(!restored) error+=L"\r\n"+Localization::Get(L"mitm.save_failed");
            MessageBox(error,Localization::Get(L"mitm.ca"),MB_ICONERROR);return;
        }
        m_tls->QueryProtocol(nlohmann::json{{"type","quic_injection_policy"},{"enabled",MitmSettings::DecryptQUIC()}}.dump().c_str(),nullptr,0);
        m_savedSkip=skip;
        m_defaultsPending=false;m_savedDecrypt=decrypt;m_savedQuic=quic;
        m_saved=values;m_effective.SetWindowText(Localization::Get(L"mitm.settings_saved"));
        if(GetParent()) GetParent()->SendMessage(WM_APP+41);
        EndDialog(IDOK);
    }
    IProxyTlsControl* m_tls;
    int m_flags;
    unsigned m_action=IProxyTlsControl::QueryCA;
    CString m_details;
public:
    CMitmCaDialog(CWnd* parent, IProxyTlsControl* tls, bool monitoring=false, const CString& udpWarning=CString()) : CModernDialog(IDD_MITM_CA, parent), m_tls(tls), m_flags(-1), m_monitoring(monitoring), m_quicUdpWarning(udpWarning) {}
    bool IsTrusted() const { return m_flags >= 0 && (m_flags & 2) != 0; }
    void Start(unsigned action) {
        m_action=action;
        for (auto& button : m_buttons) button.EnableWindow(FALSE);
        GetDlgItem(IDC_MITM_ENABLE)->EnableWindow(FALSE);m_quic.EnableWindow(FALSE);m_save.EnableWindow(FALSE);m_defaults.EnableWindow(FALSE);
        SetDlgItemText(IDC_MITM_STATUS, Localization::Get(_T("mitm.busy")));
        m_job = StartMitmJob(m_tls, action);
        LayoutOptions();
    }
    BOOL OnInitDialog() override {
        CModernDialog::OnInitDialog();
        SetWindowText(Localization::Get(_T("mitm.ca")));
        const int ids[] = {IDC_CA_INSTALL, IDC_CA_REMOVE, IDC_CA_REFRESH, IDOK};
        const LPCTSTR keys[] = {_T("mitm.install"), _T("mitm.remove"), _T("mitm.refresh"), _T("mitm.close")};
        for (int i = 0; i < _countof(ids); ++i) {
            SetDlgItemText(ids[i], Localization::Get(keys[i]));
            m_buttons[i].SubclassDlgItem(ids[i], this);
        }
        SetDlgItemText(IDC_MITM_SKIP_VERIFY, Localization::Get(L"mitm.skip_verify"));
        SetDlgItemText(IDC_MITM_SKIP_HINT, Localization::Get(L"mitm.skip_hint"));
        m_saved=MitmSettings::Load();
        const DWORD child=WS_CHILD|WS_VISIBLE;
        m_savedDecrypt=MitmSettings::DecryptHTTPS();m_savedQuic=MitmSettings::DecryptQUIC();
        m_quic.Create(Localization::Get(L"mitm.quic"),child|WS_TABSTOP|BS_AUTOCHECKBOX,CRect(),this,QuicId);m_quic.SetFont(&m_uiFont);m_quic.SetCheck(m_savedQuic?BST_CHECKED:BST_UNCHECKED);
        m_quicHint.Create(Localization::Get(L"mitm.quic_hint"),child,CRect(),this);m_quicHint.SetFont(&m_uiFont);
        m_quicUdpHint.Create(m_quicUdpWarning,WS_CHILD,CRect(),this);m_quicUdpHint.SetFont(&m_uiFont);
        SetDlgItemText(IDC_MITM_ENABLE,Localization::Get(L"mitm.enable"));
        CheckDlgButton(IDC_MITM_ENABLE,m_savedDecrypt ? BST_CHECKED:BST_UNCHECKED);
        m_enableHint.Create(Localization::Get(L"mitm.next_monitor"),child|SS_LEFTNOWORDWRAP,CRect(),this);
        m_enableHint.SetFont(&m_uiFont);
        m_enableHintRequested=false;
        m_enableHint.ShowWindow(SW_HIDE);
        UiTheme::CreateUiFont(m_sectionFont,m_hWnd,9,FW_SEMIBOLD);
        m_caTitle.SubclassDlgItem(IDC_CA_HINT,this);
        m_caTitle.ModifyStyle(SS_TYPEMASK,SS_OWNERDRAW);m_caTitle.SetWindowText(L"ProxyLane CA / TLS");
        m_caTitle.SetFont(&m_sectionFont);
        m_settingsTitle.Create(Localization::Get(L"mitm.cache_display"),child|SS_OWNERDRAW,CRect(),this);
        m_settingsTitle.SetFont(&m_sectionFont);
        for(int i=0;i<9;++i) {
            m_labels[i].Create(Localization::Get(MitmSettings::Fields()[i].label),child,CRect(),this);
            m_values[i].CreateEx(WS_EX_CLIENTEDGE,L"EDIT",L"",child|WS_TABSTOP|ES_NUMBER|ES_AUTOHSCROLL,CRect(),this,EditBase+i);
            m_labels[i].SetFont(&m_uiFont);m_values[i].SetFont(&m_uiFont);m_values[i].SetLimitText(5);
            CString value;value.Format(L"%u",m_saved[i]);m_values[i].SetWindowText(value);
        }
        m_advanced.Create(L"",child|WS_TABSTOP|BS_PUSHBUTTON,CRect(),this,AdvancedId);Place(m_advanced,12,155,100,16);
        m_save.Create(Localization::Get(L"mitm.save"),child|WS_TABSTOP|BS_PUSHBUTTON,CRect(),this,SaveId);
        m_defaults.Create(Localization::Get(L"mitm.defaults"),child|WS_TABSTOP|BS_PUSHBUTTON,CRect(),this,DefaultsId);
        m_defaults.SetFont(&m_uiFont);
        m_effective.Create(Localization::Get(L"mitm.settings_effective"),child,CRect(),this);
        m_advanced.SetFont(&m_uiFont);m_save.SetFont(&m_uiFont);m_effective.SetFont(&m_uiFont);
        SendMessage(DM_SETDEFID,SaveId);LayoutOptions();
        // The saved preference is authoritative even before the optional module
        // has been loaded. Opening/cancelling this dialog must not apply it.
        m_savedSkip=GetPrivateProfileInt(L"options",L"MitmSkipUpstreamVerify",0,Localization::SettingsPath())==1;
        CheckDlgButton(IDC_MITM_SKIP_VERIFY,m_savedSkip ? BST_CHECKED : BST_UNCHECKED);
        SetTimer(1, 150, NULL); Start(0); return TRUE;
    }
    BOOL OnCommand(WPARAM wParam, LPARAM lParam) override {
        UINT id = LOWORD(wParam);
        if(id==AdvancedId) {m_expanded=!m_expanded;LayoutOptions();return TRUE;}
        if(id==SaveId) {SaveOptions();return TRUE;}
        if(id==DefaultsId) {if(!m_job) {RestoreDefaults();m_enableHintRequested=false;UpdateEnableHint();}return TRUE;}
        if(id==IDC_MITM_ENABLE || id==QuicId) {
            m_pendingEnableId=id;
            if(m_job) return TRUE;
            m_enableHintRequested=IsDlgButtonChecked(id)==BST_CHECKED;
            UpdateEnableHint();LayoutOptions();
            if(IsDlgButtonChecked(id)==BST_CHECKED) {
                m_enablePending=true;m_saveAfterTrust=false;
                Start(IProxyTlsControl::QueryCA);
            }
            return TRUE;
        }
        if (id == IDC_MITM_SKIP_VERIFY) return TRUE; // Draft until Save.
        if (id == IDC_CA_REFRESH) {
            if (!m_job) MessageBox(m_details, Localization::Get(L"mitm.ca"), MB_OK);
            return TRUE;
        }
        if (id == IDC_CA_INSTALL || id == IDC_CA_REMOVE) {
            if(id==IDC_CA_REMOVE && m_monitoring) return TRUE;
            if (!m_job) Start(id == IDC_CA_INSTALL ? IProxyTlsControl::TrustCA :
                id == IDC_CA_REMOVE ? IProxyTlsControl::RemoveCATrust : IProxyTlsControl::QueryCA);
            return TRUE;
        }
        return CModernDialog::OnCommand(wParam, lParam);
    }
    // Do not allow a trust operation to finish invisibly after dismissing it.
    void OnOK() override { OnCancel(); } // The resource button is the Cancel action.
    void OnCancel() override { if (!m_job) CModernDialog::OnCancel(); }
    afx_msg HBRUSH OnCtlColor(CDC* dc, CWnd* wnd, UINT color) {
        HBRUSH brush=CModernDialog::OnCtlColor(dc,wnd,color);
        if(color==CTLCOLOR_STATIC && wnd && wnd->GetSafeHwnd()==m_quicUdpHint.GetSafeHwnd())
            dc->SetTextColor(UiTheme::Warning());
        if(color==CTLCOLOR_STATIC && wnd && wnd->GetDlgCtrlID()==IDC_MITM_STATUS &&
            !m_job && m_flags>=0 && !IsTrusted())
            dc->SetTextColor(UiTheme::Warning()); // Dark yellow remains readable on white.
        return brush;
    }
    afx_msg void OnTimer(UINT_PTR id) {
        if (m_job && m_job->done.load()) {
            // Consume before entering MessageBox's nested message loop: timer
            // messages must never display this completed failure repeatedly.
            auto job = std::move(m_job);
            int flags = job->result;
            m_flags = flags;
            m_details = Utf8(job->text);
            SetDlgItemText(IDC_MITM_STATUS, Localization::Get(flags < 0 ? _T("mitm.failed") :
                flags & 2 ? _T("mitm.trusted") : flags & 1 ? _T("mitm.untrusted") : _T("mitm.uninitialized")));
            for (auto& button : m_buttons) button.EnableWindow(TRUE);
            GetDlgItem(IDC_CA_INSTALL)->EnableWindow(!IsTrusted());
            SetDlgItemText(IDC_CA_REMOVE,Localization::Get(IsTrusted() && m_monitoring ?
                L"mitm.remove_stop_first" : L"mitm.remove"));
            GetDlgItem(IDC_CA_REMOVE)->EnableWindow((flags & 2) && flags >= 0 && !m_monitoring);
            GetDlgItem(IDC_MITM_ENABLE)->EnableWindow(TRUE);m_quic.EnableWindow(TRUE);m_save.EnableWindow(TRUE);m_defaults.EnableWindow(TRUE);
            if(m_enablePending && m_action==IProxyTlsControl::QueryCA && flags>=0 && !IsTrusted()) {Start(IProxyTlsControl::TrustCA);return;}
            const bool save=m_saveAfterTrust && IsTrusted();
            if(m_enablePending && !IsTrusted()) CheckDlgButton(m_pendingEnableId,BST_UNCHECKED);
            UpdateEnableHint();
            LayoutOptions();
            m_enablePending=m_saveAfterTrust=false;
            if (flags < 0) MessageBox(m_details, Localization::Get(L"mitm.ca"), MB_ICONERROR);
            else if(save) SaveOptions();
        }
        CModernDialog::OnTimer(id);
    }
    DECLARE_MESSAGE_MAP()
};
BEGIN_MESSAGE_MAP(CMitmCaDialog, CModernDialog)
    ON_WM_TIMER()
    ON_WM_CTLCOLOR()
END_MESSAGE_MAP()

IMPLEMENT_DYNAMIC(CPage4, CModernDialog)
CPage4::CPage4(CWnd* parent) : CModernDialog(IDD, parent), m_tls(nullptr), m_recording(false) {}
CPage4::~CPage4() { CompleteReconnect(false); }
void CPage4::DoDataExchange(CDataExchange* dx)
{
    CModernDialog::DoDataExchange(dx);
    DDX_Control(dx, IDC_CHECK1, m_monitor);
    DDX_Control(dx, IDC_BTN_CLEAR, m_clear);
    DDX_Control(dx, IDC_MITM_CA, m_options);
}
BOOL CPage4::OnInitDialog()
{
    CModernDialog::OnInitDialog();
    IGlobalProxy* proxy = GetGlobalProxyInstance();
    m_tls = proxy->GetTlsControl();
    ReleaseGlobalProxyInstance(); // Borrowed services outlive this proxy reference.
    // Restore display settings locally. StartMonitorJob applies the saved
    // protocol/TLS settings before starting capture; ordinary proxy startup
    // must not load the optional module just because the INI was customized.
    SetDlgItemText(IDC_MITM_CA, Localization::Get(L"monitor.options"));
    m_recordStatus.Create(L"",WS_CHILD|WS_VISIBLE|SS_LEFTNOWORDWRAP|SS_ENDELLIPSIS|SS_NOTIFY,CRect(),this,IDC_RECORDING_OPTIONS);
    m_recordStatus.SetFont(&m_uiFont);
    UiTheme::CreateUiFont(m_font, m_hWnd, 9, FW_NORMAL, _T("Consolas"));
    InitProtocolView(); ApplyMonitorSettings();
    m_tls->QueryProtocol(nlohmann::json{{"type","quic_injection_policy"},{"enabled",MitmSettings::DecryptQUIC()}}.dump().c_str(),nullptr,0);
    m_tls->SetEnabled(FALSE,nullptr,0); // A saved preference never enables interception before monitoring.
    SetMonitorControls(false); SetTimer(1, 100, NULL);
    CRect rect; GetClientRect(rect); LayoutControls(rect.Width(), rect.Height()); return TRUE;
}
BEGIN_MESSAGE_MAP(CPage4, CModernDialog)
    ON_MESSAGE(WM_APP+41, &CPage4::OnMonitorSettings)
    ON_WM_SIZE()
    ON_WM_SHOWWINDOW()
    ON_WM_TIMER()
    ON_BN_CLICKED(IDC_CHECK1, &CPage4::OnMonitor)
    ON_NOTIFY(TCN_SELCHANGE, IDC_PROTOCOL_VIEW_TABS, &CPage4::OnView)
    ON_EN_CHANGE(IDC_PROTOCOL_FILTER, &CPage4::OnFilter)
    ON_BN_CLICKED(IDC_PROTOCOL_FOLLOW, &CPage4::OnFollowLatest)
    ON_NOTIFY(LVN_ENDSCROLL, IDC_PROTOCOL_REQUESTS, &CPage4::OnListScrolled)
    ON_CBN_SELCHANGE(IDC_PROTOCOL_KIND, &CPage4::OnFilter)
    ON_NOTIFY(NM_CLICK, IDC_PROTOCOL_HEX, &CPage4::OnHexSelection)
    ON_NOTIFY(EN_SELCHANGE, IDC_PROTOCOL_DETAIL, &CPage4::OnRawSelection)
    ON_WM_LBUTTONDOWN()
    ON_WM_LBUTTONUP()
    ON_WM_MOUSEMOVE()
    ON_WM_SETCURSOR()
    ON_WM_CAPTURECHANGED()
    ON_BN_CLICKED(IDC_BTN_CLEAR, &CPage4::OnClear)
    ON_BN_CLICKED(IDC_MITM_CA, &CPage4::OnOptions)
    ON_BN_CLICKED(IDC_ARCHIVE_OPEN, &CPage4::OnOpenRecording)
    ON_BN_CLICKED(IDC_RECORDING_OPTIONS, &CPage4::OnRecordingOptions)
    ON_NOTIFY(LVN_ITEMCHANGED, IDC_PROTOCOL_REQUESTS, &CPage4::OnRequestSelected)
    ON_NOTIFY(LVN_GETINFOTIP, IDC_PROTOCOL_REQUESTS, &CPage4::OnRequestInfoTip)
    ON_NOTIFY(LVN_GETDISPINFO, IDC_PROTOCOL_REQUESTS, &CPage4::OnRequestDisplay)
    ON_NOTIFY(TCN_SELCHANGE, IDC_PROTOCOL_DETAIL_TABS, &CPage4::OnDetailTab)
END_MESSAGE_MAP()
void CPage4::OnSize(UINT type, int cx, int cy)
{
    CModernDialog::OnSize(type, cx, cy);
    CRect client; GetClientRect(client);
    LayoutControls(client.Width(), client.Height());
}
void CPage4::OnShowWindow(BOOL show, UINT status)
{
    CModernDialog::OnShowWindow(show, status);
    if (show) { InitProtocolColumns(); SetMonitorControls(m_job || m_stopJob); }
}
void CPage4::LayoutControls(int cx, int cy)
{
    // Shared layout helper: never call an MFC message handler from initialization.
    if (!m_monitor.GetSafeHwnd() || !m_openRecording.GetSafeHwnd()) return;
    auto s = [this](int v) { return UiTheme::ScaleForWindow(m_hWnd, v); };
    int width = max(0, cx - s(16)), top = s(44), h = s(28);
    // Size the single toolbar row to its localized labels, keeping actions right-aligned.
    auto labelWidth = [&](CWnd& control, int padding) {
        CClientDC dc(&control);
        CFont* old = dc.SelectObject(control.GetFont());
        CString text; control.GetWindowText(text);
        int result = dc.GetTextExtent(text).cx + s(padding);
        dc.SelectObject(old);
        return result;
    };
    const bool offline=IsViewingRecording();
    for(CWnd* control:{static_cast<CWnd*>(&m_monitor),static_cast<CWnd*>(&m_options),static_cast<CWnd*>(&m_clear),static_cast<CWnd*>(&m_recordStatus)})
        control->ShowWindow(offline?SW_HIDE:SW_SHOW);
    m_openRecording.ShowWindow(offline?SW_SHOW:SW_HIDE);
    m_recordingViewStatus.ShowWindow(offline || m_stopJob?SW_SHOW:SW_HIDE);
    int monitorWidth=labelWidth(m_monitor,56),caWidth=labelWidth(m_options,16);
    int clearWidth=max(s(48),labelWidth(m_clear,16)),gap=s(10);
    m_monitor.MoveWindow(s(8), top, monitorWidth, h);
    m_clear.MoveWindow(cx - s(8) - clearWidth, top, clearWidth, h);
    m_options.MoveWindow(cx - s(8) - clearWidth - gap - caWidth, top, caWidth, h);
    m_recordStatus.MoveWindow(s(8)+monitorWidth+gap,top+s(5),min(labelWidth(m_recordStatus,0),max(0,width-monitorWidth-caWidth-clearWidth-gap*3)),s(20));
    const int returnWidth=labelWidth(m_openRecording,16);
    m_openRecording.MoveWindow(s(8),top,returnWidth,h);
    if(offline) m_recordingViewStatus.MoveWindow(s(8)+returnWidth+gap,top+s(5),max(0,width-returnWidth-gap),s(22));
    GetDlgItem(IDC_STATIC_TASKCOUNT)->MoveWindow(max(s(160), cx - s(220)), s(10), min(s(212), max(0, cx - s(168))), s(20));
    top += s(36);
    if(!offline && m_stopJob) {m_recordingViewStatus.MoveWindow(s(8),top,width,s(22));top+=s(26);}
    LayoutProtocolView(s(8), top, width, max(0, cy - top - s(8)));
}
void CPage4::SetMonitorControls(bool busy)
{
    busy = busy || m_job || m_stopJob || IsViewingRecording();
    UpdateRecordingControls();
    m_clear.EnableWindow(!busy);
    m_options.EnableWindow(m_mitmSupported && !busy);m_monitor.EnableWindow(m_mitmSupported && !busy);
    if(!m_recording && !m_stopJob && m_recordStatus.GetSafeHwnd()) {
        m_keepRecordingRequested=RecordingSettings::Load().enabled;
        m_recordStatus.SetWindowText(Localization::Get(m_keepRecordingRequested?L"recording.enabled":L"recording.disabled"));
    }
    // While running, describe this run; edited preferences apply to the next start.
    const bool decrypt=m_recording ? m_tls->IsEnabled()!=FALSE : MitmSettings::DecryptHTTPS();
    bool quic=MitmSettings::DecryptQUIC();
    if(m_recording) {char out[512]={};if(m_tls->QueryProtocol("{\"type\":\"monitor_status\"}",out,sizeof(out))>0) {auto value=nlohmann::json::parse(out,nullptr,false);if(value.is_object())quic=value.value("quic",false);}}
    m_monitor.SetWindowText(Localization::Get(m_stopJob?L"monitor.stopping":busy && m_job ? L"monitor.preparing" :
        quic ? (decrypt?L"page4.monitor_both":L"page4.monitor_quic") : decrypt ? L"page4.monitor_decrypt" : L"page4.monitor"));
    CRect client;GetClientRect(client);LayoutControls(client.Width(),client.Height());
}
void CPage4::OnOptions() {
    if(!m_mitmSupported || m_job || m_stopJob || IsViewingRecording())return;
    CMenu menu;menu.CreatePopupMenu();
    menu.AppendMenu(MF_STRING,1,Localization::Get(L"mitm.ca"));
    menu.AppendMenu(MF_STRING,2,Localization::Get(L"recording.options"));
    menu.AppendMenu(MF_SEPARATOR);
    menu.AppendMenu(MF_STRING|(!m_openRecording.IsWindowEnabled()?MF_GRAYED:0),3,Localization::Get(L"recording.view_open"));
    menu.AppendMenu(MF_STRING,4,Localization::Get(L"recording.open_root"));
    CRect rect;m_options.GetWindowRect(rect);
    switch(menu.TrackPopupMenu(TPM_RETURNCMD|TPM_RIGHTALIGN|TPM_RIGHTBUTTON,rect.right,rect.bottom,this)) {
        case 1:OnCA();break;
        case 2:OnRecordingOptions();break;
        case 3:OnOpenRecording();break;
        case 4:{
            CString path=RecordingSettings::Load().directory;
            if((INT_PTR)ShellExecute(m_hWnd,L"open",path,nullptr,nullptr,SW_SHOWNORMAL)<=32) {
                CString message;message.Format(Localization::Get(L"recording.open_failed"),path.GetString());
                MessageBox(message,Localization::Get(L"recording.options"),MB_ICONERROR);
            }break;
        }
    }
}
void CPage4::OnCA() { OpenCA(false); }
void CPage4::OnRecordingOptions() {
    if(!m_mitmSupported || m_job || m_stopJob)return;
    bool active=false;char reply[8192]={};
    if(m_recording && m_tls->QueryProtocol("{\"type\":\"recording_status\"}",reply,sizeof(reply))>0) {
        auto state=nlohmann::json::parse(reply,nullptr,false);
        active=state.is_object() && state.value("enabled",false) && !state.value("ended",false) && !state.value("stopped",false);
    }
    CRecordingDialog dialog(this,m_recording,active);dialog.DoModal();
    m_keepRecordingRequested=RecordingSettings::Load().enabled;
    SetMonitorControls(false);
}
void CPage4::OpenCA(bool resumeStart)
{
    if (!m_mitmSupported || m_stopJob) return;
    CMitmCaDialog dialog(this, m_tls, m_recording, m_quicUdpWarning ? m_quicUdpWarning() : CString());
    const INT_PTR result=dialog.DoModal();
    ApplyMonitorSettings();
    SetMonitorControls(false);
    // This attempt requested decryption: changing the preference to off must
    // cancel it, never silently turn it into a plaintext-only monitoring start.
    if (resumeStart && result==IDOK && dialog.IsTrusted() && (MitmSettings::DecryptHTTPS() || MitmSettings::DecryptQUIC())) StartMonitoring();
    else if (resumeStart) {m_monitor.SetCheck(BST_UNCHECKED);CompleteReconnect(false);}
}
bool CPage4::PrepareReconnect(bool decrypt)
{
    CompleteReconnect(false);
    if (!decrypt) return true;
    auto manager = g_GlobalProxy ? g_GlobalProxy->GetPRCInstance()->GetPTMInstance(0) : nullptr;
    if (!manager) return true;
    DWORD count = manager->PrepareReconnect(decrypt ? TRUE : FALSE);
    m_reconnectPrepared = true;
    if (!count) return true;
    CString title = Localization::Get(L"page4.monitor");
    CString message = Localization::Format(L"mitm.reconnect", count);
    const int result = MessageBox(message, title, MB_YESNOCANCEL | MB_ICONQUESTION | MB_DEFBUTTON2);
    m_reconnectAccepted = result == IDYES;
    if (result != IDYES && result != IDNO) { CompleteReconnect(false); return false; }
    return true;
}
void CPage4::CompleteReconnect(bool commit)
{
    if (m_reconnectPrepared && g_GlobalProxy) {
        auto manager = g_GlobalProxy->GetPRCInstance()->GetPTMInstance(0);
        if (manager) manager->CompleteReconnect(commit && m_reconnectAccepted);
    }
    m_reconnectPrepared = m_reconnectAccepted = false;
}
void CPage4::StartMonitoring()
{
    if (!m_mitmSupported || m_job || m_stopJob || IsViewingRecording()) return;
    m_keepRecordingRequested=RecordingSettings::Load().enabled;
    m_job = StartMonitorJob(m_tls,MitmSettings::DecryptHTTPS());
    SetMonitorControls(true);
}
void CPage4::UpdateMonitorStatus(bool offerRecordingDirectory)
{
    if (!m_monitor.GetSafeHwnd()) return;
    if (!m_mitmSupported) {m_monitor.SetCheck(BST_UNCHECKED);return;}
    if (m_stopJob || m_job) return;
    if(m_monitor.GetCheck()==BST_CHECKED) { if(!m_recording) StartMonitoring();return; }
    auto job = std::make_shared<MitmJob>();
    try {
        auto tls = m_tls;
        std::thread([job, tls, offerRecordingDirectory]() {
            job->result=tls->QueryProtocol("{\"type\":\"monitor_stop\"}",job->text,sizeof(job->text));
            if(job->result>=0 && offerRecordingDirectory) {
                // Stop drains the recording writer first. Query this run, never LastDirectory.
                try {
                    char reply[8192]={};const int n=tls->QueryProtocol("{\"type\":\"recording_status\"}",reply,sizeof(reply));
                    auto status=nlohmann::json::parse(reply,nullptr,false);
                    if(n>0 && n<=sizeof(reply) && status.is_object() && status.value("enabled",false) &&
                        status.value("ended",false) && status.value("has_data",false))
                        job->recordingDirectory=status.value("directory",std::string());
                } catch (...) {} // An optional folder offer must not turn a successful stop into a failure.
            }
            job->done.store(true);
        }).detach();
    } catch (...) {
        m_monitor.SetCheck(m_recording ? BST_CHECKED:BST_UNCHECKED);
        MessageBox(L"Unable to start monitor stop worker.",Localization::Get(L"mitm.ca"),MB_ICONERROR);return;
    }
    m_stopJob=job;m_recording=false;m_stopStarted=GetTickCount();m_stopStatusPoll=0;
    m_recordStatus.SetWindowText(Localization::Get(m_retainedRecording?L"recording.finishing":L"recording.disabled"));
    SetMonitorControls(true);UpdateStopStatus();
    if(GetParent()) GetParent()->Invalidate(FALSE);
}
void CPage4::OnMonitor()
{
    if (!m_mitmSupported) {m_monitor.SetCheck(BST_UNCHECKED);return;}
    if(m_job || m_stopJob || IsViewingRecording()) return;
    if(!m_recording && m_monitor.GetCheck()==BST_CHECKED && !PrepareReconnect(MitmSettings::DecryptHTTPS())) {
        m_monitor.SetCheck(BST_UNCHECKED);return;
    }
    UpdateMonitorStatus(true);
}

void CPage4::OnClear() { if(!IsViewingRecording()) ClearProtocolView(); }
void CPage4::UpdateStopStatus() {
    if(!m_stopJob) return;
    const DWORD now=GetTickCount();if(m_stopStatusPoll && now-m_stopStatusPoll<250)return;
    m_stopStatusPoll=now;
    LPCTSTR key=L"monitor.stop_wait";
    char reply[2048]={};const int n=m_tls->QueryProtocol("{\"type\":\"monitor_stop_status\"}",reply,sizeof(reply));
    if(n>0 && n<=sizeof(reply)) {
        auto value=nlohmann::json::parse(reply,nullptr,false);
        if(value.is_object() && value.value("active",false)) {
            const auto phase=value.value("phase",std::string());
            if(phase=="analysis")key=L"monitor.stop_analysis";
            else if(phase=="writing")key=L"monitor.stop_writing";
            else if(phase=="finalizing")key=L"monitor.stop_finalizing";
        }
    }
    CString text;text.Format(Localization::Get(L"monitor.stop_progress"),Localization::Get(key).GetString(),(now-m_stopStarted)/1000.0);
    m_recordingViewStatus.SetWindowText(text);
    if(m_detailTooltip.GetSafeHwnd())m_detailTooltip.UpdateTipText(text,&m_recordingViewStatus);
    UpdateDetailTooltip();
}
void CPage4::OnTimer(UINT_PTR id)
{
    UpdateStopStatus();
    TickProtocolView();
    if (m_stopJob && m_stopJob->done.load()) {
        auto job = m_stopJob; m_stopJob.reset();
        SetMonitorControls(false);
        if (job->result < 0 && !job->failureReported) MessageBox(Utf8(job->text), Localization::Get(L"page4.title"), MB_ICONERROR);
        else if(!job->recordingDirectory.empty()) {
            CString path=Utf8(job->recordingDirectory.c_str());
            if(path.Left(8)==L"\\\\?\\UNC\\")path=L"\\\\"+path.Mid(8);
            else if(path.Left(4)==L"\\\\?\\")path=path.Mid(4);
            CString message;message.Format(Localization::Get(L"recording.finished_open"),path.GetString());
            if(MessageBox(message,Localization::Get(L"recording.options"),MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)==IDYES &&
                (INT_PTR)ShellExecute(m_hWnd,L"open",path,nullptr,nullptr,SW_SHOWNORMAL)<=32) {
                message.Format(Localization::Get(L"recording.open_failed"),path.GetString());
                MessageBox(message,Localization::Get(L"recording.options"),MB_ICONERROR);
            }
        }
    }
    if (m_job && m_job->done.load()) {
        auto job=std::move(m_job);SetMonitorControls(false);
        if(job->needsCA) {m_monitor.SetCheck(BST_UNCHECKED);OpenCA(true);}
        else if(job->result<0) {
            m_monitor.SetCheck(BST_UNCHECKED);m_recording=false;CompleteReconnect(false);
            MessageBox(MonitorStartError(job->text),Localization::Get(L"page4.monitor"),MB_ICONERROR);
        } else {
            m_recording=true;m_retainedRecording=false;m_recordingGapNotified=false;m_monitor.SetCheck(BST_CHECKED);CompleteReconnect(true);
            char reply[8192]={};int n=m_tls->QueryProtocol("{\"type\":\"recording_status\"}",reply,sizeof(reply));
            if(n>0 && n<=sizeof(reply)) {auto value=nlohmann::json::parse(reply,nullptr,false);
                if(value.is_object() && value.value("enabled",false)) {
                    m_retainedRecording=true;
                    CString directory=Utf8(value.value("directory",std::string()).c_str());
                    WritePrivateProfileStringW(L"recording",L"LastDirectory",directory,Localization::SettingsPath());
                    m_recordStatus.SetWindowText(Localization::Get(L"recording.active"));
                }
            }
            SetMonitorControls(false);
            if(GetParent()) GetParent()->Invalidate(FALSE);
        }
    }
    if(m_recording && !m_job && !m_stopJob) {
        char reply[8192]={};int n=m_tls->QueryProtocol("{\"type\":\"recording_status\"}",reply,sizeof(reply));
        if(n>0 && n<=sizeof(reply)) {auto value=nlohmann::json::parse(reply,nullptr,false);
            if(value.is_object()) {
                m_retainedRecording=value.value("enabled",false);
                bool active=value.value("enabled",false) && !value.value("ended",false) && !value.value("stopped",false);
                auto quality=value.value("quality",nlohmann::json::object());
                bool incomplete=quality.value("capture_incomplete",false);
                bool deferred=quality.value("analysis_deferred_count",uint64_t(0))!=0;
                CString caption=Localization::Get(active?(incomplete?L"recording.active_incomplete":deferred?L"recording.active_deferred":L"recording.active"):m_keepRecordingRequested?L"recording.pending":L"recording.disabled");
                CString current;m_recordStatus.GetWindowText(current);
                if(current!=caption) {m_recordStatus.SetWindowText(caption);CRect client;GetClientRect(client);LayoutControls(client.Width(),client.Height());}
                if(active && incomplete && !m_recordingGapNotified) {
                    m_recordingGapNotified=true;
                    MessageBox(Localization::Get(L"recording.gap_warning"),Localization::Get(L"recording.options"),MB_ICONWARNING);
                }
            }
            if(value.is_object() && value.value("stopped",false)) {
                // The host watchdog already stops interception without touching active sockets.
                m_monitor.SetCheck(BST_UNCHECKED);UpdateMonitorStatus();
                if(m_stopJob) m_stopJob->failureReported=true;
                CString reason=Utf8(value.value("reason",std::string("Recording stopped")).c_str());
                CString directory=Utf8(value.value("directory",std::string()).c_str());
                MessageBox(Localization::Get(L"recording.stopped")+L"\r\n\r\n"+reason+L"\r\n\r\n"+directory,
                    Localization::Get(value.value("enabled",false)?L"recording.options":L"page4.title"),MB_ICONWARNING);
            }
        }
    }
    if(!m_recording && !m_stopJob && m_recordStatus.GetSafeHwnd()) {
        CString current;m_recordStatus.GetWindowText(current);CString caption=Localization::Get(m_keepRecordingRequested?L"recording.enabled":L"recording.disabled");
        if(current!=caption) {m_recordStatus.SetWindowText(caption);CRect client;GetClientRect(client);LayoutControls(client.Width(),client.Height());}
    }
    if(m_detailTooltip.GetSafeHwnd() && m_recordStatus.GetSafeHwnd()) {
        CString text;m_recordStatus.GetWindowText(text);m_detailTooltip.UpdateTipText(text,&m_recordStatus);
    }
    DWORD tcp = 0, udp = 0;
    if (g_GlobalProxy) {
        auto prc = g_GlobalProxy->GetPRCInstance();
        if (prc->GetPTMInstance(0)) prc->GetPTMInstance(0)->GetTaskCount(&tcp);
        if (prc->GetPTMInstance(1)) prc->GetPTMInstance(1)->GetTaskCount(&udp);
    }
    CString status = Localization::Format(_T("page4.connections"), tcp, udp);
    CString current; GetDlgItemText(IDC_STATIC_TASKCOUNT, current);
    if (status != current) SetDlgItemText(IDC_STATIC_TASKCOUNT, status);
    CModernDialog::OnTimer(id);
}
