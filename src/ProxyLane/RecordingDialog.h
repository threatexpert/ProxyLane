#pragma once
#include "RecordingSettings.h"
#include <shlobj.h>

class CRecordingDialog : public CModernDialog {
    CModernButton m_save,m_cancel,m_browse,m_open;
    bool m_running,m_active;
    RecordingSettings::Values m_saved;
    void UpdateHint() {
        if(!m_running)return;
        const bool requested=IsDlgButtonChecked(IDC_RECORDING_ENABLE)==BST_CHECKED;
        SetDlgItemText(IDC_RECORDING_HINT,Localization::Get(m_active ?
            (requested?L"recording.running_hint":L"recording.stop_hint") :
            (requested?L"recording.restart_hint":L"recording.inactive_hint")));
    }
public:
    CRecordingDialog(CWnd* parent,bool running,bool active=false):CModernDialog(IDD_RECORDING_OPTIONS,parent),m_running(running),m_active(active){}
protected:
    BOOL OnInitDialog() override {
        CModernDialog::OnInitDialog();SetWindowText(Localization::Get(L"recording.options"));
        const std::pair<UINT,LPCWSTR> labels[]={
            {IDC_RECORDING_ENABLE,L"recording.enable"},{IDC_RECORDING_DIR_LABEL,L"recording.directory"},
            {IDC_RECORDING_CAP_LABEL,L"recording.capacity"},{IDC_RECORDING_FREE_LABEL,L"recording.reserve"},
            {IDC_RECORDING_HINT,L"recording.hint"},{IDC_RECORDING_OPEN,L"recording.open"},
            {IDOK,L"mitm.save"},{IDCANCEL,L"mitm.close"}};
        for(const auto& p:labels)SetDlgItemText(p.first,Localization::Get(p.second));
        auto v=RecordingSettings::Load();m_saved=v;CheckDlgButton(IDC_RECORDING_ENABLE,v.enabled?BST_CHECKED:BST_UNCHECKED);
        SetDlgItemText(IDC_RECORDING_DIRECTORY,v.directory);SetDlgItemInt(IDC_RECORDING_CAPACITY,v.capacityMiB);
        SetDlgItemInt(IDC_RECORDING_RESERVE,v.reserveMiB);
        m_save.SubclassDlgItem(IDOK,this);m_cancel.SubclassDlgItem(IDCANCEL,this);
        m_browse.SubclassDlgItem(IDC_RECORDING_BROWSE,this);m_open.SubclassDlgItem(IDC_RECORDING_OPEN,this);
        UpdateHint();
        return TRUE;
    }
    void OnOK() override {
        auto v=RecordingSettings::Load();v.enabled=IsDlgButtonChecked(IDC_RECORDING_ENABLE)==BST_CHECKED;
        GetDlgItemText(IDC_RECORDING_DIRECTORY,v.directory);v.directory.Trim();
        BOOL a=FALSE,b=FALSE;v.capacityMiB=GetDlgItemInt(IDC_RECORDING_CAPACITY,&a,FALSE);v.reserveMiB=GetDlgItemInt(IDC_RECORDING_RESERVE,&b,FALSE);
        bool absolute=v.directory.GetLength()>2 && ((v.directory[1]==L':' && (v.directory[2]==L'\\'||v.directory[2]==L'/')) || v.directory.Left(2)==L"\\\\");
        if(!a||!b||v.capacityMiB<16||v.capacityMiB>1048576||v.reserveMiB<16||v.reserveMiB>1048576||
            (v.enabled && (!absolute||RecordingSettings::Utf8(v.directory).size()>2048)) || v.directory.FindOneOf(L"\r\n")>=0) {
            MessageBox(Localization::Get(L"recording.invalid"),Localization::Get(L"recording.options"),MB_ICONWARNING);return;
        }
        if(!RecordingSettings::Save(v)) {MessageBox(Localization::Get(L"mitm.save_failed"),Localization::Get(L"recording.options"),MB_ICONERROR);return;}
        if(m_running && RecordingSettings::Json(v)!=RecordingSettings::Json(m_saved))
            MessageBox(Localization::Get(v.enabled&&!m_active?L"recording.restart_hint":L"recording.saved_restart"),Localization::Get(L"recording.options"),MB_ICONINFORMATION);
        EndDialog(IDOK);
    }
    void OnCancel() override {EndDialog(IDCANCEL);}
    BOOL OnCommand(WPARAM wp,LPARAM lp) override {
        if(LOWORD(wp)==IDC_RECORDING_ENABLE && HIWORD(wp)==BN_CLICKED) {UpdateHint();return TRUE;}
        if(LOWORD(wp)==IDC_RECORDING_BROWSE) {
            BROWSEINFO info={};info.hwndOwner=m_hWnd;CString title=Localization::Get(L"recording.directory");info.lpszTitle=title;
            info.ulFlags=BIF_RETURNONLYFSDIRS|BIF_NEWDIALOGSTYLE;
            auto item=SHBrowseForFolder(&info);if(item) {wchar_t path[MAX_PATH]={};if(SHGetPathFromIDList(item,path))SetDlgItemText(IDC_RECORDING_DIRECTORY,path);CoTaskMemFree(item);}return TRUE;
        }
        if(LOWORD(wp)==IDC_RECORDING_OPEN) {
            CString path=RecordingSettings::ReadPath(L"LastDirectory");if(path.IsEmpty())path=RecordingSettings::Load().directory;
            if(path.Left(8)==L"\\\\?\\UNC\\")path=L"\\\\"+path.Mid(8);
            else if(path.Left(4)==L"\\\\?\\")path=path.Mid(4);
            if((INT_PTR)ShellExecute(m_hWnd,L"open",path,nullptr,nullptr,SW_SHOWNORMAL)<=32)
                MessageBox(Localization::Get(L"recording.no_directory"),Localization::Get(L"recording.options"),MB_ICONINFORMATION);
            return TRUE;
        }
        return CModernDialog::OnCommand(wp,lp);
    }
};
