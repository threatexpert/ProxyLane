#pragma once
#include "ModernUI.h"
#include "Localization.h"
#include "SshProfile.h"
#include "SshKeyStore.h"
#include <afxdlgs.h>

// Shared compact authentication row for the profile page and node editor.
class CSshAuthControls {
public:
    enum { LabelId = 0x2410, AuthId, KeyLabelId, ImportId };
    void Create(CWnd* parent, CFont* font) {
        m_parent = parent;
        m_label.Create(Localization::Get(L"ssh.auth"), WS_CHILD | SS_NOPREFIX, CRect(), parent, LabelId);
        m_auth.Create(WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, CRect(), parent, AuthId);
        m_auth.AddString(Localization::Get(L"ssh.auth_password"));
        m_auth.AddString(Localization::Get(L"ssh.auth_key")); m_auth.SetCurSel(0);
        m_keyLabel.Create(Localization::Get(L"ssh.private_key"), WS_CHILD | SS_NOPREFIX, CRect(), parent, KeyLabelId);
        m_import.Create(L"", WS_CHILD | WS_TABSTOP | BS_OWNERDRAW, CRect(), parent, ImportId);
        for (CWnd* control : { (CWnd*)&m_label, (CWnd*)&m_auth, (CWnd*)&m_keyLabel, (CWnd*)&m_import }) control->SetFont(font);
        Caption();
    }
    void OrderAfter(CWnd* previous) {
        for (CWnd* control : { (CWnd*)&m_label, (CWnd*)&m_auth, (CWnd*)&m_keyLabel, (CWnd*)&m_import }) {
            control->SetWindowPos(previous,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE);
            previous = control;
        }
    }
    bool IsKey() const { return m_auth.GetSafeHwnd() && m_auth.GetCurSel() == 1; }
    void Load(const ProxyInfo* info) {
        m_auth.SetCurSel(info && info->sshAuth == 1 ? 1 : 0);
        m_key = info && info->sshAuth == 1 ? SshKeyStore::Reference(info->strSshKeyFile.szbuf) : CString();
        Caption();
    }
    bool Apply(ProxyInfo& info) const {
        info.sshAuth = IsKey() ? 1 : 0;
        SecureZeroMemory(info.strSshKeyFile.szbuf, sizeof(info.strSshKeyFile.szbuf));
        info.strSshKeyDigest.szbuf[0] = 0;
        return !IsKey() || (SshKeyStore::ValidReference(m_key) && SshProfile::Encode(SshKeyStore::Path(m_key), info.strSshKeyFile.szbuf));
    }
    bool Import() {
        CFileDialog dialog(TRUE, NULL, NULL, OFN_FILEMUSTEXIST | OFN_HIDEREADONLY,
            L"Private key files (*.pem;*.key)|*.pem;*.key|All files (*.*)|*.*||", m_parent);
        if (dialog.DoModal() != IDOK) return false;
        CFile file; CFileException error;
        if (!file.Open(dialog.GetPathName(), CFile::modeRead | CFile::shareDenyWrite, &error)) {
            m_parent->MessageBox(Localization::Get(L"ssh.key_read_failed"), Localization::Get(L"ssh.private_key"), MB_ICONERROR);
            return false;
        }
        std::string key;
        bool read = false;
        try {
            const ULONGLONG size = file.GetLength();
            if (size > 0 && size < SshPrivateKey::Capacity) {
                key.resize(static_cast<size_t>(size));
                read = file.Read(&key[0], static_cast<UINT>(size)) == size;
            }
        } catch (CFileException* e) { e->Delete(); }
        const bool supported = read && SshPrivateKey::Supported(key);
        CString reference;
        const bool saved = supported && SshKeyStore::Import(key, reference);
        if (!key.empty()) SecureZeroMemory(&key[0], key.size());
        if (!supported) {
            m_parent->MessageBox(Localization::Get(L"ssh.key_format"), Localization::Get(L"ssh.private_key"), MB_ICONERROR);
            return false;
        }
        if (!saved) {
            m_parent->MessageBox(Localization::Get(L"ssh.key_write_failed"), Localization::Get(L"ssh.private_key"), MB_ICONERROR);
            return false;
        }
        m_key = reference;
        Caption(); return true;
    }
    void Show(bool show) {
        if (!m_auth.GetSafeHwnd()) return;
        m_label.ShowWindow(show ? SW_SHOW : SW_HIDE); m_auth.ShowWindow(show ? SW_SHOW : SW_HIDE);
        m_keyLabel.ShowWindow(show && IsKey() ? SW_SHOW : SW_HIDE); m_import.ShowWindow(show && IsKey() ? SW_SHOW : SW_HIDE);
    }
    void Enable(bool enabled) { m_auth.EnableWindow(enabled); m_import.EnableWindow(enabled); }
    void Layout(int x, int y, int width, int gap, int labelH, int fieldH) {
        const int half = (width-gap)/2;
        const int spacing = UiTheme::ScaleForWindow(m_parent->m_hWnd, 2);
        m_label.MoveWindow(x,y,half,labelH); m_auth.MoveWindow(x,y+labelH+spacing,half,fieldH+UiTheme::ScaleForWindow(m_parent->m_hWnd,160));
        m_keyLabel.MoveWindow(x+half+gap,y,half,labelH); m_import.MoveWindow(x+half+gap,y+labelH+spacing,half,fieldH);
    }
private:
    void Caption() { m_import.SetWindowText(Localization::Get(m_key.IsEmpty() ? L"ssh.import_key" : L"ssh.replace_key")); }
    CWnd* m_parent = NULL;
    CStatic m_label, m_keyLabel;
    CSoftCombo m_auth;
    CModernButton m_import;
    CString m_key;
};
