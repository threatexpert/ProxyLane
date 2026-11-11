#pragma once
#include "ModernUI.h"
#include "Localization.h"
#include "ProxyProfileStore.h"
#include "ConfigStorage.h"
#include "SshProfile.h"
#include "SshAuthControls.h"
#include "resource.h"
#include "ProxyTestResultDialog.h"
#include "ProxyTestError.h"
#include "../ProxyLaneHook/ProxyTransportPolicy.h"
#include "../ProxyLaneHook/PlatformSupport.h"

// Edit the saved server in place, keeping the chain page and its draft intact.
class CChainNodeEditDialog : public CModernDialog, public IProxyTesterCallback
{
public:
    CChainNodeEditDialog(CProxyProfileStore& store, CIniFile& ini, const CfgProxyItem& item, CWnd* parent)
        : CModernDialog(IDD_CHAIN_NODE_EDIT, parent), m_store(store), m_ini(ini), m_item(item) {}
    ~CChainNodeEditDialog() override { StopTest(); if (m_proxy) ReleaseGlobalProxyInstance(); }
    const CfgProxyItem& Profile() const { return m_item; }
protected:
    BOOL OnInitDialog() override
    {
        CModernDialog::OnInitDialog();
        SetWindowText(Localization::Format(L"chain.edit.title", (LPCTSTR)m_item.strName));
        const CRect empty(0, 0, 0, 0);
        const DWORD child = WS_CHILD | WS_VISIBLE;
        m_notice.Create(Localization::Get(L"chain.edit.shared"), child | SS_NOPREFIX, empty, this, 1320);
        const LPCTSTR keys[] = { L"common.type", L"common.transport", L"common.host", L"common.port",
            L"common.username", L"common.password", L"common.psk" };
        for (int i = 0; i < 7; ++i)
            m_labels[i].Create(Localization::Get(keys[i]), child | SS_NOPREFIX, empty, this, 1311 + i);
        const DWORD combo = child | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL;
        m_type.Create(combo, empty, this, 1301);
        for (LPCTSTR type : { L"SOCKS5", L"HTTP", L"SSH" }) m_type.AddString(type);
        m_transport.Create(combo, empty, this, 1302);
        m_transport.AddString(Localization::Get(L"transport.plain"));
        m_transport.AddString(Localization::Get(L"transport.gonc_tls_psk"));
        CSoftEdit* fields[] = { &m_host, &m_port, &m_user, &m_password, &m_key };
        for (int i = 0; i < 5; ++i)
            fields[i]->Create(child | WS_TABSTOP | ES_AUTOHSCROLL | (i == 3 ? ES_PASSWORD : 0), empty, this, 1303 + i);
        m_error.Create(L"", child | SS_OWNERDRAW, empty, this, 1308);
        m_error.SetInlineStyle(TRUE);
        m_error.ShowWindow(SW_HIDE);
        m_test.Create(Localization::Get(L"chain.edit.test_node"), child | WS_TABSTOP | BS_OWNERDRAW, empty, this, 1309);
        m_save.Create(Localization::Get(L"common.save_profile"), child | WS_TABSTOP | BS_OWNERDRAW, empty, this, IDOK);
        m_save.SetVisualStyle(CModernButton::STYLE_PRIMARY);
        m_cancel.Create(Localization::Get(L"apps.cancel"), child | WS_TABSTOP | BS_OWNERDRAW, empty, this, IDCANCEL);
        m_sshAuth.Create(this, &m_uiFont);
        m_sshAuth.OrderAfter(&m_port);
        m_sshAuth.Load(&m_item.pi);
        UiTheme::ApplyFontToChildren(this, &m_uiFont);

        const int type = m_item.pi.GetProxyType();
        m_ssh = type == PROXYTYPE_SSH;
        m_type.SetCurSel(m_ssh ? 2 : type == PROXYTYPE_SOCKS5 ? 0 : 1);
        m_transport.SetCurSel(m_item.nTransportMode == PROXY_TRANSPORT_GONC_TLS_PSK ? 1 : 0);
        m_host.SetWindowText((CString)m_item.pi.strProxyHost);
        CString port; port.Format(L"%d", m_item.pi.nProxyPort); m_port.SetWindowText(port);
        m_user.SetWindowText(m_ssh ? SshProfile::Decode(m_item.pi.strProxyUser.szbuf) : (CString)m_item.pi.strProxyUser);
        m_password.SetWindowText(m_ssh ? SshProfile::Decode(m_item.pi.strProxyPass.szbuf) : (CString)m_item.pi.strProxyPass);
        m_key.SetWindowText(m_item.strTransportPsk);
        m_password.SetPasswordChar(L'\x25cf');
        m_ready = true;
        UpdateFields();
        SetDefID(IDOK); m_host.SetFocus();
        return FALSE;
    }
    BOOL UsesSecondaryText(UINT id) const override
    {
        return id == CSshAuthControls::LabelId || id == CSshAuthControls::KeyLabelId || id == 1320 || (id >= 1311 && id <= 1317) || CModernDialog::UsesSecondaryText(id);
    }
    BOOL OnCommand(WPARAM wParam, LPARAM lParam) override
    {
        if (LOWORD(wParam) == 1309 && HIWORD(wParam) == BN_CLICKED) { TestConnection(); return TRUE; }
        if (m_testing && LOWORD(wParam) == CSshAuthControls::ImportId) return TRUE;
        if (m_testing && (HIWORD(wParam) == CBN_SELCHANGE || HIWORD(wParam) == EN_CHANGE)) return TRUE;
        if (m_ready && LOWORD(wParam) == CSshAuthControls::ImportId && HIWORD(wParam) == BN_CLICKED) {
            if (m_sshAuth.Import()) { m_error.ShowWindow(SW_HIDE); } return TRUE;
        }
        if (m_ready && LOWORD(wParam) == CSshAuthControls::AuthId && HIWORD(wParam) == CBN_SELCHANGE) {
            m_password.SetWindowText(L""); UpdateFields(); return TRUE;
        }
        if (m_ready && HIWORD(wParam) == CBN_SELCHANGE && (LOWORD(wParam) == 1301 || LOWORD(wParam) == 1302))
        {
            const bool ssh = m_type.GetCurSel() == 2;
            if (ssh != m_ssh) {
                m_key.SetWindowText(L"");
                if (m_sshAuth.IsKey()) m_password.SetWindowText(L"");
                m_sshAuth.Load(NULL);
            } // A PSK is never an SSH host-key pin.
            m_ssh = ssh;
            UpdateFields();
            m_error.SetStatus(L"", CStatusLabel::TONE_NEUTRAL);
            m_error.ShowWindow(SW_HIDE);
            return TRUE;
        }
        if (m_ready && HIWORD(wParam) == EN_CHANGE)
        {
            m_error.SetStatus(L"", CStatusLabel::TONE_NEUTRAL);
            m_error.ShowWindow(SW_HIDE);
        }
        return CModernDialog::OnCommand(wParam, lParam);
    }
    bool ReadFields(CfgProxyItem& edited)
    {
        edited = m_item;
        CString host, port, user, password, key, type;
        m_host.GetWindowText(host); host.Trim();
        m_port.GetWindowText(port); port.Trim();
        m_user.GetWindowText(user); m_password.GetWindowText(password); m_key.GetWindowText(key);
        if (host.GetLength() > 2 && host[0] == L'[' && host[host.GetLength() - 1] == L']')
            host = host.Mid(1, host.GetLength() - 2);
        if (host.IsEmpty() || host.FindOneOf(L" \t\r\n") >= 0 || CStringA(host).GetLength() >= (int)sizeof(edited.pi.strProxyHost.szbuf))
        { Invalid(L"profile.invalid_endpoint", m_host); return false; }
        if (port.IsEmpty() || port.GetLength() > 5 || port.SpanIncluding(L"0123456789") != port || _ttoi(port) < 1 || _ttoi(port) > 65535)
        { Invalid(L"profile.invalid_endpoint", m_port); return false; }
        if (m_type.GetCurSel() < 0) { Invalid(L"profile.unsupported_type", m_type); return false; }
        m_type.GetLBText(m_type.GetCurSel(), type);
        edited.pi.strProxyType = type;
        edited.pi.strProxyHost = host; edited.pi.nProxyPort = _ttoi(port);
        edited.nTransportMode = m_ssh ? PROXY_TRANSPORT_PLAIN : m_transport.GetCurSel() == 1
            ? PROXY_TRANSPORT_GONC_TLS_PSK : PROXY_TRANSPORT_PLAIN;
        if (m_ssh)
        {
            key.Trim();
            if (!m_sshAuth.Apply(edited.pi)) { Invalid(L"ssh.key_required", *GetDlgItem(CSshAuthControls::ImportId)); return false; }
            if (user.IsEmpty() || !SshProfile::Encode(user, edited.pi.strProxyUser.szbuf))
            { Invalid(L"profile.ssh_invalid", m_user); return false; }
            if (!SshProfile::Encode(password, edited.pi.strProxyPass.szbuf))
            { Invalid(L"profile.ssh_invalid", m_password); return false; }
            if (!SshProfile::ValidFingerprint(key)) { Invalid(L"profile.ssh_invalid", m_key); return false; }
        }
        else
        {
            if (CStringA(user).GetLength() >= (int)sizeof(edited.pi.strProxyUser.szbuf))
            { Invalid(L"chain.edit.field_too_long", m_user); return false; }
            if (CStringA(password).GetLength() >= (int)sizeof(edited.pi.strProxyPass.szbuf))
            { Invalid(L"chain.edit.field_too_long", m_password); return false; }
            edited.pi.strProxyUser = user; edited.pi.strProxyPass = password;
            edited.pi.sshAuth = 0; SecureZeroMemory(edited.pi.strSshKeyFile.szbuf, sizeof(edited.pi.strSshKeyFile.szbuf));
        }
        if (edited.nTransportMode == PROXY_TRANSPORT_GONC_TLS_PSK)
        {
            if (!ProxySupportsOptionalModules()) { Invalid(L"profile.secure_transport_unavailable", m_transport); return false; }
            if (key.IsEmpty()) { Invalid(L"profile.psk_required", m_key); return false; }
        }
        SecureZeroMemory(edited.pi.strTransportPsk.szbuf, sizeof(edited.pi.strTransportPsk.szbuf));
        if ((m_ssh || edited.nTransportMode == PROXY_TRANSPORT_GONC_TLS_PSK) &&
            !SshProfile::Encode(key, edited.pi.strTransportPsk.szbuf))
        { Invalid(L"chain.edit.field_too_long", m_key); return false; }
        edited.strTransportPsk = key;
        edited.pi.reserved = edited.nTransportMode;
        return true;
    }
    void OnOK() override
    {
        if (m_testing) return;
        CfgProxyItem edited;
        if (!ReadFields(edited)) return;
        if (!m_store.SaveConnection(edited))
        {
            m_error.SetStatus(Localization::Format(L"chain.edit.save_failed", (LPCTSTR)ConfigStorage::ErrorText(GetLastError())), CStatusLabel::TONE_DANGER);
            m_error.ShowWindow(SW_SHOW);
            return;
        }
        m_item = edited;
        EndDialog(IDOK);
    }
    void OnCancel() override { StopTest(); EndDialog(IDCANCEL); }
    LRESULT WindowProc(UINT message, WPARAM wParam, LPARAM lParam) override
    {
        if (message == WM_APP + 51) { if (m_testing && wParam == m_testGeneration) FinishPhase(); return 0; }
        if (message == WM_DESTROY) StopTest();
        const LRESULT result = CModernDialog::WindowProc(message, wParam, lParam);
        if (message == WM_SIZE && m_ready) Layout();
        return result;
    }
private:
    int S(int value) const { return UiTheme::ScaleForWindow(m_hWnd, value); }
    void Invalid(LPCTSTR key, CWnd& field)
    {
        m_error.SetStatus(Localization::Get(key), CStatusLabel::TONE_DANGER);
        m_error.ShowWindow(SW_SHOW);
        field.SetFocus();
    }
    void UpdateFields()
    {
        if (m_ssh) m_transport.SetCurSel(0);
        m_sshAuth.Show(m_ssh);
        m_labels[5].SetWindowText(Localization::Get(m_ssh && m_sshAuth.IsKey() ? L"ssh.passphrase" : L"common.password"));
        m_transport.EnableWindow(!m_ssh && ProxySupportsOptionalModules());
        m_showKey = m_ssh || m_transport.GetCurSel() == 1;
        m_key.ShowWindow(m_showKey ? SW_SHOW : SW_HIDE);
        m_labels[6].ShowWindow(m_showKey ? SW_SHOW : SW_HIDE);
        m_labels[6].SetWindowText(Localization::Get(m_ssh ? L"ssh.host_key" : L"common.psk"));
        m_key.SetPasswordChar(m_ssh ? 0 : L'\x25cf'); m_key.Invalidate();
        CRect frame(0, 0, 0, 0), owner;
        AdjustWindowRectEx(&frame, GetStyle(), FALSE, GetExStyle());
        GetParent()->GetTopLevelParent()->GetWindowRect(&owner);
        MONITORINFO monitor = {sizeof(monitor)};
        if (!GetMonitorInfo(MonitorFromRect(&owner, MONITOR_DEFAULTTONEAREST), &monitor))
            SystemParametersInfo(SPI_GETWORKAREA, 0, &monitor.rcWork, 0);
        const CRect work(monitor.rcWork);
        const int width = min(S(460) + frame.Width(), work.Width() - S(24));
        const int height = S((m_showKey ? 346 : 290) + (m_ssh ? 56 : 0)) + frame.Height();
        SetWindowPos(NULL, max(work.left, min(owner.CenterPoint().x-width/2, work.right-width)),
            max(work.top, min(owner.CenterPoint().y-height/2, work.bottom-height)), width, height, SWP_NOZORDER);
        Layout();
    }
    void Layout()
    {
        CRect area; GetClientRect(&area);
        const int left = S(16), gap = S(12), width = area.Width()-2*left, half = (width-gap)/2;
        m_notice.MoveWindow(left, S(12), width, S(36));
        auto field = [&](int label, CWnd& control, int x, int y, int w, bool combo = false) {
            m_labels[label].MoveWindow(x, y, w, S(18));
            control.MoveWindow(x, y+S(20), w, S(combo ? 160 : 28));
        };
        field(0, m_type, left, S(54), half, true);
        field(1, m_transport, left+half+gap, S(54), half, true);
        field(2, m_host, left, S(110), width-S(96)-gap);
        field(3, m_port, area.right-left-S(96), S(110), S(96));
        if (m_ssh) m_sshAuth.Layout(left, S(166), width, gap, S(18), S(28));
        const int shift = m_ssh ? 56 : 0;
        field(4, m_user, left, S(166+shift), half);
        field(5, m_password, left+half+gap, S(166+shift), half);
        if (m_showKey) field(6, m_key, left, S(222+shift), width);
        const int bottom = area.bottom-S(12)-S(30);
        m_error.MoveWindow(left, bottom-S(28), width, S(24));
        m_test.MoveWindow(area.right-left-S(80)-2*gap-S(100)-S(112), bottom, S(112), S(30));
        m_cancel.MoveWindow(area.right-left-S(80), bottom, S(80), S(30));
        m_save.MoveWindow(area.right-left-S(80)-gap-S(100), bottom, S(100), S(30));
    }
    void TestControls(bool running)
    {
        m_sshAuth.Enable(!running);
        for (UINT id = 1301; id <= 1307; ++id) GetDlgItem(id)->EnableWindow(!running);
        if (!running) m_transport.EnableWindow(!m_ssh && ProxySupportsOptionalModules());
        m_save.EnableWindow(!running);
        m_test.SetWindowText(Localization::Get(running ? L"action.cancel_test" : L"chain.edit.test_node"));
    }
    void StopTest()
    {
        ++m_testGeneration; // Invalidate completions already queued by the previous run.
        if (m_tester) { m_tester->Release(); m_tester = NULL; }
        m_testing = false;
        if (m_save.GetSafeHwnd()) TestControls(false);
    }
    void TestConnection()
    {
        if (m_testing)
        {
            StopTest();
            m_error.SetStatus(Localization::Get(L"chain.test.cancelled"), CStatusLabel::TONE_NEUTRAL);
            m_error.ShowWindow(SW_SHOW);
            return;
        }
        CfgProxyItem draft;
        if (!ReadFields(draft)) return;
        m_testInfo = draft.pi;
        m_udpRequested = ProxyTransportPolicy::SupportsUdpProxy(m_testInfo.GetProxyType());
        m_fingerprint.Empty();
        m_rows.clear();
        const LPCWSTR titles[] = { L"test.result.tcp", L"test.result.udp", L"test.result.ipv6" };
        for (auto title : titles)
            m_rows.push_back({ CProxyTestResultRow::Skipped, Localization::Get(title),
                Localization::Get(L"test.result.skipped"), Localization::Get(L"test.result.prerequisite") });
        if (!m_udpRequested)
        {
            const bool supported = ProxyTransportPolicy::SupportsUdpProxy(m_testInfo.GetProxyType());
            m_rows[1].status = Localization::Get(supported ? L"test.result.disabled" : L"test.result.unsupported");
            m_rows[1].detail = Localization::Get(supported ? L"test.result.udp_disabled" : L"test.result.udp_protocol");
        }
        ++m_testGeneration;
        m_testing = true;
        TestControls(true);
        if (!m_proxy) m_proxy = GetGlobalProxyInstance();
        StartPhase(0);
    }
    void StartPhase(int phase)
    {
        m_phase = phase;
        m_phaseError = 0;
        m_lastTestStage = PTS_WAITING;
        m_phaseErrorDetail.Empty();
        PRCClient client; client.zero();
        client.sType = phase == 1 ? SOCK_DGRAM : SOCK_STREAM;
        if (phase == 0)
        {
            CString host = m_ini.GetString(L"options", L"testhost", L"www.baidu.com");
            int port = 80;
            const int separator = host.Find(L':');
            if (separator > 0) { port = _ttoi(host.Mid(separator+1)); host = host.Left(separator); }
            WideCharToMultiByte(CP_ACP, 0, host, -1, client.szDomainName, sizeof(client.szDomainName), NULL, NULL);
            client.dstAddr.SetPort(port);
            m_rows[0].detail = Localization::Format(L"test.result.tcp_target", (LPCTSTR)host, port);
        }
        else if (phase == 1)
        {
            client.dstAddr.SetIP("8.8.8.8"); client.dstAddr.SetPort(53);
            m_rows[1].detail = Localization::Get(L"test.result.udp_ok");
        }
        else
        {
            CString address = m_ini.GetString(L"options", L"IPv6TestAddress", L"2001:4860:4860::8888");
            address.Trim();
            if (address.GetLength() > 2 && address[0] == L'[' && address[address.GetLength()-1] == L']')
                address = address.Mid(1, address.GetLength()-2);
            if (!client.dstAddr.SetIP(CStringA(address)) || !client.dstAddr.IsIPv6())
            {
                m_rows[2].state = CProxyTestResultRow::Warning;
                m_rows[2].status = Localization::Get(L"test.result.invalid");
                m_rows[2].detail = Localization::Get(L"test.result.ipv6_invalid");
                ShowTestResult(); return;
            }
            client.dstAddr.SetPort(53);
            m_rows[2].detail = Localization::Format(L"test.result.ipv6_target", (LPCTSTR)address);
        }
        m_error.SetStatus(Localization::Get(phase == 0 ? L"chain.edit.testing" :
            phase == 1 ? L"status.testing_udp" : L"status.testing_ipv6"), CStatusLabel::TONE_INFO);
        m_error.ShowWindow(SW_SHOW);
        m_tester = m_proxy ? m_proxy->CreateTester() : NULL;
        WSASetLastError(0);
        if (!m_tester || !m_tester->Start(this, &client, &m_testInfo))
        {
            m_phaseError = WSAGetLastError();
            if (!m_phaseError) m_phaseError = WSAENOBUFS;
            if (m_tester) m_tester->Stop();
            PostMessage(WM_APP + 51, m_testGeneration);
        }
    }
    void OnProxyTesterCallback(IProxyTester* tester, int error, WPARAM socketError, LPARAM detail) override
    {
        if (!m_testing || tester != m_tester) return;
        if (HIWORD(error) == LAYERCALLBACK_TESTPROGRESS) {
            const int stage = LOWORD(error);
            if (stage > PTS_WAITING && stage < PTS_PASSED) m_lastTestStage = stage;
            return;
        }
        if (HIWORD(error) != LAYERCALLBACK_LAYERSPECIFIC) return;
        m_phaseError = LOWORD(error);
        m_phaseErrorDetail = ProxyTestSshErrorDescription(m_phaseError, m_testInfo, m_lastTestStage, (int)socketError);
        if (detail && (m_phaseError == PROXYERROR_SSH_HOSTKEY_UNKNOWN || m_phaseError == PROXYERROR_SSH_HOSTKEY_CHANGED))
            m_fingerprint = SshProfile::Decode(reinterpret_cast<LPCSTR>(detail));
        tester->Stop();
        // Leave the tester's callback stack before opening another modal window.
        PostMessage(WM_APP + 51, m_testGeneration);
    }
    void FinishPhase()
    {
        if (m_tester) { m_tester->Release(); m_tester = NULL; }
        auto& row = m_rows[m_phase];
        row.state = m_phaseError ? CProxyTestResultRow::Failed : CProxyTestResultRow::Passed;
        row.status = Localization::Get(m_phaseError ? L"test.result.failed" : L"test.result.passed");
        if (m_phaseError) row.detail = m_phaseErrorDetail.IsEmpty() ? ProxyTestErrorDescription(m_phaseError, FALSE) : m_phaseErrorDetail;
        if (m_phase == 1 && m_phaseError == PROXYERROR_UDP_UNSUPPORTED)
        {
            row.state = CProxyTestResultRow::Skipped;
            row.status = Localization::Get(L"test.result.unsupported");
            // This probes a node's capabilities, not the active chain's UDP policy.
            row.detail = Localization::Get(L"test.result.udp_server");
        }
        if (m_phase == 0 && !m_phaseError) { StartPhase(m_udpRequested ? 1 : 2); return; }
        if (m_phase == 1) { StartPhase(2); return; }
        ShowTestResult();
    }
    void ShowTestResult()
    {
        CString trust;
        if (m_phase == 0 && m_phaseError == PROXYERROR_SSH_HOSTKEY_UNKNOWN && SshProfile::ValidFingerprint(m_fingerprint))
        {
            trust.Format(L"%s\r\n\r\n%s\r\n%s:%d\r\n\r\n%s",
                (LPCTSTR)Localization::Get(L"test.ssh_unknown_key"), (LPCTSTR)m_fingerprint,
                (LPCTSTR)(CString)m_testInfo.strProxyHost, m_testInfo.nProxyPort,
                (LPCTSTR)Localization::Get(L"test.ssh_trust_key"));
        }
        else if (!m_fingerprint.IsEmpty()) m_rows[0].detail += L" " + m_fingerprint;
        CProxyTestResultDialog result(m_rows, trust, this);
        const INT_PTR response = result.DoModal();
        StopTest();
        // Trust updates the editor draft only. Saving remains a separate action.
        if (response == IDYES && !trust.IsEmpty()) m_key.SetWindowText(m_fingerprint);
        bool failed = false;
        for (const auto& row : m_rows) failed = failed || row.state == CProxyTestResultRow::Failed || row.state == CProxyTestResultRow::Warning;
        m_error.SetStatus(Localization::Format(L"chain.test.results", (LPCTSTR)m_rows[0].status,
            (LPCTSTR)m_rows[1].status, (LPCTSTR)m_rows[2].status), failed ? CStatusLabel::TONE_DANGER : CStatusLabel::TONE_SUCCESS);
        m_error.ShowWindow(SW_SHOW);
    }
    IGlobalProxy* m_proxy = NULL;
    IProxyTester* m_tester = NULL;
    ProxyInfo m_testInfo;
    bool m_testing = false, m_udpRequested = false;
    UINT_PTR m_testGeneration = 0;
    int m_phase = 0, m_phaseError = 0;
    int m_lastTestStage = PTS_WAITING;
    CString m_phaseErrorDetail;
    CString m_fingerprint;
    std::vector<CProxyTestResultDialog::Row> m_rows;
    CProxyProfileStore& m_store;
    CIniFile& m_ini;
    CfgProxyItem m_item;
    bool m_ready = false, m_ssh = false, m_showKey = false;
    CSshAuthControls m_sshAuth;
    CSoftCombo m_type, m_transport;
    CSoftEdit m_host, m_port, m_user, m_password, m_key;
    CStatic m_labels[7], m_notice;
    CStatusLabel m_error;
    CModernButton m_test, m_save, m_cancel;
};
