#include "stdafx.h"
#include "ProxyLane.h"
#include "Page1.h"
#include "MainTab.h"
#include "Page3.h"
#include "Page4.h"
#include "Localization.h"
#include "ProfileShareCodec.h"
#include "../ProxyLaneHook/DnsRedirectPolicy.h"
#include "../ProxyLaneHook/PlatformSupport.h"

namespace
{
using ProfileShare::Json;
struct Field { UINT id; const char* key; };
const Field textFields[] = {
    {IDC_EDIT_ADDR, "host"}, {IDC_EDIT_USER, "user"}, {IDC_EDIT_PASS, "password"},
    {IDC_EDIT_TRANSPORT_PSK, "psk"}, {IDC_EDIT_REDIRECT_DNS, "redirect_dns"}
};
const Field checkFields[] = {
    {IDC_CHECK_HOOKTCP, "hook_tcp"}, {IDC_CHECK_HOOK_UDP, "hook_udp"},
    {IDC_CHECK_BLOCKUDP, "block_udp"}, {IDC_CHECK_BLOCK_IPV6, "block_ipv6"},
    {IDC_CHECK_HOOKCHILDPROCESS, "hook_children"},
    {IDC_CHECK_REDIRECT_PRIVATE_DNS, "redirect_private_dns"}
};
const Field ruleFields[] = {{IDC_EDIT_CHILDFILTER, "child_rules"}, {IDC_EDIT_TARGETFILTER, "target_rules"}};

std::string Utf8(const CString& text)
{
    if (text.IsEmpty()) return std::string();
    int length = WideCharToMultiByte(CP_UTF8, 0, text, text.GetLength(), NULL, 0, NULL, NULL);
    std::string result(length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, text.GetLength(), &result[0], length, NULL, NULL);
    return result;
}

CString Wide(const std::string& text)
{
    if (text.empty()) return CString();
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), (int)text.size(), NULL, 0);
    if (!length) throw ProfileShare::Error("share.invalid_fields");
    CString result;
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), (int)text.size(), result.GetBuffer(length), length);
    result.ReleaseBuffer(length);
    return result;
}

void ValidateResolver(const Json& value)
{
    if (value.at("dns_mode") != PSI_DNSOPT_REMOTE || value.at("redirect_private_dns") != true) return;
    CString resolver = Wide(value.at("redirect_dns").get<std::string>());
    resolver.Trim();
    _SockAddr address;
    address.Clear();
    if (!address.SetIP(CStringA(resolver)) || !DnsRedirectPolicy::IsValidPublicResolver(address))
        throw ProfileShare::Error("profile.invalid_redirect_dns");
}

class Clipboard
{
public:
    explicit Clipboard(HWND owner) { if (!::OpenClipboard(owner)) throw ProfileShare::Error("share.clipboard_busy"); }
    ~Clipboard() { ::CloseClipboard(); }
private:
    Clipboard(const Clipboard&);
    Clipboard& operator=(const Clipboard&);
};

CString ReadClipboard(HWND owner)
{
    Clipboard clipboard(owner);
    HANDLE data = ::GetClipboardData(CF_UNICODETEXT);
    if (!data) throw ProfileShare::Error("share.no_text");
    const SIZE_T bytes = ::GlobalSize(data);
    if (bytes > (ProfileShare::MaxCodeBytes + 1) * sizeof(wchar_t)) throw ProfileShare::Error("share.too_large");
    const wchar_t* chars = static_cast<const wchar_t*>(::GlobalLock(data));
    if (!chars) throw ProfileShare::Error("share.no_text");
    const size_t capacity = bytes / sizeof(wchar_t);
    size_t length = 0;
    while (length < capacity && chars[length]) ++length;
    CString result;
    if (length < capacity) result.SetString(chars, (int)length);
    ::GlobalUnlock(data);
    if (length == capacity) throw ProfileShare::Error("share.invalid_code");
    return result;
}

void WriteClipboard(HWND owner, const CString& text)
{
    const SIZE_T bytes = (text.GetLength() + 1) * sizeof(wchar_t);
    HGLOBAL data = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!data) throw ProfileShare::Error("share.clipboard_failed");
    void* target = ::GlobalLock(data);
    if (!target) { ::GlobalFree(data); throw ProfileShare::Error("share.clipboard_failed"); }
    memcpy(target, (LPCWSTR)text, bytes);
    ::GlobalUnlock(data);
    try
    {
        Clipboard clipboard(owner);
        if (!::EmptyClipboard() || !::SetClipboardData(CF_UNICODETEXT, data))
            throw ProfileShare::Error("share.clipboard_failed");
    }
    catch (...) { ::GlobalFree(data); throw; }
    // Windows owns data after SetClipboardData succeeds.
}
}

void CPage1::ShowProfileNotice(LPCTSTR primary, LPCTSTR secondary, CStatusLabel::Tone tone)
{
    CString notice(primary);
    if (secondary && secondary[0]) notice += CString(_T(" · ")) + secondary;
    if (g_MainTab) g_MainTab->ShowTransientStatus(notice, tone);
}

void CPage1::OnProfileMenu()
{
    CMenu menu;
    if (!menu.CreatePopupMenu()) return;
    menu.AppendMenu(MF_STRING, IDC_BUTTON_COPY_PROFILE, Localization::Get(_T("share.copy")));
    menu.AppendMenu(MF_STRING | (m_bIsTesting ? MF_GRAYED : 0), IDC_BUTTON_PASTE_PROFILE,
        Localization::Get(_T("share.paste")));
    menu.AppendMenu(MF_SEPARATOR);
    menu.AppendMenu(MF_STRING, IDC_BUTTON_IMPORT_CONFIG, Localization::Get(_T("import.action")));
    menu.AppendMenu(MF_SEPARATOR);
    menu.AppendMenu(MF_STRING | (m_cfgls.GetCurSel() == CB_ERR ? MF_GRAYED : 0),
        IDC_BUTTON_DELETE_PROFILE, Localization::Get(_T("profile.delete_action")));
    CRect anchor;
    m_btnProfileMenu.GetWindowRect(&anchor);
    const UINT selected = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_RIGHTALIGN | TPM_RIGHTBUTTON,
        anchor.right, anchor.bottom, this);
    if (selected) SendMessage(WM_COMMAND, selected, 0);
}

BOOL CPage1::CanImportAllConfig()
{
    CString reason;
    if (m_bIsTesting || IsProxyRunning() || !g_MainTab || g_MainTab->GetPage4()->IsBusyForConfigImport())
        reason = Localization::Get(L"import.busy");
    else
    {
        std::vector<_myPROCESSINFO> processes;
        if (!g_MainTab->GetPage3()->GetRunningHookedProcesses(processes))
            reason = Localization::Get(L"import.process_check_failed");
        else if (!processes.empty())
        {
            reason = Localization::Get(L"import.processes_running");
            for (size_t i = 0; i < processes.size() && i < 10; ++i)
                reason += Localization::Format(L"import.process", processes[i].proname, processes[i].pid);
            if (processes.size() > 10) reason += L"\r\n...";
        }
    }
    if (reason.IsEmpty()) return TRUE;
    MessageBox(reason, Localization::Get(L"import.title"), MB_OK | MB_ICONINFORMATION);
    return FALSE;
}

namespace
{
class ImportConfigDialog : public CModernDialog
{
public:
    ImportConfigDialog(const CString& summary, CWnd* parent) : CModernDialog(IDD_IMPORT_CONFIG, parent), m_summary(summary) {}
protected:
    BOOL OnInitDialog() override
    {
        CModernDialog::OnInitDialog();
        SetWindowText(Localization::Get(L"import.title"));
        SetDlgItemText(IDC_IMPORT_SUMMARY, m_summary);
        SetDlgItemText(IDCANCEL, Localization::Get(L"apps.cancel"));
        SetDlgItemText(IDOK, Localization::Get(L"import.confirm"));
        m_cancel.SubclassDlgItem(IDCANCEL, this);
        m_confirm.SubclassDlgItem(IDOK, this);
        SetDefID(IDCANCEL); GetDlgItem(IDCANCEL)->SetFocus();
        return FALSE;
    }
    void OnOK() override { EndDialog(IDOK); }
    void OnCancel() override { EndDialog(IDCANCEL); }
private:
    CString m_summary;
    CModernButton m_cancel, m_confirm;
};
}

void CPage1::OnImportAllConfig()
{
    if (theApp.HasPendingConfigImport() || !CanImportAllConfig()) return;
    CFileDialog picker(TRUE, L"ini", L"ProxyLane.ini", OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR,
        L"INI files (*.ini)|*.ini||", this);
    const CString title = Localization::Get(L"import.action");
    picker.m_ofn.lpstrTitle = title;
    if (picker.DoModal() != IDOK) return;
    ImportConfigFromFile(picker.GetPathName());
}

void CPage1::ImportConfigFromFile(const CString& path)
{
    if (theApp.HasPendingConfigImport() || !CanImportAllConfig()) return;
    std::unique_ptr<ConfigImport::Pending> pending(new ConfigImport::Pending);
    CString error;
    if (!pending->Prepare(path, error))
    {
        MessageBox(error, Localization::Get(L"import.title"), MB_OK | MB_ICONERROR);
        return;
    }
    CString backup = pending->backup.IsEmpty() ? Localization::Get(L"import.no_previous") : pending->backup;
    CString summary = Localization::Format(L"import.summary", (LPCTSTR)pending->source, (LPCTSTR)pending->destination,
        pending->profiles, (LPCTSTR)backup);
    ImportConfigDialog confirm(summary, this);
    if (confirm.DoModal() != IDOK || !CanImportAllConfig()) return;
    if (!pending->ArmRestart(error))
    {
        MessageBox(Localization::Format(L"import.kept_original", (LPCTSTR)error), Localization::Get(L"import.title"), MB_OK | MB_ICONERROR);
        return;
    }
    theApp.ScheduleConfigImport(std::move(pending));
    // Import is already confirmed and no service/test/monitor/proxied process
    // remains. Close normally without the independent exit-warning workflow.
    GetTopLevelParent()->SendMessage(WM_CONFIG_IMPORT_RESTART);
}

void CPage1::OnCopyProfile()
{
    try
    {
        Json value = Json::object();
        CString text;
        m_cfgls.GetWindowText(text);
        text.Trim();
        value["name"] = Utf8(text);
        m_cbProxyType.GetWindowText(text);
        value["type"] = Utf8(text);
        m_edit_Port.GetWindowText(text);
        text.Trim();
        if (text.GetLength() > 5 || (!text.IsEmpty() && text.FindOneOf(_T("0123456789")) < 0))
            throw ProfileShare::Error("profile.invalid_endpoint");
        for (int i = 0; i < text.GetLength(); ++i)
            if (text[i] < '0' || text[i] > '9') throw ProfileShare::Error("profile.invalid_endpoint");
        value["port"] = text.IsEmpty() ? 0 : _ttoi(text);
        for (const auto& field : textFields)
        {
            GetDlgItemText(field.id, text);
            value[field.key] = Utf8(text);
        }
        for (const auto& field : checkFields)
            value[field.key] = IsDlgButtonChecked(field.id) == BST_CHECKED;
        for (const auto& field : ruleFields)
        {
            GetDlgItemText(field.id, text);
            text.Replace(_T("\r\n"), _T("\n"));
            text.Replace(_T("\r"), _T("\n"));
            const std::string rules = Utf8(text);
            Json lines = Json::array();
            if (!rules.empty())
            {
                size_t start = 0, end;
                do
                {
                    end = rules.find('\n', start);
                    lines.push_back(rules.substr(start, end == std::string::npos ? end : end - start));
                    start = end + 1;
                } while (end != std::string::npos);
            }
            value[field.key] = lines;
        }
        value["dns_mode"] = m_btnDNSLocal.GetCheck() == BST_CHECKED ? 0 : 1;
        value["child_mode"] = m_radioChildFilterInclude.GetCheck() == BST_CHECKED ? 1 : 0;
        value["target_mode"] = m_radioTargetFilterProxy.GetCheck() == BST_CHECKED ? 1 : 0;
        value["transport"] = m_cbTransport.GetCurSel() == PROXY_TRANSPORT_GONC_TLS_PSK ? "GONC_TLS_PSK" : "PLAIN";
        ProfileShare::Validate(value);
        ValidateResolver(value);
        WriteClipboard(m_hWnd, Wide(ProfileShare::Encode(value)));
        ShowProfileNotice(Localization::Get(_T("share.copied")),
            Localization::Get(_T("share.includes_secrets")), CStatusLabel::TONE_SUCCESS);
    }
    catch (const ProfileShare::Error& error)
    {
        MessageBox(Localization::Get(Wide(error.what())), Localization::Get(_T("share.copy_failed")), MB_ICONERROR);
    }
    catch (const std::exception&)
    {
        MessageBox(Localization::Get(_T("share.invalid_fields")), Localization::Get(_T("share.copy_failed")), MB_ICONERROR);
    }
}

void CPage1::OnPasteProfile()
{
    if (m_bIsTesting)
    {
        MessageBox(Localization::Get(_T("share.testing")), Localization::Get(_T("share.paste")), MB_ICONINFORMATION);
        return;
    }
    try
    {
        const Json value = ProfileShare::Decode(Utf8(ReadClipboard(m_hWnd)));
        ValidateResolver(value);
        // Prepare every string before touching the UI or asking to discard a draft.
        std::vector<std::pair<UINT, CString>> texts;
        for (const auto& field : textFields)
            texts.emplace_back(field.id, Wide(value.at(field.key).get<std::string>()));
        for (const auto& field : ruleFields)
        {
            std::string rules;
            bool first = true;
            for (const auto& line : value.at(field.key))
            {
                if (!first) rules += "\r\n";
                rules += line.get<std::string>();
                first = false;
            }
            texts.emplace_back(field.id, Wide(rules));
        }
        CString port;
        port.Format(_T("%d"), value.at("port").get<int>());
        if (value.at("type") == "NOPROXY" && value.at("port") == 0) port.Empty();
        const CString type = Wide(value.at("type").get<std::string>());
        const CString baseName = Wide(value.at("name").get<std::string>());
        const bool secure = value.at("transport") == "GONC_TLS_PSK";
        if (!ConfirmDiscardUnsavedChanges()) return;
        if (!RefreshProfileNames()) return;
        // The preceding prompt can save a new profile, so resolve collisions afterwards.
        CString name = baseName;
        for (int suffix = 1; m_cfgls.FindStringExact(-1, name) != CB_ERR; ++suffix)
        {
            name = baseName + Localization::Get(_T("share.import_suffix"));
            if (suffix > 1) { CString number; number.Format(_T(" %d"), suffix); name += number; }
        }
        m_loadingProfile = TRUE;
        m_cfgls.SetCurSel(-1);
        m_cfgls.SetWindowText(name);
        m_cbProxyType.SelectString(-1, type);
        m_cbTransport.SetCurSel(secure ? PROXY_TRANSPORT_GONC_TLS_PSK : PROXY_TRANSPORT_PLAIN);
        m_edit_Port.SetWindowText(port);
        for (const auto& field : texts) SetDlgItemText(field.first, field.second);
        for (const auto& field : checkFields)
            CheckDlgButton(field.id, value.at(field.key).get<bool>() ? BST_CHECKED : BST_UNCHECKED);
        const bool remote = value.at("dns_mode") == 1;
        const bool include = value.at("child_mode") == 1;
        const bool proxy = value.at("target_mode") == 1;
        m_btnDNSLocal.SetCheck(!remote); m_btnDNSRemote.SetCheck(remote);
        m_radioChildFilterExclude.SetCheck(!include); m_radioChildFilterInclude.SetCheck(include);
        m_radioTargetFilterBypass.SetCheck(!proxy); m_radioTargetFilterProxy.SetCheck(proxy);
        UpdateChildFilterEnable();
        UpdateDnsRedirectEnable();
        UpdateTransportEnable();
        m_loadedProfileName.Empty();
        m_draftProfileName = name;
        m_loadingProfile = FALSE;
        SetProfileDirty(TRUE);
        SetRuntimeDirty(TRUE);
        ShowProfileNotice(Localization::Get(_T("share.pasted")),
            Localization::Get(secure && !ProxySupportsOptionalModules() ? _T("share.secure_unavailable") :
                IsProxyRunning() ? _T("share.pending_apply") : _T("share.pending_save")), CStatusLabel::TONE_WARNING);
    }
    catch (const ProfileShare::Error& error)
    {
        MessageBox(Localization::Get(Wide(error.what())), Localization::Get(_T("share.paste_failed")), MB_ICONERROR);
    }
    catch (const std::exception&)
    {
        MessageBox(Localization::Get(_T("share.invalid_code")), Localization::Get(_T("share.paste_failed")), MB_ICONERROR);
    }
}
