#include "stdafx.h"
#include "ProxyLane.h"
#include "Page5.h"
#include "AppVersion.h"
#include "Localization.h"
#include "ConfigStorage.h"
#include "ConfigImport.h"
#include "MainTab.h"
#include "Page1.h"
#include "UpdateRelease.h"
#include "UpdateHelper.h"
#include "Page3.h"
#include "ProxyLaneDlg.h"

IMPLEMENT_DYNAMIC(CPage5, CModernDialog)

namespace
{
	LPCTSTR kProjectUrl = _T("https://github.com/threatexpert/ProxyLane");
}

CPage5::CPage5(CWnd* parent)
	: CModernDialog(CPage5::IDD, parent)
	, m_aboutIcon(NULL)
{
}

CPage5::~CPage5()
{
	if (m_aboutIcon) ::DestroyIcon(m_aboutIcon);
}

void CPage5::DoDataExchange(CDataExchange* dataExchange)
{
	CModernDialog::DoDataExchange(dataExchange);
	DDX_Control(dataExchange, IDC_COMBO_LANGUAGE, m_languageCombo);
	DDX_Control(dataExchange, IDC_STATIC_OPEN_SOURCE_GROUP, m_openSourceCard);
}

BOOL CPage5::OnInitDialog()
{
	CModernDialog::OnInitDialog();

	const CString version = AppVersion::DisplayVersion();
	CString displayVersion = version.IsEmpty() ? Localization::Get(_T("common.unknown")) : version;
	CString versionText = Localization::Format(_T("page5.version_value"),
		static_cast<LPCTSTR>(displayVersion));
	SetDlgItemText(IDC_STATIC_ABOUT_VERSION, versionText);

	m_languageCombo.AddString(Localization::Get(_T("language.auto")));
	m_languageCombo.AddString(Localization::Get(_T("language.zh-CN")));
	m_languageCombo.AddString(Localization::Get(_T("language.en-US")));
	CString preferred = Localization::PreferredLanguage();
	int selection = preferred.CompareNoCase(_T("zh-CN")) == 0 ? 1
		: preferred.CompareNoCase(_T("en-US")) == 0 ? 2 : 0;
	m_languageCombo.SetCurSel(selection);

	CWnd* projectLink = GetDlgItem(IDC_LINK_PROJECT);
	if (projectLink && m_projectTooltip.Create(this, TTS_ALWAYSTIP | TTS_NOPREFIX))
	{
		m_projectTooltip.AddTool(projectLink, kProjectUrl);
		m_projectTooltip.SetMaxTipWidth(UiTheme::ScaleForWindow(m_hWnd, 360));
		m_projectTooltip.Activate(TRUE);
	}
	// Load the icon at its display size instead of stretching the 32px one.
	m_aboutIcon = static_cast<HICON>(::LoadImage(AfxGetResourceHandle(), MAKEINTRESOURCE(IDR_MAINFRAME),
		IMAGE_ICON, UiTheme::ScaleForWindow(m_hWnd, 40), UiTheme::ScaleForWindow(m_hWnd, 40), LR_DEFAULTCOLOR));
	if (m_aboutIcon)
		static_cast<CStatic*>(GetDlgItem(IDC_ABOUT_ICON))->SetIcon(m_aboutIcon);
 UiTheme::CreateUiFont(m_smallFont, m_hWnd, 8, FW_NORMAL);
 UiTheme::CreateUiFont(m_boldFont, m_hWnd, 10, FW_BOLD);
 if (CWnd* name = GetDlgItem(IDC_ABOUT_NAME)) name->SetFont(&m_boldFont, FALSE);
 m_openSourceCard.SetWindowText(L"");
 const bool portable = ConfigStorage::Path().CompareNoCase(ConfigStorage::PortablePath()) == 0;
 const wchar_t* keys[] = { L"settings.open_folder", portable ? L"settings.use_user" : L"settings.use_portable", L"settings.import", L"settings.export", L"settings.check_update" };
 for (int i = 0; i < 5; ++i) {
  m_settingsButtons[i].Create(Localization::Get(keys[i]), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, CRect(), this, 0x2500 + i);
  m_settingsButtons[i].SetFont(&m_uiFont);
 }
 // An installed copy lives in Program Files, where portable.flag cannot be written.
 if (!portable && UpdateHelper::IsInstalledCopy()) m_settingsButtons[1].EnableWindow(FALSE);
 // Row-based cards follow lijing6006/ProxyLane PR #3.
 const DWORD child = WS_CHILD | WS_VISIBLE;
 m_configCard.Create(Localization::Get(L"settings.config_title"), child | BS_GROUPBOX, CRect(), this, 0x2530);
 m_preferencesCard.Create(Localization::Get(L"settings.preferences"), child | BS_GROUPBOX, CRect(), this, 0x2531);
 m_configCard.SetFont(&m_uiFont); m_preferencesCard.SetFont(&m_uiFont);
 CString mode = Localization::Get(ConfigStorage::Path().CompareNoCase(ConfigStorage::PortablePath()) == 0 ? L"settings.portable_short" : L"settings.user_short");
 m_storageMode.Create(Localization::Get(L"settings.location") + L" · " + mode, child | SS_NOPREFIX, CRect(), this, 0x2521);
 m_storagePath.Create(ConfigStorage::Path(), child | SS_NOPREFIX | SS_PATHELLIPSIS, CRect(), this, 0x2522);
 m_updateInfo.Create(L"", child | LWS_RIGHT, CRect(), this, 0x2524);
 m_updateInfo.SetFont(&m_uiFont);
 m_transferTitle.Create(Localization::Get(L"settings.transfer"), child | SS_NOPREFIX, CRect(), this, 0x2526);
 m_transferInfo.Create(Localization::Get(L"settings.transfer_detail"), child | SS_NOPREFIX, CRect(), this, 0x2527);
 m_downloadLabel.Create(Localization::Get(L"page5.download_site"), child | SS_NOPREFIX, CRect(), this, 0x2528);
 m_downloadLabel.SetFont(&m_uiFont);
 m_downloadLink.Create(L"<a href=\"https://10000.download/\">10000.download</a>", child | WS_TABSTOP, CRect(), this, 0x2529);
 m_downloadLink.SetFont(&m_uiFont);
 if (m_projectTooltip.GetSafeHwnd()) m_projectTooltip.AddTool(&m_downloadLink, UpdateRelease::SiteUrl);
 for (UINT id : { 0x2521, 0x2522, 0x2526, 0x2527 }) GetDlgItem(id)->SetFont(id == 0x2522 || id == 0x2527 ? &m_smallFont : &m_uiFont);
 if (m_projectTooltip.GetSafeHwnd()) m_projectTooltip.AddTool(&m_storagePath, ConfigStorage::Path());
 m_storagePath.ModifyStyle(0, SS_NOTIFY);
 // Frames paint below their sibling controls and never enter the tab order.
 m_configCard.SetWindowPos(&wndBottom, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
 m_preferencesCard.SetWindowPos(&wndBottom, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
 // CCardFrame paints only its border/title; the page owns its background.
 // WS_CLIPCHILDREN excludes the entire card rectangle from background erase,
 // leaving pixels from the previously visible page inside the cards.
 ModifyStyle(WS_CLIPCHILDREN, WS_VSCROLL);
	LayoutAboutPage();
	return TRUE;
}

BOOL CPage5::PreTranslateMessage(MSG* message)
{
	if (m_projectTooltip.GetSafeHwnd())
		m_projectTooltip.RelayEvent(message);

	return CModernDialog::PreTranslateMessage(message);
}

BEGIN_MESSAGE_MAP(CPage5, CModernDialog)
 ON_WM_VSCROLL()
 ON_WM_MOUSEWHEEL()
 ON_WM_TIMER()
 ON_WM_CTLCOLOR()
 ON_CONTROL_RANGE(BN_CLICKED, 0x2500, 0x2504, &CPage5::OnSettingsAction)
	ON_WM_SIZE()
	ON_NOTIFY(NM_CLICK, IDC_LINK_PROJECT, &CPage5::OnProjectLink)
	ON_NOTIFY(NM_RETURN, IDC_LINK_PROJECT, &CPage5::OnProjectLink)
 ON_NOTIFY(NM_CLICK, 0x2529, &CPage5::OnDownloadLink)
 ON_NOTIFY(NM_RETURN, 0x2529, &CPage5::OnDownloadLink)
 ON_NOTIFY(NM_CLICK, 0x2524, &CPage5::OnUpdateLink)
 ON_NOTIFY(NM_RETURN, 0x2524, &CPage5::OnUpdateLink)
	ON_CBN_SELCHANGE(IDC_COMBO_LANGUAGE, &CPage5::OnLanguageChanged)
END_MESSAGE_MAP()

void CPage5::OnLanguageChanged()
{
	static LPCTSTR values[] = { _T("auto"), _T("zh-CN"), _T("en-US") };
	int selection = m_languageCombo.GetCurSel();
	if (selection < 0 || selection >= _countof(values))
		return;
	if (!Localization::SetPreferredLanguage(values[selection])) {
		DWORD error = GetLastError();
		CString previous = Localization::PreferredLanguage();
		m_languageCombo.SetCurSel(previous == L"zh-CN" ? 1 : previous == L"en-US" ? 2 : 0);
		ReportStorageError(error); return;
	}
	MessageBox(Localization::Get(_T("language.restart_message")),
		Localization::Get(_T("language.restart_title")), MB_ICONINFORMATION);
}

void CPage5::OnProjectLink(NMHDR* notifyHeader, LRESULT* result)
{
	LPCTSTR url = kProjectUrl;
	if (notifyHeader)
	{
		const NMLINK* link = reinterpret_cast<const NMLINK*>(notifyHeader);
		if (link->item.szUrl[0] != _T('\0'))
			url = link->item.szUrl;
	}

	ShellExecute(m_hWnd, _T("open"), url, NULL, NULL, SW_SHOWNORMAL);
	if (result)
		*result = 0;
}

void CPage5::OnDownloadLink(NMHDR*, LRESULT* result)
{
 ShellExecute(m_hWnd, L"open", UpdateRelease::SiteUrl, NULL, NULL, SW_SHOWNORMAL);
 if (result) *result = 0;
}

void CPage5::OnUpdateLink(NMHDR*, LRESULT* result)
{
 if (result) *result = 0;
 switch (m_updateStage) {
 case UPDATE_FOUND_SITE: ShellExecute(m_hWnd, L"open", UpdateRelease::DownloadUrl, NULL, NULL, SW_SHOWNORMAL); break;
 case UPDATE_FOUND_INSTALLER: StartInstallerDownload(); break;
 case UPDATE_READY: OfferInstall(); break;
 default: break;
 }
}

HBRUSH CPage5::OnCtlColor(CDC* dc, CWnd* wnd, UINT ctlColor)
{
 HBRUSH brush = CModernDialog::OnCtlColor(dc, wnd, ctlColor);
 if (wnd && wnd->GetSafeHwnd() == m_updateInfo.GetSafeHwnd())
  dc->SetTextColor(m_updateFound ? RGB(21, 128, 61) : m_updateFailed ? UiTheme::Danger() : UiTheme::TextSecondary());
 return brush;
}

void CPage5::SetUpdateStatus(const CString& text, bool found, bool failed)
{
 m_updateFound = found;
 m_updateFailed = failed;
 CString markup(text);
 markup.Replace(L"&", L"&amp;");
 markup.Replace(L"<", L"&lt;");
 markup.Replace(L">", L"&gt;");
 if (found) markup = L"<a href=\"" + CString(UpdateRelease::DownloadUrl) + L"\">" + markup + L"</a>";
 m_updateInfo.SetWindowText(markup);
 m_updateInfo.ModifyStyle(found ? 0 : WS_TABSTOP, found ? WS_TABSTOP : 0);
 if (found) {
  // Let the native hyperlink retain keyboard/accessibility behavior and use our text color.
  LITEM item = {};
  item.mask = LIF_ITEMINDEX | LIF_STATE;
  item.stateMask = item.state = LIS_DEFAULTCOLORS;
  m_updateInfo.SendMessage(LM_SETITEM, 0, reinterpret_cast<LPARAM>(&item));
 }
 LayoutAboutPage();
}

BOOL CPage5::UsesSecondaryText(UINT controlId) const
{
	if (controlId == 0x2522 || controlId == 0x2524 || controlId == 0x2527 || controlId == 0x2528) return TRUE;
	switch (controlId)
	{
	case IDC_STATIC_ABOUT_VERSION:
	case IDC_STATIC_ABOUT_TAGLINE:
	case IDC_STATIC_PROJECT_LABEL:
	case IDC_ABOUT_COPYRIGHT:
		return TRUE;
	}
	return CModernDialog::UsesSecondaryText(controlId);
}

void CPage5::OnSize(UINT type, int cx, int cy)
{
	CModernDialog::OnSize(type, cx, cy);
	LayoutAboutPage();
}

void CPage5::LayoutAboutPage()
{
 if (!GetSafeHwnd() || !m_transferInfo.GetSafeHwnd() || m_layout) return;
 CRect client; GetClientRect(&client);
 if (client.Width() <= 0 || client.Height() <= 0) return;
 m_layout = true;
 // As on the profile page, move all overlapping card/row siblings before
 // repainting. Never enable redraw on a hidden page: it would make it visible.
 const BOOL freezeRedraw = IsWindowVisible();
 if (freezeRedraw) SetRedraw(FALSE);
 auto S = [this](int v) { return UiTheme::ScaleForWindow(m_hWnd, v); };
 auto place = [&](UINT id, int x, int y, int w, int h) {
  if (CWnd* c = GetDlgItem(id)) c->SetWindowPos(NULL, x, y - m_scroll, max(0,w), max(0,h), SWP_NOZORDER | SWP_NOACTIVATE);
 };
 const int x = S(8), pad = S(16), width = max(0, client.Width() - x * 2);
 const int inner = max(0, width - pad * 2), right = x + width - pad;
 const int gap = S(8), buttonH = S(30), titleH = S(34);
 place(IDC_STATIC_PAGE_TITLE, x, S(4), width, S(36));
 place(IDC_STATIC_PAGE_SUBTITLE, x, S(38), width, S(18));
 int y = S(62), cardTop = y;
 y += titleH;
 auto buttonWidth = [&](int index) {
  CString label; m_settingsButtons[index].GetWindowText(label);
  CClientDC dc(this); CFont* old = dc.SelectObject(&m_uiFont);
  int w = max(S(92), dc.GetTextExtent(label).cx + S(24)); dc.SelectObject(old); return w;
 };
 auto detailHeight = [&](UINT id, int available) {
  CString text; GetDlgItemText(id, text);
  if (text.IsEmpty()) return 0;
  CClientDC dc(this); CFont* old = dc.SelectObject(&m_smallFont);
  CRect bounds(0, 0, max(1, available), 0);
  dc.DrawText(text, bounds, DT_LEFT | DT_WORDBREAK | DT_NOPREFIX | DT_CALCRECT);
  dc.SelectObject(old); return max(S(18), bounds.Height());
 };
 // The same left-label/right-action rows as the PR; narrow windows wrap actions.
 auto row = [&](UINT title, UINT detail, int first, int second, bool path) {
  const int firstW = buttonWidth(first), secondW = buttonWidth(second);
  const int actions = firstW + gap + secondW;
  const bool stacked = inner - actions - S(10) < S(210);
  const int labelW = stacked ? inner : inner - actions - S(10);
  const int descriptionH = path ? S(18) : detailHeight(detail, labelW);
  const int rowH = max(S(44), S(24) + descriptionH + S(4));
  place(title, x + pad, y + S(4), labelW, S(20));
  place(detail, x + pad, y + S(24), labelW, descriptionH);
  const int actionY = stacked ? y + rowH + S(4) : y + (rowH - buttonH) / 2;
  place(0x2500 + second, right - secondW, actionY, secondW, buttonH);
  place(0x2500 + first, right - actions, actionY, firstW, buttonH);
  y += rowH + (stacked ? buttonH + S(8) : 0) + S(4);
 };
 row(0x2521, 0x2522, 0, 1, true);
 row(0x2526, 0x2527, 2, 3, false);
 y += S(8);
 place(0x2530, x, cardTop, width, y - cardTop);
 y += S(10); cardTop = y; y += titleH;
 place(IDC_STATIC_LANGUAGE_LABEL, x + pad, y + S(12), inner - S(190), S(20));
 place(IDC_COMBO_LANGUAGE, right - S(172), y + S(7), S(172), S(200));
 m_languageCombo.SetItemHeight(-1, S(24));
 y += S(52); place(0x2531, x, cardTop, width, y - cardTop);
 y += S(10); cardTop = y;
 const int checkW = buttonWidth(4), textX = x + pad + S(50);
 place(IDC_ABOUT_ICON, x + pad, y + S(12), S(40), S(40));
 place(IDC_ABOUT_NAME, textX, y + S(10), inner - S(50) - checkW - gap, S(22));
 place(IDC_STATIC_ABOUT_VERSION, textX, y + S(32), inner - S(50) - checkW - gap, S(20));
 place(0x2504, right - checkW, y + S(16), checkW, buttonH);
 GetDlgItem(IDC_STATIC_ABOUT_TAGLINE)->ShowWindow(SW_HIDE);
 y += S(60);
 CString updateText; m_updateInfo.GetWindowText(updateText);
 const int updateH = updateText.IsEmpty() ? 0 : max(S(20), (int)m_updateInfo.SendMessage(LM_GETIDEALHEIGHT, max(1, inner), 0));
 m_updateInfo.ShowWindow(updateH ? SW_SHOWNA : SW_HIDE);
 if (updateH) { place(0x2524, x + pad, y, inner, updateH); y += updateH + S(4); }
 CClientDC linkDc(this); CFont* oldLinkFont = linkDc.SelectObject(&m_uiFont);
 CString projectLabel; GetDlgItemText(IDC_STATIC_PROJECT_LABEL, projectLabel);
 const int labelW = max(linkDc.GetTextExtent(projectLabel).cx, linkDc.GetTextExtent(Localization::Get(L"page5.download_site")).cx) + S(12);
 linkDc.SelectObject(oldLinkFont);
 place(IDC_STATIC_PROJECT_LABEL, x + pad, y + S(2), labelW, S(20));
 place(IDC_LINK_PROJECT, x + pad + labelW, y, inner - labelW, S(22)); y += S(24);
 place(0x2528, x + pad, y + S(2), labelW, S(20));
 place(0x2529, x + pad + labelW, y, inner - labelW, S(22)); y += S(24);
 place(IDC_ABOUT_COPYRIGHT, x + pad, y, inner, S(20)); y += S(28);
 GetDlgItem(IDC_STATIC_OPEN_SOURCE_GROUP)->ShowWindow(SW_SHOWNA);
 place(IDC_STATIC_OPEN_SOURCE_GROUP, x, cardTop, width, y - cardTop);
 y += S(8);
 const int next = min(m_scroll, max(0, y - client.Height()));
 SCROLLINFO info = { sizeof(info), SIF_RANGE | SIF_PAGE | SIF_POS, 0, y - 1, (UINT)max(0,client.Height()), next };
 SetScrollInfo(SB_VERT, &info, TRUE);
 CRect after; GetClientRect(&after);
 bool again = next != m_scroll || after.Width() != client.Width(); m_scroll = next;
 if (freezeRedraw) SetRedraw(TRUE);
 m_layout = false;
 if (again) LayoutAboutPage();
 else RedrawWindow(NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME);
}
void CPage5::OnVScroll(UINT code, UINT, CScrollBar*)
{
 SCROLLINFO info = {sizeof(info), SIF_ALL}; GetScrollInfo(SB_VERT, &info);
 int pos = m_scroll, step = UiTheme::ScaleForWindow(m_hWnd, 30);
 switch (code) {
 case SB_LINEUP: pos -= step; break; case SB_LINEDOWN: pos += step; break;
 case SB_PAGEUP: pos -= info.nPage; break; case SB_PAGEDOWN: pos += info.nPage; break;
 case SB_THUMBTRACK: case SB_THUMBPOSITION: pos = info.nTrackPos; break;
 case SB_TOP: pos = 0; break; case SB_BOTTOM: pos = info.nMax; break;
 }
 m_scroll = max(0, min(pos, info.nMax - (int)info.nPage + 1)); LayoutAboutPage();
}
BOOL CPage5::OnMouseWheel(UINT, short delta, CPoint)
{
 m_scroll = max(0, m_scroll - MulDiv(delta, UiTheme::ScaleForWindow(m_hWnd, 60), WHEEL_DELTA));
 LayoutAboutPage(); return TRUE;
}
void CPage5::ReportStorageError(DWORD error, const CString& path)
{
 CString reason = ConfigStorage::ErrorText(error);
 MessageBox(Localization::Format(L"storage.save_failed", (LPCTSTR)reason, (LPCTSTR)(path.IsEmpty() ? ConfigStorage::Path() : path)),
  Localization::Get(L"settings.data"), MB_ICONERROR);
}
namespace
{
 const UINT_PTR kUpdateTimer = 0x2506;
 const DWORD kCheckTimeout = 60 * 1000, kDownloadTimeout = 20 * 60 * 1000;
 const wchar_t kSetupWaitingMutex[] = L"ProxyLaneSetupWaiting";
 // Waits for a helper started by CPage3::StartUpdateHelper and owns its handle.
 bool WaitHelper(HANDLE process, DWORD timeout)
 {
  DWORD code = UpdateHelper::EXIT_NETWORK;
  if (WaitForSingleObject(process, timeout) != WAIT_OBJECT_0) TerminateProcess(process, UpdateHelper::EXIT_NETWORK);
  else if (!GetExitCodeProcess(process, &code)) code = UpdateHelper::EXIT_NETWORK;
  CloseHandle(process);
  return code == UpdateHelper::EXIT_OK;
 }
 bool MatchesRelease(const CString& file, const UpdateOutcome& release)
 {
  std::string digest; unsigned long long size = 0;
  return UpdateHelper::Sha256File(file, digest, size) && size == release.size && digest == release.sha256;
 }
}
CString CPage5::UpdateRouteText() const
{
 return m_updateViaProxy && g_MainTab ? Localization::Format(L"update.route_proxy", (LPCWSTR)g_MainTab->GetRunningProfileName())
  : Localization::Get(L"update.route_direct");
}
void CPage5::StartUpdateCheck()
{
 CPage3* page3 = g_MainTab ? g_MainTab->GetPage3() : NULL;
 // Setup programs from earlier updates are no longer in use by now.
 UpdateHelper::CleanWorkDirectory(m_installerFile);
 const CString directory = UpdateHelper::WorkDirectory();
 CString output; output.Format(L"%s\\release-%lu-%lu.json", (LPCWSTR)directory, GetCurrentProcessId(), GetTickCount());
 HANDLE process = NULL; BOOL proxied = FALSE;
 if (!page3 || directory.IsEmpty() ||
  !page3->StartUpdateHelper(UpdateHelper::BuildArguments(UpdateHelper::RELEASE_METADATA, CString(), output), process, &proxied)) {
  SetUpdateStatus(Localization::Get(proxied ? L"update.proxy_start_failed" : L"settings.update_failed"), false, true);
  return;
 }
 m_updateViaProxy = proxied != FALSE;
 const bool requested = m_updateQuery.Request([process, output](UpdateOutcome& outcome) {
  const bool finished = WaitHelper(process, kCheckTimeout);
  std::string body, tag; UpdateRelease::Installer installer;
  const bool ok = finished && UpdateHelper::ReadSmallFile(output, body, UpdateRelease::MaxResponseBytes) &&
   UpdateRelease::Parse(body, tag, &installer);
  DeleteFile(output);
  if (!ok) return false;
  outcome.version = CString(tag.c_str());
  outcome.assetPath = installer.path; outcome.sha256 = installer.sha256; outcome.size = installer.size;
  return true;
 });
 if (!requested) { WaitHelper(process, 0); SetUpdateStatus(Localization::Get(L"settings.update_failed"), false, true); return; }
 m_updateStage = UPDATE_CHECKING;
 m_settingsButtons[4].EnableWindow(FALSE);
 SetUpdateStatus(Localization::Get(L"settings.checking"));
 SetTimer(kUpdateTimer, 100, NULL);
}
void CPage5::FinishUpdateCheck(std::unique_ptr<AsyncSnapshot<UpdateOutcome>::Result> result)
{
 m_updateStage = UPDATE_IDLE;
 UpdateRelease::VersionParts latest, current;
 if (!result || !result->succeeded || !UpdateRelease::Version((LPCSTR)CStringA(result->value.version), latest) || !UpdateRelease::Version((LPCSTR)CStringA(AppVersion::DisplayVersion()), current)) {
  SetUpdateStatus(Localization::Get(m_updateViaProxy ? L"update.check_failed_proxy" : L"settings.update_failed"), false, true); return;
 }
 if (!(latest > current)) { SetUpdateStatus(Localization::Get(L"settings.up_to_date")); return; }
 m_release = result->value;
 // Only an installed copy updates in place; a zip copy keeps its own folder.
 const bool install = !m_release.assetPath.empty() && UpdateHelper::IsInstalledCopy();
 m_updateStage = install ? UPDATE_FOUND_INSTALLER : UPDATE_FOUND_SITE;
 SetUpdateStatus(Localization::Format(install ? L"update.found_install" : L"settings.update_found", (LPCWSTR)m_release.version), true);
}
void CPage5::StartInstallerDownload()
{
 if (m_updateQuery.Busy()) return;
 CPage3* page3 = g_MainTab ? g_MainTab->GetPage3() : NULL;
 m_updateViaProxy = g_MainTab && g_MainTab->IsProxyRunning();
 CString megabytes; megabytes.Format(L"%.1f", m_release.size / (1024.0 * 1024.0));
 if (MessageBox(Localization::Format(L"update.download_confirm", (LPCWSTR)m_release.version, (LPCWSTR)megabytes, (LPCWSTR)UpdateRouteText()),
  Localization::Get(L"update.title"), MB_OKCANCEL | MB_ICONQUESTION) != IDOK) return;
 const CString directory = UpdateHelper::WorkDirectory();
 const CString output = directory + L"\\" + CString(UpdateRelease::InstallerName((LPCSTR)CStringA(m_release.version)).c_str());
 HANDLE process = NULL; BOOL proxied = FALSE;
 if (!page3 || directory.IsEmpty() || !page3->StartUpdateHelper(
  UpdateHelper::BuildArguments(UpdateHelper::INSTALLER, CString(m_release.assetPath.c_str()), output), process, &proxied)) {
  SetUpdateStatus(Localization::Get(proxied ? L"update.proxy_start_failed" : L"update.download_failed"), false, true);
  return;
 }
 m_updateViaProxy = proxied != FALSE;
 const UpdateOutcome expected = m_release;
 const bool requested = m_updateQuery.Request([process, output, expected](UpdateOutcome& outcome) {
  const bool ok = WaitHelper(process, kDownloadTimeout) && MatchesRelease(output, expected);
  if (!ok) { DeleteFile(output); return false; }
  outcome = expected; outcome.file = output;
  return true;
 });
 if (!requested) { WaitHelper(process, 0); SetUpdateStatus(Localization::Get(L"update.download_failed"), false, true); return; }
 m_updateStage = UPDATE_DOWNLOADING;
 m_settingsButtons[4].EnableWindow(FALSE);
 SetUpdateStatus(Localization::Format(L"update.downloading", (LPCWSTR)m_release.version, (LPCWSTR)megabytes, (LPCWSTR)UpdateRouteText()));
 SetTimer(kUpdateTimer, 200, NULL);
}
void CPage5::FinishInstallerDownload(std::unique_ptr<AsyncSnapshot<UpdateOutcome>::Result> result)
{
 if (!result || !result->succeeded) {
  // Keep the stage so that clicking the link again retries the download.
  m_updateStage = UPDATE_FOUND_INSTALLER;
  SetUpdateStatus(Localization::Format(m_updateViaProxy ? L"update.download_failed_proxy_retry" : L"update.download_failed_retry",
   (LPCWSTR)m_release.version), true);
  return;
 }
 m_installerFile = result->value.file;
 m_updateStage = UPDATE_READY;
 SetUpdateStatus(Localization::Format(L"update.ready", (LPCWSTR)m_release.version), true);
 OfferInstall();
}
void CPage5::OfferInstall()
{
 if (m_updateStage != UPDATE_READY || m_installerFile.IsEmpty()) return;
 if (MessageBox(Localization::Format(L"update.install_confirm", (LPCWSTR)m_release.version),
  Localization::Get(L"update.title"), MB_OKCANCEL | MB_ICONQUESTION) != IDOK) return;
 // theApp's main window is always the modal CProxyLaneDlg.
 CProxyLaneDlg* main = static_cast<CProxyLaneDlg*>(AfxGetMainWnd());
 if (!main) return;
 const CString file = m_installerFile;
 const UpdateOutcome expected = m_release;
 bool verified = true;
 const BOOL exiting = main->ExitForUpdate([&]() -> BOOL {
  // Verify again just before execution; the file sits in a user-writable folder.
  if (!MatchesRelease(file, expected)) { verified = false; return FALSE; }
  const CString parameters = UpdateHelper::InstallerParameters();
  SHELLEXECUTEINFO info = { sizeof(info) };
  info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  info.hwnd = main->GetSafeHwnd(); info.lpFile = file;
  info.lpParameters = parameters; info.nShow = SW_SHOWNORMAL;
  if (!ShellExecuteEx(&info) || !info.hProcess) return FALSE;
  // Setup elevates itself and then announces that it waits for ProxyLane to
  // exit. If elevation is declined, the setup process ends first instead.
  main->EnableWindow(FALSE);
  BOOL started = FALSE;
  const DWORD begin = GetTickCount();
  while (GetTickCount() - begin < 5 * 60 * 1000) {
   HANDLE ready = OpenMutex(SYNCHRONIZE, FALSE, kSetupWaitingMutex);
   // An elevated setup's mutex may deny us access; it still exists.
   if (ready || GetLastError() == ERROR_ACCESS_DENIED) { if (ready) CloseHandle(ready); started = TRUE; break; }
   if (MsgWaitForMultipleObjects(1, &info.hProcess, FALSE, 200, QS_ALLINPUT) == WAIT_OBJECT_0) break;
   MSG message;
   while (PeekMessage(&message, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&message); DispatchMessage(&message); }
  }
  main->EnableWindow(TRUE);
  CloseHandle(info.hProcess);
  return started;
 });
 if (exiting) return;
 if (!verified) {
  DeleteFile(file); m_installerFile.Empty();
  m_updateStage = UPDATE_FOUND_INSTALLER;
  SetUpdateStatus(Localization::Format(L"update.verify_failed", (LPCWSTR)m_release.version), true);
  return;
 }
 SetUpdateStatus(Localization::Format(L"update.install_not_started", (LPCWSTR)m_release.version), true);
}
void CPage5::OnSettingsAction(UINT id)
{
 CPage1* page = g_MainTab ? g_MainTab->GetPage1() : NULL;
 if (!page) return;
 switch (id - 0x2500) {
 case 0: ShellExecute(m_hWnd, L"open", ConfigStorage::Directory(ConfigStorage::Path()), NULL, NULL, SW_SHOWNORMAL); break;
 case 1: SwitchStorage(); break;
 case 2: page->OnImportAllConfig(); break;
 case 3: {
  if (page->HasUnsavedProfileChanges()) {
   int answer = MessageBox(Localization::Get(L"settings.export_draft"), Localization::Get(L"settings.export"), MB_YESNOCANCEL | MB_ICONQUESTION);
   if (answer == IDCANCEL || (answer == IDYES && !page->SavePendingProfile())) break;
  }
  CFileDialog picker(FALSE, L"ini", L"ProxyLane.ini", OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR, L"INI files (*.ini)|*.ini||", this);
  if (picker.DoModal() != IDOK) break;
  ConfigStorage::Lock lock(ConfigStorage::Path());
  if (!lock.Valid() || !ConfigStorage::Update(picker.GetPathName(), [](const CString& staged) { return CopyFile(ConfigStorage::Path(), staged, FALSE) != FALSE; })) ReportStorageError(GetLastError(), picker.GetPathName());
  break;
 }
 case 4:
  if (!m_updateQuery.Busy()) StartUpdateCheck();
  break;
 }
}
void CPage5::OnTimer(UINT_PTR id)
{
 if (id != kUpdateTimer) { CModernDialog::OnTimer(id); return; }
 auto result = m_updateQuery.Take(); if (!result && m_updateQuery.Busy()) return;
 KillTimer(id); m_settingsButtons[4].EnableWindow(TRUE);
 if (m_updateStage == UPDATE_DOWNLOADING) FinishInstallerDownload(std::move(result));
 else FinishUpdateCheck(std::move(result));
}
void CPage5::SwitchStorage()
{
 CPage1* page = g_MainTab->GetPage1();
 if (theApp.HasPendingConfigImport() || !page->CanImportAllConfig()) return;
 bool portable = ConfigStorage::Path().CompareNoCase(ConfigStorage::PortablePath()) == 0;
 CString target = portable ? ConfigStorage::UserPath() : ConfigStorage::PortablePath();
 if (target.IsEmpty()) { ReportStorageError(ERROR_PATH_NOT_FOUND); return; }
 CString title = Localization::Get(portable ? L"settings.use_user" : L"settings.use_portable");
 CString summary = Localization::Format(L"settings.switch_confirm", (LPCTSTR)target);
 if (MessageBox(summary, title, MB_OKCANCEL | MB_ICONQUESTION | MB_DEFBUTTON2) != IDOK) return;
 if (page->HasUnsavedProfileChanges() && !page->ConfirmDiscardUnsavedChanges()) return;
 std::unique_ptr<ConfigImport::Pending> pending(new ConfigImport::Pending);
 CString error;
 if (!pending->PrepareStorageSwitch(!portable, error) || !pending->ArmRestart(error)) {
  MessageBox(error, title, MB_ICONERROR); return;
 }
 theApp.ScheduleConfigImport(std::move(pending));
 GetTopLevelParent()->SendMessage(WM_CONFIG_IMPORT_RESTART);
}
