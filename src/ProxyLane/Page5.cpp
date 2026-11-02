#include "stdafx.h"
#include "ProxyLane.h"
#include "Page5.h"
#include "MainTab.h"
#include "AppVersion.h"
#include "ConfigLocation.h"
#include "ConfigLocationPolicy.h"
#include "Localization.h"
#include <wininet.h>
#include <process.h>
#include <algorithm>
#include <string>
#include <vector>
#pragma comment(lib, "wininet.lib")

IMPLEMENT_DYNAMIC(CPage5, CModernDialog)

namespace
{
	LPCTSTR kProjectUrl = _T("https://github.com/threatexpert/ProxyLane");
	LPCTSTR kReleasesUrl = _T("https://github.com/threatexpert/ProxyLane/releases/latest");
	LPCTSTR kRunKey = _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
	LPCTSTR kRunValue = _T("ProxyLane");
	const UINT WM_UPDATE_RESULT = WM_APP + 330;

	enum
	{
		IDC_S_CARD_CONFIG = 0x2400, IDC_S_CARD_STARTUP,
		IDC_S_OPEN_DIR, IDC_S_RESTORE, IDC_S_IMPORT, IDC_S_EXPORT,
		IDC_S_AUTOSTART, IDC_S_AUTOENABLE, IDC_S_DARK, IDC_S_LIGHT, IDC_S_CHECK_UPDATE,
		IDC_S_TITLE_FIRST = 0x2420, IDC_S_DETAIL_FIRST = 0x2440
	};
	enum { ROW_LOCATION, ROW_BACKUP, ROW_TRANSFER, ROW_AUTOSTART, ROW_AUTOENABLE, ROW_APPEARANCE, ROW_COUNT };

	CString ExecutablePath()
	{
		TCHAR path[MAX_PATH] = { 0 };
		::GetModuleFileName(NULL, path, _countof(path));
		return path;
	}

	BOOL IsAutostartEnabled()
	{
		HKEY key = NULL;
		if (RegOpenKeyEx(HKEY_CURRENT_USER, kRunKey, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return FALSE;
		const BOOL present = RegQueryValueEx(key, kRunValue, NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
		RegCloseKey(key);
		return present;
	}

	BOOL SetAutostart(BOOL enabled)
	{
		HKEY key = NULL;
		if (RegOpenKeyEx(HKEY_CURRENT_USER, kRunKey, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) return FALSE;
		LONG result;
		if (enabled)
		{
			CString command;
			command.Format(_T("\"%s\" --background"), static_cast<LPCTSTR>(ExecutablePath()));
			result = RegSetValueEx(key, kRunValue, 0, REG_SZ, reinterpret_cast<const BYTE*>(static_cast<LPCTSTR>(command)),
				(command.GetLength() + 1) * sizeof(TCHAR));
		}
		else
		{
			result = RegDeleteValue(key, kRunValue);
			if (result == ERROR_FILE_NOT_FOUND) result = ERROR_SUCCESS;
		}
		RegCloseKey(key);
		return result == ERROR_SUCCESS;
	}

	std::vector<int> VersionParts(CString text)
	{
		text.TrimLeft(_T("vV"));
		std::vector<int> parts;
		int position = 0;
		CString token = text.Tokenize(_T("."), position);
		while (!token.IsEmpty())
		{
			parts.push_back(_ttoi(token));
			token = text.Tokenize(_T("."), position);
		}
		return parts;
	}

	BOOL IsNewerVersion(const CString& candidate, const CString& current)
	{
		const std::vector<int> a = VersionParts(candidate), b = VersionParts(current);
		for (size_t i = 0; i < max(a.size(), b.size()); ++i)
		{
			const int left = i < a.size() ? a[i] : 0, right = i < b.size() ? b[i] : 0;
			if (left != right) return left > right;
		}
		return FALSE;
	}

	// Only runs when the user presses the button; nothing is contacted otherwise.
	unsigned __stdcall UpdateCheckThread(void* argument)
	{
		const HWND window = reinterpret_cast<HWND>(argument);
		CString* tag = new CString;
		if (HINTERNET session = InternetOpen(_T("ProxyLane"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0))
		{
			const DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE;
			if (HINTERNET request = InternetOpenUrl(session, _T("https://api.github.com/repos/threatexpert/ProxyLane/releases/latest"), NULL, 0, flags, 0))
			{
				std::string body;
				char buffer[4096];
				DWORD read = 0;
				while (body.size() < 256 * 1024 && InternetReadFile(request, buffer, sizeof(buffer), &read) && read)
					body.append(buffer, read);
				const std::string key = "\"tag_name\"";
				size_t at = body.find(key);
				if (at != std::string::npos && (at = body.find('"', body.find(':', at))) != std::string::npos)
				{
					const size_t end = body.find('"', at + 1);
					if (end != std::string::npos)
						*tag = CString(body.substr(at + 1, end - at - 1).c_str());
				}
				InternetCloseHandle(request);
			}
			InternetCloseHandle(session);
		}
		if (!::PostMessage(window, WM_UPDATE_RESULT, 0, reinterpret_cast<LPARAM>(tag)))
			delete tag;
		return 0;
	}
}

CPage5::CPage5(CWnd* parent)
	: CModernDialog(CPage5::IDD, parent)
	, m_aboutIcon(NULL)
	, m_updateFound(FALSE)
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
	// The about card needs no heading; its first line is the program name.
	m_openSourceCard.SetWindowText(_T(""));
	UiTheme::CreateUiFont(m_smallFont, m_hWnd, 8, FW_NORMAL);
	UiTheme::CreateUiFont(m_boldFont, m_hWnd, 10, FW_BOLD);
	if (CWnd* name = GetDlgItem(IDC_ABOUT_NAME))
		name->SetFont(&m_boldFont, FALSE);

	const DWORD child = WS_CHILD | WS_VISIBLE;
	const DWORD button = child | WS_TABSTOP | BS_OWNERDRAW;
	m_cardConfig.Create(Localization::Get(_T("settings.config_title")), child | BS_GROUPBOX, CRect(), this, IDC_S_CARD_CONFIG);
	m_cardStartup.Create(Localization::Get(_T("settings.startup_title")), child | BS_GROUPBOX, CRect(), this, IDC_S_CARD_STARTUP);
	m_cardConfig.SetFont(&m_uiFont);
	m_cardStartup.SetFont(&m_uiFont);

	LPCTSTR titleKeys[ROW_COUNT] = { _T("settings.location"), _T("settings.backup"), _T("settings.transfer"), _T("settings.autostart"), _T("settings.autoenable"), _T("settings.appearance") };
	LPCTSTR detailKeys[ROW_COUNT] = { NULL, _T("settings.backup_detail"), _T("settings.transfer_detail"), _T("settings.autostart_detail"), _T("settings.autoenable_detail"), NULL };
	for (int i = 0; i < ROW_COUNT; ++i)
	{
		m_rowTitle[i].Create(Localization::Get(titleKeys[i]), child | SS_NOPREFIX, CRect(), this, IDC_S_TITLE_FIRST + i);
		m_rowTitle[i].SetFont(&m_uiFont);
		m_rowDetail[i].Create(detailKeys[i] ? static_cast<LPCTSTR>(Localization::Get(detailKeys[i])) : _T(""), child | SS_NOPREFIX | SS_PATHELLIPSIS, CRect(), this, IDC_S_DETAIL_FIRST + i);
		m_rowDetail[i].SetFont(&m_smallFont);
	}
	m_rowDetail[ROW_LOCATION].SetWindowText(ConfigLocation::SettingsPath());

	struct { CModernButton& control; LPCTSTR key; UINT id; } buttons[] = {
		{ m_btnOpenDir, _T("settings.open_dir"), IDC_S_OPEN_DIR },
		{ m_btnRestore, _T("settings.restore"), IDC_S_RESTORE },
		{ m_btnImport, _T("settings.import"), IDC_S_IMPORT },
		{ m_btnExport, _T("settings.export"), IDC_S_EXPORT },
	};
	for (size_t i = 0; i < _countof(buttons); ++i)
	{
		buttons[i].control.Create(Localization::Get(buttons[i].key), button, CRect(), this, buttons[i].id);
		buttons[i].control.SetFont(&m_uiFont);
	}
	m_toggleAutostart.Create(_T(""), child | WS_TABSTOP | BS_AUTOCHECKBOX, CRect(), this, IDC_S_AUTOSTART);
	m_toggleAutoEnable.Create(_T(""), child | WS_TABSTOP | BS_AUTOCHECKBOX, CRect(), this, IDC_S_AUTOENABLE);
	m_toggleAutostart.SetCheck(IsAutostartEnabled() ? BST_CHECKED : BST_UNCHECKED);
	m_toggleAutoEnable.SetCheck(GetPrivateProfileInt(_T("options"), _T("AutoEnableProfile"), 0, ConfigLocation::SettingsPath()) == 1 ? BST_CHECKED : BST_UNCHECKED);
	m_radioDark.Create(Localization::Get(_T("settings.dark")), child | WS_TABSTOP | WS_GROUP | BS_AUTORADIOBUTTON, CRect(), this, IDC_S_DARK);
	m_radioLight.Create(Localization::Get(_T("settings.light")), child | WS_TABSTOP | BS_AUTORADIOBUTTON, CRect(), this, IDC_S_LIGHT);
	m_radioDark.SetFont(&m_uiFont);
	m_radioLight.SetFont(&m_uiFont);
	m_btnCheckUpdate.Create(Localization::Get(_T("settings.check_update")), button | WS_GROUP, CRect(), this, IDC_S_CHECK_UPDATE);
	m_btnCheckUpdate.SetFont(&m_uiFont);
	SyncThemeButtons();

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
	ON_WM_SIZE()
	ON_WM_SHOWWINDOW()
	ON_NOTIFY(NM_CLICK, IDC_LINK_PROJECT, &CPage5::OnProjectLink)
	ON_NOTIFY(NM_RETURN, IDC_LINK_PROJECT, &CPage5::OnProjectLink)
	ON_CBN_SELCHANGE(IDC_COMBO_LANGUAGE, &CPage5::OnLanguageChanged)
	ON_BN_CLICKED(IDC_S_OPEN_DIR, &CPage5::OnOpenDirectory)
	ON_BN_CLICKED(IDC_S_RESTORE, &CPage5::OnRestoreBackup)
	ON_BN_CLICKED(IDC_S_IMPORT, &CPage5::OnImportAll)
	ON_BN_CLICKED(IDC_S_EXPORT, &CPage5::OnExportAll)
	ON_BN_CLICKED(IDC_S_AUTOSTART, &CPage5::OnAutostart)
	ON_BN_CLICKED(IDC_S_AUTOENABLE, &CPage5::OnAutoEnable)
	ON_BN_CLICKED(IDC_S_DARK, &CPage5::OnThemeChanged)
	ON_BN_CLICKED(IDC_S_LIGHT, &CPage5::OnThemeChanged)
	ON_BN_CLICKED(IDC_S_CHECK_UPDATE, &CPage5::OnCheckUpdate)
	ON_MESSAGE(WM_UPDATE_RESULT, &CPage5::OnUpdateResult)
END_MESSAGE_MAP()

void CPage5::SyncThemeButtons()
{
	m_radioDark.SetCheck(UiTheme::IsDark() ? BST_CHECKED : BST_UNCHECKED);
	m_radioLight.SetCheck(UiTheme::IsDark() ? BST_UNCHECKED : BST_CHECKED);
}

void CPage5::OnShowWindow(BOOL show, UINT status)
{
	CModernDialog::OnShowWindow(show, status);
	if (show && m_radioDark.GetSafeHwnd())
		SyncThemeButtons();
}

void CPage5::OnThemeChanged()
{
	const BOOL dark = m_radioDark.GetCheck() == BST_CHECKED;
	if (dark != UiTheme::IsDark() && g_MainTab)
		g_MainTab->ToggleTheme();
}

void CPage5::OnOpenDirectory()
{
	const std::wstring directory = ConfigLocationPolicy::DirectoryOf(static_cast<LPCWSTR>(ConfigLocation::SettingsPath()));
	ShellExecute(m_hWnd, _T("open"), directory.c_str(), NULL, NULL, SW_SHOWNORMAL);
}

void CPage5::OnRestoreBackup()
{
	const std::wstring directory = ConfigLocationPolicy::DirectoryOf(static_cast<LPCWSTR>(ConfigLocation::SettingsPath())) + L"\\backups";
	std::vector<CString> names;
	WIN32_FIND_DATA found;
	HANDLE search = FindFirstFile((directory + L"\\ProxyLane-*.ini").c_str(), &found);
	if (search != INVALID_HANDLE_VALUE)
	{
		do { names.push_back(found.cFileName); } while (FindNextFile(search, &found));
		FindClose(search);
	}
	if (names.empty())
	{
		if (g_MainTab) g_MainTab->ShowTransientStatus(Localization::Get(_T("settings.no_backups")), CStatusLabel::TONE_NEUTRAL);
		return;
	}
	std::sort(names.begin(), names.end());
	std::reverse(names.begin(), names.end());
	CMenu menu;
	menu.CreatePopupMenu();
	for (size_t i = 0; i < names.size(); ++i)
	{
		// ProxyLane-YYYYMMDD-HHMMSS.ini reads better as a timestamp.
		CString name = names[i];
		CString label = name;
		if (name.GetLength() >= 29)
			label = name.Mid(10, 4) + _T("-") + name.Mid(14, 2) + _T("-") + name.Mid(16, 2) + _T(" ") + name.Mid(19, 2) + _T(":") + name.Mid(21, 2) + _T(":") + name.Mid(23, 2);
		menu.AppendMenu(MF_STRING, i + 1, label);
	}
	CRect rect;
	m_btnRestore.GetWindowRect(&rect);
	const int choice = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_RIGHTALIGN | TPM_RIGHTBUTTON, rect.right, rect.bottom, this);
	if (choice > 0 && g_MainTab)
		g_MainTab->GetPage1()->ImportConfigFromFile(CString(directory.c_str()) + _T("\\") + names[choice - 1]);
}

void CPage5::OnImportAll()
{
	if (g_MainTab) g_MainTab->GetPage1()->OnImportAllConfig();
}

void CPage5::OnExportAll()
{
	CFileDialog picker(FALSE, _T("ini"), _T("ProxyLane.ini"), OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR,
		_T("INI files (*.ini)|*.ini||"), this);
	const CString title = Localization::Get(_T("settings.export_title"));
	picker.m_ofn.lpstrTitle = title;
	if (picker.DoModal() != IDOK) return;
	if (!g_MainTab) return;
	if (::CopyFile(ConfigLocation::SettingsPath(), picker.GetPathName(), FALSE))
		g_MainTab->ShowTransientStatus(Localization::Get(_T("settings.export_done")), CStatusLabel::TONE_SUCCESS);
	else
		MessageBox(Localization::Format(_T("settings.export_failed"), GetLastError()), title, MB_ICONERROR);
}

void CPage5::OnAutostart()
{
	const BOOL enabled = m_toggleAutostart.GetCheck() == BST_CHECKED;
	if (!SetAutostart(enabled))
	{
		m_toggleAutostart.SetCheck(enabled ? BST_UNCHECKED : BST_CHECKED);
		MessageBox(Localization::Get(_T("settings.autostart_failed")), Localization::Get(_T("settings.autostart")), MB_ICONERROR);
	}
}

void CPage5::OnAutoEnable()
{
	const BOOL enabled = m_toggleAutoEnable.GetCheck() == BST_CHECKED;
	if (!::WritePrivateProfileString(_T("options"), _T("AutoEnableProfile"), enabled ? _T("1") : _T("0"), ConfigLocation::SettingsPath()))
	{
		m_toggleAutoEnable.SetCheck(enabled ? BST_UNCHECKED : BST_CHECKED);
		MessageBox(Localization::Format(_T("profile.save_write_failed"), static_cast<LPCTSTR>(ConfigLocation::SettingsPath())),
			Localization::Get(_T("profile.save_failed_title")), MB_ICONERROR);
	}
}

void CPage5::OnCheckUpdate()
{
	if (m_updateFound)
	{
		ShellExecute(m_hWnd, _T("open"), kReleasesUrl, NULL, NULL, SW_SHOWNORMAL);
		return;
	}
	m_btnCheckUpdate.EnableWindow(FALSE);
	m_btnCheckUpdate.SetWindowText(Localization::Get(_T("settings.checking")));
	HANDLE thread = reinterpret_cast<HANDLE>(_beginthreadex(NULL, 0, UpdateCheckThread, m_hWnd, 0, NULL));
	if (thread)
	{
		CloseHandle(thread);
	}
	else
	{
		m_btnCheckUpdate.EnableWindow(TRUE);
		m_btnCheckUpdate.SetWindowText(Localization::Get(_T("settings.check_update")));
	}
}

LRESULT CPage5::OnUpdateResult(WPARAM, LPARAM value)
{
	CString* tag = reinterpret_cast<CString*>(value);
	const CString latest = *tag;
	delete tag;
	const CString current = AppVersion::DisplayVersion();
	m_btnCheckUpdate.EnableWindow(TRUE);
	m_btnCheckUpdate.SetWindowText(Localization::Get(_T("settings.check_update")));
	CString versionText = Localization::Format(_T("page5.version_value"), static_cast<LPCTSTR>(current));
	if (latest.IsEmpty())
	{
		versionText += _T("  ") + Localization::Get(_T("settings.update_failed"));
	}
	else if (IsNewerVersion(latest, current))
	{
		m_updateFound = TRUE;
		versionText += _T("  ") + Localization::Format(_T("settings.update_available"), static_cast<LPCTSTR>(latest));
		m_btnCheckUpdate.SetWindowText(Localization::Get(_T("settings.open_download")));
	}
	else
	{
		versionText += _T("  ") + Localization::Get(_T("settings.up_to_date"));
	}
	SetDlgItemText(IDC_STATIC_ABOUT_VERSION, versionText);
	return 0;
}

void CPage5::OnLanguageChanged()
{
	static LPCTSTR values[] = { _T("auto"), _T("zh-CN"), _T("en-US") };
	int selection = m_languageCombo.GetCurSel();
	if (selection < 0 || selection >= _countof(values))
		return;
	Localization::SetPreferredLanguage(values[selection]);
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

BOOL CPage5::UsesSecondaryText(UINT controlId) const
{
	if (controlId >= IDC_S_DETAIL_FIRST && controlId < IDC_S_DETAIL_FIRST + ROW_COUNT)
		return TRUE;
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
	if (!GetSafeHwnd() || !m_btnCheckUpdate.GetSafeHwnd())
		return;
	CRect client;
	GetClientRect(&client);
	if (client.Width() <= 0)
		return;

	auto S = [this](int value) { return UiTheme::ScaleForWindow(m_hWnd, value); };
	auto place = [this](UINT id, int x, int y, int width, int height)
	{
		if (CWnd* control = GetDlgItem(id))
			control->SetWindowPos(NULL, x, y, max(0, width), max(0, height), SWP_NOZORDER | SWP_NOACTIVATE);
	};
	const int margin = S(8);
	const int pad = S(16);
	const int width = client.Width() - margin * 2;
	const int x0 = margin;
	const int rowHeight = S(44);
	const int titleHeight = S(34);
	const int buttonHeight = S(30);
	const int inner = width - pad * 2;
	int y = S(62);

	auto placeRow = [&](int row, int top, int rightReserve)
	{
		const int labelWidth = inner - rightReserve - S(10);
		const BOOL hasDetail = m_rowDetail[row].GetWindowTextLength() > 0;
		place(IDC_S_TITLE_FIRST + row, x0 + pad, hasDetail ? top + S(4) : top + (rowHeight - S(20)) / 2, labelWidth, S(20));
		place(IDC_S_DETAIL_FIRST + row, x0 + pad, top + S(24), labelWidth, S(18));
		m_rowDetail[row].ShowWindow(hasDetail ? SW_SHOW : SW_HIDE);
	};
	auto placeButton = [&](UINT id, int right, int top, int buttonWidth)
	{
		place(id, right - buttonWidth, top + (rowHeight - buttonHeight) / 2, buttonWidth, buttonHeight);
		return right - buttonWidth - S(8);
	};
	const int rightEdge = x0 + width - pad;

	// Settings file and backups.
	const int configHeight = titleHeight + rowHeight * 3 + S(8);
	place(IDC_S_CARD_CONFIG, x0, y, width, configHeight);
	int row = y + titleHeight;
	placeRow(ROW_LOCATION, row, S(110));
	placeButton(IDC_S_OPEN_DIR, rightEdge, row, S(100));
	row += rowHeight;
	placeRow(ROW_BACKUP, row, S(110));
	placeButton(IDC_S_RESTORE, rightEdge, row, S(100));
	row += rowHeight;
	placeRow(ROW_TRANSFER, row, S(200));
	const int exportLeft = placeButton(IDC_S_EXPORT, rightEdge, row, S(92));
	placeButton(IDC_S_IMPORT, exportLeft, row, S(92));
	y += configHeight + S(10);

	// Startup, appearance and language.
	const int startupHeight = titleHeight + rowHeight * 4 + S(8);
	place(IDC_S_CARD_STARTUP, x0, y, width, startupHeight);
	row = y + titleHeight;
	const int toggleWidth = S(32), toggleHeight = S(22);
	placeRow(ROW_AUTOSTART, row, S(50));
	place(IDC_S_AUTOSTART, rightEdge - toggleWidth, row + (rowHeight - toggleHeight) / 2, toggleWidth, toggleHeight);
	row += rowHeight;
	placeRow(ROW_AUTOENABLE, row, S(50));
	place(IDC_S_AUTOENABLE, rightEdge - toggleWidth, row + (rowHeight - toggleHeight) / 2, toggleWidth, toggleHeight);
	row += rowHeight;
	placeRow(ROW_APPEARANCE, row, S(180));
	place(IDC_S_LIGHT, rightEdge - S(84), row + (rowHeight - S(28)) / 2, S(84), S(28));
	place(IDC_S_DARK, rightEdge - S(84) * 2 - S(4), row + (rowHeight - S(28)) / 2, S(84), S(28));
	row += rowHeight;
	place(IDC_STATIC_LANGUAGE_LABEL, x0 + pad, row + (rowHeight - S(20)) / 2, inner - S(190), S(20));
	place(IDC_COMBO_LANGUAGE, rightEdge - S(172), row + (rowHeight - S(30)) / 2, S(172), S(200));
	m_languageCombo.SetItemHeight(-1, S(24));
	y += startupHeight + S(10);

	// About.
	const int aboutHeight = S(112);
	place(IDC_STATIC_OPEN_SOURCE_GROUP, x0, y, width, aboutHeight);
	place(IDC_ABOUT_ICON, x0 + pad, y + S(12), S(40), S(40));
	const int textX = x0 + pad + S(50);
	place(IDC_ABOUT_NAME, textX, y + S(10), S(200), S(22));
	place(IDC_STATIC_ABOUT_VERSION, textX, y + S(32), width - S(50) - pad * 2 - S(110), S(20));
	place(IDC_S_CHECK_UPDATE, rightEdge - S(100), y + S(16), S(100), buttonHeight);
	if (CWnd* tagline = GetDlgItem(IDC_STATIC_ABOUT_TAGLINE)) tagline->ShowWindow(SW_HIDE);
	place(IDC_STATIC_PROJECT_LABEL, x0 + pad, y + S(62), S(72), S(20));
	place(IDC_LINK_PROJECT, x0 + pad + S(76), y + S(60), inner - S(76), S(22));
	place(IDC_ABOUT_COPYRIGHT, x0 + pad, y + S(84), inner, S(20));
	RedrawWindow(NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}
