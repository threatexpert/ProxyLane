#include "stdafx.h"
#include "LaunchPanel.h"
#include <iostream>
#include <stdexcept>

// Exercise real control message handling in a hidden, test-owned window.
// No user windows, apps, or configuration files are touched.
namespace {
void Check(bool condition, const char* name) {
    if (!condition) throw std::runtime_error(name);
    std::cout << "PASS: " << name << '\n';
}
class Panel : public CLaunchPanel {
public:
    UINT menuCommand = 0, menuDefault = 0;
    bool menuSeen = false, adminAvailable = false, menuTimedOut = false;
    LRESULT WindowProc(UINT message, WPARAM wp, LPARAM lp) override {
        if (message == WM_INITMENUPOPUP) {
            HMENU menu = reinterpret_cast<HMENU>(wp);
            menuSeen = true;
            menuDefault = GetMenuDefaultItem(menu, FALSE, 0);
            adminAvailable = GetMenuState(menu, 2, MF_BYCOMMAND) != static_cast<UINT>(-1);
            // Drive this test-owned native popup through its menu-character
            // handler; never send global keyboard/mouse input.
            PostMessage(menuCommand ? WM_CHAR : WM_KEYDOWN, menuCommand ? L'~' : VK_ESCAPE);
        }
        if (message == WM_MENUCHAR && LOWORD(wp) == L'~') {
            HMENU menu = reinterpret_cast<HMENU>(lp);
            for (int i = 0; i < GetMenuItemCount(menu); ++i)
                if (GetMenuItemID(menu, i) == menuCommand)
                    return MAKELRESULT(i, MNC_EXECUTE);
            return MAKELRESULT(0, MNC_CLOSE);
        }
        if (message == WM_TIMER && wp == 99) { menuTimedOut = true; ::EndMenu(); return 0; }
        return CLaunchPanel::WindowProc(message, wp, lp);
    }
    void Menu(UINT command, CPoint point = CPoint(-1, -1)) {
        menuCommand = command; menuSeen = menuTimedOut = false;
        SetTimer(99, 3000, NULL);
        SendMessage(WM_CONTEXTMENU, reinterpret_cast<WPARAM>(m_hWnd), MAKELPARAM(point.x, point.y));
        KillTimer(99);
        Check(menuSeen && !menuTimedOut, "native context menu completes without external input");
    }
    void WaitWhileHeld() {
        Sleep(550);
        MSG message;
        while (PeekMessage(&message, m_hWnd, WM_TIMER, WM_TIMER, PM_REMOVE)) DispatchMessage(&message);
    }
    void EdgeTick() { OnTimer(3); }
    void Escape() {
        MSG message = {}; message.hwnd = m_hWnd; message.message = WM_KEYDOWN; message.wParam = VK_ESCAPE;
        PreTranslateMessage(&message);
    }
};
class Host : public CWnd {
public:
    Panel panel;
    int launches = 0, edits = 0, lastLaunch = -1;
    LPARAM lastMode = -1;
	int shortcuts = 0;
	CString shortcutId;
    CLaunchPanel::Edit last;
    LRESULT WindowProc(UINT message, WPARAM wp, LPARAM lp) override {

        if (message == WM_LAUNCH_PANEL_TILE) { ++launches; lastLaunch = static_cast<int>(wp); lastMode = lp; return 0; }
        if (message == WM_LAUNCH_PANEL_EDIT) { ++edits; last = *reinterpret_cast<CLaunchPanel::Edit*>(lp); return TRUE; }
		if (message == WM_LAUNCH_PANEL_SHORTCUT) { ++shortcuts; shortcutId = *reinterpret_cast<const CString*>(lp); return TRUE; }
        return CWnd::WindowProc(message, wp, lp);
    }
    int S(int n) { return UiTheme::ScaleForWindow(panel.m_hWnd, n); }
    void Layout() { panel.MoveWindow(0, 0, S(360), panel.PreferredHeight(S(360))); }
    void Point(UINT message, int x, int y) {
        panel.SendMessage(message, message == WM_LBUTTONUP ? 0 : MK_LBUTTON, MAKELPARAM(S(x), S(y)));
    }
    void Menu(UINT command, int x = 60, int y = 155) {
        CPoint point(S(x), S(y)); panel.ClientToScreen(&point); panel.Menu(command, point);
    }
};
void CheckTouchConfig(HWND window, bool editing) {
    struct Config { DWORD id, want, block; } config = {4, 0, 0};
    typedef BOOL (WINAPI* Query)(HWND, DWORD, DWORD, PUINT, Config*, UINT);
    Query query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandle(L"user32.dll"), "GetGestureConfig"));
    if (!query) return; // XP has no native gesture configuration.
    UINT count = 1;
    Check(query(window, 0, 0, &count, &config, sizeof(config)) != FALSE, "read native pan configuration");
    Check(editing ? ((config.want & 0x2) && !(config.block & 0x2) && (config.block & 0x8))
        : ((config.block & 0x2) && (config.want & 0x8)),
        editing ? "edit mode permits vertical dragging without directional gutter" : "browse mode restores horizontal paging");
}
}
void TestLaunchPanelInteractions() {
    Host host;
    Check(host.CreateEx(0, AfxRegisterWndClass(0), L"Launch panel tests", WS_POPUP,
        CRect(0, 0, 800, 600), NULL, 0) != FALSE, "hidden launcher host");
    Check(host.panel.Create(&host, 501) != FALSE, "launcher creation");
    std::vector<CLaunchPanel::Tile> tiles(7);
    for (size_t i = 0; i < tiles.size(); ++i) { tiles[i].id.Format(L"%u", (unsigned)i); tiles[i].name = tiles[i].id; }
    host.panel.SetTiles(tiles); host.Layout();
    const int normalHeight = host.panel.PreferredHeight();
    host.Point(WM_LBUTTONDOWN, 60, 155); host.Point(WM_LBUTTONUP, 60, 155);
    Check(host.launches == 1 && host.lastMode == CLaunchPanel::LAUNCH_DEFAULT, "short click uses saved launch preference");
    host.Point(WM_LBUTTONDOWN, 60, 155); host.panel.WaitWhileHeld(); host.Point(WM_LBUTTONUP, 60, 155);
    Check(host.launches == 2 && host.edits == 0, "holding left mouse no longer enters edit mode");
    host.Menu(1);
    Check(host.lastMode == CLaunchPanel::LAUNCH_NORMAL && host.panel.adminAvailable && host.panel.menuDefault == 1,
        "ordinary tile offers both modes and explicit normal launch");
    host.Menu(2);
    Check(host.lastMode == CLaunchPanel::LAUNCH_ADMIN, "administrator menu action is explicit");
    tiles[0].elevated = TRUE; host.panel.SetTiles(tiles);
    host.Menu(1);
    Check(host.lastMode == CLaunchPanel::LAUNCH_NORMAL && host.panel.adminAvailable && host.panel.menuDefault == 2,
        "shield tile retains ordinary action and highlights administrator default");
    host.panel.Menu(2);
    Check(host.lastMode == CLaunchPanel::LAUNCH_ADMIN, "keyboard context menu supports administrator launch");
    tiles[0].packaged = TRUE; host.panel.SetTiles(tiles); host.Menu(0);
    Check(!host.panel.adminAvailable && host.panel.menuDefault == 1, "Store app has no administrator action");
    tiles[0].packaged = FALSE; tiles[0].elevated = FALSE; host.panel.SetTiles(tiles);
    host.launches = 2;
    host.Menu(4);
    Check(!host.panel.IsInteracting() && host.panel.PreferredHeight() == normalHeight,
        "rearrange menu enters edit without capture or additional height");
    CheckTouchConfig(host.panel.m_hWnd, true);
	host.Menu(3);
	Check(host.shortcuts == 1 && host.shortcutId == L"0" && host.launches == 2 && host.edits == 0,
		"shortcut menu preserves stable identity and never launches or deletes");
	host.Menu(0);
	Check(host.shortcuts == 1 && host.launches == 2, "dismissing menu leaves actions unchanged");
	host.Menu(4);
    host.Point(WM_LBUTTONDOWN, 60, 155); host.Point(WM_LBUTTONUP, 60, 155);
    Check(host.launches == 2 && host.edits == 0, "clicking an icon in edit mode never launches");
    host.Point(WM_LBUTTONDOWN, 60, 155); host.Point(WM_MOUSEMOVE, 265, 155);
    Check(host.edits == 0, "drag preview does not save before release");
    host.Point(WM_LBUTTONUP, 265, 155);
    Check(host.edits == 1 && host.last.id == L"0" && host.last.targetId == L"2" && !host.last.remove,
        "drop saves stable source and destination identities");
    host.Point(WM_LBUTTONDOWN, 60, 155); host.Point(WM_MOUSEMOVE, 265, 155); host.Point(WM_LBUTTONUP, 200, 215);
    Check(host.edits == 1, "dropping below panel cancels and never deletes");
    host.Point(WM_LBUTTONDOWN, 60, 155); host.Point(WM_MOUSEMOVE, 265, 155); host.panel.Escape();
    host.Point(WM_LBUTTONUP, 265, 155);
    Check(host.edits == 1 && host.launches == 2, "Escape cancels preview and never launches");
    CheckTouchConfig(host.panel.m_hWnd, false);
    host.Menu(4);
    host.Point(WM_LBUTTONDOWN, 104, 130); host.Point(WM_LBUTTONUP, 60, 155);
    Check(host.edits == 1, "pressing delete then releasing outside cancels");
    host.Point(WM_LBUTTONDOWN, 104, 130); host.Point(WM_LBUTTONUP, 104, 130);
    Check(host.edits == 2 && host.last.remove && host.last.id == L"0", "top-right cross removes only its item");
    host.Point(WM_LBUTTONDOWN, 104, 130); host.panel.Escape(); host.Point(WM_LBUTTONUP, 104, 130);
    Check(host.edits == 2, "Escape cancels a pressed delete cross");
    host.Menu(4);
    host.Point(WM_LBUTTONDOWN, 60, 155); host.Point(WM_MOUSEMOVE, 265, 155);
    host.panel.SendMessage(WM_CAPTURECHANGED, 0, 0); host.Point(WM_LBUTTONUP, 265, 155);
    Check(host.edits == 2, "capture loss cancels drag");
    host.Point(WM_LBUTTONDOWN, 60, 155); host.Point(WM_MOUSEMOVE, 340, 155);
    Sleep(680); host.panel.EdgeTick(); host.Point(WM_LBUTTONUP, 340, 155);
    Check(host.edits == 3 && host.last.id == L"0" && host.last.targetId == L"5", "edge dwell reorders across pages");
    // Feed the saved snapshot and check the drop page is retained.
    std::vector<CLaunchPanel::Tile> saved = { tiles[1], tiles[2], tiles[3], tiles[4], tiles[5], tiles[0], tiles[6] };
    host.panel.SetTiles(saved); host.panel.FinishOrganizing();
    host.Point(WM_LBUTTONDOWN, 265, 155); host.Point(WM_LBUTTONUP, 265, 155);
    Check(host.lastLaunch == 5, "saved cross-page move keeps the destination page visible");
    host.panel.SetCompact(TRUE); host.panel.SetTiles(tiles); host.Layout();
    const int compactHeight = host.panel.PreferredHeight();
    host.Menu(4, 45, 78);
    Check(host.panel.PreferredHeight() == compactHeight, "compact edit mode adds no height");
	host.Menu(3, 45, 78);
	Check(host.shortcuts == 2 && host.shortcutId == L"0", "compact row supports shortcut menu");
	host.Menu(4, 45, 78);
    const int beforeCompact = host.edits;
    host.Point(WM_LBUTTONDOWN, 45, 78); host.Point(WM_MOUSEMOVE, 135, 78); host.Point(WM_LBUTTONUP, 135, 78);
    Check(host.edits == beforeCompact + 1 && !host.last.remove, "compact row supports reordering");
    host.Point(WM_LBUTTONDOWN, 56, 66); host.Point(WM_LBUTTONUP, 56, 66);
    Check(host.edits == beforeCompact + 2 && host.last.remove, "compact row supports delete crosses");
    host.Point(WM_LBUTTONDOWN, 45, 78); host.Point(WM_MOUSEMOVE, 135, 78);
    host.panel.SetTiles(tiles); host.Point(WM_LBUTTONUP, 135, 78);
    Check(host.edits == beforeCompact + 2, "snapshot replacement cancels an in-flight edit");
    host.panel.FinishOrganizing();
    const int launchesBeforeRemote = host.launches;
    host.Point(WM_LBUTTONDOWN, 45, 78);
    CPoint contextPoint(host.S(45), host.S(78)); host.panel.ClientToScreen(&contextPoint);
    host.panel.Menu(0, contextPoint);
    host.Point(WM_LBUTTONUP, 45, 78);
    Check(host.launches == launchesBeforeRemote && !host.panel.IsInteracting(),
        "remote context event cancels its original left click");
    host.DestroyWindow();
}
