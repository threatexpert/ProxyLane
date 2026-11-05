#include "stdafx.h"
#include "ModernUI.h"
#include <iostream>
#include <stdexcept>

// Component tests use hidden, test-owned controls; no user windows or settings.
namespace Localization {
void ApplyDialog(CWnd*, UINT) {}
CString Get(LPCTSTR key) { return key; }
}
CWinApp application;
void TestLaunchPanelInteractions();
static void Check(bool ok, const char* name) {
    if (!ok) throw std::runtime_error(name);
    std::cout << "PASS: " << name << '\n';
}
class Host : public CWnd {
public:
    unsigned clicks = 0;
    BOOL OnCommand(WPARAM wp, LPARAM lp) override {
        if (HIWORD(wp) == BN_CLICKED) ++clicks;
        return CWnd::OnCommand(wp, lp);
    }
};
int wmain() {
    if (!AfxWinInit(GetModuleHandle(NULL), NULL, GetCommandLine(), 0)) return 2;
    try {
        Host host;
        Check(host.CreateEx(0, AfxRegisterWndClass(0), L"Control tests", WS_POPUP,
            CRect(0, 0, 640, 480), NULL, 0) != FALSE, "hidden test host");
        CToggleButton toggle, first, second, separate;
        Check(toggle.Create(L"Toggle", WS_CHILD | WS_TABSTOP | BS_AUTOCHECKBOX,
            CRect(0, 0, 180, 30), &host, 101) != FALSE, "dynamic switch creation");
        toggle.SendMessage(BM_CLICK);
        Check(toggle.GetCheck() == BST_CHECKED && host.clicks == 1, "click toggles once and reaches parent");
        toggle.SendMessage(BM_CLICK);
        Check(toggle.GetCheck() == BST_UNCHECKED && host.clicks == 2, "second click switches off");
        toggle.SetCheck(BST_CHECKED);
        Check(host.IsDlgButtonChecked(101) == BST_CHECKED && host.clicks == 2, "programmatic check retains native API without click notification");
        host.CheckDlgButton(101, BST_UNCHECKED);
        Check(toggle.GetCheck() == BST_UNCHECKED, "CheckDlgButton updates switch");
        first.Create(L"First", WS_CHILD | WS_VISIBLE | WS_GROUP | WS_TABSTOP | BS_AUTORADIOBUTTON, CRect(0, 40, 90, 70), &host, 102);
        second.Create(L"Second", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON, CRect(100, 40, 190, 70), &host, 103);
        separate.Create(L"Separate", WS_CHILD | WS_VISIBLE | WS_GROUP | BS_AUTORADIOBUTTON, CRect(0, 80, 100, 110), &host, 104);
        // Resource dialogs list group members consecutively in tab/Z order.
        first.SetWindowPos(&toggle, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        second.SetWindowPos(&first, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        separate.SetWindowPos(&second, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        first.SetCheck(BST_CHECKED); separate.SetCheck(BST_CHECKED);
        second.SendMessage(BM_CLICK);
        Check(first.GetCheck() == BST_UNCHECKED && second.GetCheck() == BST_CHECKED && separate.GetCheck() == BST_CHECKED,
            "radio selection is exclusive within its own group");
        Check(!(first.GetStyle() & WS_TABSTOP) && (second.GetStyle() & WS_TABSTOP) &&
            (second.SendMessage(WM_GETDLGCODE) & DLGC_RADIOBUTTON), "selected radio owns keyboard tab stop and radio semantics");
        CSoftEdit password, text;
        password.Create(WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL, CRect(0, 130, 200, 160), &host, 105);
        password.SetWindowText(L"sample-test-only"); password.SetLimitText(64);
        CString value; password.GetWindowText(value);
        Check((password.GetStyle() & ES_PASSWORD) && value == L"sample-test-only" && password.GetLimitText() == 64,
            "rounded password field preserves masking, content and length limit");
        text.Create(WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL | WS_HSCROLL,
            CRect(0, 180, 400, 320), &host, 106);
        text.SetWindowText(L"first\r\nsecond");
        text.SetSel(0, 5);
        int begin, end; text.GetSel(begin, end);
        Check(text.GetLineCount() == 2 && begin == 0 && end == 5 && (text.GetStyle() & ES_READONLY) &&
            (text.GetStyle() & WS_VSCROLL) && (text.GetStyle() & WS_HSCROLL),
            "rounded multiline field preserves lines, selection, read-only and scroll bars");
        host.DestroyWindow();
        CModernDialog resourceDialog(6000);
        Check(resourceDialog.Create(6000) != FALSE, "hidden resource dialog creation");
        Check(resourceDialog.GetDlgItem(4001)->IsKindOf(RUNTIME_CLASS(CSoftEdit)) &&
            resourceDialog.GetDlgItem(4002)->IsKindOf(RUNTIME_CLASS(CToggleButton)) &&
            resourceDialog.GetDlgItem(4003)->IsKindOf(RUNTIME_CLASS(CSoftEdit)),
            "resource-only controls automatically receive the shared style");
        resourceDialog.CheckDlgButton(4002, BST_CHECKED);
        Check(resourceDialog.IsDlgButtonChecked(4002) == BST_CHECKED, "resource switch remains compatible with dialog check APIs");
        resourceDialog.DestroyWindow();
        std::cout << "PASS: resource wrappers destroyed with their windows\n";
        TestLaunchPanelInteractions();
    } catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
    return 0;
}
