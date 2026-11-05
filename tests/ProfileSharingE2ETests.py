"""Test sharing and cross-instance profile refresh in disposable GUI instances.

Uses synthetic credentials only; never touches an existing ProxyLane process/INI.
Run: python tests/ProfileSharingE2ETests.py --language zh-CN
"""
import argparse
import base64
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid

from ExitWarningE2ETests import USER, wait_for, windows, settings_page, text, capture_dialog, window_rect, CALLBACK

KERNEL = ctypes.WinDLL('kernel32', use_last_error=True)
KERNEL.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
KERNEL.GlobalAlloc.restype = wintypes.HGLOBAL
KERNEL.GlobalLock.argtypes = [wintypes.HGLOBAL]
KERNEL.GlobalLock.restype = ctypes.c_void_p
KERNEL.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
KERNEL.GlobalFree.argtypes = [wintypes.HGLOBAL]
USER.OpenClipboard.argtypes = [wintypes.HWND]
USER.GetClipboardData.argtypes = [wintypes.UINT]
USER.GetClipboardData.restype = wintypes.HANDLE
USER.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
USER.SetClipboardData.restype = wintypes.HANDLE
USER.SetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
PREFIX = 'proxylane://profile/v1/'


def clipboard_read():
    wait_for(lambda: USER.OpenClipboard(None), 'clipboard')
    try:
        handle = USER.GetClipboardData(13)
        if not handle:
            return None
        pointer = KERNEL.GlobalLock(handle)
        assert pointer
        try:
            return ctypes.wstring_at(pointer)
        finally:
            KERNEL.GlobalUnlock(handle)
    finally:
        USER.CloseClipboard()


def clipboard_write(owner, value):
    raw = (value + '\0').encode('utf-16-le')
    handle = KERNEL.GlobalAlloc(2, len(raw))
    pointer = KERNEL.GlobalLock(handle)
    assert pointer
    ctypes.memmove(pointer, raw, len(raw))
    KERNEL.GlobalUnlock(handle)
    wait_for(lambda: USER.OpenClipboard(owner), 'clipboard')
    try:
        assert USER.EmptyClipboard()
        assert USER.SetClipboardData(13, handle)
    finally:
        USER.CloseClipboard()


def command(page, control, notification=0):
    USER.PostMessageW(page, 0x111, control | (notification << 16), USER.GetDlgItem(page, control) or 0)
    # Posted notifications run after the synchronous cross-process reads used
    # by assertions. Allow dispatch before checking a state that may already
    # have matched before the action (e.g. an initially disabled Save button).
    time.sleep(.15)


def field(page, control):
    return text(USER.GetDlgItem(page, control))


def notice(page):
    USER.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    USER.GetAncestor.restype = wintypes.HWND
    return text(USER.GetDlgItem(USER.GetAncestor(page, 2), 0x1007))


def check_menu(page, pid, locale, can_delete, directory=None):
    command(page, 1132)
    def find_popup():
        found = []
        @CALLBACK
        def visit(window, _):
            owner = wintypes.DWORD()
            USER.GetWindowThreadProcessId(window, ctypes.byref(owner))
            classname = ctypes.create_unicode_buffer(64)
            USER.GetClassNameW(window, classname, len(classname))
            if owner.value == pid and classname.value == '#32768' and USER.IsWindowVisible(window):
                found.append(window)
            return True
        USER.EnumWindows(visit, 0)
        return found[0] if len(found) == 1 else None
    popup = wait_for(find_popup, 'profile actions popup')
    try:
        menu = USER.SendMessageW(popup, 0x01e1, 0, 0)  # MN_GETHMENU
        USER.GetMenuItemCount.argtypes = [wintypes.HMENU]
        USER.GetMenuItemID.argtypes = [wintypes.HMENU, ctypes.c_int]
        USER.GetMenuState.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.UINT]
        USER.GetMenuStringW.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.LPWSTR, ctypes.c_int, wintypes.UINT]
        assert USER.GetMenuItemCount(menu) == 4
        for index, command_id, key in ((0, 1129, 'share.copy'), (1, 1130, 'share.paste'), (3, 1023, 'profile.delete_action')):
            assert USER.GetMenuItemID(menu, index) == command_id
            label = ctypes.create_unicode_buffer(128)
            USER.GetMenuStringW(menu, index, label, len(label), 0x400)
            assert label.value == locale[key]
        assert bool(USER.GetMenuState(menu, 1023, 0) & 3) == (not can_delete)
        if directory:
            capture_dialog(popup, directory / 'profile-menu.png')
    finally:
        USER.PostMessageW(page, 0x001f, 0, 0)  # WM_CANCELMODE
        wait_for(lambda: not USER.IsWindow(popup), 'menu dismissed')


def set_field(page, control, value):
    buffer = ctypes.create_unicode_buffer(value)
    assert USER.SendMessageW(USER.GetDlgItem(page, control), 0x000c, 0, ctypes.addressof(buffer))


def names(page):
    combo = USER.GetDlgItem(page, 1022)
    result = []
    for index in range(USER.SendMessageW(combo, 0x146, 0, 0)):
        size = USER.SendMessageW(combo, 0x149, index, 0)
        buffer = ctypes.create_unicode_buffer(size + 1)
        USER.SendMessageW(combo, 0x148, index, ctypes.addressof(buffer))
        result.append(buffer.value)
    return result


def dropdown(page):
    # Exercise the real CBN_DROPDOWN notification without taking desktop focus.
    USER.SendMessageW(page, 0x111, 1022 | (7 << 16), USER.GetDlgItem(page, 1022))


def select(page, name):
    dropdown(page)
    index = names(page).index(name)
    USER.SendMessageW(USER.GetDlgItem(page, 1022), 0x14e, index, 0)
    command(page, 1022, 1)


def modal(process, main):
    return wait_for(lambda: next((w for w in windows(process.pid) if w != main and USER.IsWindowVisible(w)), None), 'dialog')


def dismiss(window, button):
    target = USER.GetDlgItem(window, button)
    if not target or not USER.IsWindowVisible(target):
        visible = [USER.GetDlgItem(window, item) for item in (1, 2, 6, 7)]
        visible = [item for item in visible if item and USER.IsWindowVisible(item)]
        assert len(visible) == 1, 'No unambiguous dialog button'
        target = visible[0]
    USER.GetDlgCtrlID.argtypes = [wintypes.HWND]
    # BM_CLICK requires an active dialog; notify the owned background dialog
    # with the actual visible button ID and HWND instead.
    USER.PostMessageW(window, 0x111, USER.GetDlgCtrlID(target), target)
    wait_for(lambda: not USER.IsWindow(window), 'dialog dismissed')


def code_for(value):
    return PREFIX + base64.urlsafe_b64encode(json.dumps(value, ensure_ascii=False).encode()).decode().rstrip('=')


def run(language):
    locale = json.loads(Path(f'src/ProxyLane/locales/{language}.json').read_text(encoding='utf-8-sig'))
    directory = Path('build/qa/profile-sharing-' + language + '-' + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll',
                 'ProxyLaneSecureTransport64.dll', 'ProxyLaneMitm64.dll', 'ProxyLaneProtocol64.dll'):
        source = Path('bin') / name
        if source.exists():
            shutil.copy2(source, directory / name)
    (directory / 'portable.flag').touch()
    ini = directory / 'ProxyLane.ini'
    ini.write_text('''[options]
language=%s
lastselected=ShareTest
[proxy_ShareTest]
Type=SOCKS5
Host=2001:db8::1234
Port=1080
User=demo-user
Pass=demo-password
Transport=GONC_TLS_PSK
PSK=demo-psk
HookTCP=1
HookUDP=1
BlockUDP=0
BlockIPv6=1
HookChildProcess=1
dnsOpt=1
RedirectPrivateDNS=1
RedirectDNS=8.8.8.8
ChildFilter=*.exe|# test|a\|b
ChildFilterMode=1
TargetFilter=*.example.org:443|[::1]:80
TargetFilterMode=0
''' % language, encoding='utf-16')
    processes = []
    old_clipboard = clipboard_read()
    try:
        def launch():
            process = subprocess.Popen([str(directory / 'ProxyLane64.exe')], cwd=directory,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            processes.append(process)
            main = wait_for(lambda: next((w for w in windows(process.pid)
                                         if USER.IsWindowVisible(w) and settings_page(w)), None), 'initialized main')
            time.sleep(.15)
            return process, main, settings_page(main)

        process, main, page = launch()
        assert field(page, 1005) == '2001:db8::1234'
        assert not USER.GetDlgItem(page, 1129) and not USER.GetDlgItem(page, 1130) and not USER.GetDlgItem(page, 1023)
        capture_dialog(main, directory / 'compact-layout.png')
        check_menu(page, process.pid, locale, True, directory)
        command(page, 1129)
        wait_for(lambda: 'PSK' in notice(page), 'copy status')
        code = clipboard_read()
        assert code.startswith(PREFIX)
        value = json.loads(base64.urlsafe_b64decode(code[len(PREFIX):] + '==='))
        assert value['password'] == 'demo-password' and value['psk'] == 'demo-psk'
        assert value['host'] == '2001:db8::1234' and value['port'] == 1080
        assert value['child_rules'] == ['*.exe', '# test', 'a|b']
        command(page, 1130)
        wait_for(lambda: notice(page).endswith(locale['share.pending_save']), 'complete import')
        imported = field(page, 1022)
        # Password edits deliberately conceal WM_GETTEXT across processes;
        # verify their actual values by copying the imported profile below.
        assert field(page, 1005) == value['host'] and field(page, 1002) == '1080'
        assert USER.IsWindowEnabled(USER.GetDlgItem(page, 1052))
        assert imported not in names(page)
        check_menu(page, process.pid, locale, False)
        command(page, 1129)
        wait_for(lambda: 'PSK' in notice(page), 'copied import')
        copied = clipboard_read()
        restored = json.loads(base64.urlsafe_b64decode(copied[len(PREFIX):] + '==='))
        assert restored == dict(value, name=imported)
        command(page, 1052)
        wait_for(lambda: not USER.IsWindowEnabled(USER.GetDlgItem(page, 1052)), 'save import')

        # Another real GUI adds a profile. Refresh must preserve pending edits.
        other, other_main, other_page = launch()
        set_field(other_page, 1002, '1081')
        command(other_page, 1052)
        wait_for(lambda: not USER.IsWindowEnabled(USER.GetDlgItem(other_page, 1052)), 'other updates profile')
        dropdown(page)
        assert field(page, 1002) == '1080'  # Refresh names without replacing the editor.
        select(page, imported)
        wait_for(lambda: field(page, 1002) == '1081', 'reload latest settings')
        set_field(other_page, 1022, 'RemoteAdded')
        command(other_page, 1022, 5)  # CBN_EDITCHANGE
        set_field(other_page, 1002, '2000')
        command(other_page, 1052)
        try:
            wait_for(lambda: 'RemoteAdded' in names(other_page), 'other instance save')
        except TimeoutError:
            print('Save diagnostics:', names(other_page), field(other_page, 1022), field(other_page, 1005), field(other_page, 1002), flush=True)
            for w in windows(other.pid):
                if USER.IsWindowVisible(w):
                    print('Dialog:', text(w), flush=True)
                    capture_dialog(w, directory / ('diagnostic-%s.png' % w))
            raise
        set_field(page, 1004, 'draft-user')
        dropdown(page)
        assert 'RemoteAdded' in names(page)
        assert field(page, 1004) == 'draft-user' and field(page, 1022) == imported
        # Delete the current profile from the other instance.
        select(other_page, imported)
        wait_for(lambda: field(other_page, 1002) == '1081', 'other selects import')
        command(other_page, 1023)
        dismiss(modal(other, other_main), 1)
        wait_for(lambda: imported not in names(other_page), 'other deletes import')
        dropdown(page)
        assert imported not in names(page)
        assert field(page, 1022) == imported and field(page, 1004) == 'draft-user'
        assert USER.IsWindowEnabled(USER.GetDlgItem(page, 1052))
        capture_dialog(main, directory / 'deleted-profile-draft.png')

        # Invalid data must leave the complete draft unchanged and not ask to discard it.
        before = {control: field(page, control) for control in (1022, 1005, 1002, 1004, 1024, 1035)}
        clipboard_write(main, PREFIX + 'broken')
        command(page, 1130)
        error = modal(process, main)
        assert text(error) == locale['share.paste_failed'], text(error)
        dismiss(error, 1)
        assert before == {control: field(page, control) for control in before}
        command(page, 1129)
        wait_for(lambda: 'PSK' in notice(page), 'copy unchanged draft after error')
        unchanged = clipboard_read()
        assert json.loads(base64.urlsafe_b64decode(unchanged[len(PREFIX):] + '===')) == dict(
            value, name=imported, user='draft-user', port=1081)

        # Discard only the synthetic draft; Unicode credentials and hidden rules survive.
        value['name'] = '共享测试'
        value['password'] = '测试-password'
        value['psk'] = '共享🔑'
        value['child_rules'] = ['# 中文', '', r'C:\应用\*.exe', 'a|b', '']
        clipboard_write(main, code_for(value))
        command(page, 1130)
        dismiss(modal(process, main), 7)  # No: discard synthetic edits.
        wait_for(lambda: field(page, 1022) == value['name'] and
                 notice(page).endswith(locale['share.pending_save']), 'Unicode import')
        command(page, 1129)
        wait_for(lambda: 'PSK' in notice(page), 'Unicode copy')
        copied = clipboard_read()
        assert json.loads(base64.urlsafe_b64decode(copied[len(PREFIX):] + '===')) == value
        capture_dialog(main, directory / 'sharing.png')
        USER.GetDpiForWindow.argtypes = [wintypes.HWND]
        dpi = USER.GetDpiForWindow(main)
        USER.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                                      ctypes.c_int, ctypes.c_int, wintypes.UINT]
        minimum_width = 674 if language == 'en-US' else 640
        assert USER.SetWindowPos(main, None, 0, 0, minimum_width * dpi // 96, 488 * dpi // 96, 0x16)
        outer = window_rect(main)
        for control in (1132, 1052, 1066):
            child = window_rect(USER.GetDlgItem(page, control))
            assert child[0] >= outer[0] and child[1] >= outer[1] and child[2] <= outer[2] and child[3] <= outer[3], (control, child, outer)
        USER.RedrawWindow.argtypes = [wintypes.HWND, ctypes.c_void_p, wintypes.HRGN, wintypes.UINT]
        USER.RedrawWindow(main, None, None, 0x185)
        capture_dialog(main, directory / 'minimum-window.png')
        # A failed selection after another instance deletes a listed profile restores the draft.
        combo = USER.GetDlgItem(page, 1022)
        index = names(page).index('RemoteAdded')
        # Simulate the narrow interval between opening the list and selecting its stale entry.
        KERNEL.WritePrivateProfileStringW.argtypes = [wintypes.LPCWSTR] * 4
        assert KERNEL.WritePrivateProfileStringW('proxy_RemoteAdded', None, None, str(ini))
        USER.SendMessageW(combo, 0x14e, index, 0)
        command(page, 1022, 1)
        dismiss(modal(process, main), 1)
        assert field(page, 1022) == value['name']
        assert 'RemoteAdded' not in names(page)

        # Cancel a paste over a dirty draft, then verify a running proxy is not
        # automatically saved, stopped or switched by a subsequent paste.
        direct = dict(value, name='RunningBase', type='NOPROXY', host='', port=0, transport='PLAIN')
        clipboard_write(main, code_for(direct))
        command(page, 1130)
        dismiss(modal(process, main), 2)
        assert field(page, 1022) == value['name']
        command(page, 1130)
        dismiss(modal(process, main), 7)
        wait_for(lambda: field(page, 1022) == 'RunningBase' and
                 notice(page).endswith(locale['share.pending_save']), 'direct import')
        command(page, 1052)
        wait_for(lambda: not USER.IsWindowEnabled(USER.GetDlgItem(page, 1052)), 'direct saved')
        command(page, 1)
        wait_for(lambda: not USER.IsWindowEnabled(USER.GetDlgItem(page, 1)) and
                 USER.IsWindowEnabled(USER.GetDlgItem(page, 2)), 'proxy running')
        saved = ini.read_bytes()
        clipboard_write(main, code)
        command(page, 1130)
        wait_for(lambda: notice(page).endswith(locale['share.pending_apply']), 'runtime settings stay pending')
        assert ini.read_bytes() == saved
        assert not USER.IsWindowEnabled(USER.GetDlgItem(page, 1))
        assert USER.IsWindowEnabled(USER.GetDlgItem(page, 2))
        assert field(page, 1017) == locale['status.changes_unsaved_unapplied']
        capture_dialog(main, directory / 'running-paste.png')
        command(page, 2)
        wait_for(lambda: USER.IsWindowEnabled(USER.GetDlgItem(page, 1)), 'proxy stopped')
        print(json.dumps({'language': language, 'passed': True, 'artifacts': str(directory)}, ensure_ascii=False))
    finally:
        if old_clipboard is not None:
            owner = next((w for p in processes for w in windows(p.pid)), None)
            if owner:
                clipboard_write(owner, old_clipboard)
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--language', choices=['zh-CN', 'en-US'], default='zh-CN')
    run(parser.parse_args().language)
