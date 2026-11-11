"""Exercise configuration replacement through real dialogs in disposable directories.

Only test-owned windows/processes/files are touched. Requires 64-bit Python,
psutil and Pillow. Never imports into the user's bin/ProxyLane.ini.
"""
import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid

import psutil
from ExitWarningE2ETests import (USER, KERNEL, CALLBACK, windows, settings_page,
                                text, wait_for, dismiss, capture_dialog)


def children(window):
    result = []
    @CALLBACK
    def visit(child, _):
        name = ctypes.create_unicode_buffer(128)
        USER.GetClassNameW(child, name, len(name))
        result.append((child, name.value, USER.GetDlgCtrlID(child)))
        return True
    USER.EnumChildWindows(window, visit, 0)
    return result


def set_text(window, value):
    buffer = ctypes.create_unicode_buffer(str(value))
    assert USER.SendMessageW(window, 0x000c, 0, ctypes.addressof(buffer))


def select_file(pid, page, path):
    USER.PostMessageW(page, 0x111, 1136, 0)
    picker = wait_for(lambda: next((w for w in windows(pid)
                                   if USER.IsWindowVisible(w) and any(cls == 'Edit' for _, cls, _ in children(w))
                                   and not settings_page(w)), None), 'file picker')
    time.sleep(.3)  # Vista file picker creates/replaces its controls during initialization.
    edits = [(w, ident) for w, cls, ident in children(picker) if cls == 'Edit' and USER.IsWindowVisible(w)]
    filename = next((w for w, ident in edits if ident in (1148, 1001)), None)
    assert filename, [(cls, ident, text(w)) for w, cls, ident in children(picker)]
    set_text(filename, path)
    USER.PostMessageW(picker, 0x111, 1, 0)
    wait_for(lambda: not USER.IsWindow(picker), 'file picker closed')
    return wait_for(lambda: next((w for w in windows(pid) if
                                 USER.IsWindowVisible(w) and USER.GetDlgItem(w, 2) and
                                 USER.IsWindowEnabled(USER.GetDlgItem(w, 2)) and not settings_page(w)), None),
                    'confirmation or error')


def run(bin_dir, scenario, language):
    if KERNEL.GetModuleHandleW('ProxyLaneHook64.dll'):
        assert ctypes.WinDLL('ProxyLaneHook64.dll').gp_UnhookWinsock()
    directory = Path('build/qa/config-import-' + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(bin_dir / name, directory / name)
    (directory / 'portable.flag').touch()
    destination = directory / 'ProxyLane.ini'
    destination.write_text('[options]\nlanguage=' + language + '\nlastselected=Before\n'
                           '[proxy_Before]\nType=NOPROXY\nHost=\nPort=0\n', encoding='utf-16')
    source = directory / 'Source.ini'
    imported = ('; preserve comments and unknown values\n[options]\nlanguage=' + language +
                '\nlastselected=Imported\n[proxy_Imported]\nType=NOPROXY\nPort=0\n'
                '[proxy_Second]\nType=SOCKS5\nHost=localhost\nPort=1080\n'
                '[future-extension]\nText=\u4fdd\u7559\u672a\u77e5\u5b57\u6bb5\n'
                '[empty-extension]\n')
    source.write_text(imported, encoding='utf-8-sig')
    source_original = source.read_bytes()
    process = subprocess.Popen([str(directory / 'ProxyLane64.exe')], cwd=directory)
    owned = [psutil.Process(process.pid)]
    try:
        main = wait_for(lambda: next((w for w in windows(process.pid) if settings_page(w)), None), 'main GUI')
        page = settings_page(main)
        before = destination.read_bytes()
        if scenario == 'invalid':
            source.write_text('[proxy_Broken]\nType=SOCKS5\nHost=localhost\nPort=65537\n', encoding='utf-16')
        elif scenario == 'same-file':
            source = destination
        dialog = select_file(process.pid, page, source)
        summary = USER.GetDlgItem(dialog, 1137)
        if scenario in ('invalid', 'same-file'):
            assert not summary
            dismiss(dialog, 2)
            assert destination.read_bytes() == before
            assert not list(directory.glob('ProxyLane.ini.backup-*'))
        else:
            assert summary, [(text(w), w) for w in windows(process.pid)]
            content = text(summary)
            assert str(source) in content and str(destination) in content, content
            capture_dialog(dialog, directory / 'confirmation.png')
            if scenario == 'cancel':
                dismiss(dialog, 2)
                assert destination.read_bytes() == before
                assert not list(directory.glob('ProxyLane.ini.backup-*'))
            elif scenario == 'read-only':
                KERNEL.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
                assert KERNEL.SetFileAttributesW(str(destination), 1)
                dismiss(dialog, 1)
                error = wait_for(lambda: next((w for w in windows(process.pid) if w != main and USER.IsWindowVisible(w)), None), 'read-only error')
                dismiss(error, 2)
                assert KERNEL.SetFileAttributesW(str(destination), 0x80)
                assert destination.read_bytes() == before
            else:
                # Editing the source after confirmation must not alter the fixed snapshot.
                if scenario == 'snapshot':
                    source.write_text('[proxy_Changed]\nType=NOPROXY\n', encoding='utf-16')
                if scenario == 'tampered-stage':
                    staged = list(directory.glob('ProxyLane.ini.import-*.tmp'))
                    assert len(staged) == 1
                    staged[0].write_bytes(b'not the confirmed contents')
                if scenario == 'restart-failure':
                    # The existing GUI has loaded its DLL; the new process cannot
                    # load it. The test restores it before the recovery restart.
                    (directory / 'ProxyLaneHook64.dll').rename(directory / 'ProxyLaneHook64.held')
                USER.PostMessageW(dialog, 0x111, 1, 0)
                def replacement():
                    try:
                        for item in psutil.Process(process.pid).children():
                            if item.name() == 'ProxyLane64.exe':
                                return item
                    except psutil.NoSuchProcess:
                        pass
                    for item in psutil.process_iter(['exe']):
                        if item.pid != process.pid and item.info['exe'] and Path(item.info['exe']) == directory / 'ProxyLane64.exe':
                            return item
                if scenario in ('tampered-stage', 'restart-failure'):
                    error = wait_for(lambda: next((w for w in windows(process.pid)
                                                   if USER.IsWindowVisible(w) and USER.GetDlgItem(w, 65535)), None), 'recovery message')
                    assert destination.read_bytes() == before
                    if scenario == 'restart-failure':
                        assert not list(directory.glob('ProxyLane.ini.import-*.tmp'))  # Replacement consumed the stage.
                        (directory / 'ProxyLaneHook64.held').rename(directory / 'ProxyLaneHook64.dll')
                    dismiss(error, 2)
                new = wait_for(replacement, 'replacement or recovery process')
                owned.append(new)
                new_main = wait_for(lambda: next((w for w in windows(new.pid) if settings_page(w)), None), 'restarted GUI')
                assert process.wait(timeout=35) == 0
                recovered = scenario in ('tampered-stage', 'restart-failure')
                if recovered:
                    assert destination.read_bytes() == before
                else:
                    assert destination.read_text(encoding='utf-16').replace('\r\n', '\n') == imported
                backups = list(directory.glob('ProxyLane.ini.backup-*'))
                assert len(backups) == 1 and backups[0].read_bytes() == before
                assert USER.IsWindowVisible(new_main)
                # Verify actual loaded UI, not just the INI bytes.
                assert text(USER.GetDlgItem(settings_page(new_main), 1022)) == ('Before' if recovered else 'Imported')
                assert ('[proxy_Before]' in destination.read_text(encoding='utf-16')) == recovered
                if scenario != 'snapshot':
                    assert source.read_bytes() == source_original
        wait_for(lambda: not list(directory.glob('ProxyLane.ini.import-*.tmp')), 'staging cleanup')
        print(json.dumps({'scenario': scenario, 'language': language, 'passed': True, 'directory': str(directory)}))
    except Exception:
        print([(text(w), USER.IsWindowVisible(w), [(cls, ident, text(c)[:250]) for c, cls, ident in children(w)])
               for w in windows(process.pid) if USER.IsWindowVisible(w)])
        raise
    finally:
        for item in owned:
            try:
                item.kill()
                item.wait(timeout=10)
            except psutil.NoSuchProcess:
                pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin', type=Path, default=Path('bin'))
    parser.add_argument('--scenario', choices=['success', 'snapshot', 'cancel', 'invalid', 'same-file', 'read-only', 'tampered-stage', 'restart-failure'], default='success')
    parser.add_argument('--language', choices=['zh-CN', 'en-US'], default='zh-CN')
    args = parser.parse_args()
    USER.GetDlgCtrlID.argtypes = [wintypes.HWND]
    run(args.bin.resolve(), args.scenario, args.language)
