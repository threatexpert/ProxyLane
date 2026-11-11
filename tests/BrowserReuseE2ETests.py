"""Test browser-handoff hints using only test-owned, renamed probe processes.

Build tests/tools/BrowserLaunchProbe/BrowserLaunchProbe.vcxproj first.
No installed browser is launched, inspected for injection, or terminated.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import shutil
import struct
import subprocess
import time
import uuid

import psutil
from ExitWarningE2ETests import (USER, CALLBACK, wait_for, windows, settings_page,
                                owned_pipe, attach, text, dismiss, capture_dialog,
                                warning)
from ProcessListE2ETests import Item, api, open_process, allocate, release, read, write, close


def drop(main, path):
    payload = struct.pack('<IiiII', 20, 0, 0, 0, 1) + (str(path) + '\0\0').encode('utf-16-le')
    alloc = api('GlobalAlloc', W.HANDLE, W.UINT, C.c_size_t)
    lock = api('GlobalLock', C.c_void_p, W.HANDLE)
    unlock = api('GlobalUnlock', W.BOOL, W.HANDLE)
    memory = alloc(0x42, len(payload))
    assert memory
    address = lock(memory)
    assert address
    C.memmove(address, payload, len(payload))
    unlock(memory)
    assert USER.PostMessageW(main, 0x233, memory, 0)  # Receiver owns HDROP.


def run(probe, browser, language, actions=False):
    directory = Path('build/qa/browser-reuse-' + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    # Win32 launchers forward to this GUI on a 64-bit OS.
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(Path('bin') / name, directory / name)
    executable = directory / browser
    shutil.copy2(probe, executable)
    (directory / 'portable.flag').touch()
    (directory / 'ProxyLane.ini').write_text(f'''[options]
lastselected=BrowserTest
language={language}
[proxy_BrowserTest]
HookChildProcess=1
HookTCP=1
HookUDP=0
BlockUDP=0
dnsOpt=0
ChildFilter=
ChildFilterMode=1
TargetFilter=
TargetFilterMode=1
Type=SOCKS5
Host=127.0.0.1
Port=1080
Transport=PLAIN
''', encoding='utf-8')
    processes = []
    owner = None
    handle = memory = None

    def hold(path=executable):
        process = subprocess.Popen([str(path), '--hold', '--tree'], cwd=directory,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        processes.append(process)
        wait_for(lambda: len([p for p in psutil.Process(process.pid).children()
                             if Path(p.exe()) == path]) == 2, 'browser process tree')
        return process

    def network(parent):
        return next(p for p in psutil.Process(parent.pid).children()
                    if '--utility-sub-type=network.mojom.NetworkService' in p.cmdline())

    try:
        candidate = hold()
        candidate_network = network(candidate)
        # Same executable name in another installation must not be selected.
        alternate = directory / 'other-install'
        alternate.mkdir()
        shutil.copy2(probe, alternate / browser)
        unrelated = hold(alternate / browser)
        owner = subprocess.Popen([str(directory / 'ProxyLane64.exe')], cwd=directory,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        main = wait_for(lambda: next((w for w in windows(owner.pid) if not USER.GetParent(w)), None), 'main')
        settings = wait_for(lambda: settings_page(main), 'settings')
        USER.PostMessageW(settings, 0x111, 1, 0)
        pipe = wait_for(lambda: owned_pipe(owner.pid), 'proxy service')

        def hint():
            result = next((w for w in windows(owner.pid) if USER.GetDlgItem(w, 1134)), None)
            if not result:
                # Exercise the tray-click callback, not an automatic popup.
                USER.PostMessageW(main, 0x8000 + 100, 102, 0x400 + 5)
            return result

        def launch():
            marker = directory / 'launched.pid'
            marker.unlink(missing_ok=True)
            drop(main, executable)
            wait_for(lambda: marker.exists() and marker.stat().st_size, 'probe started through launcher')

        def no_hint(seconds):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                assert not hint(), 'Unexpected reuse hint'
                time.sleep(.05)

        launch()
        dialog = wait_for(hint, 'quick-exit reuse hint')
        details = text(USER.GetDlgItem(dialog, 1134))
        assert str(candidate.pid) in details and str(unrelated.pid) not in details, details
        assert str(candidate_network.pid) in details and 'Network Service' in details, details
        message = text(USER.GetDlgItem(dialog, 1133))
        assert ('代理进程' if language == 'zh-CN' else 'Proxy processes') in message
        assert '2.5' not in message
        assert f'{browser}  (PID {candidate.pid})' in details
        assert f'   {browser}  (PID {candidate_network.pid})' in details
        time.sleep(.2)
        capture_dialog(dialog, directory / ('hint-' + language + '.png'))
        if actions:
            def message_box(button=1):
                try:
                    return wait_for(lambda: next((w for w in windows(owner.pid)
                        if w != main and USER.IsWindowVisible(w) and USER.GetDlgItem(w, 65535)
                        and (USER.GetDlgItem(w, button) or (button == 1 and USER.GetDlgItem(w, 2)))), None), 'action message')
                except TimeoutError:
                    raise AssertionError((owner.poll(), [(w, text(w), USER.IsWindowVisible(w),
                        text(USER.GetDlgItem(w, 65535)), bool(USER.GetDlgItem(w, 1)),
                        bool(USER.GetDlgItem(w, 2))) for w in windows(owner.pid)]))

            def result():
                box = message_box()
                result_text = text(USER.GetDlgItem(box, 65535))
                capture_dialog(box, directory / ('result-' + language + '.png'))
                dismiss(box, 1 if USER.GetDlgItem(box, 1) else 2)
                assert USER.IsWindowVisible(settings), 'Direct action navigated away from settings'
                return result_text

            rects = []
            for control in (1138, 1139, 1, 2):
                button = USER.GetDlgItem(dialog, control)
                assert button and USER.IsWindowVisible(button) and text(button)
                rect = W.RECT()
                assert USER.GetWindowRect(button, C.byref(rect))
                rects.append(rect)
            assert all(a.right < b.left and a.top == b.top for a, b in zip(rects, rects[1:]))
            # Cancelling termination must leave every displayed process untouched.
            dismiss(dialog, 1138)
            confirm = message_box(6)
            dismiss(confirm, 7)
            assert candidate.poll() is None and candidate_network.is_running()
            assert USER.IsWindowVisible(settings)

            launch()
            dialog = wait_for(hint, 'termination hint')
            renderer = next(p for p in psutil.Process(candidate.pid).children()
                            if '--type=renderer' in p.cmdline())
            dismiss(dialog, 1138)
            confirm = message_box(6)
            assert str(candidate.pid) in text(USER.GetDlgItem(confirm, 65535))
            dismiss(confirm, 6)
            summary = result()
            assert ('失败 0 个' if language == 'zh-CN' else '0 failed') in summary, summary
            candidate.wait(timeout=10)
            candidate_network.wait(timeout=10)
            assert renderer.is_running() and unrelated.poll() is None

            # One target exits while the dialog is open; another instance appears.
            # Proxy only the originally displayed survivor, never the new instance.
            candidate = hold()
            candidate_network = network(candidate)
            launch()
            dialog = wait_for(hint, 'proxy hint')
            candidate_network.terminate()
            candidate_network.wait(timeout=10)
            newcomer = hold()
            dismiss(dialog, 1139)
            summary = result()
            assert ('跳过 1 个' if language == 'zh-CN' else '1 skipped') in summary, summary
            cleanup = warning(owner, main)
            hooked_details = text(USER.GetDlgItem(cleanup, 1111))
            assert str(candidate.pid) in hooked_details, hooked_details
            assert str(newcomer.pid) not in hooked_details and str(unrelated.pid) not in hooked_details
            dismiss(cleanup, 2)

            # A partially hooked instance skips its main but hooks its network.
            bits = 32 if 'Win32' in str(probe) else 64
            attach(directory, bits, newcomer.pid, pipe)
            time.sleep(.5)
            launch()
            dialog = wait_for(hint, 'already hooked main hint')
            dismiss(dialog, 1139)
            summary = result()
            assert ('跳过 2 个' if language == 'zh-CN' else '2 skipped') in summary, summary
            cleanup = warning(owner, main)
            hooked_details = text(USER.GetDlgItem(cleanup, 1111))
            assert str(network(newcomer).pid) in hooked_details, hooked_details
            assert str(unrelated.pid) not in hooked_details
            dismiss(cleanup, 2)
            print(f'PASS: direct actions, {browser}, {language}, button order, cancel, '
                  f'exact termination, expired target, new instance excluded, already hooked skip, '
                  f'no navigation; screenshots={directory}', flush=True)
            return
        dismiss(dialog, 1)  # View candidates, never end them.
        pages = []

        @CALLBACK
        def visit(window, _):
            if USER.GetDlgItem(window, 1007):
                pages.append(window)
            return True

        USER.EnumChildWindows(main, visit, 0)
        assert len(pages) == 1
        view = USER.GetDlgItem(pages[0], 1007)
        assert USER.IsWindowVisible(view)
        # The old transient banner obscured the next action for 3.2 seconds.
        banner = USER.GetDlgItem(main, 0x1007)
        assert banner and not USER.IsWindowVisible(banner), 'Transient banner still covers actions'
        button = USER.GetDlgItem(pages[0], 1010)
        assert USER.IsWindowVisible(button) and USER.IsWindowEnabled(button)
        bounds = W.RECT()
        assert USER.GetWindowRect(button, C.byref(bounds))
        USER.ChildWindowFromPointEx.argtypes = [W.HWND, W.POINT, W.UINT]
        USER.ChildWindowFromPointEx.restype = W.HWND
        USER.ScreenToClient.argtypes = [W.HWND, C.POINTER(W.POINT)]
        hit = main
        for _ in range(16):
            center = W.POINT((bounds.left + bounds.right) // 2, (bounds.top + bounds.bottom) // 2)
            assert USER.ScreenToClient(hit, C.byref(center))
            child = USER.ChildWindowFromPointEx(hit, center, 1)  # Skip hidden children.
            if not child or child == hit:
                break
            hit = child
        assert hit == button, 'Proxy Selected Processes is covered by another app control'
        handle = open_process(0x38, False, owner.pid)
        assert handle
        memory = allocate(handle, None, 4096, 0x3000, 4)
        assert memory

        def selected_pids():
            result, row = [], -1
            while True:
                row = USER.SendMessageW(view, 0x100c, row, 2)  # LVM_GETNEXTITEM/LVNI_SELECTED
                if row < 0:
                    return result
                item = Item(column=0, text=memory + 256, capacity=1024)
                assert write(handle, memory, C.byref(item), C.sizeof(item), None)
                USER.SendMessageW(view, 0x1073, row, memory)
                value = C.create_unicode_buffer(1024)
                assert read(handle, memory + 256, value, C.sizeof(value), None)
                result.append(int(value.value))

        assert set(selected_pids()) == {candidate.pid, candidate_network.pid}, selected_pids()
        assert candidate.poll() is None and unrelated.poll() is None
        USER.RedrawWindow.argtypes = [W.HWND, C.c_void_p, W.HANDLE, W.UINT]
        USER.RedrawWindow(main, None, None, 0x185)  # Paint pending page changes, including children.
        capture_dialog(main, directory / ('selected-' + language + '.png'))

        # Exiting after three seconds is outside the new 2.5-second window.
        (directory / 'late.flag').touch()
        launch()
        no_hint(4)
        (directory / 'late.flag').unlink()

        # Another profile/independent instance remains alive beyond the observation window.
        (directory / 'stay.flag').touch()
        launch()
        no_hint(9)
        (directory / 'stay.flag').unlink()

        # A candidate can exit while the prompt is open; viewing must clear stale selection.
        launch()
        dialog = wait_for(hint, 'second quick-exit hint')
        candidate.terminate()
        candidate.wait(timeout=10)
        dismiss(dialog, 1)
        assert selected_pids() == []

        # Same-name process in another path alone is insufficient evidence.
        launch()
        no_hint(6)

        # A hooked main process alone is insufficient; its existing network child is unhooked.
        hooked = hold()
        hooked_network = network(hooked)
        bits = 32 if 'Win32' in str(probe) else 64
        attach(directory, bits, hooked.pid, pipe)
        time.sleep(1)
        cleanup = warning(owner, main)
        assert str(hooked.pid) in text(USER.GetDlgItem(cleanup, 1111))
        dismiss(cleanup, 2)
        launch()
        dialog = wait_for(hint, 'main hooked but network unhooked hint')
        details = text(USER.GetDlgItem(dialog, 1134))
        assert str(hooked.pid) in details and str(hooked_network.pid) in details, details
        dismiss(dialog, 1)
        assert set(selected_pids()) == {hooked.pid, hooked_network.pid}, selected_pids()

        # Hook both required roles. The existing renderer remains unhooked and must be ignored.
        attach(directory, bits, hooked_network.pid, pipe)
        time.sleep(1)
        launch()
        no_hint(4)
        print(f'PASS: {browser}, {language}, quick exit, candidate selection, independent instance, '
              f'2.5s boundary, exited candidate, other installation, main-only warning and '
              f'main+network coverage with unhooked renderer; screenshot={directory}', flush=True)
    finally:
        if memory:
            release(handle, memory, 0, 0x8000)
        if handle:
            close(handle)
        # All probes belong to this disposable directory, including any launched via GUI.
        for process in psutil.process_iter(['pid', 'exe']):
            try:
                if process.info['exe'] and Path(process.info['exe']) in (executable, directory / 'other-install' / browser):
                    process.terminate()
                    process.wait(timeout=10)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        for process in processes + ([owner] if owner else []):
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--browser', choices=('msedge.exe', 'chrome.exe'), default='msedge.exe')
    parser.add_argument('--language', choices=('zh-CN', 'en-US'), default='zh-CN')
    parser.add_argument('--actions', action='store_true')
    args = parser.parse_args()
    run(args.probe.resolve(), args.browser, args.language, args.actions)
