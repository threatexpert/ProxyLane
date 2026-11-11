"""Check tray-notification behavior with owned windows and simulated Shell callbacks.

Actual notification visibility is controlled by Windows. These tests exercise
notification acceptance, click/expiry handling and real taskbar flash events.
"""
import ctypes as C
import argparse
from ctypes import wintypes as W
from pathlib import Path
import shutil
import subprocess
import time
import uuid

import psutil
from BrowserReuseE2ETests import drop
from ExitWarningE2ETests import USER, CALLBACK, wait_for, windows, settings_page, owned_pipe, dismiss, text

USER.GetForegroundWindow.restype = W.HWND
USER.SetForegroundWindow.argtypes = [W.HWND]
USER.GetWindowLongW.argtypes = [W.HWND, C.c_int]
USER.GetWindowLongW.restype = C.c_long
USER.SetWindowPos.argtypes = [W.HWND, W.HWND, C.c_int, C.c_int, C.c_int, C.c_int, W.UINT]
USER.GetCursorPos.argtypes = [C.POINTER(W.POINT)]
USER.SetCursorPos.argtypes = [C.c_int, C.c_int]
USER.mouse_event.argtypes = [W.DWORD, W.DWORD, W.DWORD, W.DWORD, C.c_size_t]


def run(binary_directory, scenario):
    folder = Path('build/qa/browser-attention-' + uuid.uuid4().hex[:8]).resolve()
    folder.mkdir(parents=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(binary_directory / name, folder / name)
    probe = Path('build/tools/browser-launch-probe/x64/BrowserLaunchProbe.exe')
    for name in ('msedge.exe', 'unrelated.exe'):
        shutil.copy2(probe, folder / name)
    (folder / 'portable.flag').touch()
    (folder / 'ProxyLane.ini').write_text('''[options]
lastselected=BrowserTest
language=en-US
[proxy_BrowserTest]
HookChildProcess=1
HookTCP=1
HookUDP=0
BlockUDP=0
dnsOpt=0
Type=SOCKS5
Host=127.0.0.1
Port=1080
Transport=PLAIN
''', encoding='utf-8')
    processes = []
    helper_windows = []

    def start(name, *args):
        p = subprocess.Popen([str(folder / name), *args], cwd=folder,
                             creationflags=subprocess.CREATE_NO_WINDOW)
        processes.append(p)
        return p

    def probe_window(pid):
        matches = []
        @CALLBACK
        def visit(window, _):
            process_id = W.DWORD()
            USER.GetWindowThreadProcessId(window, C.byref(process_id))
            name = C.create_unicode_buffer(256)
            USER.GetClassNameW(window, name, len(name))
            if process_id.value == pid and name.value == 'ProxyLaneBrowserProbe':
                matches.append(window)
            return True
        USER.EnumWindows(visit, 0)
        return matches[0] if matches else None

    def activate(window):
        if scenario == 'lifecycle':
            return  # This scenario also works without an interactive foreground desktop.
        USER.SetForegroundWindow(window)
        if USER.GetForegroundWindow() == window:
            return
        # Fixture setup: simulate a user click on our own probe's caption. Never
        # click another application. Undo temporary fixture z-order and cursor movement.
        position, bounds = W.POINT(), W.RECT()
        assert USER.GetCursorPos(C.byref(position))
        assert USER.GetWindowRect(window, C.byref(bounds))
        assert USER.SetWindowPos(window, W.HWND(-1), 0, 0, 0, 0, 0x53)
        try:
            USER.SetCursorPos(bounds.left + 100, bounds.top + 20)
            USER.mouse_event(2, 0, 0, 0, 0)
            USER.mouse_event(4, 0, 0, 0, 0)
            wait_for(lambda: USER.GetForegroundWindow() == window, 'owned window clicked')
        finally:
            USER.SetCursorPos(position.x, position.y)
            USER.SetWindowPos(window, W.HWND(-2), 0, 0, 0, 0, 0x13)

    try:
        browser = start('msedge.exe', '--hold', '--tree', '--window')
        other = start('unrelated.exe', '--hold', '--window')
        browser_window = wait_for(lambda: probe_window(browser.pid), 'browser window')
        other_window = wait_for(lambda: probe_window(other.pid), 'unrelated window')
        helper_windows.extend([browser_window, other_window])
        owner = start('ProxyLane64.exe')
        main = wait_for(lambda: next((w for w in windows(owner.pid) if not USER.GetParent(w)), None), 'GUI')
        settings = wait_for(lambda: settings_page(main), 'settings')
        USER.PostMessageW(settings, 0x111, 1, 0)
        wait_for(lambda: owned_pipe(owner.pid), 'proxy')
        for window in helper_windows:
            USER.SendMessageW(window, 0x8000 + 23, owner.pid, 0)
        events = folder / 'attention.log'

        def hint():
            return next((w for w in windows(owner.pid) if USER.GetDlgItem(w, 1134)), None)

        def launch():
            if scenario == 'lifecycle':
                USER.SendMessageW(main, 0x112, 0xf020, 0)
            events.unlink(missing_ok=True)
            marker = folder / 'launched.pid'
            marker.unlink(missing_ok=True)
            drop(main, folder / 'msedge.exe')
            wait_for(lambda: marker.exists() and marker.stat().st_size, 'launched probe')
            deadline = time.monotonic() + 1.8
            while time.monotonic() < deadline:
                assert not hint(), 'Detection must not open the details dialog'
                foreground = USER.GetForegroundWindow()
                foreground_pid = W.DWORD()
                USER.GetWindowThreadProcessId(foreground, C.byref(foreground_pid))
                assert foreground_pid.value != owner.pid, ('Detection activated ProxyLane', text(foreground))
                assert not events.exists() or events.stat().st_size == 0, 'Detection flashed taskbar'
                time.sleep(.05)
            assert USER.IsWindowEnabled(main), 'Notification must not block the main window'

        def click():
            USER.PostMessageW(main, 0x8000 + 100, 102, 0x400 + 5)  # NIN_BALLOONUSERCLICK
            return wait_for(hint, 'details after notification click')

        expected = browser_window if scenario == 'related' else other_window
        activate(expected)
        if scenario == 'denied':
            assert USER.SendMessageW(expected, 0x8000 + 22, 1)
        launch()
        log_controls = []
        @CALLBACK
        def find_log(window, _):
            if USER.GetDlgItem(window, 1043):  # Runtime log page's Copy button.
                log_controls.append(USER.GetDlgItem(window, 1000))
            return True
        USER.EnumChildWindows(main, find_log, 0)
        assert len(log_controls) == 1, log_controls
        log = lambda: text(log_controls[0])
        wait_for(lambda: 'The system accepted the notification request' in log(), 'notification request log')
        assert 'existing instances' in log()
        assert 'possible reuse of an existing process detected' in log()
        # Simulate the display callback independently of request acceptance.
        USER.PostMessageW(main, 0x8000 + 100, 102, 0x400 + 2)  # NIN_BALLOONSHOW
        wait_for(lambda: 'System callback received: notification displayed' in log(), 'notification display log')
        (folder / 'runtime.log').write_text(log(), encoding='utf-8')
        print('PASS: detection, notification acceptance and display callback are logged separately', flush=True)
        if scenario == 'denied':
            assert USER.SendMessageW(expected, 0x8000 + 22, 2)
        # Model explicit user activation permission accompanying a tray click.
        if scenario != 'lifecycle':
            assert USER.SendMessageW(expected, 0x8000 + 21, owner.pid, 0)
        dialog = click()
        assert not (USER.GetWindowLongW(dialog, -20) & 8), 'Details must not be topmost'
        dismiss(dialog, 2)
        print('PASS: no automatic popup, activation or taskbar flash; click opens details', flush=True)

        if scenario in ('unrelated', 'lifecycle'):
            for expiry in (0x400 + 3, 0x400 + 4):  # NIN_BALLOONHIDE / NIN_BALLOONTIMEOUT
                activate(expected)
                launch()
                USER.SendMessageW(main, 0x8000 + 100, 102, expiry)
                USER.PostMessageW(main, 0x8000 + 100, 102, 0x400 + 5)
                time.sleep(.3)
                assert not hint(), 'Expired notification retained a details entry'
            print('PASS: hidden/timed-out notifications discard their pending details', flush=True)

            # Fully close the previous browser, reopen outside ProxyLane, then
            # launch through ProxyLane again. This must create a fresh notice.
            for child in psutil.Process(browser.pid).children(recursive=True):
                try:
                    child.terminate()
                    child.wait(timeout=10)
                except psutil.NoSuchProcess:
                    pass
            browser.terminate()
            browser.wait(timeout=10)
            reopened = start('msedge.exe', '--hold', '--tree')
            wait_for(lambda: len([p for p in psutil.Process(reopened.pid).children()
                                  if Path(p.exe()) == folder / 'msedge.exe']) == 2, 'reopened browser tree')
            activate(expected)
            USER.PostMessageW(main, 0x112, 0xf020, 0)  # Hide to tray.
            wait_for(lambda: not USER.IsWindowVisible(main), 'main hidden')
            launch()
            assert not USER.IsWindowVisible(main), 'Notification restored the main window'
            dialog = click()
            assert str(reopened.pid) in text(USER.GetDlgItem(dialog, 1134))
            assert str(browser.pid) not in text(USER.GetDlgItem(dialog, 1134))
            assert USER.IsWindowVisible(main)
            dismiss(dialog, 2)
            print('PASS: fresh browser lifetime triggers again; click restores a hidden GUI', flush=True)

            activate(expected)
            launch()
            for child in psutil.Process(reopened.pid).children(recursive=True):
                try:
                    child.terminate()
                    child.wait(timeout=10)
                except psutil.NoSuchProcess:
                    pass
            reopened.terminate()
            reopened.wait(timeout=10)
            USER.PostMessageW(main, 0x8000 + 100, 102, 0x400 + 5)
            resolved = wait_for(lambda: next((w for w in windows(owner.pid)
                if USER.IsWindowVisible(w) and USER.GetDlgItem(w, 65535)), None), 'resolved notice')
            assert 'No action is needed' in text(USER.GetDlgItem(resolved, 65535))
            assert not hint(), 'Click used stale process data'
            dismiss(resolved, 1 if USER.GetDlgItem(resolved, 1) else 2)
            print('PASS: notification click rechecks process lifetimes', flush=True)
        print(f'Artifacts: {folder}', flush=True)
    finally:
        for window in helper_windows:
            if USER.IsWindow(window):
                USER.SendMessageW(window, 0x8000 + 22, 2, 0)
        for process in psutil.process_iter(['exe']):
            try:
                if process.info['exe'] and Path(process.info['exe']).parent == folder:
                    process.terminate()
                    process.wait(timeout=10)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        for process in processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, default=Path('bin'))
    parser.add_argument('--scenario', choices=('related', 'denied', 'unrelated', 'lifecycle'), required=True)
    args = parser.parse_args()
    run(args.bin.resolve(), args.scenario)
