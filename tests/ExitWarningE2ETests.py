"""Exercise exit warnings with an injected orphan in a disposable normal GUI.

Only test-owned processes/windows are touched. Requires 64-bit Python + psutil.
The child makes no network requests. GUI messages exercise the actual handlers.
"""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
import uuid

import psutil
from HookRebindE2ETests import USER, KERNEL, CALLBACK, attach, owned_pipe

USER.SetProcessDPIAware()  # PrintWindow uses physical pixels.
USER.EnumChildWindows.argtypes = [wintypes.HWND, CALLBACK, wintypes.LPARAM]
USER.GetDlgItem.argtypes = [wintypes.HWND, ctypes.c_int]
USER.GetDlgItem.restype = wintypes.HWND
USER.GetParent.argtypes = [wintypes.HWND]
USER.GetParent.restype = wintypes.HWND
USER.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
USER.SendMessageW.restype = ctypes.c_ssize_t
USER.IsWindow.argtypes = [wintypes.HWND]
USER.IsWindowEnabled.argtypes = [wintypes.HWND]
USER.IsWindowVisible.argtypes = [wintypes.HWND]
USER.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]


def wait_for(probe, description):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        value = probe()
        if value:
            return value
        time.sleep(.05)
    raise TimeoutError(description)


def windows(pid):
    result = []
    @CALLBACK
    def visit(window, _):
        owner = wintypes.DWORD()
        USER.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value == pid:
            name = ctypes.create_unicode_buffer(256)
            USER.GetClassNameW(window, name, len(name))
            if name.value == '#32770':
                result.append(window)
        return True
    USER.EnumWindows(visit, 0)
    return result


def settings_page(main):
    pages = []
    @CALLBACK
    def visit(window, _):
        if USER.GetDlgItem(window, 1012) and USER.GetDlgItem(window, 1008):
            pages.append(window)
        return True
    USER.EnumChildWindows(main, visit, 0)
    assert len(pages) <= 1, pages
    return pages[0] if pages else None


def text(window):
    size = USER.SendMessageW(window, 0x000e, 0, 0)
    buffer = ctypes.create_unicode_buffer(size + 1)
    USER.SendMessageW(window, 0x000d, len(buffer), ctypes.addressof(buffer))
    return buffer.value


def warning(owner, main):
    USER.PostMessageW(main, 0x10, 0, 0)
    try:
        return wait_for(lambda: next((w for w in windows(owner.pid)
                                     if USER.GetDlgItem(w, 1111)), None), 'exit warning')
    except TimeoutError:
        raise AssertionError((owner.poll(), [(text(w), w) for w in windows(owner.pid)]))


def dismiss(window, button):
    USER.PostMessageW(window, 0x111, button, 0)
    wait_for(lambda: not USER.IsWindow(window), 'dialog dismissed')


def start_cleanup(window):
    USER.PostMessageW(window, 0x111, 1112, 0)
    wait_for(lambda: USER.IsWindow(window) and not USER.IsWindowEnabled(USER.GetDlgItem(window, 1112)),
             'cleanup started in the original dialog')


def window_rect(window):
    rect = wintypes.RECT()
    assert USER.GetWindowRect(window, ctypes.byref(rect))
    return rect.left, rect.top, rect.right, rect.bottom


def capture_dialog(window, destination):
    # Render only the owned dialog, including when other apps cover it.
    from PIL import Image
    gdi = ctypes.WinDLL('gdi32')
    USER.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    USER.GetDC.argtypes = [wintypes.HWND]
    USER.GetDC.restype = wintypes.HDC
    USER.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    USER.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
    gdi.CreateCompatibleDC.argtypes = [wintypes.HDC]
    gdi.CreateCompatibleDC.restype = wintypes.HDC
    gdi.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
    gdi.CreateCompatibleBitmap.restype = wintypes.HBITMAP
    gdi.SelectObject.argtypes = [wintypes.HDC, wintypes.HANDLE]
    gdi.SelectObject.restype = wintypes.HANDLE
    gdi.DeleteObject.argtypes = [wintypes.HANDLE]
    gdi.DeleteDC.argtypes = [wintypes.HDC]
    gdi.GetDIBits.argtypes = [wintypes.HDC, wintypes.HBITMAP, wintypes.UINT,
                            wintypes.UINT, ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT]
    rect = wintypes.RECT()
    assert USER.GetWindowRect(window, ctypes.byref(rect))
    width, height = rect.right - rect.left, rect.bottom - rect.top
    dc = USER.GetDC(window)
    memory = gdi.CreateCompatibleDC(dc)
    bitmap = gdi.CreateCompatibleBitmap(dc, width, height)
    previous = gdi.SelectObject(memory, bitmap)
    try:
        assert USER.PrintWindow(window, memory, 2)
        gdi.SelectObject(memory, previous)
        pixels = ctypes.create_string_buffer(width * height * 4)
        header = ctypes.create_string_buffer(struct.pack('<IiiHHIIiiII',
                                             40, width, -height, 1, 32, 0, 0, 0, 0, 0, 0))
        assert gdi.GetDIBits(memory, bitmap, 0, height, pixels, header, 0) == height
        Image.frombytes('RGB', (width, height), pixels.raw, 'raw', 'BGRX').save(destination)
    finally:
        gdi.SelectObject(memory, previous)
        gdi.DeleteObject(bitmap)
        gdi.DeleteDC(memory)
        USER.ReleaseDC(window, dc)


def run(binary_directory, bits, language, capture=False, exit_action='keep', child_exits_first=False,
        new_process=False, during_termination=False, cleanup_scenario=None, live_refresh=False):
    if KERNEL.GetModuleHandleW('ProxyLaneHook64.dll'):
        assert ctypes.WinDLL('ProxyLaneHook64.dll').gp_UnhookWinsock()
    directory = Path('build/qa/exit-warning-' + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    # The Win32 launcher forwards to the x64 GUI on a 64-bit OS.
    exe = 'ProxyLane64.exe'
    for name in (exe, 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        source = binary_directory / name
        if source.exists():
            shutil.copy2(source, directory / name)
    (directory / 'portable.flag').touch()
    (directory / 'ProxyLane.ini').write_text('''[options]
lastselected=ExitTest
language=%s
[proxy_ExitTest]
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
''' % language, encoding='utf-8')
    owner = subprocess.Popen([str(directory / exe)], cwd=directory,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    shell = None
    child = None
    late = None
    arrivals = []
    debugged_pid = None
    unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(180)'],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
    record = {'parent_bits': bits, 'language': language, 'exit_action': exit_action,
              'child_exits_first': child_exits_first, 'new_process': new_process,
              'during_termination': during_termination, 'cleanup_scenario': cleanup_scenario,
              'live_refresh': live_refresh}
    try:
        main = wait_for(lambda: next((w for w in windows(owner.pid)
                                     if not USER.GetParent(w)), None), 'main window')
        page = wait_for(lambda: settings_page(main), 'settings page')
        USER.PostMessageW(page, 0x111, 1, 0)  # Start proxy.
        pipe = wait_for(lambda: owned_pipe(owner.pid), 'local service')
        # Keep the parent outside the GUI process tree, then let it create a child.
        system = Path(os.environ['SystemRoot']) / ('System32' if bits == 64 else 'SysWOW64')
        shell = subprocess.Popen([str(system / 'cmd.exe'), '/d', '/q'], stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        parent = psutil.Process(shell.pid)
        attach(directory, bits, shell.pid, pipe)
        wait_for(lambda: any(('proxylanehook%d.dll' % bits) in m.path.lower()
                            for m in parent.memory_maps()), 'parent DLL loaded')
        time.sleep(1)  # AttachTo schedules bootstrap after DLL loading.
        # Loading the DLL precedes completing hooks; use a warning to verify success.
        initial = warning(owner, main)
        assert 'PID %d)' % shell.pid in text(USER.GetDlgItem(initial, 1111))
        dismiss(initial, 2)
        command = 'start "" /b "%s" -c "import time; time.sleep(180)"\r\n' % sys.executable
        shell.stdin.write(command.encode('mbcs'))
        shell.stdin.flush()
        child = wait_for(lambda: next((p for p in parent.children()
                                      if p.name().lower().startswith('python')), None), 'child')
        wait_for(lambda: any('proxylanehook64.dll' in m.path.lower()
                            for m in child.memory_maps()), 'child DLL loaded')
        time.sleep(1)
        # Confirm its successful callback before exiting the original parent.
        both = warning(owner, main)
        assert 'PID %d)' % child.pid in text(USER.GetDlgItem(both, 1111))
        dismiss(both, 2)
        shell.stdin.write(b'exit\r\n')
        shell.stdin.flush()
        shell.wait(timeout=10)
        assert child.is_running()
        orphan = warning(owner, main)
        details = text(USER.GetDlgItem(orphan, 1111))
        assert 'PID %d)' % child.pid in details, details
        assert 'PID %d)' % shell.pid not in details, details
        assert 'PID %d)' % unrelated.pid not in details, details
        assert USER.SendMessageW(orphan, 0x400, 0, 0) & 0xffff == 1135  # DM_GETDEFID
        dialog_rect = window_rect(orphan)
        rectangles = [window_rect(USER.GetDlgItem(orphan, control)) for control in (1135, 2, 1, 1112)]
        for i, rect in enumerate(rectangles):
            assert dialog_rect[0] <= rect[0] < rect[2] <= dialog_rect[2], rect
            assert dialog_rect[1] <= rect[1] < rect[3] <= dialog_rect[3], rect
            for other in rectangles[:i]:
                assert rect[0] >= other[2] or rect[2] <= other[0] or rect[1] >= other[3] or rect[3] <= other[1]
        record.update(parent_pid=shell.pid, orphan_pid=child.pid, processes=details)
        if capture:
            capture_dialog(orphan, directory / 'exit-warning.png')
            record['screenshot'] = str(directory / 'exit-warning.png')
        if cleanup_scenario:
            # Hold a debug event from our own hooked child so its requested exit
            # cannot complete. This exercises the real 10-second wait without
            # changing production timeouts or touching any existing process.
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            assert kernel.DebugActiveProcess(child.pid), ctypes.get_last_error()
            debugged_pid = child.pid
            assert kernel.DebugSetProcessKillOnExit(False)
            debug_event = ctypes.create_string_buffer(256)
            assert kernel.WaitForDebugEvent(debug_event, 2000), ctypes.get_last_error()
            assert int.from_bytes(debug_event.raw[:4], 'little') == 3  # CREATE_PROCESS_DEBUG_EVENT
            # Close the image file; Windows owns the debug event's process and
            # thread handles until the corresponding events are continued.
            image_file = struct.unpack_from('<Q', debug_event.raw, 16)[0]
            if image_file:
                kernel.CloseHandle(image_file)
            USER.IsWindowVisible.argtypes = [wintypes.HWND]
            USER.SendMessageTimeoutW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                                                 wintypes.LPARAM, wintypes.UINT, wintypes.UINT,
                                                 ctypes.POINTER(ctypes.c_size_t)]
            USER.SendMessageTimeoutW.restype = ctypes.c_ssize_t
            original_rect = window_rect(orphan)
            original_warning = text(USER.GetDlgItem(orphan, 1110))
            USER.SetPropW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.HANDLE]
            USER.GetPropW.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
            USER.GetPropW.restype = wintypes.HANDLE
            assert USER.SetPropW(orphan, 'ExitTestIdentity', 1)
            started = time.monotonic()
            start_cleanup(orphan)
            progress = orphan
            time.sleep(.2)
            assert USER.GetPropW(progress, 'ExitTestIdentity') == 1
            assert text(USER.GetDlgItem(progress, 1110)) == original_warning
            assert not USER.IsWindowVisible(USER.GetDlgItem(progress, 1113))
            wait_for(lambda: USER.IsWindowVisible(USER.GetDlgItem(progress, 1113)), 'delayed inline progress')
            assert time.monotonic() - started >= .45
            assert window_rect(progress) == original_rect
            assert [w for w in windows(owner.pid) if USER.GetDlgItem(w, 1111)] == [orphan]
            assert '10' not in text(USER.GetDlgItem(progress, 1110))
            if cleanup_scenario not in ('cancel', 'hide'):
                # More survivors than fit in the initial list must scroll at
                # timeout, never enlarge or replace the existing dialog.
                for _ in range(3):
                    arrival = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(180)'],
                                               creationflags=subprocess.CREATE_NO_WINDOW)
                    arrivals.append(arrival)
                    attach(directory, 64, arrival.pid, pipe)
            if capture:
                capture_dialog(progress, directory / 'cleanup-progress.png')
            checks = 0
            while (USER.IsWindow(progress) and not USER.IsWindowEnabled(USER.GetDlgItem(progress, 1112))
                   and time.monotonic() - started < 14):
                reply = ctypes.c_size_t()
                assert USER.SendMessageTimeoutW(progress, 0, 0, 0, 2, 250, ctypes.byref(reply)), \
                    'Cleanup dialog must remain responsive while a process exit is pending'
                checks += 1
                assert USER.GetPropW(progress, 'ExitTestIdentity') == 1
                assert window_rect(progress) == original_rect
                if cleanup_scenario in ('cancel', 'hide'):
                    # Wait until termination was actually requested, then verify
                    # cancellation interrupts the pending wait, not just startup.
                    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
                    kernel.OpenProcess.restype = wintypes.HANDLE
                    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
                    query = kernel.OpenProcess(0x1000, False, child.pid)
                    assert query
                    code = wintypes.DWORD()
                    try:
                        wait_for(lambda: kernel.GetExitCodeProcess(query, ctypes.byref(code)) and
                                 code.value != 259, 'termination request before cancellation')
                    finally:
                        kernel.CloseHandle(query)
                    dismiss(progress, 1135 if cleanup_scenario == 'hide' else 2)
                    break
                time.sleep(.1)
            record['responsive_checks'] = checks
            if cleanup_scenario in ('cancel', 'hide'):
                assert owner.poll() is None
                assert kernel.DebugActiveProcessStop(debugged_pid)
                debugged_pid = None
                child.wait(timeout=10)
                if cleanup_scenario == 'hide':
                    time.sleep(1.5)
                    assert owner.poll() is None and owned_pipe(owner.pid) == pipe
                    assert not USER.IsWindowVisible(main)
                    USER.PostMessageW(main, 0x8000 + 100, 102, 0x203)
                    wait_for(lambda: USER.IsWindowVisible(main), 'tray restore after cancelling cleanup')
                USER.PostMessageW(main, 0x10, 0, 0)
                owner.wait(timeout=10)
            else:
                timeout = orphan
                wait_for(lambda: USER.IsWindowEnabled(USER.GetDlgItem(timeout, 1112)), 'inline timeout choices')
                elapsed = time.monotonic() - started
                assert 9.5 <= elapsed <= 13, elapsed
                assert 'PID %d)' % child.pid in text(USER.GetDlgItem(timeout, 1111))
                for arrival in arrivals:
                    assert 'PID %d)' % arrival.pid in text(USER.GetDlgItem(timeout, 1111))
                USER.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
                assert USER.GetWindowLongW(USER.GetDlgItem(timeout, 1111), -16) & 0x200000
                assert USER.GetPropW(timeout, 'ExitTestIdentity') == 1
                assert window_rect(timeout) == original_rect
                assert not USER.IsWindowVisible(USER.GetDlgItem(timeout, 1113))
                assert owner.poll() is None and unrelated.poll() is None
                record['timeout_seconds'] = elapsed
                if capture:
                    time.sleep(.2)  # Let the newly opened modal finish its initial layout/paint.
                    capture_dialog(timeout, directory / 'cleanup-timeout.png')
                if cleanup_scenario == 'continue':
                    # The same window starts a fresh round without a countdown.
                    start_cleanup(timeout)
                    time.sleep(.7)
                    assert USER.GetPropW(timeout, 'ExitTestIdentity') == 1
                    assert not USER.IsWindowEnabled(USER.GetDlgItem(timeout, 1112))
                    assert USER.IsWindowVisible(USER.GetDlgItem(timeout, 1113))
                    assert window_rect(timeout) == original_rect
                    assert '10' not in text(USER.GetDlgItem(timeout, 1110))
                    assert kernel.DebugActiveProcessStop(debugged_pid)
                    debugged_pid = None
                elif cleanup_scenario == 'manual':
                    assert kernel.DebugActiveProcessStop(debugged_pid)
                    debugged_pid = None
                    child.wait(timeout=10)
                    wait_for(lambda: 'PID %d)' % child.pid not in text(USER.GetDlgItem(timeout, 1111)),
                             'timeout list removes exited child')
                    assert owner.poll() is None
                    for arrival in arrivals:
                        assert 'PID %d)' % arrival.pid in text(USER.GetDlgItem(timeout, 1111))
                    assert ('%d' % len(arrivals)) in text(USER.GetDlgItem(timeout, 1110))
                    for arrival in arrivals:
                        arrival.terminate()
                        arrival.wait(timeout=10)
                elif cleanup_scenario == 'hide-timeout':
                    dismiss(timeout, 1135)
                    assert not USER.IsWindowVisible(main)
                    assert owner.poll() is None and owned_pipe(owner.pid) == pipe
                    assert kernel.DebugActiveProcessStop(debugged_pid)
                    debugged_pid = None
                    child.wait(timeout=10)
                    for arrival in arrivals:
                        arrival.terminate()
                        arrival.wait(timeout=10)
                    time.sleep(1.5)
                    assert owner.poll() is None and owned_pipe(owner.pid) == pipe
                    USER.PostMessageW(main, 0x10, 0, 0)
                else:
                    dismiss(timeout, 1)
                owner.wait(timeout=10)
                for arrival in arrivals:
                    if cleanup_scenario in ('continue', 'manual', 'hide-timeout'):
                        arrival.wait(timeout=10)
                    else:
                        assert arrival.poll() is None, 'Exit only must leave the remaining processes alive'
        elif exit_action == 'hide':
            # Enter chooses the safe default; restoring must allow a fresh exit.
            USER.PostMessageW(orphan, 0x100, 13, 0)
            wait_for(lambda: not USER.IsWindow(orphan), 'Enter hides to tray')
            assert not USER.IsWindowVisible(main)
            assert owner.poll() is None and child.is_running() and owned_pipe(owner.pid) == pipe
            USER.PostMessageW(main, 0x8000 + 100, 102, 0x203)  # Tray double-click.
            wait_for(lambda: USER.IsWindowVisible(main), 'tray restore')
            reopened = warning(owner, main)
            assert 'PID %d)' % child.pid in text(USER.GetDlgItem(reopened, 1111))
            dismiss(reopened, 1135)
            child.terminate()
            child.wait(timeout=10)
            time.sleep(1.5)  # More than two empty refreshes: no deferred exit.
            assert owner.poll() is None and owned_pipe(owner.pid) == pipe
            assert not USER.IsWindowVisible(main)
            USER.PostMessageW(main, 0x8000 + 100, 102, 0x203)
            wait_for(lambda: USER.IsWindowVisible(main), 'tray restore after last child exits')
            USER.PostMessageW(main, 0x10, 0, 0)
            owner.wait(timeout=10)
            record['hide_cancels_automatic_exit'] = True
        elif live_refresh:
            original_rect = window_rect(orphan)
            late = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(180)'],
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            attach(directory, 64, late.pid, pipe)
            wait_for(lambda: 'PID %d)' % late.pid in text(USER.GetDlgItem(orphan, 1111)),
                     'newly proxied process appears without reopening')
            assert window_rect(orphan) == original_rect
            # The user closes the first application while the dialog stays open.
            child.terminate()
            child.wait(timeout=10)
            wait_for(lambda: 'PID %d)' % child.pid not in text(USER.GetDlgItem(orphan, 1111)),
                     'closed application removed from list')
            assert owner.poll() is None and late.poll() is None
            assert 'PID %d)' % late.pid in text(USER.GetDlgItem(orphan, 1111))
            assert '1' in text(USER.GetDlgItem(orphan, 1110))
            assert window_rect(orphan) == original_rect
            late.terminate()
            late.wait(timeout=10)
            owner.wait(timeout=10)  # No button click after the last application exits.
            record['automatic_exit_after_manual_close'] = True
        elif new_process or during_termination:
            # The button rescans: a process attached after the preview must end too.
            late = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(180)'],
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            if during_termination:
                # Register only after the first batch has actually ended. The
                # GUI must drain another batch without asking for confirmation.
                start_cleanup(orphan)
                child.wait(timeout=10)
                assert owner.poll() is None, 'Must allow in-flight registrations before exit'
            attach(directory, 64, late.pid, pipe)
            if not during_termination:
                wait_for(lambda: any('proxylanehook64.dll' in m.path.lower()
                                    for m in psutil.Process(late.pid).memory_maps()), 'late DLL')
                time.sleep(1)
                wait_for(lambda: 'PID %d)' % late.pid in text(USER.GetDlgItem(orphan, 1111)),
                         'late process appears in refreshed list')
                start_cleanup(orphan)
            child.wait(timeout=10)
            late.wait(timeout=10)
            owner.wait(timeout=10)
            record['late_pid'] = late.pid
        else:
            dismiss(orphan, 2)
            assert owner.poll() is None and child.is_running()
            USER.PostMessageW(page, 0x111, 2, 0)  # Stop service, retain hook history.
            wait_for(lambda: not owned_pipe(owner.pid), 'service stopped')
            stopped = warning(owner, main)
            assert 'PID %d)' % child.pid in text(USER.GetDlgItem(stopped, 1111))
            dismiss(stopped, 2)
            # An idle orphan sends no new Hook/traffic reports. Its one shared
            # identity must survive service destruction AND recreation.
            USER.PostMessageW(page, 0x111, 1, 0)
            restarted_pipe = wait_for(lambda: owned_pipe(owner.pid), 'service restarted')
            assert restarted_pipe == pipe
            restarted = warning(owner, main)
            assert 'PID %d)' % child.pid in text(USER.GetDlgItem(restarted, 1111))
            assert 'PID %d)' % shell.pid not in text(USER.GetDlgItem(restarted, 1111))
            dismiss(restarted, 2)
            USER.PostMessageW(page, 0x111, 2, 0)
            wait_for(lambda: not owned_pipe(owner.pid), 'service stopped again')
            stopped = warning(owner, main)
            assert 'PID %d)' % child.pid in text(USER.GetDlgItem(stopped, 1111))
            record['idle_orphan_survived_service_restart'] = True
            if child_exits_first:
                child.terminate()
                child.wait(timeout=10)
            if child_exits_first:
                owner.wait(timeout=10)  # The refreshed empty list closes automatically.
            elif exit_action == 'terminate':
                # A fast exit must not show a transient cleaning message or a
                # separate progress window, including the final quiet period.
                original_warning = text(USER.GetDlgItem(stopped, 1110))
                original_rect = window_rect(stopped)
                start_cleanup(stopped)
                deadline = time.monotonic() + 10
                while USER.IsWindow(stopped) and time.monotonic() < deadline:
                    assert not USER.IsWindowVisible(USER.GetDlgItem(stopped, 1113))
                    current_text = text(USER.GetDlgItem(stopped, 1110))
                    if USER.IsWindow(stopped) and current_text:
                        assert current_text == original_warning, (original_warning, current_text)
                        assert window_rect(stopped) == original_rect
                    time.sleep(.02)
            else:
                dismiss(stopped, 1)
            owner.wait(timeout=10)
            if exit_action == 'terminate' or child_exits_first:
                child.wait(timeout=10)
                assert not child.is_running(), 'Selected processes must be gone before exit'
            else:
                assert child.is_running(), 'Exit alone must not terminate the orphan'
        assert unrelated.poll() is None, 'Unproxied processes must survive'
        record['passed'] = True
        print('PASS', record, flush=True)
    finally:
        if debugged_pid is not None:
            kernel.DebugActiveProcessStop(debugged_pid)
        for arrival in arrivals:
            if arrival.poll() is None:
                arrival.terminate()
            arrival.wait(timeout=10)
        if late:
            if late.poll() is None:
                late.terminate()
            late.wait(timeout=10)
        if unrelated.poll() is None:
            unrelated.terminate()
        unrelated.wait(timeout=10)
        if child and child.is_running():
            child.terminate()
            child.wait(timeout=10)
        if shell:
            if shell.poll() is None:
                shell.terminate()
                shell.wait(timeout=10)
            shell.stdin.close()
        if owner.poll() is None:
            owner.terminate()
            owner.wait(timeout=10)
        (directory / 'results.json').write_text(json.dumps(record, ensure_ascii=False, indent=2),
                                               encoding='utf-8')
    # No injected survivors: a normal close should not present a confirmation.
    empty = subprocess.Popen([str(directory / exe)], cwd=directory,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        main = wait_for(lambda: next((w for w in windows(empty.pid)
                                     if not USER.GetParent(w)), None), 'empty main window')
        USER.PostMessageW(main, 0x10, 0, 0)
        empty.wait(timeout=10)
    finally:
        if empty.poll() is None:
            empty.terminate()
            empty.wait(timeout=10)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, default=Path('bin'))
    parser.add_argument('--bits', type=int, choices=(32, 64), default=64)
    parser.add_argument('--language', choices=('en-US', 'zh-CN'), default='en-US')
    parser.add_argument('--capture', action='store_true', help='Save the owned dialog (requires Pillow)')
    parser.add_argument('--exit-action', choices=('keep', 'terminate', 'hide'), default='keep')
    parser.add_argument('--child-exits-first', action='store_true')
    parser.add_argument('--new-process', action='store_true', help='Attach a new process during confirmation')
    parser.add_argument('--during-termination', action='store_true',
                        help='Attach a new process after the first termination batch')
    parser.add_argument('--live-refresh', action='store_true',
                        help='Check live additions/removals and automatic exit after manual closes')
    parser.add_argument('--cleanup-scenario', choices=('continue', 'exit', 'cancel', 'manual', 'hide', 'hide-timeout'),
                        help='Hold an owned process exit to check timeout choices and UI responsiveness')
    arguments = parser.parse_args()
    run(arguments.bin.resolve(), arguments.bits, arguments.language, arguments.capture,
        arguments.exit_action, arguments.child_exits_first, arguments.new_process,
        arguments.during_termination, arguments.cleanup_scenario, arguments.live_refresh)
