"""Owned GUI: cold close/reopen, warm catalog, shared recents and profile isolation."""
import base64
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

from ExitWarningE2ETests import USER, CALLBACK, windows, settings_page, text, wait_for, dismiss
from HookRebindE2ETests import owned_pipe
from ProcessListE2ETests import Item, open_process, allocate, release, write, read, close, send

KERNEL = ctypes.WinDLL('kernel32', use_last_error=True)
KERNEL.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
KERNEL.CreateMutexW.restype = wintypes.HANDLE
KERNEL.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
KERNEL.ReleaseMutex.argtypes = [wintypes.HANDLE]
KERNEL.CloseHandle.argtypes = [wintypes.HANDLE]


def page_with(main, control):
    found = []
    @CALLBACK
    def visit(window, _):
        if USER.GetDlgItem(window, control):
            found.append(window)
        return True
    USER.EnumChildWindows(main, visit, 0)
    return found[0] if found else None


def open_picker(owner, process_page):
    USER.PostMessageW(process_page, 0x111, 1072, 0)
    return wait_for(lambda: next((w for w in windows(owner.pid) if USER.GetDlgItem(w, 1074)), None), 'picker')


def count(picker):
    return USER.SendMessageW(USER.GetDlgItem(picker, 1074), 0x1004, 0, 0)


def search(picker, value):
    buffer = ctypes.create_unicode_buffer(value)
    USER.SendMessageW(USER.GetDlgItem(picker, 1073), 0x000c, 0, ctypes.addressof(buffer))
    return count(picker)


def idle(picker):
    status = text(USER.GetDlgItem(picker, 1075))
    return 'Loading' not in status and 'Updating' not in status


def history_gate(path):
    key = str(path.resolve()).replace('/', '\\').lower()
    hashed = 14695981039346656037
    for character in key:
        hashed = ((hashed ^ ord(character)) * 1099511628211) & ((1 << 64) - 1)
    handle = KERNEL.CreateMutexW(None, False, 'Global\\ProxyLane.RecentIni.%016x' % hashed)
    assert handle and KERNEL.WaitForSingleObject(handle, 1000) == 0
    return handle


def fixture_ini():
    result = '[options]\nlastselected=A\nlanguage=en-US\n'
    for profile, digit in [('A', 'a'), ('B', 'b')]:
        identity = digit * 32
        result += f'''[proxy_{profile}]
RecentAppsId={identity}
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
[recent_app_{identity}_{digit * 31}1]
Version=1
ProfileId={identity}
Pinned=0
Elevated=0
LastUsed=100
'''
        for field, value in [('Name', 'Warm ' + profile), ('Path', sys.executable),
                             ('Aumid', ''), ('Arguments', '--preload-fixture-' + profile),
                             ('WorkingDirectory', ''), ('Shortcut', '')]:
            result += field + 'Utf8Base64=' + base64.b64encode(value.encode()).decode() + '\n'
    # Same target/name, differing only in the saved elevation mode.
    for elevated in (0, 1):
        identity = 'a' * 32
        result += f'[recent_app_{identity}_{"c" * 31}{elevated}]\nVersion=1\nProfileId={identity}\nPinned=0\nElevated={elevated}\nLastUsed={200 + elevated}\n'
        for field, value in [('Name', 'Twin A'), ('Path', sys.executable),
                             ('Aumid', ''), ('Arguments', '--preload-twin-A'),
                             ('WorkingDirectory', ''), ('Shortcut', '')]:
            result += field + 'Utf8Base64=' + base64.b64encode(value.encode()).decode() + '\n'
    return result


def check_elevation_selection(owner, picker):
    assert search(picker, 'Twin A') == 2
    view = USER.GetDlgItem(picker, 1074)
    handle = open_process(0x38, False, owner.pid)
    assert handle
    memory = None
    try:
        memory = allocate(handle, None, 4096, 0x3000, 4)
        assert memory

        def source(row):
            item = Item(column=1, text=memory + 256, capacity=1024)
            assert write(handle, memory, ctypes.byref(item), ctypes.sizeof(item), None)
            send(view, 0x1073, row, memory)
            buffer = ctypes.create_unicode_buffer(1024)
            assert read(handle, memory + 256, buffer, ctypes.sizeof(buffer), None)
            return buffer.value

        labels = [source(row) for row in range(2)]
        admin = next(row for row, label in enumerate(labels) if 'Administrator' in label)
        assert sum('Administrator' in label for label in labels) == 1, labels
        assert send(view, 0x102c, admin, 0xf00) == 0x100, 'admin shield overlay'
        assert send(view, 0x102c, 1 - admin, 0xf00) == 0, 'normal entry has no shield'
        # Test both entries, including the later row which a target-only key
        # incorrectly collapses onto the other entry after filtering.
        for row in range(2):
            expected = labels[row]
            item = Item(state=3, stateMask=3)
            assert write(handle, memory, ctypes.byref(item), ctypes.sizeof(item), None)
            send(view, 0x102b, row, memory)
            assert search(picker, '--preload-twin-A') == 2
            selected = send(view, 0x100c, -1, 2)
            assert selected >= 0 and source(selected) == expected, (selected, expected)
            assert search(picker, 'Twin A') == 2
        assert search(picker, 'Administrator') == 1
        assert 'Administrator' in source(0)
    finally:
        if memory:
            release(handle, memory, 0, 0x8000)
        close(handle)


def main():
    directory = Path('build/qa/application-preload-' + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        source = Path(sys.argv[1]) if name == 'ProxyLane64.exe' and len(sys.argv) > 1 else Path('bin') / name
        shutil.copy2(source, directory / name)
    ini = directory / 'ProxyLane.ini'
    ini.write_text(fixture_ini(), encoding='utf-8')
    owner = subprocess.Popen([str(directory / 'ProxyLane64.exe')], cwd=directory,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    gate = None
    try:
        main_window = wait_for(lambda: next((w for w in windows(owner.pid) if not USER.GetParent(w)), None), 'main')
        page = wait_for(lambda: settings_page(main_window), 'settings')
        process_page = wait_for(lambda: page_with(main_window, 1072), 'process page')
        # The launch button now opens the picker only after the proxy starts.
        USER.PostMessageW(page, 0x111, 1, 0)
        wait_for(lambda: owned_pipe(owner.pid), 'service A')
        first = open_picker(owner, process_page)
        cold_status = text(USER.GetDlgItem(first, 1075))
        dismiss(first, 2)
        # No picker exists while the process-wide catalog continues warming.
        time.sleep(5)
        started = time.monotonic()
        picker = open_picker(owner, process_page)
        warm_open = time.monotonic() - started
        assert count(picker) > 0 and idle(picker), (count(picker), text(USER.GetDlgItem(picker, 1075)))
        dismiss(picker, 2)
        picker = open_picker(owner, process_page)
        wait_for(lambda: idle(picker), 'A ready')
        assert search(picker, 'Warm A') == 1
        assert search(picker, 'Warm B') == 0
        check_elevation_selection(owner, picker)
        search(picker, '')
        before = count(picker)
        # Hold validation pending, then close/reopen a refresh with old data.
        gate = history_gate(ini)
        USER.SendMessageW(picker, 0x111, 1079, 0)
        assert count(picker) >= before and not idle(picker)
        dismiss(picker, 2)
        picker = open_picker(owner, process_page)
        assert count(picker) > 0 and not idle(picker), 'refresh retains cached rows and pending state'
        KERNEL.ReleaseMutex(gate); KERNEL.CloseHandle(gate); gate = None
        wait_for(lambda: idle(picker), 'refresh finishes after reopening')
        assert search(picker, 'Warm A') == 1
        dismiss(picker, 2)
        # Selecting B while A is running must not display B's history.
        combo = USER.GetDlgItem(page, 1022)
        value = ctypes.create_unicode_buffer('B')
        index = USER.SendMessageW(combo, 0x158, -1, ctypes.addressof(value))
        assert index >= 0
        USER.SendMessageW(combo, 0x14e, index, 0)
        USER.SendMessageW(page, 0x111, (1 << 16) | 1022, combo)
        picker = open_picker(owner, process_page)
        wait_for(lambda: idle(picker), 'A still active')
        assert search(picker, 'Warm A') == 1 and search(picker, 'Warm B') == 0
        dismiss(picker, 2)
        USER.PostMessageW(page, 0x111, 2, 0)
        wait_for(lambda: not owned_pipe(owner.pid), 'stop A')
        time.sleep(.5)  # Selected B's preload is debounced independently.
        USER.PostMessageW(page, 0x111, 1, 0)
        wait_for(lambda: owned_pipe(owner.pid), 'service B')
        picker = open_picker(owner, process_page)
        wait_for(lambda: idle(picker), 'B ready')
        assert search(picker, 'Warm B') == 1 and search(picker, 'Warm A') == 0
        dismiss(picker, 2)
        USER.PostMessageW(main_window, 0x10, 0, 0)
        owner.wait(timeout=10)
        print('PASS', {'cold_status': cold_status, 'warm_open_seconds': round(warm_open, 3),
                       'catalog_rows': before, 'close_during_refresh': True, 'profile_isolation': True,
                       'elevation_labels_and_selection': True,
                       'fixture': str(directory)}, flush=True)
    finally:
        if gate:
            KERNEL.ReleaseMutex(gate); KERNEL.CloseHandle(gate)
        if owner.poll() is None:
            owner.terminate(); owner.wait(timeout=10)


if __name__ == '__main__':
    main()
