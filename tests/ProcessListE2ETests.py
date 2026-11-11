"""Check process-list metadata and refresh in a disposable x64 GUI.

Only test-owned processes are opened for UI inspection or terminated.
Requires 64-bit Python and the existing exit-warning test dependencies.
"""
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
import time

import psutil
from ExitWarningE2ETests import USER, CALLBACK, wait_for, windows


class Item(C.Structure):
    _fields_ = [('mask', W.UINT), ('row', C.c_int), ('column', C.c_int),
                ('state', W.UINT), ('stateMask', W.UINT), ('text', C.c_void_p),
                ('capacity', C.c_int), ('image', C.c_int), ('data', C.c_ssize_t)]


kernel = C.WinDLL('kernel32', use_last_error=True)


def api(name, result, *args):
    fn = getattr(kernel, name)
    fn.restype, fn.argtypes = result, args
    return fn


open_process = api('OpenProcess', W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
allocate = api('VirtualAllocEx', C.c_void_p, W.HANDLE, C.c_void_p, C.c_size_t, W.DWORD, W.DWORD)
release = api('VirtualFreeEx', W.BOOL, W.HANDLE, C.c_void_p, C.c_size_t, W.DWORD)
write = api('WriteProcessMemory', W.BOOL, W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p)
read = api('ReadProcessMemory', W.BOOL, W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p)
close = api('CloseHandle', W.BOOL, W.HANDLE)


USER.SendMessageTimeoutW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM, W.UINT, W.UINT, C.POINTER(C.c_size_t)]
USER.SendMessageTimeoutW.restype = C.c_ssize_t


def send(window, message, wparam=0, lparam=0):
    result = C.c_size_t()
    assert USER.SendMessageTimeoutW(window, message, wparam, lparam, 2, 1000, C.byref(result)), (message, C.get_last_error())
    return C.c_ssize_t(result.value).value


def deny_child_queries(process):
    """Apply an empty DACL to our child; keep Popen's original cleanup handle."""
    security = C.WinDLL('advapi32', use_last_error=True)
    for name, args in (
        ('InitializeAcl', (C.c_void_p, W.DWORD, W.DWORD)),
        ('InitializeSecurityDescriptor', (C.c_void_p, W.DWORD)),
        ('SetSecurityDescriptorDacl', (C.c_void_p, W.BOOL, C.c_void_p, W.BOOL)),
        ('SetKernelObjectSecurity', (W.HANDLE, W.DWORD, C.c_void_p)),
    ):
        fn = getattr(security, name)
        fn.restype, fn.argtypes = W.BOOL, args
    acl, descriptor = C.create_string_buffer(8), C.create_string_buffer(64)
    assert security.InitializeAcl(acl, C.sizeof(acl), 2), C.get_last_error()
    assert security.InitializeSecurityDescriptor(descriptor, 1), C.get_last_error()
    assert security.SetSecurityDescriptorDacl(descriptor, True, acl, False), C.get_last_error()
    assert security.SetKernelObjectSecurity(int(process._handle), 4, descriptor), C.get_last_error()
    denied = open_process(0x1000, False, process.pid)
    error = C.get_last_error()
    if denied:
        close(denied)
    assert not denied and error == 5, (denied, error)


def run():
    assert C.sizeof(C.c_void_p) == 8
    directory = Path('build/qa/process-list-' + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        source = Path(sys.argv[1]) if name == 'ProxyLane64.exe' and len(sys.argv) > 1 else Path('bin') / name
        shutil.copy2(source, directory / name)
    (directory / 'portable.flag').touch()
    (directory / 'ProxyLane.ini').write_text('[options]\nlanguage=zh-CN\nlastselected=ProcessTest\n[proxy_ProcessTest]\nType=SOCKS5\nHost=127.0.0.1\nPort=9\nTransport=PLAIN\n', encoding='utf-8')
    owner = child = None
    handle = memory = None
    try:
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(180)'],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        expected_time = datetime.fromtimestamp(psutil.Process(child.pid).create_time()).strftime('%Y-%m-%d %H:%M:%S')
        deny_child_queries(child)
        owner = subprocess.Popen([str(directory / 'ProxyLane64.exe')], cwd=directory,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        main = wait_for(lambda: next((w for w in windows(owner.pid) if not USER.GetParent(w)), None), 'GUI')
        pages = []

        @CALLBACK
        def visit(window, _):
            if USER.GetDlgItem(window, 1007):
                pages.append(window)
            return True

        def get_page():
            pages.clear()
            USER.EnumChildWindows(main, visit, 0)
            assert len(pages) <= 1, pages
            return pages[0] if pages else None

        page = wait_for(get_page, 'process page')
        view = USER.GetDlgItem(page, 1007)
        wait_for(lambda: USER.IsWindowVisible(page), 'fixture applications page becomes visible')
        refresh = USER.GetDlgItem(page, 1009)
        send(page, 0x111, 1141, 0)  # Expand the owned process list.
        wait_for(lambda: USER.IsWindowVisible(view), 'expanded process list')
        handle = open_process(0x38, False, owner.pid)  # Test GUI memory only.
        assert handle, C.get_last_error()
        memory = allocate(handle, None, 4096, 0x3000, 4)
        assert memory, C.get_last_error()

        def cell(row, column):
            item = Item(column=column, text=memory + 256, capacity=1024)
            assert write(handle, memory, C.byref(item), C.sizeof(item), None)
            send(view, 0x1073, row, memory)  # LVM_GETITEMTEXTW
            text = C.create_unicode_buffer(1024)
            assert read(handle, memory + 256, text, C.sizeof(text), None)
            return text.value

        class FindItem(C.Structure):
            _fields_ = [('flags', W.UINT), ('text', C.c_void_p), ('data', C.c_ssize_t),
                        ('point', W.POINT), ('direction', W.UINT)]

        def find_child():
            if not USER.IsWindowEnabled(refresh):
                return None
            item = FindItem(flags=1, data=child.pid)  # LVFI_PARAM: exact PID lookup.
            assert write(handle, memory, C.byref(item), C.sizeof(item), None)
            row = send(view, 0x1053, -1, memory)  # LVM_FINDITEMW
            if row >= 0:
                return [cell(row, column) for column in range(4)]
            return None

        row = wait_for(find_child, 'owned child in process list')
        assert Path(sys.executable).name.lower() in row[1].lower(), row
        assert row[2] == expected_time, (row, expected_time)
        assert Path(row[3]).resolve() == Path(sys.executable).resolve(), row

        # Native sorting and the cached row order must agree after every mode
        # change; otherwise the next snapshot writes a different process's data
        # into a row. Exercise each column, both directions and the tree reset.
        for column in range(4):
            for mode in range(3):
                # WM_NOTIFY cannot cross process boundaries. Exercise the
                # test-owned header handler so it emits its native notification.
                header = send(view, 0x101f)  # LVM_GETHEADER
                assert send(header, 0x1207, column, memory)  # HDM_GETITEMRECT
                rect = W.RECT()
                assert read(handle, memory, C.byref(rect), C.sizeof(rect), None)
                point = ((rect.top + rect.bottom) // 2 << 16) | ((rect.left + rect.right) // 2)
                send(header, 0x201, 1, point)  # Test fixture WM_LBUTTONDOWN/UP.
                send(header, 0x202, 0, point)
                send(page, 0x111, 1009, 0)
                wait_for(lambda: USER.IsWindowEnabled(refresh), 'sorted snapshot applied')
                sorted_row = wait_for(find_child, 'child identity after sort/refresh')
                assert sorted_row[0] == str(child.pid), sorted_row
                assert Path(sys.executable).name.lower() in sorted_row[1].lower(), sorted_row
                assert sorted_row[2] == expected_time, sorted_row
                assert Path(sorted_row[3]).resolve() == Path(sys.executable).resolve(), sorted_row
                if column == 0 and mode < 2:
                    pids = [int(cell(i, 0)) for i in range(send(view, 0x1004))]
                    assert pids == sorted(pids, reverse=mode == 1), (mode, pids)
        print('PASS: cached/native row identity across 12 sort-and-refresh combinations', flush=True)

        # Refresh requests must return to the message loop, not wait for enumeration.
        timings = []
        for _ in range(25):
            started = time.perf_counter()
            send(page, 0x111, 1009, 0)
            timings.append((time.perf_counter() - started) * 1000)
        assert max(timings) < 500, timings
        wait_for(lambda: USER.IsWindowEnabled(refresh), 'asynchronous refresh completed')
        # Capture another refresh then immediately collapse. Late results cannot
        # mutate the hidden list; repeated hidden refresh requests are ignored.
        send(page, 0x111, 1009, 0)
        send(page, 0x111, 1141, 0)
        assert not USER.IsWindowVisible(view)
        hidden_count = send(view, 0x1004, 0, 0)
        for _ in range(5):
            send(page, 0x111, 1009, 0)
            time.sleep(.1)
            assert send(view, 0x1004, 0, 0) == hidden_count
        send(page, 0x111, 1141, 0)
        wait_for(find_child, 'reopened list receives a fresh snapshot')
        print(f'PASS: coalesced refresh max dispatch {max(timings):.1f} ms; collapse/reopen discards late results', flush=True)
        child.terminate()
        child.wait(timeout=10)
        send(page, 0x111, 1009, 0)
        wait_for(lambda: USER.IsWindowEnabled(refresh) and find_child() is None, 'exited child removed on refresh')
        print('PASS: inaccessible child name, PID, creation time, full path and exited-row removal', flush=True)
        USER.PostMessageW(main, 0x10, 0, 0)
        owner.wait(timeout=10)
    finally:
        if memory:
            release(handle, memory, 0, 0x8000)
        if handle:
            close(handle)
        for process in (child, owner):
            if process:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)


if __name__ == '__main__':
    run()
