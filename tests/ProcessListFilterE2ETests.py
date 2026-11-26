"""Exercise debounced filters on the native list in an isolated x64 GUI."""

import ctypes as C
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

from ApplicationPreloadE2ETests import page_with
from ExitWarningE2ETests import USER, wait_for, windows
from ProcessListE2ETests import Item, allocate, close, open_process, read, release, send, write


def run():
    assert C.sizeof(C.c_void_p) == 8
    directory = Path('build/qa/process-filter-' + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('bin/ProxyLane64.exe')
    shutil.copy2(binary, directory / 'ProxyLane64.exe')
    for name in ('ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(Path('bin') / name, directory / name)
    (directory / 'portable.flag').touch()
    (directory / 'ProxyLane.ini').write_text(
        '[options]\nlanguage=en-US\nlastselected=FilterTest\n[proxy_FilterTest]\n'
        'Type=SOCKS5\nHost=127.0.0.1\nPort=9\nTransport=PLAIN\n', encoding='utf-8')

    owner = subprocess.Popen([str(directory / 'ProxyLane64.exe')], cwd=directory,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    handle = memory = None
    try:
        main = wait_for(lambda: next((w for w in windows(owner.pid) if not USER.GetParent(w)), None), 'GUI')
        page = wait_for(lambda: page_with(main, 1007), 'applications page')
        wait_for(lambda: USER.IsWindowVisible(page), 'visible applications page')
        view = USER.GetDlgItem(page, 1007)
        search = USER.GetDlgItem(page, 0x2410)
        toggle = USER.GetDlgItem(page, 0x2411)
        empty = USER.GetDlgItem(page, 0x2413)
        inject = USER.GetDlgItem(page, 1010)
        send(page, 0x111, 1141)  # Expand the process list.

        def count():
            return send(view, 0x1004)  # LVM_GETITEMCOUNT

        def top():
            return send(view, 0x1027)  # LVM_GETTOPINDEX

        def set_search(value):
            buffer = C.create_unicode_buffer(value)
            assert send(search, 0x000c, 0, C.addressof(buffer))  # WM_SETTEXT

        def set_only_hooked(checked):
            # BM_CLICK depends on foreground activation. Send the resulting
            # check state and BN_CLICKED to the owned page directly.
            send(toggle, 0x00f1, checked)  # BM_SETCHECK
            assert send(toggle, 0x00f0) == checked  # BM_GETCHECK
            send(page, 0x0111, 0x2411)  # WM_COMMAND / BN_CLICKED

        def first_changed_count(before):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                current = count()
                if current != before:
                    return current
                time.sleep(.001)
            raise TimeoutError(f'process list count stayed at {before}')

        per_page = send(view, 0x1028)  # LVM_GETCOUNTPERPAGE
        wait_for(lambda: count() > per_page and USER.IsWindowEnabled(inject), 'scrollable full snapshot')
        for scroll in (6, 7):  # SB_TOP, SB_BOTTOM
            send(view, 0x115, scroll)  # WM_VSCROLL
            assert (top() == 0) == (scroll == 6), top()
            before = count()
            set_only_hooked(True)
            first = first_changed_count(before)
            assert first == 0, ('hook-only filter exposed a partial list', scroll, before, first)
            assert USER.IsWindowVisible(empty)
            set_only_hooked(False)
            first = first_changed_count(0)
            wait_for(lambda: USER.IsWindowEnabled(inject) and count() > per_page, 'unfiltered snapshot')
            assert first == count(), (first, count())
            assert not USER.IsWindowVisible(empty)

        handle = open_process(0x38, False, owner.pid)
        assert handle
        memory = allocate(handle, None, 4096, 0x3000, 4)
        assert memory

        def pid_at(row):
            item = Item(text=memory + 256, capacity=32)
            assert write(handle, memory, C.byref(item), C.sizeof(item), None)
            assert send(view, 0x1073, row, memory)  # LVM_GETITEMTEXTW
            buffer = C.create_unicode_buffer(32)
            assert read(handle, memory + 256, buffer, C.sizeof(buffer), None)
            return int(buffer.value)

        row = next(i for i in range(count()) if pid_at(i) == owner.pid)
        item = Item(state=3, stateMask=3)  # LVIS_SELECTED | LVIS_FOCUSED
        assert write(handle, memory, C.byref(item), C.sizeof(item), None)
        assert send(view, 0x102b, row, memory)  # LVM_SETITEMSTATE
        send(view, 0x115, 7)
        assert top() > 0
        before = count()
        set_search(f'{owner.pid} ProxyLane64.exe')
        assert first_changed_count(before) == 1, 'search exposed a partial list'
        assert pid_at(0) == owner.pid
        item = Item(mask=4)  # LVIF_PARAM
        assert write(handle, memory, C.byref(item), C.sizeof(item), None)
        assert send(view, 0x104b, 0, memory)  # LVM_GETITEMW
        assert read(handle, memory, C.byref(item), C.sizeof(item), None)
        assert item.data == owner.pid
        assert send(view, 0x102c, 0, 3) == 3  # LVM_GETITEMSTATE
        assert top() == 0

        set_search(uuid.uuid4().hex)
        assert first_changed_count(1) == 0
        assert USER.IsWindowVisible(empty)
        set_search('')
        first = first_changed_count(0)
        wait_for(lambda: USER.IsWindowEnabled(inject) and count() > per_page, 'search cleared')
        assert first == count(), (first, count())
        assert not USER.IsWindowVisible(empty)

        set_search('.exe')
        filtered = first_changed_count(first)
        assert per_page + 4 < filtered < first, (per_page, filtered, first)
        for _ in range(4):
            send(view, 0x115, 1)  # SB_LINEDOWN
        assert top() == 4, top()
        anchor = pid_at(top())
        set_search('')
        assert first_changed_count(filtered) > filtered
        assert pid_at(top()) == anchor, (anchor, pid_at(top()))

        print('PASS: top/bottom hook-only toggle, search, scroll anchor, selection and empty results', flush=True)
        USER.PostMessageW(main, 0x10, 0, 0)
        owner.wait(timeout=10)
    finally:
        if memory:
            release(handle, memory, 0, 0x8000)
        if handle:
            close(handle)
        if owner.poll() is None:
            owner.terminate()
            owner.wait(timeout=10)


if __name__ == '__main__':
    run()
