"""Render an owned GUI to check age/selection/hook colors, including sorting.

Uses a disposable profile and injects only its own sleeping child (no traffic).
Requires 64-bit Python, psutil and Pillow, like ExitWarningE2ETests.
"""
import ctypes as C
from ctypes import wintypes as W
from collections import Counter
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

from PIL import Image
from ExitWarningE2ETests import USER, wait_for, windows, settings_page, capture_dialog
from ApplicationPreloadE2ETests import page_with
from HookRebindE2ETests import attach, owned_pipe
from ProcessListE2ETests import Item, open_process, allocate, release, write, read, close, send

AGE_COLORS = {(255, 236, 179), (220, 243, 228), (229, 240, 252)}
PURPLE = (112, 48, 160)


def run():
    assert C.sizeof(C.c_void_p) == 8
    directory = Path('build/qa/process-colors-' + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('bin/ProxyLane64.exe')
    shutil.copy2(binary, directory / 'ProxyLane64.exe')
    for name in ('ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(Path('bin') / name, directory / name)
    (directory / 'ProxyLane.ini').write_text(
        '[options]\nlanguage=en-US\nlastselected=Colors\n[proxy_Colors]\n'
        'Type=SOCKS5\nHost=127.0.0.1\nPort=9\nTransport=PLAIN\n'
        'HookTCP=1\nHookUDP=0\nHookChildProcess=0\n', encoding='utf-8')
    owner = child = None
    handle = memory = None
    try:
        owner = subprocess.Popen([str(directory / 'ProxyLane64.exe')], cwd=directory,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        main = wait_for(lambda: next((w for w in windows(owner.pid) if not USER.GetParent(w)), None), 'main')
        settings = wait_for(lambda: settings_page(main), 'settings')
        page = wait_for(lambda: page_with(main, 1007), 'process page')
        view = USER.GetDlgItem(page, 1007)
        send(settings, 0x111, 1)  # Start only the disposable fixture's proxy.
        pipe = wait_for(lambda: owned_pipe(owner.pid), 'owned proxy')
        send(page, 0x111, 1141)
        handle = open_process(0x38, False, owner.pid)
        assert handle
        memory = allocate(handle, None, 4096, 0x3000, 4)
        assert memory
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(90)'],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        born = time.monotonic()

        class FindItem(C.Structure):
            _fields_ = [('flags', W.UINT), ('text', C.c_void_p), ('data', C.c_ssize_t),
                        ('point', W.POINT), ('direction', C.c_uint)]

        def row_index():
            item = FindItem(flags=1, data=child.pid)
            assert write(handle, memory, C.byref(item), C.sizeof(item), None)
            return send(view, 0x1053, -1, memory)

        def refresh():
            send(page, 0x111, 1009)
            wait_for(lambda: USER.IsWindowEnabled(USER.GetDlgItem(page, 1009)) and row_index() >= 0, 'child snapshot')

        def select(selected):
            row = row_index()
            item = Item(state=2 if selected else 0, stateMask=2)
            assert write(handle, memory, C.byref(item), C.sizeof(item), None)
            send(view, 0x102b, row if selected else -1, memory)
            assert bool(send(view, 0x102c, row_index(), 2) & 2) == selected, 'native selection state'

        def colors(label):
            row = row_index()
            assert row >= 0
            send(view, 0x1013, row, 0)  # EnsureVisible, then render this row only.
            bounds = W.RECT(left=0)
            assert write(handle, memory, C.byref(bounds), C.sizeof(bounds), None)
            assert send(view, 0x100e, row, memory)
            assert read(handle, memory, C.byref(bounds), C.sizeof(bounds), None)
            origin, window = W.POINT(), W.RECT()
            USER.ClientToScreen.argtypes = [W.HWND, C.POINTER(W.POINT)]
            assert USER.ClientToScreen(view, C.byref(origin))
            assert USER.GetWindowRect(view, C.byref(window))
            image_path = directory / (label + '.png')
            capture_dialog(view, image_path)
            with Image.open(image_path) as image:
                dx, dy = origin.x - window.left, origin.y - window.top
                crop = image.crop((max(0, bounds.left + dx), bounds.top + dy,
                                   min(image.width, bounds.right + dx), bounds.bottom + dy))
                return Counter(crop.getdata())

        refresh()
        select(False)
        assert send(view, 0x1032) == 0, 'no selected rows'
        first = colors('new')
        assert sum(first[c] for c in AGE_COLORS) > 100, first.most_common(5)
        select(True)
        selected = colors('selected')
        assert sum(selected[c] for c in AGE_COLORS) == 0, selected.most_common(5)
        select(False)
        for seconds, expected in ((5.5, (220, 243, 228)), (10.5, (229, 240, 252)), (20.5, (255, 255, 255))):
            time.sleep(max(0, born + seconds - time.monotonic()))
            refresh()
            pixels = colors('age-' + str(seconds))
            assert pixels[expected] > 100, (seconds, pixels.most_common(5))
            if seconds > 20:
                assert sum(pixels[c] for c in AGE_COLORS) == 0
        attach(directory, 64, child.pid, pipe)

        def purple():
            refresh()
            return colors('hooked')[PURPLE] > 5

        wait_for(purple, 'hooked child purple text')
        header = send(view, 0x101f)
        assert send(header, 0x1207, 0, memory)
        rect = W.RECT()
        assert read(handle, memory, C.byref(rect), C.sizeof(rect), None)
        point = ((rect.top + rect.bottom) // 2 << 16) | ((rect.left + rect.right) // 2)
        send(header, 0x201, 1, point)
        send(header, 0x202, 0, point)
        refresh()
        assert colors('hooked-sorted')[PURPLE] > 5, 'hook color survives column sorting'
        child.terminate()
        child.wait(timeout=10)
        refresh_button = USER.GetDlgItem(page, 1009)
        send(page, 0x111, 1009)
        wait_for(lambda: USER.IsWindowEnabled(refresh_button) and row_index() < 0, 'child exit')
        USER.PostMessageW(main, 0x10, 0, 0)
        owner.wait(timeout=10)
        print('PASS: age colors, expiry, selection precedence and hooked text before/after sorting;', directory, flush=True)
    finally:
        if memory:
            release(handle, memory, 0, 0x8000)
        if handle:
            close(handle)
        for process in (child, owner):
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)


if __name__ == '__main__':
    run()
