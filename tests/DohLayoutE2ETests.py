"""Real settings-dialog regression using the existing GUI test harness.

Uses an isolated portable sample profile. No proxy or CA trust is enabled.
"""
import argparse
from collections import Counter
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

from MonitorLayoutE2ETests import u, k, CALLBACK, send, rect, screenshot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary-directory', default='bin')
    parser.add_argument('--language', choices=['zh-CN', 'en-US'], default='zh-CN')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = root / 'build/qa' / ('doh-layout-' + args.language + '-' + uuid.uuid4().hex[:8])
    work.mkdir()
    source = (root / args.binary_directory).resolve()
    for name in ['ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll',
                 'ProxyLaneMitm64.dll', 'ProxyLaneSecureTransport64.dll', 'ProxyLaneSsh64.dll']:
        shutil.copy2(source / name, work / name)
    config = (root / 'examples/ProxyLane.ini').read_text()
    config = config.replace('[options]', '[options]\nlanguage=' + args.language)
    config = config.replace('DecryptHTTPS=1', 'DecryptHTTPS=0').replace('DecryptQUIC=1', 'DecryptQUIC=0')
    (work / 'portable.flag').touch()
    (work / 'ProxyLane.ini').write_text(config)
    header = (root / 'src/ProxyLane/resource.h').read_text()
    ids = {name: int(value, 0) for name, value in re.findall(
        r'^#define\s+(IDC_\w+)\s+(0x[0-9a-fA-F]+|\d+)\s*$', header, re.M)}
    u.GetParent.argtypes = [w.HWND]; u.GetParent.restype = w.HWND
    u.GetDlgCtrlID.argtypes = [w.HWND]; u.GetDlgCtrlID.restype = c.c_int
    k.GetModuleHandleW.argtypes = [w.LPCWSTR]; k.GetModuleHandleW.restype = w.HMODULE
    module = k.GetModuleHandleW('ProxyLaneHook64.dll')
    if module:
        assert c.WinDLL('ProxyLaneHook64.dll', handle=module).gp_UnhookWinsock()
    u.SetProcessDPIAware()
    process = subprocess.Popen([str(work / 'ProxyLane64.exe')], cwd=work,
                               env=dict(os.environ, PROXYLANE_MITM='0', PROXYLANE_MITM_HOME=str(work / 'pki')))

    def wait(predicate):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process.poll() is None, ('GUI exited', process.returncode)
            result = predicate()
            if result:
                return result
            time.sleep(.1)
        raise AssertionError('Timed out waiting for owned settings dialog')

    def windows():
        found = []
        @CALLBACK
        def collect(hwnd, _):
            pid = w.DWORD(); u.GetWindowThreadProcessId(hwnd, c.byref(pid))
            if pid.value == process.pid and u.IsWindowVisible(hwnd) and u.GetDlgItem(hwnd, 0x1006):
                found.append(hwnd)
            return True
        u.EnumWindows(collect, 0)
        return found[0] if len(found) == 1 else None

    try:
        main_window = wait(windows)
        nav = u.GetDlgItem(main_window, 0x1006)
        pages = []
        @CALLBACK
        def collect_page(hwnd, _):
            if u.GetDlgItem(hwnd, ids['IDC_CB_PROXYTYPE']) and u.GetDlgItem(hwnd, ids['IDC_RADIO_DNSLOCAL']):
                pages.append(hwnd)
            return True
        u.EnumChildWindows(nav, collect_page, 0)
        assert len(pages) == 1, pages
        page = pages[0]
        scale = u.GetDpiForWindow(nav) / 96
        x, y = round(50 * scale), round((78 + 44 + 20) * scale)  # PAGE_PROXY = 1
        send(nav, 0x201, 1, (y << 16) | x)
        send(nav, 0x202, 0, (y << 16) | x)
        wait(lambda: u.IsWindowVisible(page))
        children = []
        @CALLBACK
        def collect_child(hwnd, _):
            if u.GetParent(hwnd) == page:
                children.append(hwnd)
            return True
        u.EnumChildWindows(page, collect_child, 0)
        counts = Counter(u.GetDlgCtrlID(hwnd) for hwnd in children)
        duplicates = {ident: count for ident, count in counts.items() if ident not in (0, -1, 65535) and count > 1}
        assert not duplicates, ('Duplicate settings control IDs', duplicates)

        def control(name):
            hwnd = u.GetDlgItem(page, ids[name]); assert hwnd, name
            return hwnd

        def click(name):
            send(control(name), 0xF5)  # BM_CLICK, including reflected custom-radio handling.

        radios = ['IDC_RADIO_DNSLOCAL', 'IDC_RADIO_DNSREMOTE', 'IDC_RADIO_DNSDOH']
        fields = ['IDC_STATIC_DOH_URL', 'IDC_EDIT_DOH_URL', 'IDC_STATIC_DOH_BOOTSTRAP',
                  'IDC_EDIT_DOH_BOOTSTRAP']
        legacy = ['IDC_CHECK_REDIRECT_PRIVATE_DNS', 'IDC_EDIT_REDIRECT_DNS']
        records = []
        assert not u.GetDlgItem(page, 0x2425), 'Removed DoH explanation is still present'
        for name, expected in [('IDC_EDIT_DOH_URL', 'https://dns.google/dns-query'),
                               ('IDC_EDIT_DOH_BOOTSTRAP', '8.8.8.8, 8.8.4.4')]:
            value = c.create_unicode_buffer(1024)
            send(control(name), 0xD, len(value), c.addressof(value))
            assert value.value == expected, ('DoH default', name, value.value)

        def validate(mode):
            assert [send(control(name), 0xF0) for name in radios] == [int(name == mode) for name in radios]
            doh = mode == radios[2]
            for name in fields:
                assert bool(u.IsWindowVisible(control(name))) == doh, ('DoH visibility', name, mode)
            for name in legacy:
                assert bool(u.IsWindowVisible(control(name))) != doh, ('Legacy visibility', name, mode)
            visible = ['IDC_CHECK_HOOKTCP', 'IDC_CHECK_HOOK_UDP', 'IDC_CHECK_HOOKCHILDPROCESS',
                       'IDC_CHECK_BLOCKUDP', 'IDC_CHECK_BLOCK_IPV6', 'IDC_STATIC_DNS_LABEL'] + radios + (fields if doh else legacy)
            bounds = {name: rect(control(name), page) for name in visible}
            for i, first in enumerate(visible):
                a = bounds[first]
                assert a[2] > a[0] and a[3] > a[1], (first, a)
                for second in visible[i + 1:]:
                    b = bounds[second]
                    assert min(a[2], b[2]) <= max(a[0], b[0]) or min(a[3], b[3]) <= max(a[1], b[1]), ('Overlap', first, second, a, b)
            if doh:
                for first, second in zip(radios, radios[1:]):
                    assert bounds[first][1] == bounds[second][1], 'DNS choices must share a row'
                    assert bounds[first][2] <= bounds[second][0]
                left, right = bounds['IDC_EDIT_DOH_URL'], bounds['IDC_EDIT_DOH_BOOTSTRAP']
                assert left[1] == right[1] and left[3] == right[3] and left[2] < right[0], 'DoH fields must be side by side'
                for label, edit in [('IDC_STATIC_DOH_URL', 'IDC_EDIT_DOH_URL'),
                                    ('IDC_STATIC_DOH_BOOTSTRAP', 'IDC_EDIT_DOH_BOOTSTRAP')]:
                    assert bounds[radios[2]][3] <= bounds[label][1]
                    assert bounds[label][3] <= bounds[edit][1]
            records.append({'mode': mode, 'rectangles': bounds})

        scale = u.GetDpiForWindow(page) / 96
        for width, height in ((800, 488), (800, 680), (1040, 680)):
            assert u.SetWindowPos(main_window, None, 0, 0, round(width * scale), round(height * scale), 0x16)
            send(page, 0x115, 6)  # WM_VSCROLL / SB_TOP: exercise automatic reveal.
            for mode in (radios[1], radios[2], radios[0], radios[2]):
                click(mode); validate(mode)
                if mode == radios[2]:
                    viewport = w.RECT()
                    assert u.GetClientRect(page, c.byref(viewport))
                    for name in [radios[2]] + fields:
                        bounds = rect(control(name), page)
                        assert 0 <= bounds[0] < bounds[2] <= viewport.right, ('DoH clipped horizontally', name, bounds)
                        assert 0 <= bounds[1] < bounds[3] <= viewport.bottom, ('DoH not automatically revealed', name, bounds, viewport.bottom)
            # Capture without manual scrolling: the selection must reveal the fields.
            time.sleep(.2)
            screenshot(main_window, work / f'doh-{width}-{height}.png')
            click('IDC_RADIO_TAB_CHILD')
            for name in radios + fields + legacy:
                assert not u.IsWindowVisible(control(name)), ('Hidden tab leaked a control', name)
            click('IDC_RADIO_TAB_BASIC'); validate(radios[2])

        proxy_type = control('IDC_CB_PROXYTYPE')
        text = c.create_unicode_buffer('SSH')
        index = send(proxy_type, 0x158, -1, c.addressof(text))  # CB_FINDSTRINGEXACT
        assert 0 <= index < 16, index
        send(proxy_type, 0x14E, index)
        send(page, 0x111, ids['IDC_CB_PROXYTYPE'] | (1 << 16), proxy_type)
        # Selecting SSH opens its existing advanced authentication row.
        assert u.IsWindowVisible(u.GetDlgItem(page, 0x2410)), 'SSH label missing'
        assert u.IsWindowVisible(u.GetDlgItem(page, 0x2411)), 'SSH authentication missing'
        validate(radios[2])
        ssh = rect(u.GetDlgItem(page, 0x2410), page)
        assert ssh[3] <= rect(control('IDC_STATIC_GROUP_OTHER'), page)[1], 'SSH moved into DNS card'
        send(u.GetDlgItem(page, 0x2402), 0xF5)
        assert not u.IsWindowVisible(u.GetDlgItem(page, 0x2410))
        validate(radios[2])
        send(u.GetDlgItem(page, 0x2402), 0xF5)
        assert u.IsWindowVisible(u.GetDlgItem(page, 0x2410))
        validate(radios[2])
        send(page, 0x115, 7)
        time.sleep(.2)
        screenshot(main_window, work / 'ssh-doh.png')
        (work / 'results.json').write_text(json.dumps(records, indent=2))
        print('PASS', args.language, work, flush=True)
    except Exception:
        if 'main_window' in locals():
            screenshot(main_window, work / 'failure.png')
        print('FAILED artifacts:', work, flush=True)
        raise
    finally:
        if process.poll() is None:
            process.terminate(); process.wait(5)


if __name__ == '__main__':
    main()
