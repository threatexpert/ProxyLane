"""Owned portable GUI: default/load/save/restart, localized adjacent switch."""
import argparse
import configparser
import ctypes as C
from pathlib import Path
import re
import shutil
import subprocess
import uuid

from ExitWarningE2ETests import USER, wait_for, windows, settings_page, text
from ProcessListE2ETests import send
from ProfileSharingE2ETests import command
from MonitorLayoutE2ETests import rect, screenshot


def run(language, binary_directory):
    root = Path(__file__).resolve().parents[1]
    folder = root / 'build/qa' / ('ping-settings-' + language + '-' + uuid.uuid4().hex[:8])
    folder.mkdir(parents=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(root / binary_directory / name, folder / name)
    (folder / 'portable.flag').touch()
    ini = folder / 'ProxyLane.ini'
    data = f'[options]\nlanguage={language}\nlastselected=Old\n'
    for name in ('Old', 'On'):
        data += (f'[proxy_{name}]\nType=SOCKS5\nHost=127.0.0.1\nPort=1080\n'
                 'HookTCP=0\nHookUDP=0\nHookChildProcess=0\nRedirectPrivateDNS=0\n')
        if name == 'On':
            data += 'BlockPing=1\n'
    ini.write_text(data, encoding='utf-16')
    header = (root / 'src/ProxyLane/resource.h').read_text()
    ping_id = int(re.search(r'#define IDC_CHECK_BLOCK_PING\s+(\d+)', header)[1])
    process = None

    def saved(name):
        config = configparser.ConfigParser(interpolation=None)
        config.read(ini, encoding='utf-16')
        return config.getboolean('proxy_' + name, 'BlockPing', fallback=False)

    def launch():
        nonlocal process
        process = subprocess.Popen([str(folder / 'ProxyLane64.exe')], cwd=folder,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        main = wait_for(lambda: next((w for w in windows(process.pid) if settings_page(w)), None), 'main')
        page = settings_page(main)
        wait_for(lambda: text(USER.GetDlgItem(page, 1022)), 'profile loaded')
        nav = USER.GetDlgItem(main, 0x1006)
        scale = USER.GetDpiForWindow(nav) / 96
        x, y = round(50 * scale), round(142 * scale)
        send(nav, 0x201, 1, (y << 16) | x); send(nav, 0x202, 0, (y << 16) | x)
        wait_for(lambda: USER.IsWindowVisible(page), 'settings visible')
        USER.SetWindowPos(main, None, 0, 0, round(1100 * scale), round(760 * scale), 0x16)
        return main, page

    def select(page, name):
        combo = USER.GetDlgItem(page, 1022); value = C.create_unicode_buffer(name)
        assert send(combo, 0x14d, -1, C.addressof(value)) >= 0
        send(page, 0x111, 1022 | (1 << 16), combo)
        assert text(combo) == name

    def toggle_save(page, expected):
        control = USER.GetDlgItem(page, ping_id)
        send(control, 0xf5)
        assert send(control, 0xf0) == expected
        wait_for(lambda: USER.IsWindowEnabled(USER.GetDlgItem(page, 1052)), 'dirty after toggle')
        command(page, 1052)
        wait_for(lambda: not USER.IsWindowEnabled(USER.GetDlgItem(page, 1052)), 'saved')

    def close():
        nonlocal process
        if process is not None:
            process.terminate(); process.wait(10); process = None

    try:
        main, page = launch()
        control = USER.GetDlgItem(page, ping_id)
        assert control and send(control, 0xf0) == 0, 'old profile defaults off'
        assert text(control) == ('屏蔽 Ping' if language == 'zh-CN' else 'Block Ping')
        ping, ipv6 = rect(control, page), rect(USER.GetDlgItem(page, 1071), page)
        assert ping[1] == ipv6[1] and ping[0] >= ipv6[2], ('not next to IPv6', ping, ipv6)
        toggle_save(page, 1); assert saved('Old')
        select(page, 'On'); assert send(control, 0xf0) == 1
        toggle_save(page, 0); assert not saved('On')
        select(page, 'Old'); assert send(control, 0xf0) == 1
        screenshot(main, folder / 'ping-settings.png')
        scale = USER.GetDpiForWindow(page) / 96
        for width in (800, 1100):
            USER.SetWindowPos(main, None, 0, 0, round(width * scale), round(760 * scale), 0x16)
            # The existing flow layout may wrap at narrow widths, but the new
            # switch must never overlap another setting or escape the card.
            card = rect(USER.GetDlgItem(page, 1033), page)
            bounds = [rect(USER.GetDlgItem(page, ident), page) for ident in (1040, 1071, ping_id)]
            for i, first in enumerate(bounds):
                assert card[0] <= first[0] < first[2] <= card[2] and card[1] <= first[1] < first[3] <= card[3], ('outside card', card, first)
                for second in bounds[i+1:]:
                    assert min(first[2], second[2]) <= max(first[0], second[0]) or min(first[3], second[3]) <= max(first[1], second[1]), ('overlap', first, second)
        close()
        main, page = launch()
        assert send(USER.GetDlgItem(page, ping_id), 0xf0) == 1, 'restart retains saved setting'
        select(page, 'On'); assert send(USER.GetDlgItem(page, ping_id), 0xf0) == 0
        print('PASS Ping default/load/save/restart/layout', language, folder, flush=True)
    finally:
        close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--language', choices=['zh-CN', 'en-US'], default='zh-CN')
    parser.add_argument('--binary-directory', default='bin')
    args = parser.parse_args()
    run(args.language, args.binary_directory)
