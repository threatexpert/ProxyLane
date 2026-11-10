"""Preserve each profile's UDP settings across real GUI profile switches.

Uses an isolated portable configuration with synthetic endpoints; no connections.
"""
import configparser
import ctypes as C
from pathlib import Path
import shutil
import subprocess
import uuid

from ExitWarningE2ETests import USER, wait_for, windows, settings_page, text
from ProcessListE2ETests import send


def run():
    root = Path(__file__).resolve().parents[1]
    folder = root / 'build/qa' / ('profile-switch-udp-' + uuid.uuid4().hex[:8])
    folder.mkdir(parents=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(root / 'bin' / name, folder / name)
    (folder / 'portable.flag').touch()
    ini = folder / 'ProxyLane.ini'
    profiles = {'SG': ('SOCKS5', 1, 0), 'Blocked': ('SOCKS5', 1, 1),
                'Off': ('SOCKS5', 0, 0), 'HTTP': ('HTTP', 0, 0), 'SSH': ('SSH', 0, 1)}
    data = '[options]\nlanguage=zh-CN\nlastselected=SG\n'
    for name, (protocol, hook, block) in profiles.items():
        data += (f'[proxy_{name}]\nType={protocol}\nHost=127.0.0.1\nPort=1080\n'
                 f'User=fixture\nPass=fixture\nHookUDP={hook}\nBlockUDP={block}\n'
                 'HookTCP=1\nTransport=PLAIN\nTargetFilter=fixture.example\n')
    data += '[proxy_Chain]\nType=CHAIN\nHop1=SG\nHop2=HTTP\nHookUDP=0\nBlockUDP=1\n'
    ini.write_text(data, encoding='utf-16')

    def disk():
        value = configparser.ConfigParser(interpolation=None)
        value.read(ini, encoding='utf-16')
        return {name: dict(value[name]) for name in value.sections() if name.startswith('proxy_')}

    original = disk()
    process = subprocess.Popen([str(folder / 'ProxyLane64.exe'), '--profile', 'SG'], cwd=folder,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        main = wait_for(lambda: next((w for w in windows(process.pid) if settings_page(w)), None), 'main')
        page = settings_page(main)
        navigation = USER.GetParent(page)
        USER.GetDpiForWindow.argtypes = [C.c_void_p]
        dpi = USER.GetDpiForWindow(navigation)
        point = (20 * dpi // 96) | ((136 * dpi // 96) << 16)
        USER.PostMessageW(navigation, 0x201, 1, point)
        USER.PostMessageW(navigation, 0x202, 0, point)
        wait_for(lambda: USER.IsWindowVisible(page), 'profiles page ready')
        combo = USER.GetDlgItem(page, 1022)
        hook, block = USER.GetDlgItem(page, 1013), USER.GetDlgItem(page, 1040)
        save = USER.GetDlgItem(page, 1052)

        def select(name):
            value = C.create_unicode_buffer(name)
            assert send(combo, 0x14d, -1, C.addressof(value)) >= 0  # CB_SELECTSTRING
            send(page, 0x111, 1022 | (1 << 16), combo)
            assert text(combo) == name
            assert not USER.IsWindowEnabled(save), 'loading must not dirty a profile'

        def check(name):
            _, expected_hook, expected_block = profiles[name]
            actual = (send(hook, 0xf0), send(block, 0xf0))
            assert actual == (expected_hook, expected_block), (name, actual, disk()['proxy_' + name])

        check('SG')
        for source in ('Chain', 'HTTP', 'SSH', 'Blocked', 'Off', 'Chain'):
            select(source)
            if source == 'Chain':
                assert not USER.IsWindowEnabled(hook) and send(hook, 0xf0) == 0
            else:
                check(source)
            select('SG')
            check('SG')
            assert disk() == original, 'switching only changes lastselected, never profile contents'
        print('PASS: Chain/HTTP/SSH/SOCKS5 switches preserve UDP flags without dirtying or writing profiles', flush=True)

        # Saving an unrelated edit after a chain round trip cannot persist a lost UDP checkbox.
        select('Chain'); select('SG')
        port = USER.GetDlgItem(page, 1002)
        value = C.create_unicode_buffer('1081')
        send(port, 0xc, 0, C.addressof(value))
        wait_for(lambda: USER.IsWindowEnabled(save), 'unrelated edit is dirty')
        send(page, 0x111, 1052, save)
        wait_for(lambda: not USER.IsWindowEnabled(save), 'saved')
        saved = disk()
        assert saved['proxy_SG']['hookudp'] == '1' and saved['proxy_SG']['blockudp'] == '0'
        assert saved['proxy_SG']['port'] == '1081'
        assert all(saved[name] == original[name] for name in original if name != 'proxy_SG')
        select('Chain'); select('SG'); check('SG')
        print('PASS: saving another field after a chain round trip retains SG UDP settings and other profiles', flush=True)
        print(folder, flush=True)
    finally:
        process.terminate(); process.wait(10)


if __name__ == '__main__':
    run()
