"""Remember only successful explicit UI enables, using a disposable portable INI."""
import configparser
import ctypes as C
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

from ExitWarningE2ETests import USER, CALLBACK, wait_for, windows, settings_page, text
from ProcessListE2ETests import send
from ProfileSharingE2ETests import command, modal, dismiss


def run():
    root = Path(__file__).resolve().parents[1]
    folder = root / 'build/qa' / ('lastselected-' + uuid.uuid4().hex[:8])
    folder.mkdir(parents=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(root / 'bin' / name, folder / name)
    (folder / 'portable.flag').touch()
    ini = folder / 'ProxyLane.ini'
    data = '[options]\nlanguage=en-US\nlastselected=A\n'
    for name in ('A', 'B'):
        data += (f'[proxy_{name}]\nType=SOCKS5\nHost=127.0.0.1\nPort=1080\n'
                 'HookTCP=0\nHookUDP=0\nBlockUDP=0\nHookChildProcess=0\n'
                 'RedirectPrivateDNS=0\nTransport=PLAIN\n')
    data += '[proxy_Bad]\nType=CHAIN\nHop1=Missing\n'
    ini.write_text(data, encoding='utf-16')
    process = None

    def remembered():
        saved = configparser.ConfigParser(interpolation=None)
        saved.read(ini, encoding='utf-16')
        return saved['options']['lastselected']

    def launch(*args):
        nonlocal process
        process = subprocess.Popen([str(folder / 'ProxyLane64.exe'), *args], cwd=folder,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        main = wait_for(lambda: next((w for w in windows(process.pid) if settings_page(w)), None), 'main')
        page = settings_page(main)
        wait_for(lambda: text(USER.GetDlgItem(page, 1022)), 'initial profile loaded')
        return main, page

    def close():
        nonlocal process
        if process is not None:
            process.terminate()
            process.wait(10)
            process = None

    def select(page, name):
        combo = USER.GetDlgItem(page, 1022)
        value = C.create_unicode_buffer(name)
        assert send(combo, 0x14d, -1, C.addressof(value)) >= 0
        send(page, 0x111, 1022 | (1 << 16), combo)
        assert text(combo) == name

    def stop(page):
        command(page, 2)
        wait_for(lambda: USER.IsWindowEnabled(USER.GetDlgItem(page, 1)), 'stopped')

    try:
        main, page = launch()
        assert text(USER.GetDlgItem(page, 1022)) == 'A'
        select(page, 'B')
        assert remembered() == 'A', 'viewing must not remember B'
        port = USER.GetDlgItem(page, 1002)
        value = C.create_unicode_buffer('1081')
        send(port, 0xc, 0, C.addressof(value))
        wait_for(lambda: USER.IsWindowEnabled(USER.GetDlgItem(page, 1052)), 'dirty')
        command(page, 1052)
        wait_for(lambda: not USER.IsWindowEnabled(USER.GetDlgItem(page, 1052)), 'saved')
        assert remembered() == 'A', 'saving must not remember B'
        select(page, 'Bad')
        command(page, 1)
        dismiss(modal(process, main), 1)
        assert remembered() == 'A', 'failed enable must not remember Bad'
        select(page, 'B')
        command(page, 1)
        wait_for(lambda: remembered() == 'B', 'explicit enable remembers B')
        select(page, 'A')
        # Even a stale notification for the disabled button cannot remember a
        # viewed profile while another profile is still running.
        command(page, 1)
        assert remembered() == 'B'
        stop(page)
        assert remembered() == 'B', 'stopping after browsing must retain B'
        close()
        print('PASS: viewing/saving/failure/stop preserve selection; UI enable remembers it', flush=True)

        main, page = launch()
        assert text(USER.GetDlgItem(page, 1022)) == 'B', 'restart restores last UI-enabled profile'
        select(page, 'A')
        home_pages = []
        @CALLBACK
        def find_home(window, _):
            if USER.GetDlgItem(window, 1072):
                home_pages.append(window)
            return True
        USER.EnumChildWindows(main, find_home, 0)
        assert len(home_pages) == 1
        command(home_pages[0], 1072)
        wait_for(lambda: remembered() == 'A', 'home enable remembers A')
        stop(page)
        close()
        print('PASS: restart restores selection and home Enable also remembers it', flush=True)

        marker = folder / 'automation-complete.txt'
        main, page = launch('--auto', '--profile', 'B', '--run', sys.executable, '--', '-c',
                            'from pathlib import Path; Path(' + repr(str(marker)) + ').write_text("ok")')
        wait_for(marker.exists, 'CLI launched its target')
        wait_for(lambda: USER.IsWindowEnabled(USER.GetDlgItem(page, 2)), 'CLI enabled B')
        assert text(USER.GetDlgItem(page, 1022)) == 'B'
        assert remembered() == 'A', 'CLI enable must retain the last UI-enabled profile'
        close()
        print('PASS: successful CLI enable does not change lastselected', flush=True)
        print(folder, flush=True)
    finally:
        close()


if __name__ == '__main__':
    run()
