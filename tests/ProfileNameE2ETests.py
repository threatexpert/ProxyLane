"""Exercise profile-name saves and legacy duplicate sections in a portable GUI."""
import argparse
from ctypes import wintypes
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory

from ExitWarningE2ETests import USER, settings_page, wait_for, windows
from ProfileSharingE2ETests import command, dropdown, field, names, select, set_field

USER.FindWindowExW.argtypes = [wintypes.HWND, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR]
USER.FindWindowExW.restype = wintypes.HWND


def type_name(page, name):
    combo = USER.GetDlgItem(page, 1022)
    edit = USER.FindWindowExW(combo, None, 'Edit', None)
    assert edit
    set_field(page, 1022, '')
    for character in name:
        USER.SendMessageW(edit, 0x0102, ord(character), 1)  # WM_CHAR
    actual = field(page, 1022)
    assert actual == name, f'Input accepted {len(actual)} of {len(name)} characters'


def run(language, legacy_exe):
    root = Path(__file__).resolve().parents[1]
    legacy = 'Legacy[100%5D'
    long_prefix = '香港' * 60
    name = long_prefix + '[IEPL%5D]'
    other = '香港[IEPL~PLc~5D]]'
    encoded_name = long_prefix + '[IEPL%5D~PLc~5D'
    encoded_other = '香港[IEPL~PLc~005D~PLc~5D~PLc~5D'
    with TemporaryDirectory(prefix='ProxyLane-profile-name-') as temporary:
        directory = Path(temporary)
        for filename in ('ProxyLane64.exe', 'ProxyLaneHook32.dll', 'ProxyLaneHook64.dll'):
            shutil.copy2(root / 'bin' / filename, directory / filename)
        (directory / 'portable.flag').touch()
        ini = directory / 'ProxyLane.ini'
        ini.write_text(f'''[options]
language={language}
lastselected=Direct
[proxy_Direct]
Type=NOPROXY
[proxy_{legacy}]
Type=NOPROXY
[proxy_Old[broken]]
Type=NOPROXY
[proxy_Old[broken]]
HookTCP=1
''', encoding='utf-16')

        def launch():
            return subprocess.Popen([str(directory / 'ProxyLane64.exe')], cwd=directory,
                                    creationflags=subprocess.CREATE_NO_WINDOW)

        def profile_page(process, selected):
            main = wait_for(lambda: next((w for w in windows(process.pid)
                                         if USER.IsWindowVisible(w) and settings_page(w)), None), 'main window')
            page = settings_page(main)
            wait_for(lambda: field(page, 1022) == selected, 'initial profile')
            return main, page

        before = ini.read_bytes()
        with launch() as process:
            try:
                _, page = profile_page(process, 'Direct')
                assert names(page).count('Old[broken') == 1
                dropdown(page)
                assert names(page).count('Old[broken') == 1 and legacy in names(page)
                assert ini.read_bytes() == before
                for attempted in (name, other, name.lower()):
                    type_name(page, attempted)
                    command(page, 1052)  # Save profile
                    wait_for(lambda: not USER.IsWindowEnabled(USER.GetDlgItem(page, 1052)), 'profile saved')
                    dropdown(page)
                    assert sum(n.casefold() == attempted.casefold() for n in names(page)) == 1
                sections = [line.casefold() for line in ini.read_text(encoding='utf-16').splitlines()
                            if line.startswith('[')]
                assert sections.count(f'[proxy_{encoded_name}]'.casefold()) == 1, sections
                assert sections.count(f'[proxy_{encoded_other}]'.casefold()) == 1, sections
                assert sections.count(f'[proxy_{legacy}]'.casefold()) == 1, sections
                assert not list(directory.glob('ProxyLane.ini.*.tmp'))
                select(page, name)
                command(page, 1)  # Enable profile
                wait_for(lambda: f'lastselected={encoded_name}' in ini.read_text(encoding='utf-16'),
                         'remembered the name recognized by the legacy reader')
                command(page, 2)  # Disable profile
                wait_for(lambda: USER.IsWindowEnabled(USER.GetDlgItem(page, 1)), 'stopped')
            finally:
                process.terminate()

        with launch() as process:
            try:
                _, page = profile_page(process, name)
                assert all(names(page).count(profile) == 1 for profile in (name, other, legacy, 'Old[broken'))
            finally:
                process.terminate()
        if legacy_exe:
            shutil.copy2(legacy_exe, directory / 'ProxyLane64.exe')
            with launch() as process:
                try:
                    _, page = profile_page(process, encoded_name)
                    assert all(names(page).count(profile) == 1 for profile in (encoded_name, encoded_other, legacy))
                    print('PASS: old executable loads the same profiles by their stored names')
                finally:
                    process.terminate()
    print(f'PASS: {language} profile names survive repeat saves and restart alongside legacy profiles')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--language', choices=['zh-CN', 'en-US'], default='zh-CN')
    parser.add_argument('--legacy-exe', type=Path, help='also verify loading with a pre-escape x64 executable')
    args = parser.parse_args()
    run(args.language, args.legacy_exe)
