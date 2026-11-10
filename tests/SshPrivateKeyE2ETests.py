"""Real private-key profile, sharing, restart and node-editor tests; disposable data only."""
import argparse
import base64
import configparser
import ctypes as C
from ctypes import wintypes as W
import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
from ProfileSharingE2ETests import (USER, wait_for, windows, settings_page, text,
    command, field, dismiss, select, set_field, clipboard_read, clipboard_write, notice)
from ExitWarningE2ETests import capture_dialog, CALLBACK
from SshKeyStoreConcurrencyTests import keys_directory


def run(language, key_name):
    root = Path(__file__).resolve().parents[1]
    folder = root / 'build/qa' / ('ssh-private-key-' + uuid.uuid4().hex[:8])
    folder.mkdir(parents=True)
    processes = []
    old_clipboard = clipboard_read()
    main = None
    owned_keys = []
    log = (folder / 'server.log').open('w')
    try:
        fixture_file = folder / 'fixture.json'
        fixture = subprocess.Popen([sys.executable, str(root / 'tests/ssh_test_servers.py'), str(fixture_file)],
            creationflags=subprocess.CREATE_NO_WINDOW, stderr=log)
        processes.append(fixture)
        wait_for(fixture_file.exists, 'fixture ready')
        ports = json.loads(fixture_file.read_text())
        for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll', 'ProxyLaneSsh64.dll'):
            shutil.copy2(root / 'bin' / name, folder / name)
        (folder / 'portable.flag').touch()
        locale = json.loads((root / f'src/ProxyLane/locales/{language}.json').read_text(encoding='utf-8'))
        pem = (folder / key_name).read_text()
        # Both LF (legacy/share) and CRLF (native imported file) are owned fixtures.
        for raw in {pem.encode(), pem.replace('\n','\r\n').encode()}:
            target = keys_directory() / (hashlib.sha256(raw).hexdigest() + '.pem')
            assert not target.exists()
            owned_keys.append(target)
        managed = keys_directory() / (hashlib.sha256(pem.encode()).hexdigest() + '.pem')
        ini = folder / 'ProxyLane.ini'
        ini.write_text(f'''[options]
language={language}
lastselected=Key
testhost=127.0.0.1:{ports['echo']}
IPv6TestAddress=::1
[proxy_Key]
Type=SSH
Host=127.0.0.1
Port={ports['a']}
User=key-user
Pass=
SshAuth=private_key
SshPrivateKey={pem.replace(chr(10), '|')}
SshKeyPassphrase=key-passphrase
SshHostKey={ports['fingerprint']}
HookTCP=1
HookUDP=0
BlockUDP=1
BlockIPv6=1
TargetFilter=preserve.example
[proxy_Password]
Type=SSH
Host=127.0.0.1
Port={ports['b']}
User=test-user
Pass=test-password
SshHostKey={ports['fingerprint']}
HookTCP=1
BlockUDP=1
[proxy_Chain]
Type=CHAIN
Hop1=Key
Hop2=Password
HookTCP=1
BlockUDP=1
''', encoding='utf-16')

        def config():
            result = configparser.ConfigParser(interpolation=None)
            result.read(ini, encoding='utf-16')
            return result

        def launch():
            process = subprocess.Popen([str(folder / 'ProxyLane64.exe')], cwd=folder,
                creationflags=subprocess.CREATE_NO_WINDOW)
            processes.append(process)
            main = wait_for(lambda: next((w for w in windows(process.pid)
                if USER.IsWindowVisible(w) and settings_page(w)), None), 'main window')
            page = settings_page(main)
            navigation = USER.GetParent(page)
            USER.GetDpiForWindow.argtypes = [W.HWND]
            dpi = USER.GetDpiForWindow(navigation)
            point = (20*dpi//96) | ((136*dpi//96) << 16)
            USER.SendMessageW(navigation, 0x201, 1, point)
            USER.SendMessageW(navigation, 0x202, 0, point)
            wait_for(lambda: USER.IsWindowVisible(page), 'profiles page')
            return process, main, page

        def test(owner, button, expected=None):
            command(owner, button)
            report = wait_for(lambda: next((w for w in windows(process.pid)
                if USER.GetDlgItem(w, 1201)), None), 'test results')
            wait_for(lambda: USER.IsWindowVisible(USER.GetDlgItem(report, 2)), 'report ready')
            assert (expected or locale['test.result.passed']) in text(USER.GetDlgItem(report, 1201)), text(USER.GetDlgItem(report, 1201))
            dismiss(report, 2)

        def choose(owner, control, index):
            USER.SendMessageW(USER.GetDlgItem(owner, control), 0x14e, index, 0)
            command(owner, control, 1)

        process, main, page = launch()
        assert USER.SendMessageW(USER.GetDlgItem(page, 0x2411), 0x147, 0, 0) == 1
        assert field(page, 1059) == locale['ssh.passphrase']
        assert field(page, 0x2413) == locale['ssh.replace_key']
        test(page, 1008)
        time.sleep(.2)
        capture_dialog(main, folder / 'key-profile.png')
        print('PASS saved encrypted key loads and authenticates', flush=True)

        command(page, 1129)
        wait_for(lambda: locale['share.includes_private_key'] in notice(page), 'secret notice')
        code = clipboard_read()
        prefix = 'proxylane://profile/v2/'
        assert code.startswith(prefix)
        value = json.loads(base64.urlsafe_b64decode(code[len(prefix):] + '==='))
        assert value['ssh_private_key'] == pem and value['password'] == 'key-passphrase'
        assert value['ssh_auth'] == 'private_key'
        managed.unlink()  # Pasting must materialize the shared key again.
        command(page, 1130)
        wait_for(lambda: notice(page).endswith(locale['share.pending_save']), 'paste completed')
        assert managed.read_bytes() == pem.encode()
        imported = field(page, 1022)
        command(page, 1052)
        wait_for(lambda: not USER.IsWindowEnabled(USER.GetDlgItem(page, 1052)), 'saved import')
        saved = config()['proxy_' + imported]
        assert saved['pass'] == '' and saved['sshkeypassphrase'] == 'key-passphrase'
        assert saved['sshkeyfile'] == managed.name and 'sshprivatekey' not in saved
        assert managed.read_bytes() == pem.encode()
        # Eliminate the original file: this profile must remain self-contained.
        (folder / key_name).unlink()
        test(page, 1008)
        USER.PostMessageW(main, 0x10, 0, 0)
        process.wait(timeout=15)
        process, main, page = launch()
        assert field(page, 1022) == imported and field(page, 0x2413) == locale['ssh.replace_key']
        test(page, 1008)
        print('PASS profile stores only a reference; paste writes key atomically; original file removal and restart preserve authentication', flush=True)
        backup = folder / 'managed-key-backup.pem'
        shutil.move(str(managed), str(backup))
        try:
            test(page, 1008, locale['test.ssh_key_file_failed'])
            command(page, 1129)
            error = wait_for(lambda: next((w for w in windows(process.pid) if w != main and USER.IsWindowVisible(w)), None), 'missing-key copy error')
            assert text(error) == locale['share.copy_failed']
            dismiss(error, 1)
            assert clipboard_read() == code, 'failed copy must preserve clipboard'
            assert field(page, 1022) == imported, 'missing file must not remove the profile'
        finally:
            shutil.move(str(backup), str(managed))
        print('PASS missing key reports an error and preserves profile and clipboard', flush=True)

        select(page, 'Password')
        assert USER.SendMessageW(USER.GetDlgItem(page, 0x2411), 0x147, 0, 0) == 0
        assert not USER.IsWindowVisible(USER.GetDlgItem(page, 0x2413))
        test(page, 1008)
        select(page, imported)
        choose(page, 0x2411, 0)
        command(page, 1129)
        password_code = clipboard_read()
        copied = json.loads(base64.urlsafe_b64decode(password_code.split('/')[-1] + '==='))
        assert password_code.startswith('proxylane://profile/v1/')
        assert copied['password'] == '' and 'ssh_private_key' not in copied
        choose(page, 0x2411, 1)
        set_field(page, 1003, 'key-passphrase')
        command(page, 1052)
        wait_for(lambda: not USER.IsWindowEnabled(USER.GetDlgItem(page, 1052)), 'restored key mode')
        print('PASS switching profiles and auth modes does not leak or reinterpret credentials', flush=True)

        # Import an actual file through the native picker (Unicode filename).
        key_file = folder / '测试密钥🔑.pem'
        key_file.write_text(pem, encoding='ascii')
        command(page, 0x2413)
        picker = wait_for(lambda: next((w for w in windows(process.pid)
            if w != main and USER.IsWindowVisible(w) and not settings_page(w)), None), 'key picker')
        edits = []
        @CALLBACK
        def find_edit(window, _):
            classname = C.create_unicode_buffer(64)
            USER.GetClassNameW(window, classname, 64)
            if classname.value == 'Edit' and USER.IsWindowVisible(window):
                edits.append(window)
            return True
        USER.EnumChildWindows(picker, find_edit, 0)
        assert edits, 'file picker filename edit'
        path = C.create_unicode_buffer(str(key_file))
        USER.SendMessageW(edits[-1], 0x000c, 0, C.addressof(path))
        USER.PostMessageW(picker, 0x111, 1, 0)
        wait_for(lambda: not USER.IsWindow(picker), 'key file imported')
        assert field(page, 0x2413) == locale['ssh.replace_key']
        command(page, 1052)
        wait_for(lambda: not USER.IsWindowEnabled(USER.GetDlgItem(page, 1052)), 'key file saved')
        test(page, 1008)
        print('PASS import from Unicode filename', flush=True)

        select(page, 'Chain')
        view = USER.GetDlgItem(page, 0x2405)
        # LVM_SETITEMSTATE needs remote memory, just as the existing node test.
        from ProcessListE2ETests import Item, open_process, allocate, release, write, close
        handle = open_process(0x38, False, process.pid)
        memory = allocate(handle, None, 4096, 0x3000, 4)
        try:
            item = Item(state=3, stateMask=3)
            assert write(handle, memory, C.byref(item), C.sizeof(item), None)
            USER.SendMessageW(view, 0x102b, 0, memory)
        finally:
            release(handle, memory, 0, 0x8000); close(handle)
        command(page, 0x240a)
        editor = wait_for(lambda: next((w for w in windows(process.pid) if USER.GetDlgItem(w, 1301)), None), 'node editor')
        wait_for(lambda: USER.IsWindowVisible(USER.GetDlgItem(editor, 0x2413)), 'key controls')
        assert field(editor, 1316) == locale['ssh.passphrase']
        assert field(editor, 0x2413) == locale['ssh.replace_key']
        capture_dialog(editor, folder / 'key-node-editor.png')
        test(editor, 1309)
        set_field(editor, 1306, 'wrong-passphrase')
        test(editor, 1309, locale['test.ssh_key_auth_failed'])
        set_field(editor, 1306, 'key-passphrase')
        set_field(editor, 1305, 'key-user')
        command(editor, 1)
        wait_for(lambda: not USER.IsWindow(editor), 'node saved')
        saved = config()
        assert saved['proxy_Key']['targetfilter'] == 'preserve.example'
        assert saved['proxy_Key']['sshkeyfile'] == managed.name and 'sshprivatekey' not in saved['proxy_Key']
        assert saved['options']['lastselected'] == 'Chain'
        assert saved['proxy_Chain']['hop1'] == 'Key'
        test(page, 1008)
        print('PASS compact node editor, save and mixed-auth chain test', flush=True)
        select(page, imported)
        command(page, 1023)
        confirmation = wait_for(lambda: next((w for w in windows(process.pid) if w != main and USER.IsWindowVisible(w)), None), 'delete profile prompt')
        dismiss(confirmation, 1)
        assert managed.exists(), 'deleting a profile must retain keys used by other profiles/instances'
        select(page, 'Key')
        test(page, 1008)
        print('PASS deleting one profile leaves shared private keys usable', flush=True)
        print(json.dumps({'passed': True, 'language': language, 'artifacts': str(folder)}, ensure_ascii=False))
    finally:
        if main and USER.IsWindow(main):
            clipboard_write(main, old_clipboard or '')
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate(); process.wait(timeout=10)
        log.close()
        for path in owned_keys:
            path.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--language', choices=['zh-CN', 'en-US'], default='zh-CN')
    parser.add_argument('--key', default='client-key-encrypted.pem')
    args = parser.parse_args()
    run(args.language, args.key)
