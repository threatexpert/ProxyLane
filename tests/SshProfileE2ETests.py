"""SSH first-use trust and persistence through a disposable real Profiles UI.
Only owned processes and a portable test configuration are touched.
"""
import configparser
import ctypes
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import uuid
from ProfileSharingE2ETests import USER, wait_for, windows, settings_page, text, command, field, modal, dismiss

directory = Path('build/qa/ssh-profile-' + uuid.uuid4().hex[:8]).resolve()
directory.mkdir(parents=True)
fixture_file = directory / 'fixture.json'
processes = []
log = (directory / 'server.log').open('w')
try:
    fixture = subprocess.Popen([sys.executable, str(Path('tests/ssh_test_servers.py').resolve()), str(fixture_file)],
        creationflags=subprocess.CREATE_NO_WINDOW, stderr=log)
    processes.append(fixture)
    wait_for(fixture_file.exists, 'SSH fixture')
    ports = json.loads(fixture_file.read_text())
    def stats():
        with socket.create_connection(('127.0.0.1',ports['control'])) as connection:
            connection.sendall(b'stats\n')
            return json.loads(connection.makefile().readline())
    for name in ('ProxyLane64.exe','ProxyLaneHook64.dll','ProxyLaneHook32.dll','ProxyLaneSsh64.dll'):
        shutil.copy2(Path('bin') / name, directory / name)
    (directory / 'portable.flag').touch()
    ini = directory / 'ProxyLane.ini'
    ini.write_text(f'''[options]
language=zh-CN
lastselected=SSH-test
[proxy_SSH-test]
Type=SSH
Host=127.0.0.1
Port={ports['a']}
User=test-user
Pass=test-password
Transport=PLAIN
HookTCP=1
HookUDP=0
BlockUDP=1
BlockIPv6=1
''',encoding='utf-16')
    def launch():
        process = subprocess.Popen([str(directory / 'ProxyLane64.exe')],cwd=directory,creationflags=subprocess.CREATE_NO_WINDOW)
        processes.append(process)
        main = wait_for(lambda: next((w for w in windows(process.pid) if USER.IsWindowVisible(w) and settings_page(w)),None),'Profiles window')
        page = settings_page(main)
        navigation = USER.GetParent(page)
        USER.GetDpiForWindow.argtypes = [ctypes.c_void_p]
        dpi = USER.GetDpiForWindow(navigation)
        point = (20*dpi//96) | ((136*dpi//96) << 16)
        USER.SendMessageW(navigation,0x201,1,point)
        USER.SendMessageW(navigation,0x202,0,point)
        wait_for(lambda: USER.IsWindowVisible(page),'Profiles page selected')
        return process,main,page
    process,main,page = launch()
    assert field(page,1001) == 'SSH'
    assert not USER.IsWindowEnabled(USER.GetDlgItem(page,1013))
    assert USER.IsWindowVisible(USER.GetDlgItem(page,1070))
    assert not USER.IsWindowVisible(USER.GetDlgItem(page,1068))
    assert USER.SendMessageW(USER.GetDlgItem(page,1070),0xd2,0,0) == 0  # EM_GETPASSWORDCHAR
    print('PASS SSH controls and visible host-key field',flush=True)
    for accept in (False,True):
        command(page,1008)
        prompt = modal(process,main)
        wait_for(lambda: USER.IsWindowVisible(USER.GetDlgItem(prompt,6)), 'explicit trust action')
        contents = text(USER.GetDlgItem(prompt,1207))
        assert ports['fingerprint'] in contents, contents
        assert '127.0.0.1' in contents, contents
        assert stats()['auth_a'] == 0
        dismiss(prompt,6 if accept else 2)
        wait_for(lambda: USER.IsWindowEnabled(USER.GetDlgItem(page,1008)),'test reset')
        assert field(page,1070) == (ports['fingerprint'] if accept else '')
    print('PASS trust rejection and confirmation send no password',flush=True)
    USER.SetWindowTextW(USER.GetDlgItem(page,1070), '  ' + ports['fingerprint'] + '  ')
    command(page,1052)
    wait_for(lambda: not USER.IsWindowEnabled(USER.GetDlgItem(page,1052)),'saved SSH profile')
    saved = configparser.ConfigParser(); saved.read(ini,encoding='utf-16')
    assert saved['proxy_SSH-test']['SshHostKey'] == ports['fingerprint']
    assert 'PSK' not in saved['proxy_SSH-test']
    USER.PostMessageW(main,0x10,0,0); process.wait(timeout=15)
    process,main,page = launch()
    assert field(page,1070) == ports['fingerprint'] and field(page,1004) == 'test-user'
    print('PASS SSH trust persists across restart in SshHostKey',flush=True)
    locale = json.loads(Path('src/ProxyLane/locales/zh-CN.json').read_text(encoding='utf-8'))
    for password, expected in [('wrong-password', 'test.ssh_password_auth_failed'),
                               ('disconnect-during-auth', 'test.ssh_password_auth_interrupted')]:
        secret = ctypes.create_unicode_buffer(password)
        assert USER.SendMessageW(USER.GetDlgItem(page,1003),0x000c,0,ctypes.addressof(secret))
        command(page,1008)
        prompt = modal(process,main)
        result = text(USER.GetDlgItem(prompt,1201))
        assert locale[expected] in result, result
        dismiss(prompt,2)
    secret = ctypes.create_unicode_buffer('test-password')
    assert USER.SendMessageW(USER.GetDlgItem(page,1003),0x000c,0,ctypes.addressof(secret))
    print('PASS standalone SSH distinguishes rejected credentials from authentication disconnect',flush=True)
    # Changing protocols drops a fingerprint instead of reusing it as a PSK.
    combo = USER.GetDlgItem(page,1001)
    protocol = ctypes.create_unicode_buffer('SOCKS5')
    USER.SendMessageW(combo,0x14d,-1,ctypes.addressof(protocol))  # CB_SELECTSTRING
    command(page,1001,1)
    assert field(page,1070) == ''
    assert USER.SendMessageW(USER.GetDlgItem(page,1070),0xd2,0,0) != 0
    print('PASS changing protocol separates fingerprint from TLS PSK',flush=True)
    process.terminate(); process.wait(timeout=15)
    for password, expected in [('wrong-password', 'test.ssh_password_auth_failed'),
                               ('disconnect-during-auth', 'test.ssh_password_auth_interrupted')]:
        saved['options']['lastselected'] = 'SSH-chain'
        saved['proxy_SSH-test']['Pass'] = password
        saved['proxy_First'] = {'Type':'SOCKS5', 'Host':'127.0.0.1', 'Port':str(ports['socks'])}
        saved['proxy_SSH-chain'] = {'Type':'CHAIN', 'Hop1':'First', 'Hop2':'SSH-test', 'HookTCP':'1', 'BlockUDP':'1'}
        with ini.open('w',encoding='utf-16') as output: saved.write(output)
        process,main,page = launch()
        command(page,1008)
        prompt = modal(process,main)
        result = text(USER.GetDlgItem(prompt,1201))
        assert locale[expected] in result and 'SSH-test' in result, result
        assert locale[expected] in text(USER.GetDlgItem(page,1017)), text(USER.GetDlgItem(page,1017))
        dismiss(prompt,2)
        process.terminate(); process.wait(timeout=15)
    print('PASS chain SSH preserves authentication-stage detail in result and shared status',flush=True)
finally:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate(); process.wait(timeout=15)
    log.close()
