"""Edit saved chain nodes in a disposable GUI; never touches user profiles."""
import argparse
import configparser
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

from ChainProgressE2ETests import Relay
from Ipv6ConfigTestE2E import Endpoint, KERNEL
from ExitWarningE2ETests import USER, wait_for, windows, settings_page, text, capture_dialog
from ProcessListE2ETests import send
from ChainViewProbe import ChainView


def run(language, capture):
    module = KERNEL.GetModuleHandleW('ProxyLaneHook64.dll')
    if module:
        assert C.WinDLL('ProxyLaneHook64.dll', handle=module).gp_UnhookWinsock()
    root = Path(__file__).resolve().parents[1]
    folder = root / 'build/qa' / ('chain-node-edit-' + uuid.uuid4().hex[:8])
    folder.mkdir(parents=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll', 'ProxyLaneSsh64.dll'):
        shutil.copy2(root / 'bin' / name, folder / name)
    locale = json.loads((root / f'src/ProxyLane/locales/{language}.json').read_text(encoding='utf-8'))
    (folder / 'portable.flag').touch()
    relays = [Relay(i) for i in range(7)]
    ini = folder / 'ProxyLane.ini'
    probe = Endpoint(protocol='SOCKS5')
    target = Endpoint()
    ssh_process = ssh_log = None
    profile = f'[options]\nlanguage={language}\nlastselected=Chain\ntesthost=127.0.0.1:{target.port}\nIPv6TestAddress=::1\n'
    for i, relay in enumerate(relays):
        profile += f'[proxy_Node{i+1}]\nType=SOCKS5\nHost=127.0.0.1\nPort={relay.port}\nUser=test\nPass=test\n'
        profile += f'HookTCP=1\nHookUDP={int(i == 6)}\nBlockUDP=0\nHookChildProcess=0\nBlockIPv6=1\nTargetFilter=keep.example\nCustomFutureKey=preserved\n'
    profile += '[proxy_Chain]\nType=CHAIN\nHookTCP=1\nHookUDP=0\nBlockUDP=1\n'
    profile += ''.join(f'Hop{i+1}=Node{i+1}\n' for i in range(7))
    profile += '[proxy_OtherChain]\nType=CHAIN\nHop1=Node1\nHop2=Node7\n'
    ini.write_text(profile, encoding='utf-16')

    def config():
        value = configparser.ConfigParser(interpolation=None)
        value.read(ini, encoding='utf-16')
        return value

    initial = config()
    process = subprocess.Popen([str(folder / 'ProxyLane64.exe'), '--profile', 'Chain'], cwd=folder,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    handle = memory = None
    try:
        main = wait_for(lambda: next((w for w in windows(process.pid)
            if USER.IsWindowVisible(w) and settings_page(w)), None), 'main')
        page = settings_page(main)
        navigation = USER.GetParent(page)
        USER.GetDpiForWindow.argtypes = [W.HWND]
        dpi = USER.GetDpiForWindow(navigation)
        point = (20 * dpi // 96) | ((136 * dpi // 96) << 16)
        send(navigation, 0x201, 1, point); send(navigation, 0x202, 0, point)
        wait_for(lambda: USER.IsWindowVisible(page), 'profiles visible')
        view = USER.GetDlgItem(page, 0x2405)
        cards = ChainView(view, locale)
        cell = cards.cell
        def rows():
            return [(cell(i, 3), cell(i, 4)) for i in range(7)]
        select = cards.select
        def double_click(row):
            cards.select(row)
            cards.edit(double=True)

        def opened():
            return next((w for w in windows(process.pid) if w != main and USER.GetDlgItem(w, 1301)), None)

        def open_editor(double=False):
            if double:
                double_click(cards.selected())
            else:
                cards.edit()
            dialog = wait_for(opened, 'node editor')
            wait_for(lambda: USER.IsWindowVisible(dialog) and USER.GetDlgItem(dialog, 1), 'editor ready')
            return dialog

        def set_field(dialog, control, value):
            buffer = C.create_unicode_buffer(value)
            assert send(USER.GetDlgItem(dialog, control), 0x000c, 0, C.addressof(buffer))
            if not send(USER.GetDlgItem(dialog, control), 0xd2):  # Windows masks cross-process password reads.
                assert text(USER.GetDlgItem(dialog, control)) == value, (control, value)

        def choose(dialog, control, index):
            send(USER.GetDlgItem(dialog, control), 0x14e, index)
            send(dialog, 0x111, control | (1 << 16), USER.GetDlgItem(dialog, control))

        def dismiss(dialog, button):
            USER.PostMessageW(dialog, 0x111, button, 0)
            wait_for(lambda: not USER.IsWindow(dialog), 'editor closes')

        def test_result(dialog):
            USER.PostMessageW(dialog, 0x111, 1309, 0)
            report = wait_for(lambda: next((w for w in windows(process.pid)
                if USER.GetDlgItem(w, 1201)), None), 'node test results')
            wait_for(lambda: USER.IsWindowVisible(USER.GetDlgItem(report, 2)), 'results ready')
            return report

        def invalid(dialog, value):
            set_field(dialog, 1304, value)
            USER.PostMessageW(dialog, 0x111, 1, 0)
            try:
                wait_for(lambda: text(USER.GetDlgItem(dialog, 1308)), 'inline validation')
            except TimeoutError:
                if USER.IsWindow(dialog):
                    capture_dialog(dialog, folder / 'validation-failed.png')
                raise AssertionError((value, USER.IsWindow(dialog), [(w, text(w)) for w in windows(process.pid)]))
            assert USER.IsWindow(dialog) and config()['proxy_Node7']['port'] == str(relays[6].port)

        assert cards.selected() == -1, 'no initial selection'
        cards.edit()
        time.sleep(.1)
        assert not opened(), 'no selection cannot edit'
        select(6)
        assert not (cards.state(6) & 0x40), 'selected node is editable'
        left, right = W.RECT(), W.RECT()

        USER.PostMessageW(page, 0x111, 1008, 0)
        wait_for(lambda: locale['chain.test.auth'] in cell(3, 3), 'test authenticating')
        select(3)
        assert cards.state(3) & 0x40, 'testing disables Edit'
        double_click(3)
        time.sleep(.15)
        assert not opened(), 'double click cannot edit during a test'
        USER.PostMessageW(page, 0x111, 1008, 0)
        wait_for(lambda: locale['chain.test.cancelled'] in cell(3, 3), 'cancelled results')
        relays[3].auth_gate.set()

        select(6)
        top, frozen = cards.top(), rows()
        assert top > 0, 'fixture is scrolled'
        original_disk = ini.read_bytes()
        dialog = open_editor(double=True)
        assert 'Node7' in text(dialog)
        assert text(USER.GetDlgItem(dialog, 1303)) == '127.0.0.1'
        assert not USER.IsWindowVisible(USER.GetDlgItem(dialog, 1307)), 'plain mode stays compact'
        USER.GetWindowRect(USER.GetDlgItem(dialog, 1309), C.byref(left))
        USER.GetWindowRect(USER.GetDlgItem(dialog, 1), C.byref(right))
        assert left.right < right.left, 'Test precedes Save'
        set_field(dialog, 1304, str(probe.port))
        report = test_result(dialog)
        if capture:
            capture_dialog(report, folder / 'node-test-result.png')
        for control in (1201, 1202, 1203):
            assert locale['test.result.passed'] in text(USER.GetDlgItem(report, control)), (control, text(USER.GetDlgItem(report, control)), probe.commands, probe.errors)
        assert 3 in probe.commands, 'node capabilities include a UDP probe'
        assert ini.read_bytes() == original_disk and rows() == frozen, 'testing the draft is independent of saved chain results'
        if capture:
            capture_dialog(report, folder / 'node-test-result.png')
        dismiss(report, 2)
        probe.outcome = 'udp_unsupported'
        report = test_result(dialog)
        udp = text(USER.GetDlgItem(report, 1202))
        assert locale['test.result.unsupported'] in udp
        assert locale['test.result.udp_suggest_block'] not in udp
        dismiss(report, 2)
        choose(dialog, 1301, 1)
        probe.protocol = 'HTTP11'
        report = test_result(dialog)
        assert locale['test.result.passed'] in text(USER.GetDlgItem(report, 1201))
        assert locale['test.result.unsupported'] in text(USER.GetDlgItem(report, 1202))
        assert locale['test.result.udp_suggest_block'] not in text(USER.GetDlgItem(report, 1202))
        dismiss(report, 2)
        choose(dialog, 1301, 0)
        set_field(dialog, 1304, str(relays[6].port))
        USER.PostMessageW(dialog, 0x111, 1309, 0)
        wait_for(relays[6].ipv6_seen.is_set, 'pending IPv6 test')
        assert not USER.IsWindowEnabled(USER.GetDlgItem(dialog, 1)), 'test disables Save'
        assert not USER.IsWindowEnabled(USER.GetDlgItem(dialog, 1304)), 'test freezes input'
        USER.PostMessageW(dialog, 0x111, 1309, 0)
        wait_for(lambda: USER.IsWindowEnabled(USER.GetDlgItem(dialog, 1)), 'test cancelled')
        relays[6].ipv6_gate.set()
        time.sleep(.15)
        assert not any(USER.GetDlgItem(w, 1201) for w in windows(process.pid)), 'cancel prevents late result popup'
        assert ini.read_bytes() == original_disk and rows() == frozen
        relays[6].ipv6_seen.clear(); relays[6].ipv6_gate.clear()
        USER.PostMessageW(dialog, 0x111, 1309, 0)
        wait_for(relays[6].ipv6_seen.is_set, 'second pending IPv6 test')
        dismiss(dialog, 2)
        relays[6].ipv6_gate.set()
        time.sleep(.15)
        assert not any(USER.GetDlgItem(w, 1201) for w in windows(process.pid)), 'closing the editor stops its test'
        assert ini.read_bytes() == original_disk and rows() == frozen
        dialog = open_editor()
        print(f'PASS {language}: independent draft TCP/UDP/IPv6 testing, protocol results and cancellation', flush=True)
        set_field(dialog, 1303, 'cancelled.example')
        dismiss(dialog, 2)
        assert rows() == frozen and ini.read_bytes() == original_disk, 'Cancel preserves configuration and test results'
        assert cards.top() == top and cards.selected() == 6
        print(f'PASS {language}: Edit placement/enabling, double click, test lock and cancellation', flush=True)

        dialog = open_editor()
        for value in ('', '65536', '80abc'):
            invalid(dialog, value)
        set_field(dialog, 1303, '127.0.0.2')
        set_field(dialog, 1304, '18080')
        if capture:
            capture_dialog(dialog, folder / 'edit-plain.png')
        dismiss(dialog, 1)
        assert cards.top() == top and cards.selected() == 6, 'Save preserves scroll and selection'
        assert '127.0.0.2:18080' in cell(6, 2), cell(6, 2)
        assert all(state == '' and elapsed == '—' for state, elapsed in rows())
        saved = config()
        assert saved['options']['lastselected'] == 'Chain'
        assert dict(saved['proxy_Chain']) == dict(initial['proxy_Chain'])
        assert dict(saved['proxy_OtherChain']) == dict(initial['proxy_OtherChain'])
        for key in ('hooktcp', 'hookudp', 'blockudp', 'hookchildprocess', 'blockipv6', 'targetfilter', 'customfuturekey'):
            assert saved['proxy_Node7'][key] == initial['proxy_Node7'][key]
        if capture:
            capture_dialog(main, folder / 'list-after-save.png')
        print(f'PASS {language}: validated save updates only node connection, preserves position/rules/chain, clears results', flush=True)

        dialog = open_editor()
        choose(dialog, 1302, 1)
        assert USER.IsWindowVisible(USER.GetDlgItem(dialog, 1307))
        assert send(USER.GetDlgItem(dialog, 1307), 0xd2) != 0, 'PSK is masked'
        USER.PostMessageW(dialog, 0x111, 1, 0)
        wait_for(lambda: locale['profile.psk_required'] in text(USER.GetDlgItem(dialog, 1308)), 'PSK required')
        set_field(dialog, 1307, 'fixture-PSK-测试')
        if capture:
            capture_dialog(dialog, folder / 'edit-tls.png')
        dismiss(dialog, 1)
        assert config()['proxy_Node7']['psk'] == 'fixture-PSK-测试'

        dialog = open_editor(double=True)
        choose(dialog, 1301, 2)
        assert not USER.IsWindowEnabled(USER.GetDlgItem(dialog, 1302))
        assert text(USER.GetDlgItem(dialog, 1307)) == '' and send(USER.GetDlgItem(dialog, 1307), 0xd2) == 0
        set_field(dialog, 1305, '测试用户')
        set_field(dialog, 1306, '测试密码')
        fingerprint = 'SHA256:' + 'A' * 43
        set_field(dialog, 1307, 'invalid')
        USER.PostMessageW(dialog, 0x111, 1, 0)
        wait_for(lambda: locale['profile.ssh_invalid'] in text(USER.GetDlgItem(dialog, 1308)), 'fingerprint validation')
        set_field(dialog, 1307, fingerprint)
        if capture:
            capture_dialog(dialog, folder / 'edit-ssh.png')
        dismiss(dialog, 1)
        saved = config()['proxy_Node7']
        assert saved['type'] == 'SSH' and saved['user'] == '测试用户' and saved['pass'] == '测试密码'
        assert saved['sshhostkey'] == fingerprint and 'psk' not in saved and saved['transport'] == 'PLAIN'
        dialog = open_editor()
        assert text(USER.GetDlgItem(dialog, 1305)) == '测试用户'
        choose(dialog, 1301, 0)
        assert text(USER.GetDlgItem(dialog, 1307)) == '', 'SSH pin is not reused as PSK'
        dismiss(dialog, 2)
        print(f'PASS {language}: compact TLS/SSH fields, secret separation, fingerprint validation and UTF-8 persistence', flush=True)

        # Editing a shared node must not commit an unsaved chain reordering.
        cards.move_before(6, 5)
        wait_for(lambda: cell(5, 1) == 'Node7', 'unsaved chain order')
        assert USER.IsWindowEnabled(USER.GetDlgItem(page, 1052)), 'chain draft is dirty'
        dialog = open_editor()
        set_field(dialog, 1304, '18081')
        dismiss(dialog, 1)
        assert cell(5, 1) == 'Node7' and USER.IsWindowEnabled(USER.GetDlgItem(page, 1052))
        assert dict(config()['proxy_Chain']) == dict(initial['proxy_Chain']), 'node save cannot save the chain draft'
        print(f'PASS {language}: unsaved chain draft survives node editing', flush=True)

        fixture = folder / 'ssh-fixture.json'
        ssh_log = (folder / 'ssh-server.log').open('w')
        ssh_process = subprocess.Popen([sys.executable, str(root / 'tests/ssh_test_servers.py'), str(fixture)],
            creationflags=subprocess.CREATE_NO_WINDOW, stderr=ssh_log)
        wait_for(fixture.exists, 'SSH fixture')
        ssh = json.loads(fixture.read_text())
        before_ssh = ini.read_bytes()
        dialog = open_editor()
        set_field(dialog, 1303, '127.0.0.1')
        set_field(dialog, 1304, str(ssh['a']))
        set_field(dialog, 1305, 'test-user')
        set_field(dialog, 1306, 'test-password')
        set_field(dialog, 1307, '')
        report = test_result(dialog)
        assert USER.IsWindowVisible(USER.GetDlgItem(report, 6)), ('first use offers explicit fingerprint trust', text(USER.GetDlgItem(report, 1201)))
        dismiss(report, 6)
        wait_for(lambda: text(USER.GetDlgItem(dialog, 1307)) == ssh['fingerprint'], 'fingerprint fills the draft')
        assert ini.read_bytes() == before_ssh, 'trust cannot save implicitly'
        report = test_result(dialog)
        assert locale['test.result.passed'] in text(USER.GetDlgItem(report, 1201))
        assert locale['test.result.unsupported'] in text(USER.GetDlgItem(report, 1202))
        dismiss(report, 2)
        for password, expected in [('wrong-password', 'test.ssh_password_auth_failed'),
                                   ('disconnect-during-auth', 'test.ssh_password_auth_interrupted')]:
            set_field(dialog, 1306, password)
            report = test_result(dialog)
            assert locale[expected] in text(USER.GetDlgItem(report, 1201)), text(USER.GetDlgItem(report, 1201))
            if capture:
                capture_dialog(report, folder / (password + '.png'))
            dismiss(report, 2)
        set_field(dialog, 1306, 'test-password')
        print(f'PASS {language}: SSH wrong password is distinct from authentication-stage disconnect', flush=True)
        set_field(dialog, 1307, fingerprint)
        report = test_result(dialog)
        assert locale['test.ssh_changed_key'] in text(USER.GetDlgItem(report, 1201))
        assert not USER.IsWindowVisible(USER.GetDlgItem(report, 6)), 'changed host key cannot be silently trusted'
        dismiss(report, 2)
        dismiss(dialog, 2)
        assert ini.read_bytes() == before_ssh
        print(f'PASS {language}: independent SSH testing, draft-only trust, fingerprint transmission and changed-key rejection', flush=True)
        print(folder, flush=True)
    finally:
        if 'cards' in locals():
            cards.close()
        process.terminate(); process.wait(10)
        for relay in relays:
            relay.stop()
        probe.close()
        target.close()
        if ssh_process:
            ssh_process.terminate(); ssh_process.wait(10)
        if ssh_log:
            ssh_log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--language', choices=['zh-CN', 'en-US'], default='zh-CN')
    parser.add_argument('--capture', action='store_true')
    args = parser.parse_args()
    run(args.language, args.capture)
