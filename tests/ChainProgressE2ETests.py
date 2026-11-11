"""Real seven-hop UI progress, using isolated GUI and loopback-only relays."""
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import select
import shutil
import socket
import subprocess
import threading
import time
import uuid

from ExitWarningE2ETests import USER, CALLBACK, wait_for, windows, settings_page, text, capture_dialog
from HookRebindE2ETests import exact
from ProcessListE2ETests import send
from ChainViewProbe import ChainView


class Relay:
    def __init__(self, number):
        self.number = number
        self.mode = 'success'
        self.protocol = 'SOCKS5'
        self.link_gate = threading.Event()
        self.link_gate.set()
        self.link_seen = threading.Event()
        self.refused = threading.Event()
        self.auth_gate = threading.Event()
        self.ipv6_gate = threading.Event()
        self.ipv6_seen = threading.Event()
        self.stopped = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(.1)
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while not self.stopped.is_set():
            try:
                peer, _ = self.listener.accept()
                threading.Thread(target=self.connection, args=(peer,), daemon=True).start()
            except socket.timeout:
                pass
            except OSError:
                return

    def connection(self, peer):
        upstream = None
        try:
            peer.settimeout(35)
            if self.protocol == 'HTTP':
                request = b''
                while not request.endswith(b'\r\n\r\n'):
                    request += exact(peer, 1)
                target = request.split(b' ')[1].decode()
                host, port = target.rsplit(':', 1)
                port, kind = int(port), 1
                if self.mode == 'auth_failure':
                    peer.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n\r\n')
                    return
            else:
                _, count = exact(peer, 2)
                exact(peer, count)
                peer.sendall(bytes([5, 2 if self.number == 3 else 0]))
                if self.number == 3:
                    _, length = exact(peer, 2)
                    exact(peer, length)
                    exact(peer, exact(peer, 1)[0])
                    self.auth_gate.wait(35)
                    peer.sendall(bytes([1, int(self.mode == 'failure')]))
                    if self.mode == 'failure':
                        return
                version, command, _, kind = exact(peer, 4)
                assert version == 5 and command == 1
                if kind == 3:
                    host = exact(peer, exact(peer, 1)[0]).decode()
                else:
                    host = socket.inet_ntop(socket.AF_INET6 if kind == 4 else socket.AF_INET,
                                            exact(peer, 16 if kind == 4 else 4))
                port = int.from_bytes(exact(peer, 2), 'big')
            if self.mode == 'link_failure':
                self.link_seen.set()
                self.link_gate.wait(35)
                peer.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n' if self.protocol == 'HTTP' else b'\x05\x05\x00\x01' + bytes(6))
                return
            if kind == 4:
                assert self.number == 6 and host == '::1'
                self.ipv6_seen.set()
                self.ipv6_gate.wait(35)
                peer.sendall(b'\x05\x05\x00\x01' + bytes(6))
                return
            if self.number != 6:
                assert host == '127.0.0.1'
                if self.mode == 'observe_link':
                    self.link_seen.set()
                    self.link_gate.wait(35)
                try:
                    upstream = socket.create_connection((host, port), 3)
                except ConnectionRefusedError:
                    self.refused.set()
                    peer.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n' if self.protocol == 'HTTP' else b'\x05\x05\x00\x01' + bytes(6))
                    return
            peer.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n' if self.protocol == 'HTTP' else b'\x05\x00\x00\x01' + bytes(6))
            while not self.stopped.is_set():
                sockets = [peer, upstream] if upstream else [peer]
                ready, _, _ = select.select(sockets, [], [], .1)
                for source in ready:
                    data = source.recv(8192)
                    if not data:
                        return
                    if upstream:
                        (upstream if source is peer else peer).sendall(data)
        except (OSError, EOFError, AssertionError):
            # Cancelled tests close their sockets before the fixture releases gates.
            pass
        finally:
            peer.close()
            if upstream:
                upstream.close()

    def stop(self):
        self.stopped.set()
        self.auth_gate.set()
        self.link_gate.set()
        self.ipv6_gate.set()
        self.listener.close()


def run(language, capture, http=False, allow_udp=False):
    root = Path(__file__).resolve().parents[1]
    folder = root / 'build/qa' / ('chain-progress-' + uuid.uuid4().hex[:8])
    folder.mkdir(parents=True)
    locale = json.loads((root / f'src/ProxyLane/locales/{language}.json').read_text(encoding='utf-8'))
    for name in ('ProxyLane64.exe', 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(root / 'bin' / name, folder / name)
    (folder / 'portable.flag').touch()
    relays = [Relay(i) for i in range(7)]
    if http:
        relays[4].protocol = 'HTTP'
    profile = f'[options]\nlanguage={language}\nlastselected=Chain\ntesthost=127.0.0.1:80\nIPv6TestAddress=::1\n'
    for i, relay in enumerate(relays):
        profile += f'[proxy_Node{i+1}]\nType={relay.protocol}\nHost=127.0.0.1\nPort={relay.port}\nUser=test\nPass=test\n'
    profile += f'[proxy_Chain]\nType=CHAIN\nHookTCP=1\nHookUDP=0\nBlockUDP={int(not allow_udp)}\n'
    profile += ''.join(f'Hop{i+1}=Node{i+1}\n' for i in range(7))
    (folder / 'ProxyLane.ini').write_text(profile, encoding='utf-8')
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
        send(navigation, 0x201, 1, point)
        send(navigation, 0x202, 0, point)
        wait_for(lambda: USER.IsWindowVisible(page), 'profiles visible')
        view, status, button = (USER.GetDlgItem(page, control) for control in (0x2405, 1017, 1008))
        probe = ChainView(view, locale)
        wait_for(lambda: probe.count() == 7, 'seven cards')
        cell = probe.cell
        def rows():
            return [(cell(i), cell(i, 4)) for i in range(7)]
        tooltip = probe.description

        def start():
            USER.PostMessageW(page, 0x111, 1008, 0)
            wait_for(lambda: text(button) == locale['action.cancel_test'], 'new test started')
            wait_for(lambda: locale['chain.test.auth'] in cell(3), 'fourth node authentication')
            assert all(locale['chain.test.passed'] in cell(i) for i in range(3)), rows()
            assert all(locale['chain.test.waiting'] in cell(i) and cell(i, 4) == '—' for i in range(4, 7)), rows()
            assert probe.visible(3), 'active node follows into view'
            before = rows()
            time.sleep(.35)
            after = rows()
            assert before[:3] == after[:3] and before[3][1] != after[3][1], (before, after)
            assert probe.state(3) & 0x40, 'test mode exposes read-only nodes'

        def finish(tcp_passed, failed_link=None, image_name=None):
            dialog = wait_for(lambda: next((w for w in windows(process.pid)
                if w != main and text(w) == locale['test.title']), None), 'chain result dialog')
            wait_for(lambda: USER.GetDlgItem(dialog, 1203) and USER.GetDlgItem(dialog, 2), 'result rows')
            for control, key in ((1201, 'passed' if tcp_passed else 'failed'),
                                 (1202, 'unsupported'), (1203, 'failed' if tcp_passed else 'skipped')):
                assert locale['test.result.' + key] in text(USER.GetDlgItem(dialog, control))
            if failed_link:
                assert text(USER.GetDlgItem(dialog, 1201)).splitlines()[-1] == failed_link, text(USER.GetDlgItem(dialog, 1201))
                assert failed_link in text(status), text(status)
            assert (locale['test.result.udp_suggest_block'] in text(USER.GetDlgItem(dialog, 1202))) == allow_udp
            frozen, summary = rows(), text(status)
            time.sleep(.3)
            assert frozen == rows() and summary == text(status), 'timing freezes while result dialog is open'
            if capture:
                name = image_name or ('result-tcp-passed.png' if tcp_passed else 'result-tcp-failed.png')
                capture_dialog(dialog, folder / name)
            USER.PostMessageW(dialog, 0x111, 2, 0)
            wait_for(lambda: not USER.IsWindow(dialog), 'close result dialog')
            wait_for(lambda: text(button) == locale['action.test_current'], 'test complete')
            assert frozen == rows(), 'closing the dialog preserves node results'

        start()
        wait_for(lambda: USER.IsWindowVisible(page), 'profiles visible')
        if capture:
            capture_dialog(main, folder / 'active.png')
        probe.first_page()  # Manual scroll suspends following later nodes.
        relays[3].auth_gate.set()
        wait_for(relays[6].ipv6_seen.is_set, 'IPv6 supplemental probe')
        assert probe.top() == 0, 'user scroll is preserved while later nodes complete'
        assert all(locale['chain.test.passed'] in cell(i) for i in range(7)), rows()
        before = rows()
        time.sleep(.4)
        assert before == rows(), 'IPv6 must not replace TCP node states or times'
        relays[6].ipv6_gate.set()
        finish(True)
        assert before == rows(), 'final IPv6 failure must retain TCP node results'
        assert locale['test.result.failed'] in text(status) and locale['test.result.unsupported'] in text(status), text(status)
        stable = text(status)
        time.sleep(.25)
        assert stable == text(status), 'total timer stops'
        if capture:
            capture_dialog(main, folder / 'completed.png')
        print(f'PASS {language}: seven live nodes, independent timing, supplemental IPv6 isolation', flush=True)

        # Retry, select/scroll back while hop 4 is waiting, and fail its authentication.
        relays[3].auth_gate.clear()
        relays[3].mode = 'failure'
        start()
        probe.first_page()  # SB_TOP: user navigation suspends automatic following.
        relays[3].auth_gate.set()
        finish(False)
        assert all(locale['chain.test.passed'] in cell(i) for i in range(3)), rows()
        assert locale['chain.test.failed'] in cell(3) and locale['chain.test.auth'] in cell(3), rows()
        tip = tooltip(3)
        assert locale['test.auth_failed'] in tip and locale['chain.test.auth'] in tip and 'Node4' in tip, tip
        assert all(cell(i) == locale['chain.test.skipped'] and cell(i, 4) == '—' for i in range(4, 7)), rows()
        if capture:
            capture_dialog(main, folder / 'failed.png')
        print(f'PASS {language}: authentication failure preserves preceding nodes and skips later nodes', flush=True)

        # Next-hop waits and errors belong to the destination card. Confirmed
        # proxies remain successful; the final target has no proxy card.
        for failed_node in (4, 6):
            relay = relays[failed_node]
            relay.mode = 'link_failure'
            relay.link_gate.clear()
            relays[3].mode = 'success'
            relays[3].auth_gate.clear()
            start()
            relays[3].auth_gate.set()
            wait_for(relay.link_seen.is_set, 'pending next-hop connection')
            source_status = locale['chain.test.auth'] if relay.protocol == 'HTTP' else locale['chain.test.passed']
            assert source_status in cell(failed_node), rows()
            before_time = cell(failed_node, 4)
            if failed_node < 6:
                assert locale['chain.test.connecting'] in cell(failed_node + 1), rows()
                destination_time = cell(failed_node + 1, 4)
                assert probe.visible(failed_node + 1), 'follow the destination being connected'
            time.sleep(.3)
            assert before_time == cell(failed_node, 4), 'outgoing wait must not increase source card time'
            if failed_node < 6:
                assert destination_time != cell(failed_node + 1, 4), 'inbound wait increases destination time'
            source = locale['chain.test.node'] % (failed_node + 1)
            target = locale['chain.test.node'] % (failed_node + 2) if failed_node < 6 else locale['chain.test.target']
            failed_link = locale['chain.test.link'] % (source, target, locale['chain.test.link_failed'])
            relay.link_gate.set()
            finish(False, failed_link, f'result-link-{failed_node + 1}.png')
            assert all(locale['chain.test.passed'] in cell(i) for i in range(failed_node)), rows()
            assert locale['chain.test.connected_unconfirmed' if relay.protocol == 'HTTP' else 'chain.test.passed'] in cell(failed_node), rows()
            assert locale['chain.test.failed'] not in cell(failed_node), rows()
            if failed_node < 6:
                assert locale['chain.test.failed'] in cell(failed_node + 1), rows()
                assert cell(6) == locale['chain.test.skipped'] and cell(6, 4) == '—', rows()
                assert failed_link in tooltip(failed_node + 1), tooltip(failed_node + 1)
            else:
                assert all(locale['chain.test.failed'] not in cell(i) for i in range(7)), rows()
            if capture:
                capture_dialog(main, folder / f'link-{failed_node + 1}-failed.png')
            relay.mode = 'success'
        print(f'PASS {language}: destination owns link errors/time; final target does not fail successful proxies', flush=True)

        if http:
            relays[4].mode = 'auth_failure'
            relays[3].auth_gate.clear()
            start()
            relays[3].auth_gate.set()
            finish(False)
            assert locale['chain.test.auth'] in cell(4) and locale['chain.test.failed'] in cell(4), rows()
            assert cell(5) == locale['chain.test.skipped'], rows()
            assert '→' not in text(status), 'HTTP authentication failure belongs to the node'
            relays[4].mode = 'success'
            print(f'PASS {language}: HTTP 407 is a node authentication failure, not a failed link', flush=True)

        relays[3].auth_gate.clear()
        relays[3].mode = 'success'
        start()
        USER.PostMessageW(page, 0x111, 1008, 0)
        wait_for(lambda: locale['chain.test.cancelled'] in cell(3), 'cancel active node')
        before = rows()
        relays[3].auth_gate.set()
        time.sleep(.4)
        assert before == rows(), 'late replies cannot change cancelled results'
        assert all(locale['chain.test.passed'] in cell(i) for i in range(3)), rows()
        assert all(cell(i) == locale['chain.test.skipped'] for i in range(4, 7)), rows()
        # Reorder selects node 2 and moves it up; every previous result becomes stale.
        probe.move_to(1, 0, right_half=True,
                      preview=(lambda: capture_dialog(main, folder / 'reorder-first.png')) if capture else None)
        wait_for(lambda: cell(0, 1) == 'Node2', 'reorder')
        assert all(cell(i) == '' and cell(i, 4) == '—' for i in range(7)), rows()
        print(f'PASS {language}: cancellation freezes state/time; reorder clears stale results', flush=True)
        probe.move_to(5, 6,
                      preview=(lambda: capture_dialog(main, folder / 'reorder-last.png')) if capture else None)
        wait_for(lambda: cell(6, 1) == 'Node6', 'penultimate node moves to last across pages')
        assert [cell(i, 1) for i in range(7)] == ['Node2', 'Node1', 'Node3', 'Node4', 'Node5', 'Node7', 'Node6']
        probe.move_to(6, 5, right_half=True)
        wait_for(lambda: cell(5, 1) == 'Node6', 'last node moves back across pages')
        assert [cell(i, 1) for i in range(7)] == ['Node2', 'Node1', 'Node3', 'Node4', 'Node5', 'Node6', 'Node7']
        print(f'PASS {language}: first/last reorder accepts whole target cards, including both cross-page directions', flush=True)
        # Restore the original route, then close the REAL third listener. The
        # second relay must actually attempt TCP and receive connection refused.
        probe.move_to(0, 1)
        assert [cell(i, 1) for i in range(7)] == [f'Node{i+1}' for i in range(7)]
        relays[2].stop()
        time.sleep(.2)  # Let the listener's bounded accept finish releasing the socket.
        relays[1].mode = 'observe_link'
        relays[1].link_seen.clear()
        relays[1].link_gate.clear()
        USER.PostMessageW(page, 0x111, 1008, 0)
        wait_for(relays[1].link_seen.is_set, 'second proxy connecting to third closed port')
        wait_for(lambda: locale['chain.test.connecting'] in cell(2), 'third card connecting')
        assert all(locale['chain.test.passed'] in cell(i) for i in (0, 1)), rows()
        assert all(cell(i, 4) == '—' for i in range(3, 7)), rows()
        assert probe.visible(2), 'third destination is followed'
        source_before, destination_before = cell(1, 4), cell(2, 4)
        time.sleep(.35)
        assert cell(1, 4) == source_before and cell(2, 4) != destination_before, rows()
        if capture:
            capture_dialog(main, folder / 'third-port-connecting.png')
        relays[1].link_gate.set()
        wait_for(relays[1].refused.is_set, 'real TCP connection to third port refused')
        failed_link = locale['chain.test.link'] % (locale['chain.test.node'] % 2,
                        locale['chain.test.node'] % 3, locale['chain.test.link_failed'])
        finish(False, failed_link, 'third-port-result.png')
        assert all(locale['chain.test.passed'] in cell(i) for i in (0, 1)), rows()
        assert cell(1, 4) == source_before, 'second card freezes before third connection'
        assert locale['chain.test.failed'] in cell(2) and locale['chain.test.connecting'] in cell(2), rows()
        assert failed_link in tooltip(2) and failed_link not in tooltip(1)
        assert all(cell(i) == locale['chain.test.skipped'] and cell(i, 4) == '—' for i in range(3, 7)), rows()
        if capture:
            capture_dialog(main, folder / 'third-port-failed.png')
        print(f'PASS {language}: REAL third-port refusal keeps second green/frozen, third failed, later nodes skipped', flush=True)
        print(folder, flush=True)
    finally:
        if 'probe' in locals():
            probe.close()
        process.terminate()
        process.wait(10)
        for relay in relays:
            relay.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--language', choices=['zh-CN', 'en-US'], default='zh-CN')
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--http', action='store_true')
    parser.add_argument('--allow-udp', action='store_true')
    args = parser.parse_args()
    run(args.language, args.capture, args.http, args.allow_udp)
