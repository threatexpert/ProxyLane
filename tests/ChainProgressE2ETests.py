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
from ProcessListE2ETests import Item, open_process, allocate, release, write, read, close, send


class Relay:
    def __init__(self, number):
        self.number = number
        self.mode = 'success'
        self.protocol = 'SOCKS5'
        self.link_gate = threading.Event()
        self.link_gate.set()
        self.link_seen = threading.Event()
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
                upstream = socket.create_connection((host, port), 3)
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
        wait_for(lambda: send(view, 0x1004) == 7, 'seven rows')
        handle = open_process(0x38, False, process.pid)
        memory = allocate(handle, None, 4096, 0x3000, 4)
        assert handle and memory

        def cell(row, column=3):
            item = Item(column=column, text=memory + 256, capacity=1024)
            assert write(handle, memory, C.byref(item), C.sizeof(item), None)
            send(view, 0x1073, row, memory)
            result = C.create_unicode_buffer(1024)
            assert read(handle, memory + 256, result, C.sizeof(result), None)
            return result.value

        def rows():
            return [(cell(i), cell(i, 4)) for i in range(7)]

        def tooltip(row):
            # Drive the owned window's message queue, then read the custom
            # tooltip text without moving the user's desktop pointer.
            rect = W.RECT(left=0, top=3)  # LVIR_BOUNDS, status subitem
            assert write(handle, memory, C.byref(rect), C.sizeof(rect), None)
            send(view, 0x1038, row, memory)  # LVM_GETSUBITEMRECT
            assert read(handle, memory, C.byref(rect), C.sizeof(rect), None)
            USER.PostMessageW(view, 0x200, 0, (rect.left + 10) | ((rect.top + 5) << 16))
            class ToolInfo(C.Structure):
                _fields_ = [('size', W.UINT), ('flags', W.UINT), ('window', W.HWND),
                            ('id', C.c_size_t), ('rect', W.RECT), ('instance', W.HANDLE),
                            ('text', C.c_void_p), ('data', C.c_ssize_t), ('reserved', C.c_void_p)]
            def inspect():
                found = []
                @CALLBACK
                def visit(window, _):
                    name = C.create_unicode_buffer(80)
                    USER.GetClassNameW(window, name, len(name))
                    owner = W.DWORD()
                    USER.GetWindowThreadProcessId(window, C.byref(owner))
                    if name.value == 'tooltips_class32' and owner.value == process.pid:
                        info = ToolInfo(size=C.sizeof(ToolInfo), window=view, id=1)
                        assert write(handle, memory, C.byref(info), C.sizeof(info), None)
                        if send(window, 0x435, 0, memory):  # TTM_GETTOOLINFOW
                            found.append(window)
                    return True
                USER.EnumWindows(visit, 0)
                return found
            tip = wait_for(inspect, 'row tooltip tool')[0]
            info = ToolInfo(size=C.sizeof(ToolInfo), window=view, id=1, text=memory + 256)
            assert write(handle, memory, C.byref(info), C.sizeof(info), None)
            send(tip, 0x438, 0, memory)  # TTM_GETTEXTW
            result = C.create_unicode_buffer(1024)
            assert read(handle, memory + 256, result, C.sizeof(result), None)
            return result.value

        def start():
            USER.PostMessageW(page, 0x111, 1008, 0)
            wait_for(lambda: text(button) == locale['action.cancel_test'], 'new test started')
            wait_for(lambda: locale['chain.test.auth'] in cell(3), 'fourth node authentication')
            assert all(locale['chain.test.passed'] in cell(i) for i in range(3)), rows()
            assert all(locale['chain.test.waiting'] in cell(i) and cell(i, 4) == '—' for i in range(4, 7)), rows()
            assert send(view, 0x1027) <= 3 < send(view, 0x1027) + send(view, 0x1028), 'active node follows into view'
            before = rows()
            time.sleep(.35)
            after = rows()
            assert before[:3] == after[:3] and before[3][1] != after[3][1], (before, after)
            assert not USER.IsWindowEnabled(USER.GetDlgItem(page, 0x2407))

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
        send(view, 0x115, 6, 0)  # Manual scroll suspends following later nodes.
        relays[3].auth_gate.set()
        wait_for(relays[6].ipv6_seen.is_set, 'IPv6 supplemental probe')
        assert send(view, 0x1027) == 0, 'user scroll is preserved while later nodes complete'
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
        send(view, 0x115, 6, 0)  # SB_TOP: user navigation suspends automatic following.
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

        # A node that negotiated successfully must remain green when its outgoing
        # CONNECT fails. Attribute the failure to the edge, including the last edge.
        for failed_node in (4, 6):
            relay = relays[failed_node]
            relay.mode = 'link_failure'
            relay.link_gate.clear()
            relays[3].mode = 'success'
            relays[3].auth_gate.clear()
            start()
            relays[3].auth_gate.set()
            wait_for(relay.link_seen.is_set, 'pending next-hop connection')
            if relay.protocol == 'SOCKS5':
                assert locale['chain.test.passed'] in cell(failed_node), rows()
            else:
                assert locale['chain.test.passed'] not in cell(failed_node), 'HTTP cannot confirm negotiation before CONNECT reply'
            before_time = cell(failed_node, 4)
            time.sleep(.3)
            assert before_time != cell(failed_node, 4), 'next-hop wait remains included in node elapsed'
            source = locale['chain.test.node'] % (failed_node + 1)
            target = locale['chain.test.node'] % (failed_node + 2) if failed_node < 6 else locale['chain.test.target']
            failed_link = locale['chain.test.link'] % (source, target, locale['chain.test.link_failed'])
            relay.link_gate.set()
            finish(False, failed_link, f'result-link-{failed_node + 1}.png')
            assert all(locale['chain.test.passed'] in cell(i) for i in range(failed_node)), rows()
            assert locale['chain.test.connected' if relay.protocol == 'HTTP' else 'chain.test.passed'] in cell(failed_node), rows()
            assert locale['chain.test.failed'] not in cell(failed_node), rows()
            if failed_node < 6:
                assert cell(failed_node + 1) == locale['chain.test.not_reached'], rows()
                assert cell(6) == locale['chain.test.skipped'] and cell(5, 4) == '—', rows()
            tip = tooltip(failed_node)
            assert failed_link in tip, tip
            if capture:
                capture_dialog(main, folder / f'link-{failed_node + 1}-failed.png')
            relay.mode = 'success'
        print(f'PASS {language}: negotiated nodes remain successful; list and dialog identify failed edges', flush=True)

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
        item = Item(state=3, stateMask=3)
        assert write(handle, memory, C.byref(item), C.sizeof(item), None)
        send(view, 0x102b, 1, memory)
        USER.PostMessageW(page, 0x111, 0x2407, 0)
        wait_for(lambda: cell(0, 1) == 'Node2', 'reorder')
        assert all(cell(i) == locale['status.test_not_run'] and cell(i, 4) == '—' for i in range(7)), rows()
        print(f'PASS {language}: cancellation freezes state/time; reorder clears stale results', flush=True)
        print(folder, flush=True)
    finally:
        if memory:
            release(handle, memory, 0, 0x8000)
        if handle:
            close(handle)
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
