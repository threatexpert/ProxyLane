"""Exercise a portable profile against four loopback nodes. Supply the official Mihomo EXE."""
import argparse
import base64
import ctypes
import datetime
import http.server
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import tempfile
import threading
import uuid

import psutil
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from ExitWarningE2ETests import CALLBACK, KERNEL, USER, settings_page, text, wait_for, windows
from ProfileSharingE2ETests import dismiss
from ProxyLaneSecureE2ETests import local_ipv4, udp_echo


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def start_socks5_relay(username, password, host_map):
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sock.listen(16)
    port_num = sock.getsockname()[1]
    stop = threading.Event()

    def pipe(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def handle(conn):
        remote = None
        try:
            ver, nmethods = conn.recv(2)
            assert ver == 5
            conn.recv(nmethods)
            conn.sendall(b'\x05\x02')
            aver, ulen = conn.recv(2)
            u = conn.recv(ulen).decode()
            plen = conn.recv(1)[0]
            pw = conn.recv(plen).decode()
            if aver != 1 or u != username or pw != password:
                conn.sendall(b'\x01\x01')
                return
            conn.sendall(b'\x01\x00')
            ver, cmd, _, atyp = conn.recv(4)
            if ver != 5 or cmd != 1:
                return
            if atyp == 1:
                host = socket.inet_ntoa(conn.recv(4))
            elif atyp == 3:
                host = conn.recv(conn.recv(1)[0]).decode()
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
            else:
                return
            dst_port = int.from_bytes(conn.recv(2), 'big')
            remote = socket.create_connection((host_map.get(host, host), dst_port), timeout=5)
            conn.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            t1 = threading.Thread(target=pipe, args=(conn, remote), daemon=True)
            t2 = threading.Thread(target=pipe, args=(remote, conn), daemon=True)
            t1.start(); t2.start(); t1.join(); t2.join()
        except Exception:
            pass
        finally:
            conn.close()
            if remote:
                remote.close()

    def accept_loop():
        while not stop.is_set():
            try:
                sock.settimeout(0.2)
                c, _ = sock.accept()
                threading.Thread(target=handle, args=(c,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    threading.Thread(target=accept_loop, daemon=True).start()
    return port_num, lambda: (stop.set(), sock.close())


def fixture(folder):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1)).sign(key, hashes.SHA256()))
    (folder / 'tls.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / 'tls.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ident = str(uuid.uuid4())
    password = uuid.uuid4().hex
    nodes = []
    links = []
    for protocol in ('vless', 'vmess', 'shadowsocks', 'anytls', 'trojan'):
        p = port()
        node = dict(name=protocol, type=protocol, listen='127.0.0.1', port=p)
        if protocol in ('vless', 'vmess'):
            node['users'] = [dict(username='test', uuid=ident)]
        if protocol == 'vless':
            node['allow-insecure'] = True  # Loopback fixture only.
            link = f'vless://{ident}@127.0.0.1:{p}?type=tcp&security=none'
        elif protocol == 'vmess':
            payload = dict(v='2', ps='VMess', add='127.0.0.1', port=str(p), id=ident,
                           aid='0', scy='auto', net='tcp', type='none', tls='')
            link = 'vmess://' + base64.b64encode(json.dumps(payload).encode()).decode()
        elif protocol == 'shadowsocks':
            node.update(cipher='aes-128-gcm', password=password, udp=True)
            auth = base64.urlsafe_b64encode(f'aes-128-gcm:{password}'.encode()).decode().rstrip('=')
            link = f'ss://{auth}@127.0.0.1:{p}#fixture'
        elif protocol == 'trojan':
            node.update(users=[dict(username='test', password=password)], certificate='./tls.crt')
            node['private-key'] = './tls.key'
            link = f'trojan://{password}@127.0.0.1:{p}?sni=localhost&allowInsecure=1'
        else:
            node.update(users={'test': password}, certificate='./tls.crt')
            node['private-key'] = './tls.key'
            link = f'anytls://{password}@127.0.0.1:{p}?sni=localhost&insecure=1'
        nodes.append(node)
        links.append(link)
    # A reachable TCP-only SS node exercises UDP failure independently of TCP.
    tcp_only = dict(nodes[2], name='tcp-only', port=port(), udp=False)
    links.append(links[2].replace(f":{nodes[2]['port']}#", f":{tcp_only['port']}#"))
    nodes.append(tcp_only)
    # Answer the standard UDP DNS probe inside the remote fixture, offline.
    (folder / 'server.json').write_text(json.dumps(dict(listeners=nodes,
        proxies=[dict(name='probe-dns', type='dns')],
        rules=['IP-CIDR,8.8.8.8/32,probe-dns,no-resolve', 'MATCH,DIRECT'],
        dns=dict(enable=True, nameserver=['127.0.0.1:9']),
        hosts={'extension-target.invalid': '127.0.0.1', 'example.com': '192.0.2.1'})))
    return links, password


def run(core, binaries):
    # Keep child processes of this test runner on the disposable profile even
    # when the developer's terminal is already running under ProxyLane.
    hook = 'ProxyLaneHook%d.dll' % (ctypes.sizeof(ctypes.c_void_p) * 8)
    if KERNEL.GetModuleHandleW(hook) and not ctypes.WinDLL(hook).gp_UnhookWinsock():
        raise RuntimeError('Run the fixture from an unproxied process')
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_HEAD(self):
            requests.append(self.path)
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    with tempfile.TemporaryDirectory(prefix='pl-mihomo-test-') as temp, \
            http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler) as target:
        folder = Path(temp)
        links, hop2_password = fixture(folder)
        hop2_port, stop_hop2 = start_socks5_relay('hop2', hop2_password, {'extension-target.invalid': '127.0.0.1'})
        for name in ('ProxyLane64.exe', 'ProxyLaneHook32.dll', 'ProxyLaneHook64.dll'):
            shutil.copy2(binaries / name, folder / name)
        (folder / 'portable.flag').touch()
        dest = folder / 'extensions/upstream/mihomo/mihomo.exe'
        ini = folder / 'ProxyLane.ini'
        ini.write_text(f'[options]\nlanguage=en-US\nlastselected=Node\n'
                       f'testhost=extension-target.invalid:{target.server_port}\nIPv6TestAddress=::1\n'
                       f'HookLanIP=1\n'
                       f'[proxy_Node]\nType=EXTENSION\nNodeURI={links[0]}\nHookUDP=1\nBlockUDP=0\n'
                       f'[proxy_Hop2]\nType=SOCKS5\nHost=127.0.0.1\nPort={hop2_port}\nUser=hop2\nPass={hop2_password}\n'
                       f'[proxy_ExtFirstChain]\nType=CHAIN\nHop1=Node\nHop2=Hop2\n'
                       f'[proxy_ExtSecondChain]\nType=CHAIN\nHop1=Hop2\nHop2=Node\n',
                       encoding='utf-16')
        server = subprocess.Popen([core, '-d', folder, '-f', folder / 'server.json'],
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        app = subprocess.Popen([folder / 'ProxyLane64.exe', '--profile', 'Node'], cwd=folder)
        owner = psutil.Process(app.pid)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        try:
            main = wait_for(lambda: next((w for w in windows(app.pid) if settings_page(w)), None), 'main')
            page = settings_page(main)
            edit = USER.GetDlgItem(page, 0x2430)
            assert text(edit) == links[0]
            udp_box = USER.GetDlgItem(page, 1013)
            assert USER.IsWindowEnabled(udp_box) and USER.SendMessageW(udp_box, 0xf0, 0, 0) == 1
            # Check visibility styles even when another tab is in front.
            visible = lambda c: bool(USER.GetWindowLongW(USER.GetDlgItem(page, c), -16) & 0x10000000)
            assert visible(0x2430) and not any(visible(c) for c in (1002, 1003, 1004, 1005, 0x2402))

            def set_link(link):
                buf = ctypes.create_unicode_buffer(link)
                USER.SendMessageW(edit, 0xC, 0, ctypes.addressof(buf))

            def command(control):
                USER.PostMessageW(page, 0x111, control, 0)

            def test_link(link, success, udp_success):
                set_link(link)
                previous = len(requests)
                command(1008)
                dialog = wait_for(lambda: next((w for w in windows(app.pid) if w != main and
                    USER.IsWindowVisible(w) and (USER.GetDlgItem(w, 1201) or USER.GetDlgItem(w, 0xffff))), None),
                    'test result')
                row = USER.GetDlgItem(dialog, 1201)
                assert row, (text(dialog), text(USER.GetDlgItem(dialog, 0xffff)))
                assert ('Connected' in text(row)) == success, (text(row), len(requests) - previous)
                assert (len(requests) > previous) == success
                udp_row = text(USER.GetDlgItem(dialog, 1202))
                assert ('Connected' in udp_row) == udp_success, udp_row
                if success and not udp_success:
                    assert 'Failed' in udp_row, udp_row
                dismiss(dialog, 2)
                wait_for(lambda: not owner.children(), 'test core cleanup')

            def message(title, button=1, expect=None):
                dialog = wait_for(lambda: next((w for w in windows(app.pid) if w != main and
                    text(w) == title and USER.IsWindowVisible(w)), None), title)
                if expect:
                    body = text(USER.GetDlgItem(dialog, 0xffff))
                    assert expect in body, body
                dismiss(dialog, button)

            catalog = json.loads((Path(__file__).resolve().parents[1] /
                                  'src/ProxyLane/locales/en-US.json').read_text(encoding='utf-8'))
            pages5 = []
            @CALLBACK
            def find_page5(window, _):
                if USER.GetDlgItem(window, 0x2532):
                    pages5.append(window)
                return True
            USER.EnumChildWindows(main, find_page5, 0)
            assert len(pages5) == 1
            page5 = pages5[0]
            p5_visible = lambda c: bool(USER.GetWindowLongW(USER.GetDlgItem(page5, c), -16) & 0x10000000)
            if not (Path(os.environ['LOCALAPPDATA']) / 'ProxyLane/extensions/upstream/mihomo/mihomo.exe').exists():
                assert text(USER.GetDlgItem(page5, 0x252A)) == catalog['settings.extension_missing']
                assert text(USER.GetDlgItem(page5, 0x2505)) == catalog['extension.install']
                assert not p5_visible(0x2506)
                set_link(links[1])
                command(1052)
                wait_for(lambda: links[1] in ini.read_text(encoding='utf-16'), 'offline save')
                command(1008)
                message(catalog['test.invalid_title'])
                assert not owner.children() and not requests
                print('PASS offline save and missing core', flush=True)
            USER.PostMessageW(page5, 0x111, 0x2505, 0)
            picker = wait_for(lambda: next((w for w in windows(app.pid) if w != main and
                USER.IsWindowVisible(w) and not settings_page(w)), None), 'install picker')
            edits = []
            @CALLBACK
            def find_filename(window, _):
                classname = ctypes.create_unicode_buffer(64)
                USER.GetClassNameW(window, classname, 64)
                if classname.value == 'Edit' and USER.IsWindowVisible(window):
                    edits.append(window)
                return True
            USER.EnumChildWindows(picker, find_filename, 0)
            filename = ctypes.create_unicode_buffer(str(core))
            USER.SendMessageW(edits[-1], 0xC, 0, ctypes.addressof(filename))
            USER.PostMessageW(picker, 0x111, 1, 0)
            message('ProxyLane')
            assert dest.is_file() and dest.stat().st_size == core.stat().st_size
            assert text(USER.GetDlgItem(page5, 0x252A)) == catalog['settings.extension_installed']
            assert text(USER.GetDlgItem(page5, 0x252B)) == str(dest)
            assert text(USER.GetDlgItem(page5, 0x2505)) == catalog['settings.extension_browse']
            assert p5_visible(0x2506)
            print('PASS install Mihomo from Settings & About', flush=True)
            set_link('vmess://invalid-base64')
            command(1008)
            message(catalog['test.invalid_title'], expect='convert v2ray subscribe error')
            assert not owner.children() and not requests
            print('PASS invalid node surfaces Mihomo error', flush=True)
            for link in links[:5]:
                test_link(link, True, True)
                print('PASS TCP and UDP', link.split(':')[0], flush=True)
            test_link(links[5], True, False)
            print('PASS TCP-only remote node', flush=True)
            test_link(links[0].replace(links[0][8:44], str(uuid.uuid4())), False, False)
            set_link(links[2])
            command(1052)
            wait_for(lambda: links[2] in ini.read_text(encoding='utf-16'), 'save node URI')
            command(1)
            wait_for(lambda: owner.children(), 'business core')
            wait_for(lambda: USER.IsWindowEnabled(USER.GetDlgItem(page, 2)), 'running')
            active = owner.children()[0]
            set_link('vmess://invalid-base64')
            command(1052)
            message(catalog['apply.failed_title'])
            assert owner.children() == [active] and active.is_running()
            set_link(links[2])
            command(1052)
            message(catalog['apply.saved_success_title'])
            assert owner.children() == [active], 'unchanged node must retain established sessions'
            log_edits = []
            @CALLBACK
            def find_log(window, _):
                if USER.GetDlgItem(window, 1043):
                    log_edits.append(USER.GetDlgItem(window, 1000))
                return True
            USER.EnumChildWindows(main, find_log, 0)
            assert len(log_edits) == 1 and log_edits[0]
            entries = wait_for(lambda: re.findall(r'Mihomo profile SOCKS5 ready: (\S+)',
                text(log_edits[0])), 'profile SOCKS5 endpoint in log')
            assert len(entries) == 1
            assert 'Mihomo test SOCKS5 ready: ' in text(log_edits[0])
            # Only the remote fixture knows this name. A direct connection
            # cannot deliver the managed application's request to the target.
            curl = Path(os.environ['SystemRoot']) / 'System32/curl.exe'
            probe = subprocess.run([curl, '--proxy', entries[0], '--noproxy', '', '--max-time', '8',
                '--head', '--fail', '--silent', '--output', os.devnull,
                f'http://127.0.0.1:{target.server_port}/logged-endpoint'],
                creationflags=subprocess.CREATE_NO_WINDOW)
            assert probe.returncode == 0 and '/logged-endpoint' in requests
            print('PASS authenticated SOCKS5 request using the profile log entry', flush=True)
            report = folder / 'client.log'
            result = subprocess.run([folder / 'ProxyLane64.exe', '--auto', '--profile', 'Node',
                '--run', curl, '--wait-exit', '--', '-4', '--noproxy', '*', '--max-time', '8',
                '--head', '--fail', '--trace-ascii', report, '--output', os.devnull,
                f'http://extension-target.invalid:{target.server_port}/business'],
                cwd=folder, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode or '/business' not in requests:
                time.sleep(.5)  # Allow the GUI log queue to flush for diagnostics.
                log = re.sub(r'socks5://\S+@', 'socks5://***@', text(log_edits[0]))
                raise AssertionError((result.returncode, log, report.read_text() if report.exists() else 'no target'))
            print('PASS managed application through the saved extension profile', flush=True)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo:
                echo.bind((local_ipv4(), 0))
                echo.settimeout(10)
                observed = []
                responder = threading.Thread(target=udp_echo, args=(echo, observed), daemon=True)
                responder.start()
                probe = folder / 'udp_client.py'
                probe.write_text("import socket, sys\n"
                                 "dest = (sys.argv[1], int(sys.argv[2]))\n"
                                 "with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:\n"
                                 "    s.settimeout(8)\n"
                                 "    s.sendto(b'extension UDP echo', dest)\n"
                                 "    data, peer = s.recvfrom(512)\n"
                                 "    assert data == b'extension UDP echo' and peer[0] == '127.0.0.1' and peer != dest\n")
                address, udp_port = echo.getsockname()
                subprocess.run([folder / 'ProxyLane64.exe', '--auto', '--profile', 'Node',
                    '--run', sys.executable, '--wait-exit', '--', probe, address, str(udp_port)],
                    cwd=folder, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW, check=True)
                responder.join(4)
                assert observed == [server.pid], ('remote UDP sender', observed, server.pid)
            print('PASS managed UDP echo through remote node, with actual relay source', flush=True)
            command(2)
            wait_for(lambda: not owner.children(), 'stop business core')
            print('PASS wrong credentials, save, apply, stop and process cleanup', flush=True)
            # Extension as chain hop 1 works; hop 2+ is rejected.
            bad_chain = subprocess.run([folder / 'ProxyLane64.exe', '--auto', '--profile', 'ExtSecondChain',
                '--run', curl, '--wait-exit', '--', '-4', '--noproxy', '*', '--max-time', '5',
                '--head', f'http://extension-target.invalid:{target.server_port}/bad-chain'],
                cwd=folder, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
            assert bad_chain.returncode != 0 and '/bad-chain' not in requests, bad_chain.returncode
            good_chain = subprocess.run([folder / 'ProxyLane64.exe', '--auto', '--profile', 'ExtFirstChain',
                '--run', curl, '--wait-exit', '--', '-4', '--noproxy', '*', '--max-time', '8',
                '--head', '--fail', f'http://extension-target.invalid:{target.server_port}/ext-chain'],
                cwd=folder, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
            assert good_chain.returncode == 0 and '/ext-chain' in requests, (good_chain.returncode, requests)
            print('PASS Extension as chain hop 1 (and hop 2+ rejected)', flush=True)
        finally:
            stop_hop2()
            if app.poll() is None:
                app.terminate()
            app.wait(10)
            server.terminate()
            server.wait(10)
            target.shutdown()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--bin', type=Path, default=Path('bin'))
    args = parser.parse_args()
    run(args.core.resolve(), args.bin.resolve())
