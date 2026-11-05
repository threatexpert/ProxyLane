"""Exercise the real configuration-test UI using only owned local endpoints."""
import argparse
import ctypes
import json
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
import uuid

from ExitWarningE2ETests import USER, CALLBACK, wait_for, windows, settings_page, text
from HookRebindE2ETests import KERNEL, exact


class Endpoint:
    def __init__(self, family=socket.AF_INET, port=0, protocol=None, outcome='success', listen=True):
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        self.socket.bind(('::1' if family == socket.AF_INET6 else '127.0.0.1', port))
        self.port = self.socket.getsockname()[1]
        self.protocol, self.outcome = protocol, outcome
        self.requests, self.errors = [], []
        self.stopped = threading.Event()
        self.thread = None
        if listen:
            self.socket.listen()
            self.socket.settimeout(.1)
            self.thread = threading.Thread(target=self.serve, daemon=True)
            self.thread.start()

    def serve(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with connection:
                    connection.settimeout(3)
                    if self.protocol == 'SOCKS5':
                        version, count = exact(connection, 2)
                        assert version == 5
                        exact(connection, count)
                        connection.sendall(b'\x05\x00')
                        version, command, _, kind = exact(connection, 4)
                        assert version == 5 and command == 1
                        size = {1: 4, 4: 16}.get(kind)
                        if kind == 3:
                            size = exact(connection, 1)[0]
                        address = exact(connection, size)
                        exact(connection, 2)
                        self.requests.append((kind, address.hex()))
                        if kind == 4 and self.outcome == 'timeout':
                            self.stopped.wait(12)
                            continue
                        reply = 5 if kind == 4 and self.outcome == 'refused' else 0
                        connection.sendall(bytes([5, reply, 0, 1, 127, 0, 0, 1, 0, 80]))
                    elif self.protocol == 'SOCKS4':
                        header = exact(connection, 8)
                        assert header[:2] == b'\x04\x01'
                        while exact(connection, 1) != b'\x00':
                            pass
                        self.requests.append(('socks4', header.hex()))
                        connection.sendall(b'\x00\x5a' + header[2:8])
                    elif self.protocol in ('HTTP10', 'HTTP11'):
                        request = b''
                        while b'\r\n\r\n' not in request:
                            request += exact(connection, 1)
                        self.requests.append(('http', request.decode('ascii')))
                        connection.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                    else:
                        self.requests.append(('direct', ''))
                    # Keep the endpoint open until the tester observes success and closes it.
                    try:
                        while connection.recv(256):
                            pass
                    except socket.timeout:
                        pass
            except Exception as error:
                self.errors.append(repr(error))

    def close(self):
        self.stopped.set()
        self.socket.close()
        if self.thread:
            self.thread.join(4)


def children(window):
    result = []
    @CALLBACK
    def visit(child, _):
        result.append(text(child))
        return True
    USER.EnumChildWindows(window, visit, 0)
    return '\n'.join(result)


def run(binary_dir, bits, language):
    if bits == 32 and ctypes.sizeof(ctypes.c_void_p) == 8:
        raise RuntimeError('The 32-bit GUI forwards to 64-bit on this OS; use run-ipv6-proxy-tester-tests.ps1 for the 32-bit backend.')
    module = KERNEL.GetModuleHandleW('ProxyLaneHook64.dll')
    if module:
        assert ctypes.WinDLL('ProxyLaneHook64.dll', handle=module).gp_UnhookWinsock()
    root = Path(__file__).resolve().parents[1]
    directory = root / 'build/qa' / ('ipv6-config-' + uuid.uuid4().hex[:8])
    directory.mkdir(parents=True)
    executable = 'ProxyLane64.exe' if bits == 64 else 'ProxyLane.exe'
    for name in (executable, 'ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        shutil.copy2(binary_dir / name, directory / name)
    locale = json.loads((root / 'src/ProxyLane/locales' / (language + '.json')).read_text(encoding='utf-8'))
    base = Endpoint()
    reports = []
    try:
        cases = [('NOPROXY', 'success'), ('NOPROXY', 'refused'), ('NOPROXY', 'invalid'),
                 ('SOCKS5', 'success'), ('SOCKS5', 'refused'), ('SOCKS5', 'timeout'),
                 ('HTTP10', 'success'), ('HTTP11', 'success'), ('SOCKS4', 'unsupported')]
        for protocol, outcome in cases:
            endpoint = None
            if protocol == 'NOPROXY' and outcome != 'invalid':
                endpoint = Endpoint(socket.AF_INET6, 53, listen=outcome == 'success')
            elif protocol != 'NOPROXY':
                endpoint = Endpoint(protocol=protocol, outcome=outcome)
            port = endpoint.port if endpoint else 0
            address = 'invalid-address' if outcome == 'invalid' else '::1'
            (directory / 'portable.flag').touch()
            (directory / 'ProxyLane.ini').write_text(f'''[options]
language={language}
lastselected=Probe
testhost=127.0.0.1:{base.port}
IPv6TestAddress={address}
[proxy_Probe]
Type={protocol}
Host=127.0.0.1
Port={port}
Transport=PLAIN
HookTCP=1
HookUDP=0
HookChildProcess=0
BlockIPv6=0
''', encoding='utf-8')
            process = subprocess.Popen([str(directory / executable), '--profile', 'Probe'], cwd=directory,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                main = wait_for(lambda: next((w for w in windows(process.pid) if settings_page(w)), None), 'main')
                page = settings_page(main)
                USER.PostMessageW(page, 0x111, 1008, 0)
                try:
                    dialog = wait_for(lambda: next((w for w in windows(process.pid)
                        if w != main and text(w) == locale['test.title']), None), 'test result')
                except TimeoutError:
                    raise AssertionError({'status': text(USER.GetDlgItem(page, 1017)),
                        'button': text(USER.GetDlgItem(page, 1008)), 'base': base.requests,
                        'probe': endpoint.requests if endpoint else [],
                        'windows': [(text(w), children(w)) for w in windows(process.pid)]})
                result = children(dialog)
                key = {'success': 'test.ipv6_available', 'refused': 'test.ipv6_target_failed',
                       'timeout': 'test.ipv6_unknown', 'invalid': 'test.ipv6_invalid_config',
                       'unsupported': 'test.ipv6_unsupported'}[outcome]
                assert locale[key].strip() in result, (protocol, outcome, result)
                if outcome != 'unsupported':
                    assert locale['test.ipv6_unsupported'].strip() not in result, result
                if outcome not in ('invalid', 'unsupported'):
                    assert '[::1]:53' in result, result
                if outcome == 'refused':
                    assert locale['test.ipv6_error'].split('%s')[0].strip() in result, result
                    description = ctypes.FormatError(10061).strip() if protocol == 'NOPROXY' else locale['test.target_failed']
                    assert description in result, result
                    assert '10061' not in result, result
                if endpoint:
                    assert not endpoint.errors, endpoint.errors
                    if protocol == 'NOPROXY' and outcome == 'success':
                        assert endpoint.requests, 'IPv6 listener never received a connection'
                    if protocol == 'SOCKS5':
                        assert any(kind == 4 and value == '00000000000000000000000000000001'
                                   for kind, value in endpoint.requests), endpoint.requests
                    if protocol.startswith('HTTP'):
                        assert any('CONNECT [::1]:53 ' in value for _, value in endpoint.requests), endpoint.requests
                reports.append({'protocol': protocol, 'outcome': outcome, 'dialog': result})
                print(f'PASS {bits}-bit {language} {protocol} {outcome}', flush=True)
                # Each case owns a disposable GUI; leave profile-changing prompts
                # unanswered and tear down that GUI in finally.
            finally:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)
                if endpoint:
                    endpoint.close()
        (directory / 'results.json').write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding='utf-8')
    finally:
        base.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin', default='bin', type=Path)
    parser.add_argument('--bits', type=int, choices=(32, 64), default=64)
    parser.add_argument('--language', choices=('zh-CN', 'en-US'), default='zh-CN')
    arguments = parser.parse_args()
    run(arguments.bin.resolve(), arguments.bits, arguments.language)
