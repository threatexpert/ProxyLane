"""Keep one real cmd alive across two real ProxyLane processes; exercise curl.

Uses only test-owned GUI/shell processes and local HTTP/SOCKS5 endpoints. Needs
64-bit Python, psutil, Windows curl (both bitnesses for the default matrix).
"""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
import uuid

import psutil

KERNEL = ctypes.WinDLL('kernel32', use_last_error=True)
USER = ctypes.WinDLL('user32', use_last_error=True)
KERNEL.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
KERNEL.GetModuleHandleW.restype = wintypes.HMODULE
KERNEL.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                              ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
KERNEL.CreateFileW.restype = wintypes.HANDLE
KERNEL.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
KERNEL.CloseHandle.argtypes = [wintypes.HANDLE]
CALLBACK = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
USER.EnumWindows.argtypes = [CALLBACK, wintypes.LPARAM]
USER.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
USER.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
USER.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]


def exact(conn, size):
    data = b''
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError('Socket closed')
        data += chunk
    return data


def serve(listener, proxied, observations, destination):
    def client(conn):
        try:
            with conn:
                conn.settimeout(8)
                if proxied:
                    version, count = exact(conn, 2)
                    assert version == 5
                    exact(conn, count)
                    conn.sendall(b'\x05\x00')
                    assert exact(conn, 4) == b'\x05\x01\x00\x01'
                    address = socket.inet_ntoa(exact(conn, 4))
                    port = int.from_bytes(exact(conn, 2), 'big')
                    assert (address, port) == destination, (address, port)
                    conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                request = b''
                while b'\r\n\r\n' not in request:
                    chunk = conn.recv(4096)
                    if not chunk:
                        raise EOFError('HTTP request incomplete')
                    request += chunk
                    assert len(request) < 65536
                token = request.split(b' ', 2)[1].decode('ascii')
                route = 'PROXY' if proxied else 'DIRECT'
                observations.append((route, token))
                body = (route + ':' + token).encode('ascii')
                conn.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ' +
                             str(len(body)).encode() + b'\r\n\r\n' + body)
        except Exception as error:
            observations.append(('ERROR', repr(error)))
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=client, args=(conn,), daemon=True).start()


def owned_pipe(pid):
    for name in os.listdir('\\\\.\\pipe\\'):
        if not name.startswith('PRCPipeName'):
            continue
        path = '\\\\.\\pipe\\' + name
        handle = KERNEL.CreateFileW(path, 0x12019b, 3, None, 3, 0x110000, None)
        if handle == ctypes.c_void_p(-1).value:
            continue
        try:
            server = wintypes.ULONG()
            if KERNEL.GetNamedPipeServerProcessId(handle, ctypes.byref(server)) and server.value == pid:
                return path
        finally:
            KERNEL.CloseHandle(handle)
    return None


def start_gui(directory):
    owner = subprocess.Popen([str(directory / 'ProxyLane64.exe'), '--auto', '--profile', 'Rebind',
                              '--run', str(Path(os.environ['SystemRoot']) / 'System32/cmd.exe'),
                              '--', '/d', '/c', 'exit'], cwd=directory,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if owner.poll() is not None:
                raise RuntimeError('Test ProxyLane exited before starting PRC')
            pipe = owned_pipe(owner.pid)
            if pipe:
                return owner, pipe
            time.sleep(.05)
        raise TimeoutError('Test ProxyLane PRC startup timed out')
    except Exception:
        owner.terminate()
        owner.wait(timeout=10)
        raise


def close_gui(owner):
    windows = []
    @CALLBACK
    def visit(window, _):
        pid = wintypes.DWORD()
        USER.GetWindowThreadProcessId(window, ctypes.byref(pid))
        if pid.value == owner.pid:
            name = ctypes.create_unicode_buffer(256)
            USER.GetClassNameW(window, name, len(name))
            if name.value == '#32770':
                windows.append(window)
        return True
    USER.EnumWindows(visit, 0)
    if not windows:
        raise RuntimeError('Test GUI main dialog not found')
    for window in windows:
        USER.PostMessageW(window, 0x10, 0, 0)  # WM_CLOSE, only our GUI PID
    owner.wait(timeout=15)


def attach(directory, bits, pid, pipe):
    system = Path(os.environ['SystemRoot']) / ('System32' if bits == 64 else 'SysWOW64')
    result = subprocess.run([str(system / 'rundll32.exe'),
                             str(directory / ('ProxyLaneHook%d.dll' % bits)) + ',AttachTo',
                             '--pid=%d' % pid, '--tid=0', '--pipe=' + pipe], timeout=20)
    if result.returncode != 0xff01:
        raise RuntimeError('AttachTo did not schedule injection: %d' % result.returncode)


def request(shell, curl, directory, target, stage, expected, observations):
    # Initial/repeated injection is asynchronous; wait for observable traffic,
    # never treat AttachTo's "queued" return as successful hook initialization.
    deadline = time.monotonic() + 12
    last = None
    while time.monotonic() < deadline:
        token = stage + '-' + uuid.uuid4().hex[:8]
        body, done, error = (directory / (token + suffix) for suffix in ('.body', '.done', '.err'))
        command = ('"%s" --silent --show-error --noproxy "*" --proxy "" --connect-timeout 2 '
                   '--max-time 4 --output "%s" "http://%s:%d/%s" 2>"%s"\r\n'
                   'echo %%errorlevel%% > "%s"\r\n') % (curl, body, target[0], target[1], token, error, done)
        shell.stdin.write(command.encode('mbcs'))
        shell.stdin.flush()
        command_deadline = time.monotonic() + 7
        while not done.exists() and time.monotonic() < command_deadline:
            if shell.poll() is not None:
                raise RuntimeError('The persistent cmd exited')
            time.sleep(.02)
        if not done.exists():
            raise TimeoutError('curl did not complete in persistent cmd')
        last = body.read_text() if body.exists() else error.read_text(errors='replace')
        if done.read_text().strip() == '0' and last == expected + ':/' + token:
            assert (expected, '/' + token) in observations
            return
        time.sleep(.1)
    raise AssertionError('%s: expected %s from the same cmd PID %d, got %r' % (stage, expected, shell.pid, last))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, default=Path('bin'))
    parser.add_argument('--bits', type=int, nargs='+', choices=(32, 64), default=[32, 64])
    args = parser.parse_args()
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError('Use 64-bit Python')
    # Quiescent disposable runner only; never modify the user's ProxyLane.
    if KERNEL.GetModuleHandleW('ProxyLaneHook64.dll'):
        if not ctypes.WinDLL('ProxyLaneHook64.dll').gp_UnhookWinsock():
            raise RuntimeError('Run tests from an unproxied process')
    directory = Path('build/qa/hook-rebind-' + uuid.uuid4().hex[:8]).resolve()
    directory.mkdir(parents=True)
    print('Results:', directory, flush=True)
    for name in ('ProxyLane64.exe', 'ProxyLaneHook32.dll', 'ProxyLaneHook64.dll'):
        if name == 'ProxyLaneHook32.dll' and 32 not in args.bits:
            continue
        shutil.copy2(args.bin / name, directory / name)
    # A genuine local non-loopback address permits a successful DIRECT phase.
    # Loopback is intentionally bypassed by production hooks, even with HookLanIP.
    addresses = [a.address for values in psutil.net_if_addrs().values() for a in values
                 if a.family == socket.AF_INET and not a.address.startswith(('127.', '169.254.'))]
    if not addresses:
        raise RuntimeError('Test requires a local non-loopback IPv4 interface')
    observations = []
    with socket.socket() as direct, socket.socket() as socks:
        direct.bind((addresses[0], 0)); direct.listen()
        socks.bind(('127.0.0.1', 0)); socks.listen()
        target = direct.getsockname()
        for listener, proxied in ((direct, False), (socks, True)):
            threading.Thread(target=serve, args=(listener, proxied, observations, target), daemon=True).start()
        (directory / 'ProxyLane.ini').write_text('''[options]
lastselected=Rebind
language=en-US
HookLanIP=1
[proxy_Rebind]
HookChildProcess=1
HookTCP=1
HookUDP=0
BlockUDP=0
dnsOpt=0
ChildFilter=
ChildFilterMode=1
TargetFilter=
TargetFilterMode=1
Type=SOCKS5
Host=127.0.0.1
Port=%d
Transport=PLAIN
''' % socks.getsockname()[1], encoding='utf-8')
        records = []
        try:
            for bits in args.bits:
                system = Path(os.environ['SystemRoot']) / ('System32' if bits == 64 else 'SysWOW64')
                shell_path = directory / ('cmd%d.exe' % bits)
                curl = directory / ('curl%d.exe' % bits)
                shutil.copy2(system / 'cmd.exe', shell_path)
                shutil.copy2(system / 'curl.exe', curl)
                shell = subprocess.Popen([str(shell_path), '/d', '/q'], stdin=subprocess.PIPE,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         creationflags=subprocess.CREATE_NO_WINDOW, cwd=directory)
                identity = psutil.Process(shell.pid).create_time()
                owner = None
                record = {'bits': bits, 'cmd_pid': shell.pid, 'cmd_created': identity}
                records.append(record)
                try:
                    owner, first_pipe = start_gui(directory)
                    record.update(first_owner=owner.pid, first_pipe=first_pipe)
                    attach(directory, bits, shell.pid, first_pipe)
                    request(shell, curl, directory, target, 'initial', 'PROXY', observations)
                    close_gui(owner); owner = None
                    request(shell, curl, directory, target, 'service-exited', 'DIRECT', observations)
                    owner, second_pipe = start_gui(directory)
                    record.update(second_owner=owner.pid, second_pipe=second_pipe)
                    assert first_pipe != second_pipe, 'Must test a new service instance/pipe'
                    request(shell, curl, directory, target, 'before-rebind', 'DIRECT', observations)
                    attach(directory, bits, shell.pid, second_pipe)
                    request(shell, curl, directory, target, 'rebound', 'PROXY', observations)
                    attach(directory, bits, shell.pid, second_pipe)
                    request(shell, curl, directory, target, 'same-service-rebind', 'PROXY', observations)
                    attach(directory, bits, shell.pid, '\\\\.\\pipe\\Missing-Rebind-' + uuid.uuid4().hex)
                    request(shell, curl, directory, target, 'failed-rebind-keeps-service', 'PROXY', observations)
                    assert psutil.Process(shell.pid).create_time() == identity
                    record['passed'] = True
                    print('PASS x%d: same cmd %d, PROXY -> DIRECT -> PROXY, repeat/failed rebind' %
                          (bits, shell.pid), flush=True)
                    close_gui(owner); owner = None
                finally:
                    if owner and owner.poll() is None:
                        owner.terminate(); owner.wait(timeout=10)
                    if shell.poll() is None:
                        shell.stdin.write(b'exit\r\n'); shell.stdin.flush()
                        shell.wait(timeout=10)
                    shell.stdin.close()
        finally:
            (directory / 'results.json').write_text(json.dumps({'runs': records, 'traffic': observations}, indent=2))
        assert not any(route == 'ERROR' for route, _ in observations), observations


if __name__ == '__main__':
    main()
