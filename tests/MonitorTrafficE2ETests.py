"""Exercise a disposable GUI under 128 MiB of real injected TCP traffic.

Uses a unique profile and localhost SOCKS relay, without CA or user settings
changes. Verifies one live TCP session, bounded cache/HEX display and memory/responsiveness.
"""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import subprocess
import sys
import time
import uuid

from MonitorLayoutE2ETests import u, k, CALLBACK, send, screenshot

PAYLOAD = bytes(range(256)) * 64
BLOCKS = 8192


def client(port, output):
    with socket.create_connection(('203.0.113.10', port), 20) as stream:
        stream.sendall(b'\x00STREAM-TEST\r\n\r\n')
        result = hashlib.sha256(); size = 0
        while True:
            data = stream.recv(65536)
            if not data: break
            result.update(data); size += len(data)
    Path(output).write_text(json.dumps({'bytes': size, 'sha256': result.hexdigest()}))


class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        data = b''
        while b'\r\n\r\n' not in data: data += self.request.recv(4096)
        for _ in range(BLOCKS):
            self.request.sendall(PAYLOAD)
            time.sleep(.0015)


class Memory(c.Structure):
    _fields_ = [('cb', w.DWORD), ('faults', w.DWORD)] + [
        (name, c.c_size_t) for name in ['peakWorking', 'working', 'peakPaged',
        'paged', 'peakNonPaged', 'nonPaged', 'pagefile', 'peakPagefile', 'private']]


class Scroll(c.Structure):
    _fields_ = [('size', w.UINT), ('mask', w.UINT), ('minimum', c.c_int),
        ('maximum', c.c_int), ('page', w.UINT), ('position', c.c_int), ('track', c.c_int)]


def memory(process):
    info = Memory(); info.cb = c.sizeof(info)
    api = c.windll.psapi.GetProcessMemoryInfo
    api.argtypes = [w.HANDLE, c.POINTER(Memory), w.DWORD]
    assert api(int(process._handle), c.byref(info), info.cb)
    return info.private


def text(hwnd):
    length = send(hwnd, 0xE)
    buf = c.create_unicode_buffer(length + 1)
    send(hwnd, 0xD, length + 1, c.addressof(buf))
    return buf.value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary-directory', default='bin')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root/'tests/e2e'))
    from mitm_e2e import Proxy, start
    k.GetModuleHandleW.argtypes = [w.LPCWSTR]; k.GetModuleHandleW.restype = w.HMODULE
    module = k.GetModuleHandleW('ProxyLaneHook64.dll')
    if module: assert c.WinDLL('ProxyLaneHook64.dll', handle=module).gp_UnhookWinsock()
    u.SetProcessDPIAware()
    origin, relay = start(Origin), start(Proxy)
    unique = uuid.uuid4().hex[:10]
    work = root/'build/qa'/('monitor-traffic-'+unique); work.mkdir()
    source = (root/args.binary_directory).resolve()
    for pattern in ('ProxyLane*.exe', 'ProxyLane*.dll'):
        for path in source.glob(pattern): shutil.copy2(path, work/path.name)
    profile = 'MonitorLoad'+unique
    config = (root/'examples/ProxyLane.ini').read_text().replace('Test', profile)
    config = config.replace('Port=1080', 'Port='+str(relay.server_address[1]))
    # This is a plaintext throughput test, independent of the example profile's
    # saved decryption preference (which may require CA onboarding).
    config = '\n'.join(line for line in config.splitlines() if not line.startswith('DecryptHTTPS='))
    config = config.replace('[options]', '[options]\nlanguage=zh-CN\nDecryptHTTPS=0')
    (work / 'portable.flag').touch()
    (work/'ProxyLane.ini').write_text(config)
    env = dict(os.environ, PROXYLANE_MITM='0', PROXYLANE_MITM_HOME=str(work/'pki'), PROXYLANE_PROTOCOL_CACHE_ROOT=str(work/'cache'),
        PROXYLANE_PROTOCOL_ENTRY_BYTES=str(1024*1024), PROXYLANE_PROTOCOL_TOTAL_BYTES=str(2*1024*1024))
    process = subprocess.Popen([str(work/'ProxyLane64.exe')], cwd=work, env=env)
    launch = None
    try:
        windows = []
        @CALLBACK
        def collect(hwnd, _):
            pid = w.DWORD(); u.GetWindowThreadProcessId(hwnd, c.byref(pid))
            if pid.value == process.pid and u.IsWindowVisible(hwnd):
                title = c.create_unicode_buffer(256); u.GetWindowTextW(hwnd, title, 256)
                if title.value.startswith('ProxyLane '): windows.append(hwnd)
            return True
        deadline = time.monotonic()+15
        while not windows:
            assert process.poll() is None and time.monotonic()<deadline
            u.EnumWindows(collect, 0); time.sleep(.1)
        hwnd = windows[0]; nav = u.GetDlgItem(hwnd, 0x1006)
        pages = {}; scale = u.GetDpiForWindow(nav)/96
        @CALLBACK
        def find(hwnd, _):
            if u.GetDlgItem(hwnd, 1086): pages['monitor'] = hwnd
            if u.GetDlgItem(hwnd, 1005) and u.GetDlgItem(hwnd, 1): pages['proxy'] = hwnd
            return True
        u.EnumChildWindows(nav, find, 0)
        page = pages['monitor']; edit = u.GetDlgItem(page, 1100)
        assert not u.GetDlgItem(page, 1000) and not u.GetDlgItem(page, 1097)
        def activate(index):
            x, y = round(50*scale), round((78+index*44+20)*scale)
            send(nav, 0x201, 1, (y<<16)|x); send(nav, 0x202, 0, (y<<16)|x)
        def check(ident, enabled):
            control = u.GetDlgItem(page, ident)
            send(control, 0xF1, int(enabled)); send(page, 0x111, ident, control)
        send(pages['proxy'], 0x111, 1, u.GetDlgItem(pages['proxy'], 1))
        time.sleep(.5)
        activate(3); check(1011, True)
        deadline = time.monotonic()+15
        monitor = u.GetDlgItem(page,1011)
        while not u.IsWindowEnabled(monitor):
            assert process.poll() is None and time.monotonic()<deadline, 'Monitoring did not start'
            time.sleep(.05)
        assert send(monitor,0xF0)==1, 'Plain monitoring failed to start'
        baseline = memory(process)
        output = work/'client-result.json'
        launch = subprocess.Popen([str(work/'ProxyLane64.exe'), '--auto', '--profile', profile,
            '--run', sys.executable, '--', str(Path(__file__).resolve()),
            '--client', str(origin.server_address[1]), str(output)], cwd=work, env=env)
        peak = baseline; max_chars = 0; max_latency = 0; samples = 0
        deadline = time.monotonic()+75
        while not output.exists():
            assert process.poll() is None and time.monotonic()<deadline, 'Transfer did not finish'
            activate(3)
            began = time.perf_counter(); send(hwnd, 0)
            max_latency = max(max_latency, time.perf_counter()-began)
            chars = send(edit, 0xE); max_chars = max(max_chars, chars)
            assert chars == 0, ('Raw bytes entered protocol details', chars)
            peak = max(peak, memory(process)); samples += 1
            time.sleep(.1)
        time.sleep(1.5)
        check(1011, False)
        result = json.loads(output.read_text())
        expected = hashlib.sha256()
        for _ in range(BLOCKS): expected.update(PAYLOAD)
        assert result == {'bytes': len(PAYLOAD)*BLOCKS, 'sha256': expected.hexdigest()}, result
        assert peak-baseline < 48*1024*1024, ('Memory grew excessively', baseline, peak)
        assert max_latency < 1, ('Window stalled', max_latency)
        assert max_chars == 0 and samples > 50, (max_chars, samples)
        assert send(u.GetDlgItem(page,1098), 0x1004) == 1, 'One TCP connection must stay one row across progress updates'
        assert not (work/'pki'/'ca.json').exists(), 'Plain TCP monitoring must not create a CA'
        assert not u.IsWindowEnabled(u.GetDlgItem(page,1102)), 'HEX needs a selected body'
        listing = u.GetDlgItem(page,1098)
        send(listing, 0x100, 0x24)  # Home selects first session.
        deadline = time.monotonic()+8
        while 'STREAM-TEST' not in text(edit) and time.monotonic()<deadline: time.sleep(.1)
        assert text(edit) == '.STREAM-TEST\r\n\r\n', repr(text(edit))
        tabs = u.GetDlgItem(page,1099)
        # Native tab mouse input sends its standard selection notification.
        x, y = round(80*scale), round(12*scale)
        send(tabs,0x201,1,(y<<16)|x); send(tabs,0x202,0,(y<<16)|x)
        time.sleep(.3)
        detail = text(edit)
        assert 'Connection' not in detail and len(detail) > 60000, detail[:1500]
        assert 'per-exchange payload limit' in text(u.GetDlgItem(page,1101))
        views = u.GetDlgItem(page,1102)
        send(views,0x201,1,(y<<16)|x); send(views,0x202,0,(y<<16)|x)
        assert u.IsWindowVisible(u.GetDlgItem(page,1103)), 'Native HexView not shown'
        assert len(detail) < 400000, len(detail)
        screenshot(hwnd, work/'monitor-stream-load.png')
        send(page, 0x111, 1021, u.GetDlgItem(page, 1021))
        assert not text(edit), 'Clear did not empty the view'
        metrics = dict(result, samples=samples, maximum_characters=max_chars,
            baseline_private_bytes=baseline, peak_private_bytes=peak,
            maximum_response_seconds=max_latency)
        (work/'metrics.json').write_text(json.dumps(metrics, indent=2))
        print('PASS', work, json.dumps(metrics), flush=True)
    finally:
        if launch and launch.poll() is None: launch.terminate(); launch.wait(5)
        if process.poll() is None: process.terminate(); process.wait(5)
        origin.shutdown(); relay.shutdown()


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--client': client(int(sys.argv[2]), sys.argv[3])
    else: main()
