"""Exercise real injected UDP routes and the datagram viewer.

Uses a unique profile and localhost SOCKS relay, or --direct with no relay,
without CA or user settings changes. Verifies multiple UDP routes/sockets,
zero-length datagrams and Raw/HexView; --dns-quic checks protocol reconstruction.
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

class GUIThreadInfo(c.Structure):
    _fields_=[('cbSize',w.DWORD),('flags',w.DWORD)]+[(name,w.HWND) for name in
        ('hwndActive','hwndFocus','hwndCapture','hwndMenuOwner','hwndMoveSize','hwndCaret')]+[('rcCaret',w.RECT)]
u.GetGUIThreadInfo.argtypes=[w.DWORD,c.POINTER(GUIThreadInfo)]

def assert_raw_caret(edit):
    info=GUIThreadInfo();info.cbSize=c.sizeof(info)
    thread=u.GetWindowThreadProcessId(edit,None)
    assert u.GetGUIThreadInfo(thread,c.byref(info))
    assert info.hwndFocus==edit and info.hwndCaret==edit, 'Raw must own focus and the native caret'
    rect=w.RECT();u.GetClientRect(edit,c.byref(rect))
    assert 0<=info.rcCaret.left<info.rcCaret.right<=rect.right and 0<=info.rcCaret.top<info.rcCaret.bottom<=rect.bottom, 'Raw caret must be visible in the viewport'

PAYLOAD = bytes(range(256)) * 64
BLOCKS = 8192


def client(ports, output, analysis=False, host='203.0.113.10', live=False):
    if analysis:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(10)
            for ident,name in [(1,'a.test'),(2,'missing.test')]:
                query=ident.to_bytes(2,'big')+bytes.fromhex('01000001000000000000')
                query+=b''.join(bytes([len(p)])+p.encode() for p in name.split('.'))+b'\x00\x00\x01\x00\x01'
                stream.sendto(query,(host,ports[0]))
                response=stream.recvfrom(65535)[0];assert response[2]&128
        root=Path(__file__).resolve().parents[1]
        for rfc in (9001,9369):
            payload=bytes.fromhex((root/f'src/ProxyLaneMitm/testdata/rfc{rfc}-client-initial.hex').read_text())
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
                stream.settimeout(10);stream.sendto(payload,(host,ports[1]))
                assert stream.recvfrom(65535)[0]==payload
        Path(output).write_text(json.dumps({'pid':os.getpid(),'dns':2,'quic':2}))
        return
    received = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(10)
        for port in ports:
            for payload in (b'\x00ONE', b'TWO', b''):
                stream.sendto(payload, (host,port))
                result, _ = stream.recvfrom(65535)
                assert result == payload, (result,payload)
                received.append(result.hex())
                if live and len(received)==1:
                    Path(output+'.ready').touch()
                    deadline=time.monotonic()+30
                    while not Path(output+'.continue').exists():
                        assert time.monotonic()<deadline, 'Viewer did not release live client'
                        time.sleep(.05)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(10); stream.sendto(b'THREE', (host,ports[0]))
        assert stream.recvfrom(65535)[0] == b'THREE'
    Path(output).write_text(json.dumps({'pid':os.getpid(), 'received':received}))

class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        payload, connection = self.request
        if len(payload)>12 and payload[2:12]==bytes.fromhex('01000001000000000000'):
            missing=b'missing' in payload
            payload=payload[:2]+(bytes.fromhex('81830001000000000000') if missing else bytes.fromhex('81800001000100000000'))+payload[12:]
            if not missing: payload+=bytes.fromhex('c00c000100010000003c000401020304')
        connection.sendto(payload,self.client_address)


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
    parser.add_argument('--dns-quic', action='store_true')
    parser.add_argument('--direct', action='store_true')
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root/'tests/e2e'))
    from mitm_e2e import Proxy, start
    k.GetModuleHandleW.argtypes = [w.LPCWSTR]; k.GetModuleHandleW.restype = w.HMODULE
    module = k.GetModuleHandleW('ProxyLaneHook64.dll')
    if module: assert c.WinDLL('ProxyLaneHook64.dll', handle=module).gp_UnhookWinsock()
    u.SetProcessDPIAware()
    import threading
    from ProxyLaneSecureE2ETests import local_ipv4
    target_host = local_ipv4() if args.direct else '203.0.113.10'
    origins = [socketserver.ThreadingUDPServer((target_host if args.direct else '127.0.0.1',0), Origin) for _ in range(2)]
    for server in origins: threading.Thread(target=server.serve_forever,daemon=True).start()
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1',0)); relay_port = reservation.getsockname()[1]
    unique = uuid.uuid4().hex[:10]
    work = root/'build/qa'/('monitor-udp-'+unique); work.mkdir()
    source = (root/args.binary_directory).resolve()
    for pattern in ('ProxyLane*.exe', 'ProxyLane*.dll'):
        for path in source.glob(pattern): shutil.copy2(path, work/path.name)
    profile = 'MonitorLoad'+unique
    config = (root/'examples/ProxyLane.ini').read_text().replace('lastselected=Test', 'lastselected='+profile).replace('[proxy_Test]', '[proxy_'+profile+']')
    config = config.replace('Port=1080', 'Port='+str(relay_port))
    config = config.replace('[options]', '[options]\nlanguage=zh-CN').replace('HookUDP=0','HookUDP=1').replace('BlockUDP=1','BlockUDP=0')
    if args.direct:
        config = config.replace('Type=SOCKS5', 'Type=NOPROXY').replace('Host=127.0.0.1', 'Host=')
        config = config.replace('Port='+str(relay_port), 'Port=')
        config = config.replace('[options]', '[options]\nHookLanIP=1')
        config = config.replace('dnsOpt=1', 'dnsOpt=0\nRedirectPrivateDNS=0')
    (work / 'portable.flag').touch()
    (work/'ProxyLane.ini').write_text(config)
    env = dict(os.environ, PROXYLANE_MITM='0', PROXYLANE_MITM_HOME=str(work/'pki'), PROXYLANE_PROTOCOL_CACHE_ROOT=str(work/'cache'),
        PROXYLANE_PROTOCOL_ENTRY_BYTES=str(1024*1024), PROXYLANE_PROTOCOL_TOTAL_BYTES=str(2*1024*1024))
    relay = None if args.direct else subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--relay', str(relay_port), str(work/'relay.log')])
    time.sleep(.5)
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
        if args.direct:
            proxy = pages['proxy']
            # Loading an endpoint-free profile must retain both the type and UDP.
            assert text(u.GetDlgItem(proxy,1001)) == 'NOPROXY'
            for ident in (1005,1002,1003,1004,1068,1070):
                assert not u.IsWindowEnabled(u.GetDlgItem(proxy,ident)), ident
            assert text(u.GetDlgItem(proxy,1005)) == ''
            assert text(u.GetDlgItem(proxy,1002)) == ''
            udp = u.GetDlgItem(proxy,1013)
            assert u.IsWindowEnabled(udp) and send(udp,0xF0)==1
            assert text(udp) == '接管 UDP'
            # Save into the existing profile; the subsequent --auto process
            # reloads it independently before injecting the test client.
            send(proxy,0x111,1052,u.GetDlgItem(proxy,1052))
            screenshot(hwnd,work/'noproxy-settings.png')
        send(pages['proxy'], 0x111, 1, u.GetDlgItem(pages['proxy'], 1))
        time.sleep(.5)
        activate(3); check(1011, True)
        baseline = memory(process)
        output = work/'client-result.json'
        launch = subprocess.Popen([str(work/'ProxyLane64.exe'), '--auto', '--profile', profile,
            '--run', sys.executable, '--', str(Path(__file__).resolve()),
            '--client', ','.join(str(server.server_address[1]) for server in origins), str(output),
            'analysis' if args.dns_quic else 'raw', target_host, 'live' if args.live else 'batch'], cwd=work, env=env)
        peak = baseline; max_chars = 0; max_latency = 0; samples = 0
        deadline = time.monotonic()+75
        while not output.exists():
            error = output.with_suffix('.error.txt')
            assert not error.exists(), error.read_text() if error.exists() else ''
            assert process.poll() is None and time.monotonic()<deadline, 'Transfer did not finish'
            activate(3)
            began = time.perf_counter(); send(hwnd, 0)
            max_latency = max(max_latency, time.perf_counter()-began)
            chars = send(edit, 0xE); max_chars = max(max_chars, chars)
            assert chars <= 65536 if args.live else chars == 0, ('Preview exceeded expected size', chars)
            if args.live and Path(str(output)+'.ready').exists() and not Path(str(output)+'.continue').exists():
                listing=u.GetDlgItem(page,1098)
                if send(listing,0x1004):
                    send(listing,0x100,0x24)
                    if '.ONE' in text(edit):
                        assert 'TWO' not in text(edit)
                        send(edit,0xB1,1,3)
                        views=u.GetDlgItem(page,1102)
                        x,y=round(80*scale),round(12*scale)
                        send(views,0x201,1,(y<<16)|x);send(views,0x202,0,(y<<16)|x)
                        Path(str(output)+'.continue').touch()
            peak = max(peak, memory(process)); samples += 1
            time.sleep(.1)
        time.sleep(1.5)
        if args.live:
            deadline=time.monotonic()+8
            while 'TWO' not in text(edit) and time.monotonic()<deadline:time.sleep(.1)
            assert '.ONE' in text(edit) and 'TWO' in text(edit), 'Live Raw did not accumulate packets'
            assert send(edit,0xB0)==((3<<16)|1), 'Live refresh replaced the selection'
            assert not u.IsWindowVisible(edit) and u.IsWindowVisible(u.GetDlgItem(page,1103)), 'Live background Raw update must not overlap HexView'
            views=u.GetDlgItem(page,1102);x,y=round(25*scale),round(12*scale)
            send(views,0x201,1,(y<<16)|x);send(views,0x202,0,(y<<16)|x)
        check(1011, False)
        result = json.loads(output.read_text())
        if args.dns_quic:
            validate_analysis(page,edit,hwnd,scale,work)
            assert not (work/'pki'/'ca.json').exists()
            print('PASS', 'NOPROXY' if args.direct else 'SOCKS5', 'DNS/QUIC injected GUI',work,json.dumps(result),flush=True)
            return
        assert result['received'] == ['004f4e45','54574f','']*2, result
        listing = u.GetDlgItem(page,1098)
        assert send(listing,0x1004) == 3, 'UDP routes/sockets must stay separate sessions'
        assert not (work/'pki'/'ca.json').exists()
        send(listing,0x100,0x24)
        expected='.ONETWO'
        deadline = time.monotonic()+8
        while text(edit) != expected and time.monotonic()<deadline: time.sleep(.1)
        assert text(edit) == expected, repr(text(edit))
        assert not u.GetDlgItem(page,1106) and not u.GetDlgItem(page,1110), 'No packet navigation controls'
        views = u.GetDlgItem(page,1102)
        def raw():
            x,y = round(25*scale),round(12*scale)
            send(views,0x201,1,(y<<16)|x); send(views,0x202,0,(y<<16)|x)
        send(edit,0xB1,4,4)
        assert u.IsWindowVisible(edit) and not u.IsWindowVisible(u.GetDlgItem(page,1103)), 'Raw selection must stay in Raw'
        assert send(edit,0xB0)==((4<<16)|4), 'Second datagram start'
        assert '#2' in text(u.GetDlgItem(page,1101)), 'Raw click packet status'
        screenshot(hwnd,work/'monitor-udp-raw.png')
        raw()
        deadline = time.monotonic()+8
        while text(edit) != expected and time.monotonic()<deadline: time.sleep(.1)
        assert text(edit) == expected, repr(text(edit))
        x,y = round(80*scale),round(12*scale)
        send(views,0x201,1,(y<<16)|x);send(views,0x202,0,(y<<16)|x)
        hexview=u.GetDlgItem(page,1103)
        assert u.IsWindowVisible(hexview)
        assert '#2' in text(u.GetDlgItem(page,1101)) and 'Offset 0x0' in text(u.GetDlgItem(page,1101)), 'Raw packet selection transfers to HexView'
        send(hexview,0x100,0x23) # End: last row is an empty datagram.
        assert '#3' in text(u.GetDlgItem(page,1101)), 'Empty datagram accessible in cumulative HexView'
        assert 'Offset 0x0' in text(u.GetDlgItem(page,1101))
        raw()
        assert send(edit,0xB0)==((7<<16)|7), 'Empty Hex packet locates Raw insertion point'
        assert_raw_caret(edit)
        x,y=round(80*scale),round(12*scale)
        send(views,0x201,1,(y<<16)|x);send(views,0x202,0,(y<<16)|x)
        assert '#3' in text(u.GetDlgItem(page,1101)), 'Empty packet round trip'
        send(hexview,0x100,0x26) # Up: second datagram has its own row and offset.
        assert '#2' in text(u.GetDlgItem(page,1101))
        screenshot(hwnd,work/'monitor-udp-hex-packets.png')
        raw()
        time.sleep(.6);assert text(edit)==expected, 'Empty packet must not insert text'
        # Receive direction has its own datagram selection.
        tabs = u.GetDlgItem(page,1099); x,y = round(80*scale),round(12*scale)
        send(tabs,0x201,1,(y<<16)|x); send(tabs,0x202,0,(y<<16)|x)
        time.sleep(.2); assert text(edit) == expected
        send(edit,0xB1,4,4)
        raw()
        deadline = time.monotonic()+8
        while text(edit) != expected and time.monotonic()<deadline: time.sleep(.1)
        assert text(edit) == expected
        views = u.GetDlgItem(page,1102)
        send(views,0x201,1,(y<<16)|x); send(views,0x202,0,(y<<16)|x)
        assert u.IsWindowVisible(u.GetDlgItem(page,1103))
        screenshot(hwnd,work/'monitor-udp.png')
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
        if relay and relay.poll() is None: relay.terminate(); relay.wait(5)
        for server in origins: server.shutdown(); server.server_close()


def validate_analysis(page,edit,hwnd,scale,work):
    listing=u.GetDlgItem(page,1098);kind=u.GetDlgItem(page,1105)
    assert send(listing,0x1004)==4, 'Two DNS transactions and two QUIC connections expected'
    def protocol(index,count):
        send(kind,0x14e,index);send(page,0x111,(1<<16)|1105,kind)
        assert send(listing,0x1004)==count
        send(listing,0x100,0x24)
    def wait_text(needle):
        deadline=time.monotonic()+8
        while needle not in text(edit) and time.monotonic()<deadline:time.sleep(.1)
        assert needle in text(edit),(needle,text(edit))
    def tab(ident,index):
        h=u.GetDlgItem(page,ident);x,y=round((25+55*index)*scale),round(12*scale)
        send(h,0x201,1,(y<<16)|x);send(h,0x202,0,(y<<16)|x)
    protocol(5,2);wait_text('a.test.');assert not u.IsWindowVisible(u.GetDlgItem(page,1106))
    tab(1099,1);wait_text('1.2.3.4');assert '60 IN A' in text(edit)
    screenshot(hwnd,work/'monitor-dns.png')
    tab(1102,1);assert u.IsWindowVisible(u.GetDlgItem(page,1103));tab(1102,0)
    send(listing,0x100,0x28);wait_text('NXDOMAIN');assert 'missing.test.' in text(edit)
    protocol(6,2);wait_text('example.com');assert 'Application payload: encrypted' in text(edit)
    assert 'QUIC v1' in text(edit) and 'Client-offered ALPN: alpn' in text(edit)
    assert not u.IsWindowVisible(u.GetDlgItem(page,1106))
    send(listing,0x100,0x28);wait_text('QUIC v2')
    screenshot(hwnd,work/'monitor-quic.png')
    tab(1102,1);assert u.IsWindowVisible(u.GetDlgItem(page,1103))


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--client':
        try:
            client([int(v) for v in sys.argv[2].split(',')],sys.argv[3],len(sys.argv)>4 and sys.argv[4]=='analysis',sys.argv[5] if len(sys.argv)>5 else '203.0.113.10',len(sys.argv)>6 and sys.argv[6]=='live')
        except Exception:
            import traceback
            Path(sys.argv[3]).with_suffix('.error.txt').write_text(traceback.format_exc())
            raise
    elif len(sys.argv)>1 and sys.argv[1]=='--relay':
        import struct
        from types import SimpleNamespace
        sys.path.insert(0,str(Path(__file__).resolve().parent/'e2e'))
        from socks5_udp_server import Server
        Server.frame = staticmethod(lambda source,payload: b'\x00\x00\x00\x01'+socket.inet_aton('203.0.113.10')+struct.pack('!H',source[1])+payload)
        Server(SimpleNamespace(host='127.0.0.1',port=int(sys.argv[2]),log=sys.argv[3],username=None,
            password=None,inject_forged=False,inject_malformed=False,delay_ms=0,quiet_packets=False)).run()
    else: main()
