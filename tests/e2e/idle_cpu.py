"""Real injected idle TLS 1.2/1.3 + plaintext, resume/backpressure/half-close.

Uses a unique temporary CA (removed in finally) and localhost origins. CPU is
measured in the actual PRC host, including its Winsock notification worker.
"""
import argparse
import base64
import ctypes as c
from ctypes import wintypes as w
import datetime
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import time
import uuid

from mitm_e2e import Proxy, exact, start, free_port, unprotect
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

BLOCK = bytes(range(256)) * 256
BLOCKS = 128


class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        stream = self.server.context.wrap_socket(self.request, server_side=True) if self.server.context else self.request
        with stream:
            stream.settimeout(30)
            while True:
                command = exact(stream, 1)
                if command == b'\x00':
                    stream.sendall(b'ready')
                elif command == b'\x01':
                    for _ in range(BLOCKS): stream.sendall(BLOCK)
                elif command == b'\x02':
                    if not self.server.context:
                        assert stream.recv(1) == b''
                    stream.sendall(b'closed')
                    if self.server.context: stream.unwrap().close()
                    break
                else: raise AssertionError(command)


def gate(path):
    path.with_suffix('.ready').write_text('ready')
    deadline = time.monotonic() + 20
    while not path.exists():
        assert time.monotonic() < deadline, path
        time.sleep(.02)


def client(tls_port, plain_port, ca, work):
    streams = []
    try:
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(Path(ca).read_bytes()))
            context.minimum_version = context.maximum_version = version
            stream = context.wrap_socket(socket.create_connection(('203.0.113.10', tls_port), 10), server_hostname='idle.test')
            streams.append(stream)
        streams.append(socket.create_connection(('203.0.113.10', plain_port), 10))
        for stream in streams:
            stream.settimeout(20)
            stream.sendall(b'\x00'); assert exact(stream, 5) == b'ready'
        gate(work/'initial')
        for stream in streams:
            stream.sendall(b'\x01')
            # Stop reading long enough for the proxy's outgoing socket to block.
            time.sleep(.4)
            for _ in range(BLOCKS): assert exact(stream, len(BLOCK)) == BLOCK
        gate(work/'resumed')
        for stream in streams:
            stream.sendall(b'\x02')
            if not isinstance(stream, ssl.SSLSocket): stream.shutdown(socket.SHUT_WR)
            assert exact(stream, 6) == b'closed'
            if isinstance(stream, ssl.SSLSocket): stream.unwrap().close()
            else: assert stream.recv(1) == b''
        print('CLIENT_PASS idle, 24 MiB resume, backpressure, TLS shutdown and TCP half-close', flush=True)
    finally:
        for stream in streams: stream.close()


def cpu_seconds(process):
    values = [w.FILETIME() for _ in range(4)]
    api = c.windll.kernel32.GetProcessTimes
    api.argtypes = [w.HANDLE] + [c.POINTER(w.FILETIME)] * 4
    assert api(int(process._handle), *[c.byref(v) for v in values])
    return sum((v.dwHighDateTime << 32) | v.dwLowDateTime for v in values[2:]) / 1e7


def main():
    kernel = c.windll.kernel32
    kernel.GetModuleHandleW.argtypes = [w.LPCWSTR]
    kernel.GetModuleHandleW.restype = w.HMODULE
    for name in ('ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        module = kernel.GetModuleHandleW(name)
        if module:
            assert c.WinDLL(name, handle=module).gp_UnhookWinsock(), 'Isolate test controller'
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary-directory', default='build/idle-log-fix/bin')
    parser.add_argument('--tool-directory', default='build/idle-log-fix/tools')
    parser.add_argument('--baseline-hook')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = root/'build/qa'/('idle-cpu-'+uuid.uuid4().hex[:10]); work.mkdir(parents=True)
    runtime = work/'runtime'; runtime.mkdir()
    for dll in (root/args.binary_directory).glob('*.dll'): shutil.copy2(dll, runtime/dll.name)
    if args.baseline_hook: shutil.copy2(root/args.baseline_hook, runtime/'ProxyLaneHook64.dll')
    shutil.copy2(root/args.tool_directory/'mitm_host64.exe', runtime/'mitm_host64.exe')
    shutil.copy2(root/'build/tools/ProxyLaneMitm64.exe', runtime/'ProxyLaneMitm64.exe')
    env = dict(os.environ, PROXYLANE_MITM='0', PROXYLANE_MITM_HOME=str(work/'pki'),
               PROXYLANE_MITM_CRL_PORT=str(free_port()), PROXYLANE_PROTOCOL_CACHE_ROOT=str(work/'cache'),
               PROXYLANE_TEST_PROTOCOL='1', PROXYLANE_TEST_NO_PREVIEW='1')
    def ca(action):
        return json.loads(subprocess.check_output([str(runtime/'ProxyLaneMitm64.exe'), action], env=env, text=True))
    installed = False
    servers = []
    process = None
    try:
        ca('init'); installed = True; ca('install')
        stored = json.loads((work/'pki/ca.json').read_text())
        authority = x509.load_der_x509_certificate(base64.b64decode(stored['certificate']))
        key = serialization.load_der_private_key(unprotect(base64.b64decode(stored['protected_key'])), None)
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'idle.test')]))
                .issuer_name(authority.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('idle.test')]),False)
                .add_extension(x509.BasicConstraints(ca=False,path_length=None),True).sign(key,hashes.SHA256()))
        (work/'origin.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (work/'origin-key.pem').write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(work/'origin.pem',work/'origin-key.pem')
        relay, tls, plain = start(Proxy), start(Origin,context), start(Origin)
        servers = [relay,tls,plain]
        metrics = []
        for route in ('SOCKS5','HTTP11'):
            case = work/route;case.mkdir()
            command = [sys.executable,str(Path(__file__).resolve()),'client',str(tls.server_address[1]),
                       str(plain.server_address[1]),str(work/'pki/proxylane-ca.cer'),str(case)]
            with (case/'host.log').open('wb') as log:
                process = subprocess.Popen([str(runtime/'mitm_host64.exe'),str(relay.server_address[1]),route,
                                            subprocess.list2cmdline(command)],env=env,stdout=log,stderr=log)
                for phase in ('initial','resumed'):
                    deadline=time.monotonic()+25
                    while not (case/(phase+'.ready')).exists():
                        assert process.poll() is None and time.monotonic()<deadline, (case,process.poll())
                        time.sleep(.05)
                    time.sleep(.5)
                    cpu=cpu_seconds(process); start_time=time.monotonic()
                    time.sleep(6)
                    assert process.poll() is None, case
                    elapsed=time.monotonic()-start_time; cpu=cpu_seconds(process)-cpu
                    result=dict(route=route,phase=phase,seconds=elapsed,cpu_seconds=cpu,one_core_percent=cpu/elapsed*100)
                    metrics.append(result);print(json.dumps(result),flush=True)
                    (case/phase).write_text('continue')
                assert process.wait(15)==0, case
            output = (case/'host.log').read_text(errors='replace')
            assert 'CLIENT_PASS' in output,case
            assert '"decrypted":true' in output, 'Idle test must exercise MITM, not bypass TLS'
        (work/'metrics.json').write_text(json.dumps(metrics,indent=2))
        if not args.baseline_hook:
            assert max(m['one_core_percent'] for m in metrics)<5, metrics
        print('PASS' if not args.baseline_hook else 'BASELINE',work,flush=True)
    finally:
        if process and process.poll() is None:
            process.terminate();process.wait(5)
        for server in servers: server.shutdown();server.server_close()
        if installed:
            ca('remove')
            assert not ca('status')['trusted_current_user'], 'Test CA cleanup failed'


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='client':
        client(int(sys.argv[2]),int(sys.argv[3]),sys.argv[4],Path(sys.argv[5]))
    else: main()
