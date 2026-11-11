"""Injected TLS stop/resume using the existing trusted CA; no trust-store changes."""
import datetime
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import time
import uuid


def client(port, gate):
    def checkpoint(request, reply):
        Path(str(gate)+request).touch()
        deadline=time.monotonic()+20
        while not Path(str(gate)+reply).exists():
            assert time.monotonic()<deadline, reply
            time.sleep(.02)

    def connect():
        context=ssl._create_unverified_context()
        context.set_alpn_protocols(['http/1.1'])
        return context.wrap_socket(socket.create_connection(('203.0.113.10',port),timeout=15),server_hostname='mitm.test')

    def request(s, path, size):
        payload=(b'captured-only-when-enabled-'*((size//27)+1))[:size]
        s.sendall(f'POST {path} HTTP/1.1\r\nHost: mitm.test\r\nContent-Length: {len(payload)}\r\n\r\n'.encode()+payload)
        stream=s.makefile('rb')
        assert stream.readline().startswith(b'HTTP/1.1 200')
        length=0
        while True:
            line=stream.readline()
            if line==b'\r\n':break
            if line.lower().startswith(b'content-length:'):length=int(line.split(b':')[1])
        assert stream.read(length)==payload
        stream.close()

    original=ssl.PEM_cert_to_DER_cert((gate.parent/'origin.pem').read_text())
    with connect() as existing:
        assert existing.getpeercert(binary_form=True)!=original, 'monitoring must perform configured MITM'
        request(existing,'/before-stop',128)
        checkpoint('.stop','.stopped')
        request(existing,'/while-stopped',512*1024)
        with connect() as created_while_stopped:
            assert created_while_stopped.getpeercert(binary_form=True)==original, "stopped monitoring must preserve the server certificate on new connections"
            request(created_while_stopped,'/new-while-stopped',128)
            checkpoint('.resume','.resumed')
            request(existing,'/old-after-resume',512*1024)
            request(created_while_stopped,'/uncaptured-after-resume',128)
            checkpoint('.check','.new')
            with connect() as fresh:
                assert fresh.getpeercert(binary_form=True)!=original, 'resumed monitoring must restore requested MITM'
                request(fresh,'/fresh-after-resume',256)


def main():
    import ctypes
    kernel=ctypes.windll.kernel32
    kernel.GetModuleHandleW.argtypes=[ctypes.c_wchar_p];kernel.GetModuleHandleW.restype=ctypes.c_void_p
    for name in ('ProxyLaneHook64.dll','ProxyLaneHook32.dll'):
        module=kernel.GetModuleHandleW(name)
        if module:
            inherited=ctypes.WinDLL(name,handle=module)
            assert inherited.gp_UnhookWinsock(), 'isolate the test controller only'
    from http.server import BaseHTTPRequestHandler
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from mitm_e2e import start, Proxy, free_port
    root=Path(__file__).resolve().parents[2]
    work=root/'build/qa'/('monitor-stop-'+uuid.uuid4().hex[:12]);work.mkdir(parents=True)
    for name in ('ProxyLaneHook32.dll','ProxyLaneHook64.dll','ProxyLaneMitm64.dll'):
        shutil.copy2(root/'bin'/name,work/name)
    shutil.copy2(root/'build/tools/mitm_host64.exe',work/'mitm_host64.exe')
    key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'mitm.test')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
          .not_valid_after(now+datetime.timedelta(hours=1)).sign(key,hashes.SHA256()))
    (work/'origin.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (work/'origin-key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(work/'origin.pem',work/'origin-key.pem')
    context.set_alpn_protocols(['http/1.1'])
    class Echo(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def setup(self):
            self.request=self.server.context.wrap_socket(self.request,server_side=True)
            super().setup()
        def finish(self):
            try:super().finish()
            finally:self.connection.close()
        def log_message(self,*args):pass
        def do_POST(self):
            body=self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
            self.wfile.write(body);self.wfile.flush()
    origin=start(Echo,context);proxy=start(Proxy)
    gate=work/'gate'
    ca=Path(os.environ['LOCALAPPDATA'])/'ProxyLane'
    ca_snapshot=(ca/'ca.json').read_bytes()
    env=dict(os.environ,PROXYLANE_MITM='0',PROXYLANE_MITM_HOME=str(ca),
        PROXYLANE_MITM_CRL_PORT=str(free_port()),PROXYLANE_TEST_PROTOCOL='1',PROXYLANE_TEST_SKIP_UPSTREAM='1',
        PROXYLANE_PROTOCOL_CACHE_ROOT=str(work/'cache'),PROXYLANE_TEST_MONITOR_STOP=str(gate))
    command=[sys.executable,str(Path(__file__).resolve()),'--client',str(origin.server_address[1]),str(gate)]
    try:
        result=subprocess.run([str(work/'mitm_host64.exe'),str(proxy.server_address[1]),'SOCKS5',subprocess.list2cmdline(command)],
            cwd=work,env=env,capture_output=True,timeout=60)
        (work/'host.stdout').write_bytes(result.stdout);(work/'host.stderr').write_bytes(result.stderr)
        assert result.returncode==0,(result.returncode,result.stderr.decode(errors='replace'),work)
        rows=[]
        for line in result.stdout.splitlines():
            if line.startswith(b'PROTOCOL_JSON '):rows.extend(json.loads(line[len(b'PROTOCOL_JSON '):]).get('records',[]))
        paths=[row['exchange']['request']['target'] for row in rows if row['type']=='exchange']
        assert paths==['/before-stop','/fresh-after-resume'],paths
        assert not list((work/'cache').glob('run-*')),'exit must clean retained payloads'
        print('PASS injected TLS: same-connection duplex transfer, frozen analysis/cache, disabled new connections, safe resume and cleanup',work)
    finally:
        origin.shutdown();proxy.shutdown();origin.server_close();proxy.server_close()
        assert (ca/'ca.json').read_bytes()==ca_snapshot, 'existing CA identity must remain unchanged'


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--client':client(int(sys.argv[2]),Path(sys.argv[3]))
    else:main()
