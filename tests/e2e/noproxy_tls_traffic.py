"""Exact NOPROXY MITM wire accounting with a local HTTPS origin.

Uses the existing trusted ProxyLane CA's public certificate only. No trust-store
changes. The disposable host skips verification of the test origin's certificate.
Counts upstream received ciphertext and downstream received ciphertext separately:
MITM's two TLS connections need not have identical record sizes.
"""
import argparse
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time

import quic_live_route_probe as route
import quic_mitm_probe as probe
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class TLS:
    def __init__(self, sock, context, server=False):
        self.sock = sock
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=server,
                                   server_hostname=None if server else probe.NAME)
        self.received = 0
        self.call(self.tls.do_handshake)

    def flush(self):
        while self.outgoing.pending:
            self.sock.sendall(self.outgoing.read())

    def call(self, fn, *args):
        while True:
            try:
                result = fn(*args)
                self.flush()
                return result
            except ssl.SSLWantReadError:
                self.flush()
                data = self.sock.recv(65536)
                if not data:
                    raise EOFError('unexpected TLS EOF')
                self.received += len(data)
                self.incoming.write(data)

    def send(self, data):
        for start in range(0, len(data), 16384):
            part = memoryview(data)[start:start + 16384]
            while part:
                part = part[self.call(self.tls.write, part):]

    def message(self):
        data = b''
        while b'\r\n\r\n' not in data:
            data += self.call(self.tls.read, 16384)
        head, body = data.split(b'\r\n\r\n', 1)
        size = int(next(line.split(b':', 1)[1] for line in head.split(b'\r\n')
                        if line.lower().startswith(b'content-length:')))
        while len(body) < size:
            part = self.call(self.tls.read, min(16384, size - len(body)))
            assert part, 'truncated body'
            body += part
        assert len(body) == size
        return head, body


def child(ip, port, ca, origin, size):
    assert input() == 'start'
    context = ssl.create_default_context(cafile=ca)
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    body = bytes(range(256)) * (size // 256) + b'x' * (size % 256)
    with socket.create_connection((ip, port), 20) as sock:
        peer = TLS(sock, context)
        assert peer.tls.getpeercert(binary_form=True) != Path(origin).read_bytes(), 'MITM not active'
        peer.send(f'POST /echo HTTP/1.1\r\nHost: {probe.NAME}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode() + body)
        head, response = peer.message()
        assert head.startswith(b'HTTP/1.1 200') and response == body + b'response-suffix17'
        peer.call(peer.tls.unwrap)
        print(json.dumps({'received_wire': peer.received, 'body': len(response)}), flush=True)


def origin(listener, context):
    sock, _ = listener.accept()
    with sock:
        sock.settimeout(30)
        peer = TLS(sock, context, True)
        head, body = peer.message()
        assert head.startswith(b'POST /echo HTTP/1.1')
        response = body + b'response-suffix17'
        peer.send(f'HTTP/1.1 200 OK\r\nContent-Length: {len(response)}\r\nConnection: close\r\n\r\n'.encode() + response)
        peer.call(peer.tls.unwrap)
        return peer.received


def run(runtime):
    probe.isolate()
    route.RUNTIME = runtime.resolve()
    with tempfile.TemporaryDirectory(prefix='tls-traffic-', dir=runtime) as tmp:
        work = Path(tmp)
        probe.origin_pki(work)
        cert = x509.load_pem_x509_certificate((work/'origin-cert.pem').read_bytes())
        (work/'origin.der').write_bytes(cert.public_bytes(serialization.Encoding.DER))
        # Export only the public certificate. The test never reads/decrypts the CA key.
        ca = json.loads((Path(os.environ['LOCALAPPDATA'])/'ProxyLane/ca.json').read_text())
        cert = x509.load_der_x509_certificate(base64.b64decode(ca['certificate']))
        (work/'ca.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(work/'origin-cert.pem', work/'origin-key.pem')
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        ip = next(ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith('127.'))
        host = route.Host(work)
        client = None
        try:
            host.call(type='test_tcp_policy', enabled=True)
            host.call(type='mitm_options', skip_upstream_verify=True)
            host.call(type='monitor_start', decrypt=True, quic=False)
            expected = {'upload': 0, 'download': 0}
            assert host.call(type='test_traffic') == expected
            with socket.socket() as listener, concurrent.futures.ThreadPoolExecutor(1) as pool:
                listener.bind(('0.0.0.0', 0))
                listener.listen()
                listener.settimeout(30)
                for size in (65537, 2 * 1024 * 1024):
                    result = pool.submit(origin, listener, context)
                    client = subprocess.Popen([sys.executable, __file__, 'child', ip,
                        str(listener.getsockname()[1]), str(work/'ca.pem'), str(work/'origin.der'), str(size)],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    assert host.call(type='attach', pid=client.pid)['result'] == 0xff01
                    output, error = client.communicate('start\n', timeout=60)
                    assert client.returncode == 0, error
                    row = json.loads(output)
                    expected['upload'] += result.result(timeout=10)
                    expected['download'] += row['received_wire']
                    # All TLS close_notify bytes have been consumed by the endpoints.
                    time.sleep(.3)
                    actual = host.call(type='test_traffic')
                    assert actual == expected, (actual, expected)
                    print(json.dumps({'request_body': size, 'response_body': row['body'],
                                      'expected': expected, 'actual': actual}), flush=True)
            records = host.call(type='poll', limit=512)
            (runtime/'tls-protocol.json').write_text(json.dumps(records, indent=2), encoding='utf8')
            host.call(type='monitor_stop')
            time.sleep(.3)
            assert host.call(type='test_traffic') == expected, 'duplicate late accounting'
        finally:
            if client and client.poll() is None:
                client.kill()
                client.wait()
            host.close()
            (runtime/'tls-host.log').write_bytes((work/'host.log').read_bytes())


if __name__ == '__main__':
    if sys.argv[1] == 'child':
        child(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], int(sys.argv[6]))
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('--runtime', type=Path, required=True)
        run(parser.parse_args().runtime)
