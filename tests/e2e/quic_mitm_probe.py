"""Independent aioquic peers -> Rust h3 MITM -> shipping Hook -> SOCKS5 UDP.

Run after scripts/build-quic-probe.ps1. Uses a COPY of the current CA, never
changes trust or user profiles. All binaries, profiles and diagnostics live in
build. Network targets are locally controlled. No HTTP/2 fallback counts as h3.
"""
import argparse
import asyncio
import base64
import ctypes
import datetime
import hashlib
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
import importlib.metadata

# Keep newer protocol-test dependencies out of the user's Python environment.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'build'/'quic-probe'/'python'))

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NAME = 'quic-probe.test'
MARKER = b'ProxyLane QUIC MITM HTTP/3 verified\n'


def isolate():
    api = ctypes.windll.kernel32.GetModuleHandleW
    api.argtypes = [ctypes.c_wchar_p]
    api.restype = ctypes.c_void_p
    for name in ('ProxyLaneHook64.dll', 'ProxyLaneHook32.dll'):
        if api(name):
            if not ctypes.WinDLL(name).gp_UnhookWinsock():
                raise RuntimeError('Cannot isolate test runner from inherited Hook')


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def origin_pki(work):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'QUIC probe isolated origin')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .sign(key, hashes.SHA256()))
    leafkey = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAME)]))
            .issuer_name(name).public_key(leafkey.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(NAME)]), False)
            .sign(key, hashes.SHA256()))
    (work/'origin-ca.der').write_bytes(ca.public_bytes(serialization.Encoding.DER))
    (work/'origin-cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (work/'origin-key.pem').write_bytes(leafkey.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


class Peer(QuicConnectionProtocol):
    def __init__(self, *args, origin=False, events=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.origin = origin
        self.events = events if events is not None else []
        self.streams = {}
        self.waiters = {}

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.events.append({'event': 'handshake', 'alpn': event.alpn_protocol})
        if isinstance(event, ConnectionTerminated):
            for waiter in self.waiters.values():
                if not waiter.done():
                    waiter.set_exception(ConnectionError(str(event)))
        for item in self.h3.handle_event(event):
            if not isinstance(item, (HeadersReceived, DataReceived)):
                continue
            state = self.streams.setdefault(item.stream_id, {'headers': [], 'body': bytearray()})
            if isinstance(item, HeadersReceived):
                state['headers'] += item.headers
            else:
                state['body'].extend(item.data)
                if len(state['body']) > 8 * 1024 * 1024:
                    self.close(error_code=0x107, reason_phrase='probe cap')
                    continue
            if item.stream_ended:
                if self.origin:
                    method = dict(state['headers'])[b':method']
                    body = bytes(state['body']) if method == b'POST' else MARKER
                    self.events.append({'event': 'request', 'method': method.decode(), 'bytes': len(body),
                        'path': dict(state['headers'])[b':path'].decode()})
                    self.h3.send_headers(item.stream_id, [(b':status', b'200'), (b'content-length', str(len(body)).encode()),
                        (b'x-proxylane-origin', b'aioquic'), (b'content-type', b'text/plain')])
                    self.h3.send_data(item.stream_id, body, end_stream=True)
                    self.transmit()
                    del self.streams[item.stream_id]
                else:
                    # Deliberately malformed/cancelled streams can receive a terminal
                    # response without having a request() waiter.
                    waiter = self.waiters.get(item.stream_id)
                    if waiter is not None and not waiter.done():
                        waiter.set_result(state)

    async def request(self, method, body=b'', index=0, timeout=18):
        stream = self._quic.get_next_available_stream_id()
        waiter = self.waiters[stream] = asyncio.get_running_loop().create_future()
        self.h3.send_headers(stream, [(b':method', method.encode()), (b':scheme', b'https'),
            (b':authority', NAME.encode()), (b':path', f'/probe?index={index}'.encode()),
            (b'content-length', str(len(body)).encode())])
        self.h3.send_data(stream, body, end_stream=True)
        self.transmit()
        try:
            return await asyncio.wait_for(waiter, timeout)
        finally:
            self.waiters.pop(stream, None)
            self.streams.pop(stream, None)


async def client_case(listen, ca, leaf_hash, name=NAME, batch=True):
    config = QuicConfiguration(is_client=True, alpn_protocols=['h3'], server_name=name,
                               idle_timeout=5, supported_versions=[1])
    # Explicit isolated roots: negative case must never inherit Windows trust.
    cert = x509.load_der_x509_certificate(ca)
    config.load_verify_locations(cadata=cert.public_bytes(serialization.Encoding.PEM))
    async with connect('127.0.0.1', listen, configuration=config, create_protocol=Peer) as peer:
        fingerprint = peer._quic.tls._peer_certificate.fingerprint(hashes.SHA256()).hex()
        assert fingerprint == leaf_hash, 'client did not see the MITM leaf'
        payloads = [b'', b'QUIC POST payload', bytes(range(256))*4096] if batch else [b'']
        if batch:
            payloads += [f'parallel-{i}'.encode()*100 for i in range(8)]
        replies = await asyncio.gather(*(peer.request('POST' if body else 'GET', body, i)
                                        for i, body in enumerate(payloads)))
        for body, reply in zip(payloads, replies):
            assert dict(reply['headers'])[b':status'] == b'200'
            assert dict(reply['headers'])[b'x-proxylane-origin'] == b'aioquic'
            assert bytes(reply['body']) == (body or MARKER)
        return {'requests': len(replies), 'large_echo_bytes': max(map(len, payloads)),
                'leaf_sha256': fingerprint, 'alpn': 'h3', 'body_integrity': True}


class Processes:
    def __init__(self, work):
        self.work, self.items, self.files = work, [], []

    def start(self, name, command):
        output = open(self.work/(name+'.log'), 'wb')
        self.files.append(output)
        env = dict(os.environ, PROXYLANE_MITM='0')
        # Probes do not inherit generic shell proxy choices.
        for key in list(env):
            if key.lower() in ('http_proxy','https_proxy','all_proxy'):
                del env[key]
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, env=env,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        self.items.append(process)
        return process

    def stop(self, process):
        if process.poll() is None:
            # Exact test-owned PID and its descendants, never executable-name kills.
            subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'], capture_output=True)
            process.wait(timeout=10)

    def close(self):
        for p in reversed(self.items):
            self.stop(p)
        for f in self.files:
            f.close()


async def wait_ready(path, process):
    for _ in range(300):
        if path.exists():
            try:
                return json.loads(path.read_text())
            except json.JSONDecodeError:
                pass
        if process.poll() is not None:
            raise RuntimeError(f'probe exited {process.returncode}: {path}')
        await asyncio.sleep(.05)
    raise TimeoutError(f'probe not ready: {path}')


def events(path):
    result = []
    for line in path.read_text(errors='replace').splitlines():
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                result.append(item)
        except ValueError:
            pass
    return result


async def browsers(work, processes, listen, mitm_log):
    result = []
    paths = {'chrome': Path(r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'),
             'edge': Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'),
             'firefox': Path(r'C:\Program Files\Mozilla Firefox\firefox.exe')}
    for name, exe in paths.items():
        if not exe.exists():
            result.append({'browser': name, 'result': 'not installed'})
            continue
        for mode in (['normal','force-quic'] if name != 'firefox' else ['normal','allow-third-party-root']):
            label = name+'-'+mode
            profile = work/label
            profile.mkdir()
            url = f'https://{NAME}:{listen}/browser-start?name={label}'
            if name == 'firefox':
                prefs = {'network.dns.localDomains': NAME, 'security.enterprise_roots.enabled': True,
                         'network.proxy.type': 0, 'network.http.http3.enable': True,
                         'browser.shell.checkDefaultBrowser': False, 'browser.startup.homepage_override.mstone': 'ignore',
                         'datareporting.policy.dataSubmissionEnabled': False}
                if mode == 'allow-third-party-root':
                    prefs['network.http.http3.disable_when_third_party_roots_found'] = False
                (profile/'user.js').write_text('\n'.join('user_pref(%s, %s);' % (json.dumps(k),json.dumps(v)) for k,v in prefs.items()))
                command = [str(exe),'-headless','-no-remote','-profile',str(profile),url]
            else:
                command = [str(exe),'--headless=new','--no-first-run','--no-default-browser-check',
                           '--disable-background-networking','--disable-component-update','--no-proxy-server',
                           '--enable-quic',f'--user-data-dir={profile}',
                           f'--host-resolver-rules=MAP {NAME} 127.0.0.1',
                           f'--log-net-log={profile}/netlog.json',url]
                if mode == 'force-quic':
                    command.insert(-1,f'--origin-to-force-quic-on={NAME}:{listen}')
            before = len(events(mitm_log))
            p = processes.start(label,command)
            await asyncio.sleep(12)
            processes.stop(p)
            new = events(mitm_log)[before:]
            h3 = [e for e in new if e.get('event') == 'request' and e.get('role') == 'mitm']
            tcp = [e for e in new if e.get('event') == 'tcp_bootstrap']
            evidence = {'browser':name,'mode':mode,'h3_requests':len(h3), 'tcp_requests':len(tcp),
                        'quic_decrypted':bool(h3),'certificate_errors_ignored':False}
            netlog = profile/'netlog.json'
            if netlog.exists():
                # Chromium is test-owned and force-closed: finish its streaming JSON.
                text = netlog.read_text(errors='replace')
                try:
                    data = json.loads(text)
                except ValueError:
                    data = json.loads(text.rstrip().rstrip(',')+']}')
                names = {v:k for k,v in data['constants']['logEventTypes'].items()}
                target_sources = {e['source']['id'] for e in data['events']
                    if 'QUIC' in names.get(e['type'],'') and e.get('params',{}).get('host') == NAME}
                evidence['client_info'] = data['constants'].get('clientInfo',{})
                evidence['quic_proof_errors'] = [e.get('params',{}) for e in data['events']
                    if e['source']['id'] in target_sources and 'QUIC' in names.get(e['type'],'')
                    and any(k in e.get('params',{}) for k in ('net_error','details','quic_error'))]
            result.append(evidence)
            print(label, {k:v for k,v in evidence.items() if k not in ('client_info','quic_proof_errors')},flush=True)
    return result


async def main(args):
    isolate()
    root = Path(__file__).resolve().parents[2]
    work = root/'build'/'qa'/('quic-mitm-'+uuid.uuid4().hex[:12])
    work.mkdir(parents=True)
    print('WORK',work,flush=True)
    runtime = root/'build'/'quic-probe'
    pki = work/'mitm-pki'
    pki.mkdir()
    shutil.copy2(Path(os.environ['LOCALAPPDATA'])/'ProxyLane'/'ca.json',pki/'ca.json')
    ca = base64.b64decode(json.loads((pki/'ca.json').read_text())['certificate'])
    origin_pki(work)
    origin_events = []
    oc = QuicConfiguration(is_client=False, alpn_protocols=['h3'], supported_versions=[1])
    oc.load_cert_chain(str(work/'origin-cert.pem'), str(work/'origin-key.pem'))
    origin_port, relay_port = port(), port()
    origin = await serve('0.0.0.0',origin_port,configuration=oc,
                         create_protocol=lambda *a,**kw: Peer(*a,origin=True,events=origin_events,**kw))
    processes = Processes(work)
    results = {'work': str(work), 'cases': [], 'browsers': [], 'origin_port': origin_port,
               'aioquic':importlib.metadata.version('aioquic')}
    try:
        relay = processes.start('socks',[sys.executable,str(root/'tests/e2e/socks5_udp_server.py'),
            '--port',str(relay_port),'--log',str(work/'relay.log')])
        for _ in range(100):
            if (work/'relay.log').exists() and 'LISTEN' in (work/'relay.log').read_text():
                break
            await asyncio.sleep(.05)
        else:
            raise RuntimeError('SOCKS relay not ready')
        # Direct baseline, numeric UDP through real Hook, remote DNS domain route.
        lan_ip = next(ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith('127.'))
        for route, target in [('direct',f'127.0.0.1:{origin_port}'),
                              ('noproxy',f'{lan_ip}:{origin_port}'),
                              ('socks-ip',f'203.0.113.10:{origin_port}'),
                              ('socks-domain',f'origin.quic.test:{origin_port}'),
                              ('upstream-untrusted',f'127.0.0.1:{origin_port}'),
                              ('socks-unavailable',f'{lan_ip}:{origin_port}')]:
            listen = port()
            config = {'role':'mitm','listen':f'127.0.0.1:{listen}', 'ca_directory':str(pki),'name':NAME,
                      'upstream':target,'upstream_ca':str(work/'origin-ca.der'),
                      'ready':str(work/(route+'.ready.json')),'stop':str(work/(route+'.stop'))}
            config_file = work/(route+'.json')
            if route == 'upstream-untrusted':
                config['upstream_ca'] = str(pki/'proxylane-ca.cer')
            config_file.write_text(json.dumps(config))
            command = [str(runtime/'quic-probe.exe'),str(config_file)]
            if route not in ('direct','upstream-untrusted'):
                command = [str(runtime/'route-host.exe'),'NOPROXY' if route == 'noproxy' else 'SOCKS5',
                           str(port() if route == 'socks-unavailable' else relay_port),subprocess.list2cmdline(command)]
            p = processes.start(route,command)
            meta = await wait_ready(Path(config['ready']),p)
            if route in ('upstream-untrusted','socks-unavailable'):
                before = len(origin_events)
                try:
                    await asyncio.wait_for(client_case(listen,ca,meta['certificate_sha256'],batch=False),12)
                except (ConnectionError,TimeoutError):
                    pass
                else:
                    raise AssertionError(f'{route} unexpectedly transferred HTTP data')
                await asyncio.sleep(4)
                text = (work/(route+'.log')).read_text(errors='replace')
                assert not any(e['event']=='request' for e in origin_events[before:])
                if route == 'upstream-untrusted':
                    assert 'UnknownIssuer' in text, 'upstream failure was not a trust failure'
                else:
                    assert len(origin_events) == before, 'unavailable SOCKS route leaked direct QUIC'
                results['cases'].append({'case':route,'rejected':True,'no_http_forwarded':True})
                Path(config['stop']).touch()
                for _ in range(100):
                    if p.poll() is not None: break
                    await asyncio.sleep(.05)
                assert p.poll() == 0, f'{route} shutdown failed'
                print('PASS',route,flush=True)
                continue
            result = await asyncio.wait_for(client_case(listen,ca,meta['certificate_sha256']),30)
            result.update(route=route, current_user_trust=meta['current_user_trust'])
            results['cases'].append(result)
            print('PASS',route,result,flush=True)
            if route == 'direct':
                for negative, options in [('untrusted',{'ca':(work/'origin-ca.der').read_bytes()}),
                                          ('unknown-sni',{'name':'wrong.test'})]:
                    try:
                        await asyncio.wait_for(client_case(listen,options.pop('ca',ca),meta['certificate_sha256'],batch=False,**options),10)
                    except ConnectionError as e:
                        results['cases'].append({'case':negative,'rejected':True,'error':str(e)})
                    else:
                        raise AssertionError(f'{negative} unexpectedly accepted')
            if route == 'socks-domain' and args.browsers:
                assert meta['current_user_trust'], 'CA is not trusted: browser trust test would be invalid'
                results['browsers'] = await browsers(work,processes,listen,work/(route+'.log'))
            Path(config['stop']).touch()
            for _ in range(100):
                if p.poll() is not None: break
                await asyncio.sleep(.05)
            assert p.poll() == 0, f'{route} did not shut down cleanly: {p.poll()}'
            if route != 'direct':
                text = (work/(route+'.log')).read_text(errors='replace')
                assert 'ROUTE pid=' in text, 'real Hook route not exercised'
                # Production totals intentionally exclude NOPROXY transfers.
                if route != 'noproxy':
                    assert 'ROUTE_TOTALS sent=0 ' not in text, 'no proxied bytes'
        relay_text = (work/'relay.log').read_text()
        assert 'IPV4:203.0.113.10' in relay_text and 'DOMAIN:origin.quic.test' in relay_text
        assert len([e for e in origin_events if e['event']=='request']) >= 44
        results['route_evidence'] = {'ip_route':True, 'remote_domain_route':True,
                                     'origin_requests':len([e for e in origin_events if e['event']=='request'])}
        results['passed'] = True
    finally:
        origin.close()
        processes.close()
        results['origin_events'] = origin_events
        (work/'results.json').write_text(json.dumps(results,indent=2))
        # Test private keys are not retained with diagnostics. User CA untouched.
        (work/'origin-key.pem').unlink(missing_ok=True)
        (pki/'ca.json').unlink(missing_ok=True)
        print('RESULT',work/'results.json',flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--browsers',action='store_true')
    asyncio.run(main(parser.parse_args()))
