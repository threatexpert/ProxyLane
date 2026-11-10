"""Loopback SSH/SOCKS5/CONNECT fixtures; Paramiko >=3.5 for AES-GCM. No system accounts."""
import base64
import io
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
import hashlib
import json
import select
import socket
import threading
import sys
import time
from pathlib import Path
import paramiko

lock = threading.Lock()
stats = {"auth_a": 0, "auth_b": 0, "channels_a": 0, "channels_b": 0,
         "key_auth_a": 0, "key_auth_b": 0, "keepalive": 0, "socks": 0, "http": 0, "open_held": 0,
         "open_peak": 0, "fast_while_held": 0, "late_close": 0}
open_gate = threading.Event()
open_gate.set()
transports = []
reply_keepalive = True
listeners = []

def count(name):
    with lock:
        stats[name] += 1

def exact(s, n):
    data = b""
    while len(data) < n:
        part = s.recv(n - len(data))
        if not part:
            raise EOFError()
        data += part
    return data

def bridge(a, b):
    def copy(source, target):
        try:
            while True:
                data = source.recv(32768)
                if not data:
                    break
                target.sendall(data)
            if isinstance(target, paramiko.Channel):
                target.shutdown_write()
            else:
                target.shutdown(socket.SHUT_WR)
        except (OSError, EOFError):
            pass
    left = threading.Thread(target=copy, args=(a,b), daemon=True)
    left.start()
    copy(b,a)
    left.join(timeout=70)
    a.close(); b.close()

def listen(handler):
    server = socket.socket()
    server.bind(("127.0.0.1", 0)); server.listen(64)
    listeners.append(server)
    def accept():
        while True:
            try: client, _ = server.accept()
            except OSError: break
            def run(client=client):
                try: handler(client)
                except (EOFError, OSError, paramiko.SSHException): client.close()
            threading.Thread(target=run, daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()
    return server.getsockname()[1]

def echo(s):
    try:
        while True:
            data = s.recv(32768)
            if not data: break
            s.sendall(data)
        s.shutdown(socket.SHUT_WR)
    finally: s.close()

def socks(s):
    count("socks")
    version, methods = exact(s,2); exact(s,methods)
    s.sendall(b"\x05\x00")
    version, command, reserved, kind = exact(s,4)
    if kind == 1: host = socket.inet_ntop(socket.AF_INET, exact(s,4))
    elif kind == 4: host = socket.inet_ntop(socket.AF_INET6, exact(s,16))
    elif kind == 3: host = exact(s,exact(s,1)[0]).decode()
    else: raise EOFError()
    port = int.from_bytes(exact(s,2),'big')
    target = socket.create_connection((host,port))
    s.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
    bridge(s,target)

def http(s):
    count("http")
    request = b""
    while not request.endswith(b"\r\n\r\n"):
        request += exact(s,1)
        if len(request) > 8192: raise EOFError()
    endpoint = request.split(b" ")[1].decode()
    host, port = endpoint.rsplit(':',1)
    target = socket.create_connection((host.strip('[]'),int(port)))
    s.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    bridge(s,target)

client_key = paramiko.RSAKey.generate(2048)
key_folder = Path(sys.argv[1]).resolve().parent
client_key.write_private_key_file(str(key_folder / 'client-key.pem'))
client_key.write_private_key_file(str(key_folder / 'client-key-encrypted.pem'), password='key-passphrase')
# Exercise real keys in each supported container, including encrypted variants.
authorized_keys = [client_key]
for algorithm, crypto_key in [('rsa', client_key.key), ('ecdsa', ec.generate_private_key(ec.SECP256R1())), ('ed25519', ed25519.Ed25519PrivateKey.generate())]:
    openssh = crypto_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
    reader = {'rsa': paramiko.RSAKey, 'ecdsa': paramiko.ECDSAKey, 'ed25519': paramiko.Ed25519Key}[algorithm]
    public_key = reader.from_private_key(io.StringIO(openssh.decode()))
    authorized_keys.append(public_key)
    if algorithm == 'ed25519': modern_host_key = public_key
    formats = [('openssh', serialization.PrivateFormat.OpenSSH), ('pkcs8', serialization.PrivateFormat.PKCS8)]
    if algorithm == 'ecdsa': formats.append(('pem', serialization.PrivateFormat.TraditionalOpenSSL))
    for label, fmt in formats:
        for encrypted in (False, True):
            encryption = serialization.BestAvailableEncryption(b'key-passphrase') if encrypted else serialization.NoEncryption()
            name = f'{algorithm}-{label}' + ('-encrypted' if encrypted else '') + '.pem'
            (key_folder / name).write_bytes(crypto_key.private_bytes(serialization.Encoding.PEM, fmt, encryption))
modern_fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(modern_host_key.asbytes()).digest()).decode().rstrip('=')
key = paramiko.RSAKey.generate(2048)
fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')

class SshServer(paramiko.ServerInterface):
    def __init__(self, name):
        self.name = name; self.destinations = {}
    def get_allowed_auths(self, username): return 'password,publickey'
    def check_auth_publickey(self, username, offered):
        count('key_auth_' + self.name)
        return paramiko.AUTH_SUCCESSFUL if username == 'key-user' and offered in authorized_keys else paramiko.AUTH_FAILED
    def check_auth_password(self, username, password):
        count('auth_' + self.name)
        return paramiko.AUTH_SUCCESSFUL if (username,password) == ('test-user','test-password') else paramiko.AUTH_FAILED
    def check_channel_direct_tcpip_request(self, channel, origin, destination):
        count('channels_' + self.name)
        if destination[1] == 1 or destination[0] == 'hold-fail.test':
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        if destination[0] == 'hold-open.test': destination = ('127.0.0.1', destination[1])
        self.destinations[channel] = destination
        return paramiko.OPEN_SUCCEEDED
    def check_global_request(self, kind, message):
        if kind == 'keepalive@libssh2.org': count('keepalive')
        return False  # REQUEST_FAILURE is a valid keepalive response.

def ssh(s, name, modern=False):
    server = SshServer(name)
    transport = paramiko.Transport(s)
    if modern:
        options = transport.get_security_options()
        options.kex = ('curve25519-sha256@libssh.org',)
        options.ciphers = ('aes256-gcm@openssh.com',)
        transport.add_server_key(modern_host_key)
    else:
        transport.add_server_key(key)
    with lock: transports.append(transport)
    def dispatch(handler, message):
        if getattr(handler, '__self__', None) is not None: handler(message)
        else: handler(transport, message)
    original_global = transport._handler_table[80]
    def global_request(*args):
        message = args[-1]
        if reply_keepalive: dispatch(original_global, message)
        else: count('keepalive')
    # Per-instance table, do not change Paramiko's class dispatch table.
    transport._handler_table = dict(transport._handler_table)
    transport._handler_table[80] = global_request
    original_open = transport._handler_table[90]
    original_send = transport._send_message
    held_ids = set()
    held_local_ids = set()
    local_pending = set()
    def channel_open(*args):
        message = args[-1]
        # Inspect a copy; retain the original cursor for Paramiko's parser.
        probe = paramiko.Message(message.asbytes())
        kind = probe.get_text(); remote_id = probe.get_int()
        probe.get_int(); probe.get_int()
        host = probe.get_text() if kind == 'direct-tcpip' else ''
        if host in ('hold-open.test', 'hold-fail.test'):
            held_ids.add(remote_id)
        dispatch(original_open, message)
    def send_message(message):
        wire = message.asbytes()
        if wire[0] in (91, 92):
            remote_id = int.from_bytes(wire[1:5], 'big')
            if remote_id in held_ids and not open_gate.is_set():
                local_pending.add(remote_id)
                if wire[0] == 91:
                    held_local_ids.add(int.from_bytes(wire[5:9], 'big'))
                with lock:
                    stats['open_held'] += 1
                    stats['open_peak'] = max(stats['open_peak'], stats['open_held'])
                def delayed():
                    open_gate.wait()
                    try:
                        if transport.is_active(): original_send(paramiko.Message(wire))
                    except (OSError, EOFError): pass
                    finally:
                        local_pending.discard(remote_id)
                        with lock: stats['open_held'] -= 1
                threading.Thread(target=delayed, daemon=True).start()
                return
            elif wire[0] == 91 and local_pending:
                count('fast_while_held')  # Same transport, not just same server.
        original_send(message)
    original_close = transport._channel_handler_table[97]
    transport._channel_handler_table = dict(transport._channel_handler_table)
    def channel_close(channel, message):
        if channel.get_id() in held_local_ids:
            held_local_ids.remove(channel.get_id()); count('late_close')
        original_close(channel, message)
    transport._handler_table[90] = channel_open
    transport._channel_handler_table[97] = channel_close
    transport._send_message = send_message
    try:
        transport.start_server(server=server)
        while transport.is_active():
            channel = transport.accept(1)
            if channel is None: continue
            destination = server.destinations[channel.get_id()]
            def forward(channel=channel, destination=destination):
                try:
                    target = socket.create_connection(destination, timeout=5)
                    target.settimeout(None)
                    bridge(channel,target)
                except OSError: channel.close()
            threading.Thread(target=forward, daemon=True).start()
    finally:
        transport.close()
        with lock:
            if transport in transports: transports.remove(transport)

def control(s):
    global reply_keepalive
    command = b""
    while not command.endswith(b'\n'): command += exact(s,1)
    command = command.strip()
    if command == b'drop':
        with lock: current = list(transports)
        for t in current: t.close()
    elif command == b'silence': reply_keepalive = False
    elif command == b'respond': reply_keepalive = True
    elif command == b'hold-opens': open_gate.clear()
    elif command == b'release-opens': open_gate.set()
    with lock:
        result = dict(stats)
        result['active_sessions'] = sum(t.is_active() for t in transports)
    s.sendall(json.dumps(result).encode() + b'\n'); s.close()

configuration = {'a': listen(lambda s: ssh(s,'a')), 'b': listen(lambda s: ssh(s,'b')),
                 'socks': listen(socks), 'http': listen(http), 'echo': listen(echo),
                 'control': listen(control), 'fingerprint': fingerprint,
                 'modern': listen(lambda s: ssh(s, 'a', modern=True)), 'modern_fingerprint': modern_fingerprint}
with open(sys.argv[1], 'w') as output: json.dump(configuration, output)
threading.Event().wait()
