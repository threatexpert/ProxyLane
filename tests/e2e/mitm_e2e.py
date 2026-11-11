"""Real injected Schannel curl -> ProxyLane -> SOCKS5/CONNECT -> local TLS origin.

Installs a UNIQUE temporary CurrentUser CA, removes that exact CA in finally.
Requires Python cryptography and compiled build/tools/mitm_host64.exe.
No proxy profiles, existing certificates, or revocation-cache settings are changed.
"""
import argparse
import base64
import ctypes
import datetime
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def unprotect(data):
    class Blob(ctypes.Structure):
        _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]
    buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source, result = Blob(len(data), buf), Blob()
    api = ctypes.windll.crypt32.CryptUnprotectData
    api.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(Blob)]
    if not api(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        ctypes.memset(result.data, 0, result.size)
        ctypes.windll.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        ctypes.windll.kernel32.LocalFree(result.data)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def exact(s, n):
    result = b""
    while len(result) < n:
        part = s.recv(n - len(result))
        if not part:
            raise EOFError()
        result += part
    return result


class ThreadServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def handle_error(self, *_):
        # Negative identity tests intentionally abort origin handshakes.
        pass


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        s.settimeout(20)
        first = exact(s, 1)
        if first == b"\x05":
            exact(s, exact(s, 1)[0]); s.sendall(b"\x05\x00")
            version, command, _, kind = exact(s, 4)
            assert (version, command) == (5, 1)
            if kind == 1: exact(s, 4)
            elif kind == 3: exact(s, exact(s, 1)[0])
            elif kind == 4: exact(s, 16)
            else: raise ValueError(kind)
            port = int.from_bytes(exact(s, 2), "big")
            reply = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00"
        else:
            header = first
            while not header.endswith(b"\r\n\r\n"):
                header += exact(s, 1)
                assert len(header) <= 8192
            target = header.split(b" ")[1]
            port = int(target.rsplit(b":", 1)[1])
            reply = b"HTTP/1.1 200 Connection Established\r\n\r\n"
        with socket.create_connection((getattr(self.server, "upstream_host", "127.0.0.1"), port), 10) as up:
            s.sendall(reply)
            active = [s, up]
            while active:
                ready, _, _ = select.select(active, [], [], 20)
                if not ready: return
                for source in ready:
                    dest = up if source is s else s
                    data = source.recv(16384)
                    if not data:
                        active.remove(source)
                        dest.shutdown(socket.SHUT_WR)
                    else:
                        dest.sendall(data)


class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.server.context.wrap_socket(self.request, server_side=True) if self.server.context else self.request
        s.settimeout(20)
        data = b""
        while b"\r\n\r\n" not in data:
            part = s.recv(4096)
            if not part: raise EOFError()
            data += part
            if len(data) > 32768: raise ValueError("header too long")
        head, body = data.split(b"\r\n\r\n", 1)
        size = int(re.search(br"(?i)content-length: (\d+)", head).group(1)) if b"content-length:" in head.lower() else 0
        while len(body) < size:
            part = s.recv(min(16384, size - len(body)))
            if not part: raise EOFError()
            body += part
        reply = body if size else b"ProxyLane MITM verified\n"
        mode = getattr(self.server, "close_mode", "clean")
        length = len(reply) + (100 if mode == "truncated" else 0)
        connection = b"keep-alive" if mode == "after-client-close" else b"close"
        s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(length).encode() + b"\r\nConnection: " + connection + b"\r\n\r\n" + reply)
        if mode == "after-client-close":
            assert s.recv(1) == b"", "wait for curl's TLS close_notify"
        if mode != "clean":
            s.close()  # Deliberately omit the origin's TLS close_notify.
            return
        if self.server.context:
            try: s.unwrap().close()
            except (OSError, ssl.SSLError): pass


def start(handler, context=None):
    server = ThreadServer(("127.0.0.1", 0), handler)
    server.context = context
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    # Isolate this test-owned controller before starting threads/children. The
    # developer's interactive ProxyLane may inject every child of the terminal.
    kernel = ctypes.windll.kernel32
    kernel.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel.GetModuleHandleW.restype = ctypes.c_void_p
    for name in ("ProxyLaneHook64.dll", "ProxyLaneHook32.dll"):
        module = kernel.GetModuleHandleW(name)
        if module:
            inherited = ctypes.WinDLL(name, handle=module)
            inherited.gp_UnhookWinsock.argtypes = []
            inherited.gp_UnhookWinsock.restype = ctypes.c_int
            if not inherited.gp_UnhookWinsock():
                raise RuntimeError("Could not isolate inherited hooks in test controller")
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=["32", "64"], default="64", help="Target curl architecture; the proxy host is always x64")
    parser.add_argument("--binary-directory", default="bin")
    parser.add_argument("--tool-directory", default="build/tools")
    parser.add_argument("--external-ifconfig", action="store_true", help="Optional live reproduction against ifconfig.io")
    parser.add_argument("--protocol", action="store_true", help="Also verify live HTTP reconstruction and bounded payload cache")
    parser.add_argument("--multi-instance", action="store_true", help="Verify shared CA, separate CRL listeners and Schannel revocation")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = root / "build" / "qa" / ("mitm-" + uuid.uuid4().hex[:12])
    work.mkdir(parents=True)
    env = dict(os.environ, PROXYLANE_MITM="0", PROXYLANE_MITM_HOME=str(work / "pki"), PROXYLANE_MITM_CRL_PORT=str(free_port()))
    env["PROXYLANE_PROTOCOL_CACHE_ROOT"] = str(work / "protocol-cache")
    if args.protocol:
        env["PROXYLANE_TEST_PROTOCOL"] = "1"
    for key in list(env):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy"): del env[key]
    # Stage test hosts beside their runtime DLLs in this run's private directory.
    runtime_source = (root / args.binary_directory).resolve()
    tool_source = (root / args.tool_directory).resolve()
    binary_directory = work / "runtime"
    binary_directory.mkdir()
    for source in runtime_source.glob("*.dll"):
        shutil.copy2(source, binary_directory/source.name)
    for pattern in ("mitm_host*.exe", "ProxyLaneMitm*.exe"):
        for source in tool_source.glob(pattern):
            shutil.copy2(source, binary_directory/source.name)
    ca_tool = binary_directory / "ProxyLaneMitm64.exe"
    host = binary_directory / "mitm_host64.exe"
    curl = Path(os.environ["WINDIR"]) / ("SysWOW64" if args.arch == "32" else "System32") / "curl.exe"
    def ca(action):
        return json.loads(subprocess.check_output([str(ca_tool), action], env=env, text=True))
    def gui_ca(action):
        return subprocess.run([str(host), f"ca-{action}"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    installed = False
    servers = []
    try:
        assert b"FLAGS=0" in gui_ca(0).stdout
        assert b"FLAGS=1" in gui_ca(1).stdout
        initial = ca("status")
        assert not initial["trusted_current_user"]
        assert gui_ca(4).returncode == 1, "GUI must reject enabling without trust"
        assert ca("init")["sha256"] == initial["sha256"]
        installed = True  # finally removes even if command output parsing fails after import.
        assert b"FLAGS=3" in gui_ca(2).stdout
        assert ca("install")["trusted_current_user"]
        stored = json.loads((work / "pki" / "ca.json").read_text())
        authority = x509.load_der_x509_certificate(base64.b64decode(stored["certificate"]))
        assert authority.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "ProxyLane CA"
        authority_key = serialization.load_der_private_key(unprotect(base64.b64decode(stored["protected_key"])), None)
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mitm.test")]))
                .issuer_name(authority.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("mitm.test")]), False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(f"http://127.0.0.1:{stored['crl_port']}/pki/{initial['sha256']}.crl")],
                    relative_name=None, reasons=None, crl_issuer=None)]), False)
                .sign(authority_key, hashes.SHA256()))
        (work / "origin.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (work / "origin-key.pem").write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(work / "origin.pem", work / "origin-key.pem")
        context.set_alpn_protocols(["http/1.1"])
        proxy, tls, plain = start(Proxy), start(Origin, context), start(Origin)
        servers = [proxy, tls, plain]
        upload = bytes(range(256)) * 8192  # 2 MiB crosses every buffering boundary.
        (work / "upload.bin").write_bytes(upload)
        results = []
        child_pids = set()
        cases = [("socks-tls12", "SOCKS5", True, ["--tls-max", "1.2"], "mitm.test"),
                 ("connect-tls12", "HTTP11", True, ["--tls-max", "1.2"], "mitm.test"),
                 ("plain", "SOCKS5", False, [], "mitm.test"),
                 ("large", "SOCKS5", True, ["--data-binary", "@" + str(work / "upload.bin")], "mitm.test"),
                 ("gui-disabled", "SOCKS5", True, [], "mitm.test"),
                 ("invalid-name", "SOCKS5", True, [], "wrong.test")]
        for label, route, encrypted, options, name in cases:
            port = (tls if encrypted else plain).server_address[1]
            output = work / (label + ".body")
            command = [str(curl), "--verbose", "--silent", "--show-error", "--noproxy", "*", "--max-time", "25",
                       "--resolve", f"{name}:{port}:203.0.113.10", "--output", str(output), *options,
                       f"{'https' if encrypted else 'http'}://{name}:{port}/probe"]
            case_env = dict(env, PROXYLANE_MITM_TEST_DISABLED="1") if label == "gui-disabled" else env
            result = subprocess.run([str(host), str(proxy.server_address[1]), route, subprocess.list2cmdline(command)], env=case_env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
            (work / (label + ".log")).write_bytes(result.stdout + result.stderr)
            child_pids.add(int(re.search(br"CHILD pid=(\d+)", result.stderr).group(1)))
            if args.protocol:
                from realtime_protocol import check_original
                check_original(result, label, encrypted and label not in ("gui-disabled", "invalid-name"), work)
            if label == "invalid-name":
                assert result.returncode != 0, "upstream name mismatch must be rejected"
            else:
                assert result.returncode == 0, (label, result.returncode, result.stderr.decode(errors="replace"))
                if encrypted and label != "gui-disabled":
                    assert b"RAW_EVENT" not in result.stderr, "Decrypted TLS must not duplicate raw ciphertext"
                    assert b"TLS_ERROR" not in result.stderr, "Clean shutdown must not report truncation"
                else:
                    assert b"RAW_EVENT" in result.stderr, "Non-decrypted connections must retain raw data"
                assert output.read_bytes() == (upload if label == "large" else b"ProxyLane MITM verified\n")
                if encrypted and label != "gui-disabled":
                    assert b"response=1" in result.stderr, "GUI must receive response plaintext"
                    if label != "large": assert b"get=1" in result.stderr, "GUI must receive request plaintext"
            results.append({"case":label, "exit":result.returncode})
            print(label, result.returncode, flush=True)
        if args.arch == "64":
            output = work / "tls13.body"
            command = [sys.executable, str(Path(__file__).with_name("mitm_tls_client.py")), str(tls.server_address[1]),
                       str(work / "pki" / "proxylane-ca.cer"), str(output)]
            result = subprocess.run([str(host), str(proxy.server_address[1]), "HTTP11", subprocess.list2cmdline(command)], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
            (work / "tls13.log").write_bytes(result.stdout + result.stderr)
            child_pids.add(int(re.search(br"CHILD pid=(\d+)", result.stderr).group(1)))
            assert result.returncode == 0, result.stderr.decode(errors="replace")
            assert b"RAW_EVENT" not in result.stderr
            assert b"TLS_ERROR" not in result.stderr
            assert output.read_bytes() == b"ProxyLane MITM verified\n"
            results.append({"case":"tls13-openssl", "exit":0})
            print("tls13-openssl 0", flush=True)
        for mode in ("abrupt", "after-client-close", "truncated"):
            broken = start(Origin, context)
            broken.close_mode = mode
            servers.append(broken)
            port = broken.server_address[1]
            output = work / (mode + ".body")
            command = [str(curl), "--silent", "--show-error", "--noproxy", "*", "--max-time", "15",
                       "--resolve", f"mitm.test:{port}:203.0.113.10", "--output", str(output),
                       f"https://mitm.test:{port}/probe"]
            result = subprocess.run([str(host), str(proxy.server_address[1]), "SOCKS5", subprocess.list2cmdline(command)], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
            (work / (mode + ".log")).write_bytes(result.stdout + result.stderr)
            assert result.stderr.count(b"TLS_ERROR ") == 1, result.stderr.decode(errors="replace")
            assert b"upstream TCP EOF without close_notify" in result.stderr
            assert b"RAW_EVENT" not in result.stderr
            if mode == "truncated":
                assert result.returncode != 0, "Truncated HTTP response must not be silently accepted"
            else:
                assert result.returncode == 0, result.stderr.decode(errors="replace")
                assert output.read_bytes() == b"ProxyLane MITM verified\n"
            if mode == "after-client-close":
                assert b"opposite peer already sent close_notify" in result.stderr
            results.append({"case":mode, "exit":result.returncode})
            print(mode, result.returncode, flush=True)
        if args.external_ifconfig:
            proxy.upstream_host = "ifconfig.io"
            command = [str(curl), "--silent", "--show-error", "--noproxy", "*", "--max-time", "20",
                       "--resolve", "ifconfig.io:443:203.0.113.10",
                       "--output", str(work / "ifconfig.body"), "https://ifconfig.io/"]
            result = subprocess.run([str(host), str(proxy.server_address[1]), "SOCKS5", subprocess.list2cmdline(command)], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            (work / "ifconfig.log").write_bytes(result.stdout + result.stderr)
            assert b"GUI_EVENT" in result.stderr, "External reproduction must pass through MITM"
            print("ifconfig", result.returncode, result.stderr.decode(errors="replace"), flush=True)
        if args.protocol and args.arch == "64":
            from realtime_protocol import run
            run(host, env, work, proxy, start, servers)
        if args.multi_instance:
            from mitm_multi_instance import run as run_multi_instance
            run_multi_instance(binary_directory, env, work, proxy, tls, authority)
        assert not list((work / "protocol-cache").glob("run-*")), "Normal host exit must remove its payload cache"
        assert not (work / "pki" / "captures").exists(), "Default MITM must not create disk captures"
        (work / "results.json").write_text(json.dumps(results, indent=2))
        print("PASS", work, flush=True)
    finally:
        for server in servers: server.shutdown(); server.server_close()
        if installed:
            assert b"FLAGS=1" in gui_ca(3).stdout
            assert not ca("status")["trusted_current_user"]
            print("Temporary CA removed", flush=True)


if __name__ == "__main__":
    main()
