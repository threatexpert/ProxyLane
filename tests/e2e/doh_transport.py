"""Opt-in network test: real DoH TLS through local SOCKS5 / HTTP chain fixtures.

Only the DoH service is external. All business TCP/UDP payloads are echoed by
the last fixture. No certificate trust or user configuration is changed.
"""
import argparse
import ipaddress
import re
import select
import socket
import struct
import subprocess
import ctypes
import os
import threading
import time


def isolate_controller():
    # Remove only this test controller's inherited hook before fixture threads
    # start, so a running PL cannot redirect the fixture's UDP echo replies.
    if os.name != "nt":
        return
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel.GetModuleHandleW.restype = ctypes.c_void_p
    for name in ("ProxyLaneHook64.dll", "ProxyLaneHook32.dll"):
        module = kernel.GetModuleHandleW(name)
        if module:
            hook = ctypes.WinDLL(name, handle=module, use_last_error=True)
            hook.gp_UnhookWinsock.argtypes = []
            hook.gp_UnhookWinsock.restype = ctypes.c_int
            assert hook.gp_UnhookWinsock() or ctypes.get_last_error() == 1168, "isolate test controller"


def exact(sock, count):
    result = b""
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise EOFError()
        result += part
    return result


class Proxy:
    def __init__(self, kind):
        self.kind = kind
        self.requests = []
        self.errors = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        try:
            while True:
                peer, _ = self.listener.accept()
                threading.Thread(target=self.serve, args=(peer,), daemon=True).start()
        except OSError:
            pass

    def serve(self, peer):
        try:
            with peer:
                peer.settimeout(70)
                if self.kind == "socks":
                    version, n = exact(peer, 2)
                    assert version == 5
                    exact(peer, n)
                    peer.sendall(b"\x05\x00")
                    version, cmd, _, atyp = exact(peer, 4)
                    if atyp == 1:
                        host = socket.inet_ntop(socket.AF_INET, exact(peer, 4))
                    elif atyp == 4:
                        host = socket.inet_ntop(socket.AF_INET6, exact(peer, 16))
                    else:
                        host = exact(peer, exact(peer, 1)[0]).decode()
                    port = struct.unpack("!H", exact(peer, 2))[0]
                    if cmd == 3:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                            udp.bind(("127.0.0.1", 0))
                            peer.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp.getsockname()[1]))
                            while True:
                                ready, _, _ = select.select([udp, peer], [], [], 15)
                                if peer in ready or not ready:
                                    return
                                packet, source = udp.recvfrom(65536)
                                assert packet[3] in (1, 4), "UDP must use a numeric DoH answer"
                                self.requests.append(("udp", packet[3]))
                                udp.sendto(packet, source)
                    assert cmd == 1
                else:
                    header = b""
                    while not header.endswith(b"\r\n\r\n"):
                        header += exact(peer, 1)
                        assert len(header) < 8192
                    method, authority, _ = header.split(b"\r\n", 1)[0].split()
                    assert method == b"CONNECT"
                    host, port = authority.decode().rsplit(":", 1)
                    host = host.strip("[]")
                    port = int(port)
                    atyp = 4 if ":" in host else 1
                self.requests.append((host, port, atyp))
                if host == "192.0.2.254" and port == 443:
                    # Reserved test address: reject locally to exercise deferred
                    # bootstrap retry without waiting for a timeout or network.
                    peer.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00" if self.kind == "socks"
                                 else b"HTTP/1.1 502 Test bootstrap rejection\r\nContent-Length: 0\r\n\r\n")
                    return
                if port == 443:
                    assert atyp != 3, "DoH bootstrap must be numeric"
                    time.sleep(0.5)  # Ensure several business clients await one query.
                if self.kind == "socks":
                    peer.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                else:
                    peer.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if port == 18888:
                    ipaddress.ip_address(host)
                    assert atyp != 3 and host != "127.255.0.1", "business target must use a real numeric answer"
                    while data := peer.recv(65536):
                        peer.sendall(data)
                    return
                # Literal endpoints only: the fixture never resolves a domain.
                ipaddress.ip_address(host)
                with socket.create_connection((host, port), timeout=15) as remote:
                    while True:
                        ready, _, _ = select.select([peer, remote], [], [], 70)
                        if not ready:
                            return
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                return
                            (remote if source is peer else peer).sendall(data)
        except (EOFError, ConnectionError, TimeoutError, OSError):
            pass
        except Exception as error:
            self.errors.append(repr(error))


def run(binary, chain=False, failure=False, udp=True, url="https://dns.google/dns-query", bootstrap="8.8.8.8", retry=False):
    socks = Proxy("socks")
    http = Proxy("http") if chain else None
    if failure:
        url = url.rsplit("/", 1)[0] + "/not-a-doh-endpoint"
    args = [binary, str(socks.port), str(http.port if http else 0), url, "192.0.2.254," + bootstrap if retry else bootstrap]
    if failure:
        args.append("failure")
    if not udp:
        args.append("skip-udp")
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=100)
        assert result.returncode == 0, (result.stdout + result.stderr, socks.requests, socks.errors, http.requests if http else [])
        if not failure:
            lines = [line.strip() for line in (result.stdout + result.stderr).splitlines() if line.startswith('[DoH]')]
            assert len(lines) >= 10, ('Missing DoH result logs', lines)
            for line in lines:
                match = re.fullmatch(r'\[DoH\] host\.exe \(\d+\) : example\.org -> (\S+)', line)
                assert match, ('DoH log must identify the process', line)
                assert ipaddress.ip_address(match[1]).version == 4, ('DoH log must contain only the answer IP, without a business port', line)
        last = http or socks
        queries = [r for r in last.requests if len(r) == 3 and r[1] == 443]
        targets = [r for r in last.requests if len(r) == 3 and r[1] == 18888]
        assert len(queries) == (4 if retry else 2), ("concurrent queries/cache were not shared", last.requests)
        assert (len(targets) == 0 if failure else len(targets) == 12), last.requests
        assert not socks.errors and (not http or not http.errors), (socks.errors, http.errors if http else [])
        if udp and not chain and not failure:
            assert any(r[0] == "udp" for r in socks.requests), socks.requests
        print("PASS", "chain" if chain else "single", "failure" if failure else "bootstrap-retry" if retry else "cache+coalescing+cancellation+tester-without-timers", len(queries), "DoH tunnel")
    finally:
        socks.listener.close()
        if http:
            http.listener.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--doh-url", default="https://dns.google/dns-query")
    parser.add_argument("--bootstrap", default="8.8.8.8")
    args = parser.parse_args()
    isolate_controller()
    run(args.host, url=args.doh_url, bootstrap=args.bootstrap)
    run(args.host, chain=True, url=args.doh_url, bootstrap=args.bootstrap)
    run(args.host, failure=True, url=args.doh_url, bootstrap=args.bootstrap)

    run(args.host, retry=True, url=args.doh_url, bootstrap=args.bootstrap)
