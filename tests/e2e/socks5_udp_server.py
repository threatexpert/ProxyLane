"""Small deterministic SOCKS5 UDP server used by ProxyLane E2E tests."""

import argparse
import select
import socket
import struct
import threading
import time


def recv_exact(conn, length):
    data = b""
    while len(data) < length:
        part = conn.recv(length - len(data))
        if not part:
            raise ConnectionError("control connection closed")
        data += part
    return data


class Server:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()

    def log(self, text):
        line = f"{time.time():.3f} {text}\n"
        with self.lock:
            with open(self.args.log, "a", encoding="utf-8") as stream:
                stream.write(line)

    def authenticate(self, conn):
        version, count = recv_exact(conn, 2)
        if version != 5:
            return False
        methods = recv_exact(conn, count)
        required = 2 if self.args.username is not None else 0
        if required not in methods:
            conn.sendall(bytes((5, 0xFF)))
            return False
        conn.sendall(bytes((5, required)))
        if required == 0:
            return True
        version = recv_exact(conn, 1)[0]
        user = recv_exact(conn, recv_exact(conn, 1)[0]).decode("utf-8", "replace")
        password = recv_exact(conn, recv_exact(conn, 1)[0]).decode("utf-8", "replace")
        ok = version == 1 and user == self.args.username and password == self.args.password
        conn.sendall(bytes((1, 0 if ok else 1)))
        self.log(f"AUTH {'OK' if ok else 'FAIL'} user={user}")
        return ok

    @staticmethod
    def parse_request(data):
        if len(data) < 4 or data[:3] != b"\x00\x00\x00":
            return None
        atyp = data[3]
        if atyp == 1 and len(data) >= 10:
            original = socket.inet_ntoa(data[4:8])
            port = struct.unpack("!H", data[8:10])[0]
            target = "127.0.0.1" if original.startswith("203.0.113.") else original
            return target, port, data[10:], f"IPV4:{original}"
        if atyp == 3 and len(data) >= 7:
            length = data[4]
            header = 7 + length
            if not length or len(data) < header:
                return None
            domain = data[5:5 + length].decode("ascii", "replace")
            port = struct.unpack("!H", data[5 + length:header])[0]
            target = "127.0.0.1" if domain.endswith(".test") else socket.gethostbyname(domain)
            return target, port, data[header:], f"DOMAIN:{domain}"
        return None

    @staticmethod
    def frame(source, payload):
        return (b"\x00\x00\x00\x01" + socket.inet_aton(source[0]) +
                struct.pack("!H", source[1]) + payload)

    def inject_faults(self, relay, client, target):
        if self.args.inject_forged:
            attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                attacker.bind(("127.0.0.1", 0))
                attacker.sendto(self.frame(target, b"FORGED-RELAY-SOURCE"), client)
                self.log(f"INJECT FORGED source_port={attacker.getsockname()[1]}")
            finally:
                attacker.close()
        if self.args.inject_malformed:
            relay.sendto(b"\x00\x00\x01\x01malformed", client)
            self.log("INJECT MALFORMED")

    def association(self, conn, address):
        relay = None
        try:
            if not self.authenticate(conn):
                return
            header = recv_exact(conn, 4)
            if header[0] != 5 or header[1] != 3:
                return
            if header[3] == 1:
                recv_exact(conn, 6)
            elif header[3] == 3:
                recv_exact(conn, recv_exact(conn, 1)[0] + 2)
            else:
                return
            relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            relay.bind(("127.0.0.1", 0))
            relay_host, relay_port = relay.getsockname()
            conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(relay_host) +
                         struct.pack("!H", relay_port))
            self.log(f"ASSOC READY tcp={address[0]}:{address[1]} relay={relay_port}")
            client = None
            faults_injected = False
            while True:
                readable, _, _ = select.select((conn, relay), (), (), 1.0)
                if conn in readable and not conn.recv(1):
                    break
                if relay not in readable:
                    continue
                packet, source = relay.recvfrom(65535)
                if client is None or source == client:
                    client = source
                    request = self.parse_request(packet)
                    if request is None:
                        self.log("DROP malformed request")
                        continue
                    host, port, payload, target_type = request
                    if not self.args.quiet_packets:
                        self.log(f"REQUEST {target_type} target={host}:{port} bytes={len(payload)}")
                    if not faults_injected:
                        self.inject_faults(relay, client, (host, port))
                        faults_injected = True
                    if self.args.delay_ms:
                        time.sleep(self.args.delay_ms / 1000.0)
                    relay.sendto(payload, (host, port))
                else:
                    relay.sendto(self.frame(source, packet), client)
                    if not self.args.quiet_packets:
                        self.log(f"REPLY source={source[0]}:{source[1]} bytes={len(packet)}")
        except Exception as exc:  # diagnostics are part of the test contract
            self.log(f"ASSOC ERROR {type(exc).__name__}:{exc}")
        finally:
            if relay is not None:
                relay.close()
            conn.close()
            self.log("ASSOC CLOSED")

    def run(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.args.host, self.args.port))
        listener.listen()
        self.log(f"LISTEN {self.args.host}:{self.args.port}")
        while True:
            conn, address = listener.accept()
            threading.Thread(target=self.association, args=(conn, address), daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--inject-forged", action="store_true")
    parser.add_argument("--inject-malformed", action="store_true")
    parser.add_argument("--delay-ms", type=int, default=0)
    parser.add_argument("--quiet-packets", action="store_true")
    args = parser.parse_args()
    open(args.log, "w", encoding="utf-8").close()
    Server(args).run()


if __name__ == "__main__":
    main()
