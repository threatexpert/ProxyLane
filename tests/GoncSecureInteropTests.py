"""End-to-end interoperability test for ProxyLaneSecureTransport and gonc.

Starts a real gonc TLS-PSK SOCKS5 server and verifies both CONNECT and
UDP ASSOCIATE against local echo endpoints.  No external network is used.
"""

import argparse
import ctypes
import socket
import struct
import subprocess
import threading
import time


class Transport:
    OK = 0
    WOULD_BLOCK = -2

    def __init__(self, path):
        self.dll = ctypes.CDLL(path)
        size = ctypes.c_size_t
        byte_p = ctypes.POINTER(ctypes.c_ubyte)
        void_p_p = ctypes.POINTER(ctypes.c_void_p)
        self.dll.plst_session_create.argtypes = [byte_p, size, ctypes.c_char_p, void_p_p]
        self.dll.plst_session_create.restype = ctypes.c_int
        self.dll.plst_session_free.argtypes = [ctypes.c_void_p]
        self.dll.plst_session_is_ready.argtypes = [ctypes.c_void_p]
        self.dll.plst_session_is_ready.restype = ctypes.c_int
        self.dll.plst_session_feed_tls.argtypes = [ctypes.c_void_p, byte_p, size, ctypes.POINTER(size)]
        self.dll.plst_session_feed_tls.restype = ctypes.c_int
        self.dll.plst_session_drain_tls.argtypes = [ctypes.c_void_p, byte_p, size, ctypes.POINTER(size)]
        self.dll.plst_session_drain_tls.restype = ctypes.c_int
        self.dll.plst_session_write_plain.argtypes = [ctypes.c_void_p, byte_p, size, ctypes.POINTER(size)]
        self.dll.plst_session_write_plain.restype = ctypes.c_int
        self.dll.plst_session_read_plain.argtypes = [ctypes.c_void_p, byte_p, size, ctypes.POINTER(size)]
        self.dll.plst_session_read_plain.restype = ctypes.c_int
        self.dll.plst_session_export_key.argtypes = [ctypes.c_void_p, byte_p, size]
        self.dll.plst_session_export_key.restype = ctypes.c_int
        udp_args = [byte_p, size, byte_p, size, byte_p, size, ctypes.POINTER(size)]
        self.dll.plst_udp_encrypt.argtypes = udp_args
        self.dll.plst_udp_encrypt.restype = ctypes.c_int
        self.dll.plst_udp_decrypt.argtypes = udp_args
        self.dll.plst_udp_decrypt.restype = ctypes.c_int

    @staticmethod
    def array(data):
        return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)

    def create(self, psk=b"123"):
        session = ctypes.c_void_p()
        key = self.array(psk)
        result = self.dll.plst_session_create(key, len(psk), b"127.0.0.1", ctypes.byref(session))
        if result != self.OK:
            raise RuntimeError(f"session create failed: {result}")
        return Session(self, session)

    def udp_crypt(self, function, key, packet, extra):
        key_buf, packet_buf = self.array(key), self.array(packet)
        output = (ctypes.c_ubyte * (len(packet) + extra))()
        written = ctypes.c_size_t()
        result = function(key_buf, len(key), packet_buf, len(packet), output,
                          len(output), ctypes.byref(written))
        if result != self.OK:
            raise RuntimeError(f"UDP crypt failed: {result}")
        return bytes(output[:written.value])


class Session:
    def __init__(self, transport, handle):
        self.t = transport
        self.handle = handle

    def close(self):
        if self.handle:
            self.t.dll.plst_session_free(self.handle)
            self.handle = None

    def flush(self, sock):
        while True:
            output = (ctypes.c_ubyte * 65536)()
            written = ctypes.c_size_t()
            result = self.t.dll.plst_session_drain_tls(
                self.handle, output, len(output), ctypes.byref(written))
            if result != self.t.OK:
                raise RuntimeError(f"TLS drain failed: {result}")
            if not written.value:
                return
            sock.sendall(bytes(output[:written.value]))

    def feed(self, sock):
        data = sock.recv(65536)
        if not data:
            raise RuntimeError("unexpected TLS EOF")
        source = self.t.array(data)
        consumed = ctypes.c_size_t()
        result = self.t.dll.plst_session_feed_tls(
            self.handle, source, len(data), ctypes.byref(consumed))
        if result != self.t.OK or consumed.value != len(data):
            raise RuntimeError(f"TLS feed failed: {result}/{consumed.value}")
        self.flush(sock)

    def handshake(self, sock):
        self.flush(sock)
        deadline = time.monotonic() + 5
        while self.t.dll.plst_session_is_ready(self.handle) != 1:
            if time.monotonic() > deadline:
                raise TimeoutError("TLS handshake timed out")
            self.feed(sock)

    def send(self, sock, data):
        offset = 0
        while offset < len(data):
            source = self.t.array(data[offset:])
            written = ctypes.c_size_t()
            result = self.t.dll.plst_session_write_plain(
                self.handle, source, len(source), ctypes.byref(written))
            if result != self.t.OK:
                raise RuntimeError(f"plain write failed: {result}")
            offset += written.value
            self.flush(sock)

    def read(self, sock, minimum):
        result = bytearray()
        deadline = time.monotonic() + 5
        while len(result) < minimum:
            output = (ctypes.c_ubyte * 65536)()
            count = ctypes.c_size_t()
            status = self.t.dll.plst_session_read_plain(
                self.handle, output, len(output), ctypes.byref(count))
            if status == self.t.OK:
                result.extend(output[:count.value])
                continue
            if status != self.t.WOULD_BLOCK:
                raise RuntimeError(f"plain read failed: {status}")
            if time.monotonic() > deadline:
                raise TimeoutError("plain read timed out")
            self.feed(sock)
        return bytes(result)

    def export_key(self):
        key = (ctypes.c_ubyte * 32)()
        result = self.t.dll.plst_session_export_key(self.handle, key, len(key))
        if result != self.t.OK:
            raise RuntimeError(f"key export failed: {result}")
        return bytes(key)


def free_port(kind=socket.SOCK_STREAM):
    sock = socket.socket(socket.AF_INET, kind)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def tcp_echo_server(listener, stop):
    listener.settimeout(5)
    try:
        conn, _ = listener.accept()
        with conn:
            data = conn.recv(65536)
            conn.sendall(data)
    finally:
        stop.set()


def udp_echo_server(sock, stop):
    sock.settimeout(5)
    try:
        data, address = sock.recvfrom(65535)
        sock.sendto(data, address)
    finally:
        stop.set()


def connect_secure(transport, port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    session = transport.create()
    session.handshake(sock)
    session.send(sock, b"\x05\x01\x00")
    if session.read(sock, 2)[:2] != b"\x05\x00":
        raise RuntimeError("SOCKS5 method negotiation failed")
    return sock, session


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dll", required=True)
    parser.add_argument("--gonc", required=True)
    args = parser.parse_args()

    transport = Transport(args.dll)
    gonc_port = free_port()
    process = subprocess.Popen(
        [args.gonc, "-e", ":s5s -u", "-l", "-k", "-psk", "123",
         "-tls", "127.0.0.1", str(gonc_port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    time.sleep(0.5)
    try:
        wrong_control = socket.create_connection(("127.0.0.1", gonc_port), timeout=5)
        wrong_session = transport.create(b"wrong-psk")
        rejected = False
        try:
            wrong_session.handshake(wrong_control)
        except RuntimeError:
            rejected = True
        finally:
            wrong_session.close()
            wrong_control.close()
        if not rejected:
            raise RuntimeError("gonc accepted an incorrect PSK")

        tcp_listener = socket.socket()
        tcp_listener.bind(("127.0.0.1", 0))
        tcp_listener.listen(1)
        tcp_port = tcp_listener.getsockname()[1]
        tcp_done = threading.Event()
        threading.Thread(target=tcp_echo_server,
                         args=(tcp_listener, tcp_done), daemon=True).start()

        control, session = connect_secure(transport, gonc_port)
        request = b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", tcp_port)
        session.send(control, request)
        if session.read(control, 10)[1] != 0:
            raise RuntimeError("SOCKS5 CONNECT failed")
        payload = b"ProxyLane secure TCP interoperability"
        session.send(control, payload)
        if session.read(control, len(payload)) != payload:
            raise RuntimeError("TCP echo mismatch")
        session.close()
        control.close()
        if not tcp_done.wait(2):
            raise RuntimeError("TCP echo server did not finish")

        udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_server.bind(("127.0.0.1", 0))
        udp_port = udp_server.getsockname()[1]
        udp_done = threading.Event()
        threading.Thread(target=udp_echo_server,
                         args=(udp_server, udp_done), daemon=True).start()

        control, session = connect_secure(transport, gonc_port)
        session.send(control, b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = session.read(control, 10)
        if reply[1] != 0 or reply[3] != 1:
            raise RuntimeError("SOCKS5 UDP ASSOCIATE failed")
        relay = ("127.0.0.1", struct.unpack("!H", reply[8:10])[0])
        key = session.export_key()
        payload = b"ProxyLane secure UDP interoperability"
        socks_packet = (b"\x00\x00\x00\x01\x7f\x00\x00\x01" +
                        struct.pack("!H", udp_port) + payload)
        encrypted = transport.udp_crypt(transport.dll.plst_udp_encrypt,
                                        key, socks_packet, 16)
        udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_client.settimeout(5)
        udp_client.sendto(encrypted, relay)
        response, _ = udp_client.recvfrom(65535)
        plain = transport.udp_crypt(transport.dll.plst_udp_decrypt,
                                    key, response, -16)
        if plain[10:] != payload:
            raise RuntimeError("UDP echo mismatch")
        if not udp_done.wait(2):
            raise RuntimeError("UDP echo server did not finish")
        session.close()
        control.close()
        udp_client.close()
        udp_server.close()
        tcp_listener.close()
        print("PASS: gonc TLS-PSK SOCKS5 TCP and UDP interoperability")
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


if __name__ == "__main__":
    main()
