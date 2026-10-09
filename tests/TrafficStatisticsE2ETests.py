"""Check native traffic_statistics.exe against controlled local endpoints."""
import argparse
import pathlib
import socket
import subprocess
import tempfile
import threading
import time


def tcp_client(conn):
    with conn:
        while data := conn.recv(65536):
            conn.sendall(data * 2)


def tcp_server(listener):
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=tcp_client, args=(conn,), daemon=True).start()


def udp_server(sock):
    while True:
        data, address = sock.recvfrom(65535)
        sock.sendto(data * 2, address)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", type=pathlib.Path, required=True)
    parser.add_argument("--socks-server", type=pathlib.Path, required=True)
    args = parser.parse_args()
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", 0))
    tcp.listen()
    port = tcp.getsockname()[1]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", port))
    for target, sock in ((tcp_server, tcp), (udp_server, udp)):
        threading.Thread(target=target, args=(sock,), daemon=True).start()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        proxy_port = reservation.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="proxylane-traffic-") as directory:
        server = subprocess.Popen([
            str(args.socks_server.resolve()), "-listen", f"127.0.0.1:{proxy_port}",
            "-log", str(pathlib.Path(directory) / "socks.log"),
        ], creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(("127.0.0.1", proxy_port), 0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("SOCKS test server did not start")
            subprocess.run([str(args.probe.resolve()), str(proxy_port), str(port)],
                           check=True, timeout=40)
        finally:
            server.terminate()
            server.wait(timeout=5)


if __name__ == "__main__":
    main()
