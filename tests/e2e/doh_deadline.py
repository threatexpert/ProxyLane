"""Stalled proxy handshake/TLS: 12 s tunnel connect, 60 s query and 15 s bootstrap deadlines."""
import argparse
import concurrent.futures
import socket
import subprocess
import threading
from doh_transport import exact, isolate_controller


def run(host, stage, multiple=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    stopped = threading.Event()
    requests = []
    peers = []
    errors = []

    def serve_inner(peer):
        with peer:
            if stage in ("open", "tls"):
                version, methods = exact(peer, 2)
                assert version == 5
                exact(peer, methods)
                peer.sendall(b"\x05\x00")
                header = exact(peer, 4)
                assert header == b"\x05\x01\x00\x01"
                address = socket.inet_ntoa(exact(peer, 4))
                assert exact(peer, 2) == b"\x01\xbb"
                requests.append(address)
                if stage == "tls":
                    peer.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            stopped.wait(70)  # Deliberately never reply to TLS/proxy negotiation.

    def serve(peer):
        try:
            peer.settimeout(70)
            serve_inner(peer)
        except Exception as error:
            errors.append(repr(error))
            peer.close()

    def accept():
        try:
            while not stopped.is_set():
                peer, _ = listener.accept()
                peers.append(peer)
                threading.Thread(target=serve, args=(peer,), daemon=True).start()
        except OSError:
            pass

    threading.Thread(target=accept, daemon=True).start()
    try:
        bootstrap = "192.0.2.1,192.0.2.2" if multiple else "192.0.2.1"
        expected = (30000 if multiple else 60000) if stage == "tls" else (24000 if multiple else 12000)
        result = subprocess.run([host, str(listener.getsockname()[1]), bootstrap, str(expected)],
                                capture_output=True, text=True, errors="replace", timeout=70)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert "DEADLINE_PASS" in result.stdout, result.stdout
        assert "timed out" in result.stderr, result.stderr
        assert not errors, errors
        assert len(peers) == (2 if multiple else 1), "TCP/UDP should share the pending query"
        if stage != "tls":
            assert "proxy tunnel connection timed out (12 s)" in result.stderr, result.stderr
        if stage in ("open", "tls"):
            assert requests == bootstrap.split(","), requests
        print("PASS", stage, bootstrap, result.stdout.strip(), flush=True)
    finally:
        stopped.set()
        listener.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    args = parser.parse_args()
    isolate_controller()
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        jobs = [pool.submit(run, args.host, "proxy"),
                pool.submit(run, args.host, "open"),
                pool.submit(run, args.host, "open", True),
                pool.submit(run, args.host, "tls"),
                pool.submit(run, args.host, "tls", True)]
        for job in jobs:
            job.result()
