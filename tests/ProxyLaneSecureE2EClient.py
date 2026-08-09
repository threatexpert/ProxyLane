import socket
import sys
import time
import traceback


target_host = sys.argv[1]
tcp_port = int(sys.argv[2])
udp_port = int(sys.argv[3])
result_path = sys.argv[4]
tcp_only = len(sys.argv) > 5 and sys.argv[5] == "tcp-only"

try:
    tcp_request = b"ProxyLane-PRC-secure-TCP-stream"
    tcp_stream_size = 8 * 1024 * 1024
    tcp_stream_chunk = bytes(range(256)) * 64
    expected = tcp_stream_chunk * (tcp_stream_size // len(tcp_stream_chunk))
    with socket.create_connection((target_host, tcp_port), timeout=15) as sock:
        sock.sendall(tcp_request)
        data = bytearray()
        while len(data) < tcp_stream_size:
            chunk = sock.recv(min(16 * 1024, tcp_stream_size - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            time.sleep(0.002)
        if data != expected:
            raise RuntimeError(
                f"TCP stream mismatch: received {len(data)} of {tcp_stream_size} bytes")

    if not tcp_only:
        udp_payload = b"ProxyLane-PRC-secure-UDP"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(8)
            sock.sendto(udp_payload, (target_host, udp_port))
            data, _ = sock.recvfrom(65535)
            if data != udp_payload:
                raise RuntimeError("UDP echo mismatch")

    outcome = "PASS"
except Exception:
    outcome = "FAIL\n" + traceback.format_exc()

with open(result_path, "w", encoding="utf-8") as result:
    result.write(outcome)
