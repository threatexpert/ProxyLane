import socket
import sys
import traceback


target_host = sys.argv[1]
tcp_port = int(sys.argv[2])
udp_port = int(sys.argv[3])
result_path = sys.argv[4]

try:
    tcp_payload = b"ProxyLane-PRC-secure-TCP"
    with socket.create_connection((target_host, tcp_port), timeout=8) as sock:
        sock.sendall(tcp_payload)
        data = bytearray()
        while len(data) < len(tcp_payload):
            chunk = sock.recv(len(tcp_payload) - len(data))
            if not chunk:
                break
            data.extend(chunk)
        if data != tcp_payload:
            raise RuntimeError(f"TCP echo mismatch: received {bytes(data)!r}")

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
