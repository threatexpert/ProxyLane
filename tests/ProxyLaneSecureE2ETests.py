"""Full PRC/Hook end-to-end test using a real gonc encrypted server."""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

import psutil


TCP_STREAM_SIZE = 8 * 1024 * 1024
TCP_STREAM_CHUNK = bytes(range(256)) * 64


def local_ipv4():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect selects the default-route source address without sending
        # a packet. This keeps the E2E target local while avoiding loopback's
        # intentional transparent-proxy bypass.
        try:
            probe.connect(("8.8.8.8", 53))
            address = probe.getsockname()[0]
            if not address.startswith("127."):
                return address
        except OSError:
            pass
    finally:
        probe.close()
    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            if (address.family == socket.AF_INET and
                    not address.address.startswith(("127.", "169.254."))):
                return address.address
    raise RuntimeError("no non-loopback IPv4 address is available for E2E testing")


def owner_for_flow(kind, local_port, remote_port):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        for item in psutil.net_connections(kind=kind):
            if not item.laddr:
                continue
            if item.laddr.port != remote_port:
                continue
            if kind == "tcp" and (not item.raddr or item.raddr.port != local_port):
                continue
            if item.pid:
                return item.pid
        time.sleep(0.03)
    return None


def tcp_echo(listener, observation):
    conn, address = listener.accept()
    with conn:
        data = conn.recv(65535)
        observation.append(("payload", data))
        try:
            observation.append(owner_for_flow("tcp", listener.getsockname()[1], address[1]))
        except Exception as error:
            observation.append(f"error: {error}")
        time.sleep(0.2)
        remaining = TCP_STREAM_SIZE
        while remaining:
            chunk = TCP_STREAM_CHUNK[:min(len(TCP_STREAM_CHUNK), remaining)]
            conn.sendall(chunk)
            remaining -= len(chunk)


def udp_echo(sock, observation):
    data, address = sock.recvfrom(65535)
    sock.sendto(data, address)
    try:
        observation.append(owner_for_flow("udp", sock.getsockname()[1], address[1]))
    except Exception as error:
        observation.append(f"error: {error}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", required=True)
    parser.add_argument("--gonc", required=True)
    parser.add_argument("--plain", action="store_true")
    parser.add_argument("--proxy-type", choices=("SOCKS5", "HTTP10", "HTTP11"),
                        default="SOCKS5")
    args = parser.parse_args()
    test_udp = args.proxy_type == "SOCKS5"

    # Hook a LAN destination so the target stays entirely local and the test
    # does not depend on external DNS. The observed target PID below proves
    # that gonc, rather than the proxied client, established the connection.
    target_host = local_ipv4()

    tcp_listener = socket.socket()
    tcp_listener.bind(("0.0.0.0", 0))
    tcp_listener.listen(1)
    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind(("0.0.0.0", 0))
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    gonc_port = probe.getsockname()[1]
    probe.close()

    tcp_owner, udp_owner = [], []
    threading.Thread(target=tcp_echo, args=(tcp_listener, tcp_owner), daemon=True).start()
    threading.Thread(target=udp_echo, args=(udp_server, udp_owner), daemon=True).start()

    with tempfile.TemporaryDirectory(prefix="ProxyLaneSecureE2E-",
                                     ignore_cleanup_errors=True) as temp:
        for name in ("ProxyLane64.exe", "ProxyLaneHook32.dll", "ProxyLaneHook64.dll",
                     "ProxyLaneSecureTransport32.dll", "ProxyLaneSecureTransport64.dll"):
            shutil.copy2(os.path.join(args.bin, name), os.path.join(temp, name))
        ini = f"""[options]
lastselected=SecureTest
HookLanIP=1
DisableLLMNR=1
DisableMDNS=1
language=en-US

[proxy_SecureTest]
HookChildProcess=0
HookTCP=1
HookUDP={1 if test_udp else 0}
BlockUDP=0
dnsOpt=1
RedirectPrivateDNS=0
ChildFilter=
ChildFilterMode=1
TargetFilter=
TargetFilterMode=0
Type={args.proxy_type}
Host=127.0.0.1
Port={gonc_port}
User=
Pass=
Transport={'PLAIN' if args.plain else 'GONC_TLS_PSK'}
PSK={' ' if args.plain else '123'}
"""
        with open(os.path.join(temp, "ProxyLane.ini"), "w", encoding="utf-8") as profile:
            profile.write(ini)
        result_path = os.path.join(temp, "client-result.txt")
        trace_path = os.path.join(temp, "secure-trace.log")
        client_path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                   "ProxyLaneSecureE2EClient.py"))
        gonc_arguments = [args.gonc, "-e", ":s5s -u -http", "-l", "-k"]
        if not args.plain:
            gonc_arguments += ["-psk", "123", "-tls"]
        gonc_arguments += ["127.0.0.1", str(gonc_port)]
        gonc = subprocess.Popen(
            gonc_arguments,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        time.sleep(0.5)
        environment = os.environ.copy()
        environment["PROXYLANE_SECURE_TRACE"] = trace_path
        client_arguments = [
            client_path, target_host, str(tcp_listener.getsockname()[1]),
            str(udp_server.getsockname()[1]), result_path]
        if not test_udp:
            client_arguments.append("tcp-only")
        proxylane = subprocess.Popen(
            [os.path.join(temp, "ProxyLane64.exe"), "--auto", "--profile",
             "SecureTest", "--run", sys.executable, "--"] + client_arguments,
            cwd=temp, env=environment)
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline and not os.path.exists(result_path):
                if proxylane.poll() is not None:
                    raise RuntimeError(f"ProxyLane exited early with {proxylane.returncode}")
                time.sleep(0.1)
            if not os.path.exists(result_path):
                raise TimeoutError("proxied client timed out")
            outcome = open(result_path, encoding="utf-8").read()
            if outcome != "PASS":
                raise RuntimeError("proxied client failed:\n" + outcome +
                                   f"\nProxyLane status: {proxylane.poll()}" +
                                   f"\nTCP observations: {tcp_owner}\nUDP observations: {udp_owner}")
            tcp_pids = [item for item in tcp_owner if isinstance(item, int)]
            if tcp_pids != [gonc.pid]:
                raise RuntimeError(f"TCP target owner was {tcp_owner}, expected gonc {gonc.pid}")
            if test_udp and udp_owner != [gonc.pid]:
                raise RuntimeError(f"UDP target owner was {udp_owner}, expected gonc {gonc.pid}")
            suffix = "TCP and UDP" if test_udp else "TCP"
            print(f"PASS: x64 ProxyLane {args.proxy_type} Hook/PRC gonc "
                  f"TLS-PSK {suffix} path")
        finally:
            proxylane.terminate()
            try:
                proxylane.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proxylane.kill()
            gonc.terminate()
            try:
                gonc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                gonc.kill()
            if sys.exc_info()[0] is not None and gonc.stdout:
                output = gonc.stdout.read().decode("utf-8", errors="replace")
                if output:
                    print("gonc output:\n" + output, file=sys.stderr)
            if sys.exc_info()[0] is not None and os.path.exists(trace_path):
                print("secure trace:\n" + open(trace_path, encoding="utf-16-le").read(),
                      file=sys.stderr)


if __name__ == "__main__":
    main()
