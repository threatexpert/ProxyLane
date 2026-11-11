"""Local-only UDP hook regression using the existing SOCKS5 datagram fixture."""
import argparse
import subprocess
from doh_transport import Proxy, isolate_controller


def run(host, mode):
    proxy = Proxy("socks")
    try:
        result = subprocess.run([host, str(proxy.port), mode], capture_output=True,
                                text=True, errors="replace", timeout=45)
        assert result.returncode == 0, (mode, result.stdout, result.stderr, proxy.errors)
        assert "UDP_SEND_HOOK_PASS" in result.stdout, result.stdout
        packets = [request for request in proxy.requests if request[0] == "udp"]
        assert len(packets) == (120 if mode == "normal" else 0), (mode, proxy.requests)
        assert len(proxy.requests) == len(packets), "No external TCP/DoH/plain DNS connection is needed"
        assert not proxy.errors, proxy.errors
        print("PASS", mode, len(packets), "upstream datagrams", flush=True)
    finally:
        proxy.listener.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--doh", action="store_true")
    args = parser.parse_args()
    isolate_controller()
    for mode in ["normal", "blocked", "doh-blocked", "ipv6-blocked", "mdns-blocked"]:
        run(args.host, mode)
    if args.doh:
        run(args.host, "doh-local")
