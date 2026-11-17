"""Local-only UDP hook regression using the existing SOCKS5 datagram fixture."""
import argparse
import subprocess
from doh_transport import Proxy, isolate_controller


def run(host, mode):
    fake = mode in ("fakeip", "fakeip6")
    proxy = Proxy("socks", udp_domain="udp-send-hook.invalid" if fake else None)
    try:
        result = subprocess.run([host, str(proxy.port), mode], capture_output=True,
                                text=True, errors="replace", timeout=45)
        assert result.returncode == 0, (mode, result.stdout, result.stderr, proxy.errors)
        assert "UDP_SEND_HOOK_PASS" in result.stdout, result.stdout
        packets = [request for request in proxy.requests if request[0] == "udp"]
        assert len(packets) == (120 if mode == "normal" or fake else 0), (mode, proxy.requests)
        if fake:
            assert all(request[1] == 3 for request in packets), proxy.requests
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
    for mode in ["loopback", "loopback-lan-off", "loopback-blocked", "fakeip", "fakeip6",
                 "normal", "blocked", "doh-blocked", "ipv6-blocked", "mdns-blocked"]:
        run(args.host, mode)
    if args.doh:
        run(args.host, "doh-local")
