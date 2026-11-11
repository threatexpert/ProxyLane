"""Live DoH probes, cancellation, node errors and the 12-second deadline."""
import argparse
import json
import socket
import subprocess
import threading
from doh_transport import Proxy, exact, isolate_controller


def host(args, port, mode, detail=None, ssh=None, url=None, bootstrap=None, third=None):
    command = [args.host, str(port), str(ssh['a']) if ssh else '0',
               ssh['fingerprint'] if ssh else '-', url or args.url,
               bootstrap or args.bootstrap, mode]
    if detail:
        command.append(detail)
    if third:
        assert detail
        command.append(str(third))
    result = subprocess.run(command, capture_output=True, text=True, errors='replace', timeout=45)
    assert result.returncode == 0, (command, result.stdout, result.stderr)
    print('PASS', mode, result.stdout.strip(), flush=True)
    return result.stdout


def stalled(args, cancel, ssh=None):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0)); listener.listen()
    stop = threading.Event()
    def serve():
        peer, _ = listener.accept()
        with peer:
            stop.wait(18)  # Do not complete SOCKS negotiation.
    threading.Thread(target=serve, daemon=True).start()
    try:
        result = host(args, listener.getsockname()[1], 'cancel' if cancel else 'timeout',
                      None if cancel else 'connection timed out (12 s)', ssh=ssh,
                      bootstrap='192.0.2.1,192.0.2.2')
        if not cancel:
            assert 'hop=0' in result, result
            assert 'attempts=1' in result, 'Do not retry a stalled proxy with another resolver IP'
    finally:
        stop.set(); listener.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--url', default='https://dns.alidns.com/dns-query')
    parser.add_argument('--bootstrap', default='223.5.5.5')
    parser.add_argument('--online', action='store_true')
    parser.add_argument('--ssh-config')
    args = parser.parse_args()
    isolate_controller()
    stalled(args, False)
    stalled(args, True)
    proxy = Proxy('socks')
    try:
        result = host(args, proxy.port, 'error', 'handshake failed', bootstrap='192.0.2.254')
        assert 'hop=0' in result, result
        if args.online:
            before = len(proxy.requests)
            host(args, proxy.port, 'pass')
            assert len(proxy.requests) - before == 2, 'Each probe must use a fresh connection'
            assert all(r[1] == 443 for r in proxy.requests), 'No target IP connections'
            result = host(args, proxy.port, 'error', 'certificate', url='https://invalid.example/dns-query')
            assert 'hop=-1' in result, 'TLS failure must not blame a proxy node'
        if args.ssh_config:
            cfg = json.load(open(args.ssh_config, encoding='utf-8'))
            stalled(args, False, ssh=cfg)
            unknown = dict(cfg, fingerprint='unknown')
            before = len(proxy.requests)
            result = host(args, proxy.port, 'error', 'SHA256:', ssh=unknown, bootstrap='192.0.2.1,192.0.2.2')
            assert 'hop=1' in result, 'SSH trust failure must identify hop 2'
            assert 'attempts=1' in result, result
            assert len(proxy.requests) - before == 1, 'Do not retry SSH trust errors with another resolver IP'
            # A third proxy refuses authentication. Earlier hops must not be
            # rebuilt just because the profile contains two resolver IPs.
            rejected = socket.socket()
            rejected.bind(('127.0.0.1', 0)); rejected.listen()
            def reject():
                try:
                    while True:
                        peer, _ = rejected.accept()
                        with peer:
                            _, methods = exact(peer, 2); exact(peer, methods)
                            peer.sendall(b'\x05\xff')
                except OSError:
                    pass
            threading.Thread(target=reject, daemon=True).start()
            try:
                before = len(proxy.requests)
                result = host(args, proxy.port, 'error', 'handshake failed', ssh=cfg,
                              bootstrap='192.0.2.1,192.0.2.2', third=rejected.getsockname()[1])
                assert 'hop=2' in result, 'Identify the invalid third node'
                assert 'attempts=1' in result, result
                assert len(proxy.requests) - before == 1, 'Invalid third node must fail after one chain attempt'
            finally:
                rejected.close()
            unavailable = socket.socket()
            unavailable.bind(('127.0.0.1', 0))
            closed_port = unavailable.getsockname()[1]
            unavailable.close()
            before = len(proxy.requests)
            result = host(args, proxy.port, 'error', 'DoH', ssh=cfg,
                          bootstrap='192.0.2.1,192.0.2.2', third=closed_port)
            assert 'attempts=1' in result, result
            assert len(proxy.requests) - before == 1, 'Unreachable third node must not rebuild the route'
            if args.online:
                before = len(proxy.requests)
                host(args, proxy.port, 'pass', ssh=cfg)
                assert len(proxy.requests) - before == 2, 'Two fresh SOCKS/SSH probes, no second business tunnel'
        assert not proxy.errors, proxy.errors
    finally:
        proxy.listener.close()
