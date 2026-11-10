"""Real DNS/TCP+UDP hook -> owned PRC -> proxy chain -> standard Google DoH.

Only test-owned processes are hooked/unhooked. No settings, trust or services
are modified. The fixtures assert that no upstream connection uses port 53.
"""
import argparse
import subprocess
from doh_transport import Proxy, isolate_controller


def run(host, mode, failure=False, url="https://dns.google/dns-query", bootstrap="8.8.8.8", query_name="example.org"):
    socks = Proxy('socks') if mode != 'http' else None
    http = Proxy('http') if mode != 'socks' else None
    if failure:
        url = url.rsplit("/", 1)[0] + "/not-a-doh-endpoint"
    args = [host, str(socks.port if socks else 0), str(http.port if http else 0), url, bootstrap]
    args.append("name=" + query_name)
    if failure:
        args.append('failure')
    try:
        result = subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=160)
        fixtures = [p for p in [socks, http] if p]
        assert result.returncode == 0, (result.stdout, result.stderr, [p.requests for p in fixtures])
        assert 'DNS_RELAY_PASS' in result.stdout
        for p in fixtures:
            assert not p.errors, p.errors
            assert all(len(r) == 3 and r[1] != 53 for r in p.requests), p.requests
        last = http or socks
        assert all(r[:2] == (bootstrap, 443) for r in last.requests), last.requests
        # Only the stable default fixture asserts an exact cached query count;
        # arbitrary live domains may legitimately have zero/short TTLs.
        if not failure and query_name == "example.org":
            assert len(last.requests) == 3, ('Only public PTR, coalesced A and fresh AAAA may reach DoH; private PTR must stay local', last.requests)
        print('PASS DNS relay', mode, 'SERVFAIL/no fallback' if failure else 'TCP+UDP replies+fresh UDP query+cache+block priority', flush=True)
    finally:
        for p in [socks, http]:
            if p:
                p.listener.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument("--doh-url", default="https://dns.google/dns-query")
    parser.add_argument("--bootstrap", default="8.8.8.8")
    parser.add_argument("--query-name", default="example.org")
    args = parser.parse_args()
    isolate_controller()
    for mode in ['socks', 'http', 'chain']:
        run(args.host, mode, url=args.doh_url, bootstrap=args.bootstrap, query_name=args.query_name)
    run(args.host, 'chain', True, url=args.doh_url, bootstrap=args.bootstrap, query_name=args.query_name)
