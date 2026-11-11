"""Real DNS/TCP+UDP hook -> owned PRC -> proxy chain -> standard Google DoH.

Only test-owned processes are hooked/unhooked. No settings, trust or services
are modified. The fixtures assert that no upstream connection uses port 53.
"""
import argparse
import re
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
        assert ' -> query started' in result.stderr, result.stderr
        assert 'intercepted; waiting for DNS datagram' not in result.stderr, result.stderr
        assert 'query received; resolving via proxy' not in result.stderr, result.stderr
        assert 'DNS response received' not in result.stderr, result.stderr
        assert '. A ->' not in result.stderr and '. AAAA ->' not in result.stderr and '. PTR ->' not in result.stderr, result.stderr
        assert 'REFUSED; reason=private IPv4 reverse lookup; elapsed=' in result.stderr, result.stderr
        assert 'ttl_min=' not in result.stderr and 'cname=' not in result.stderr and 'answers=' not in result.stderr, result.stderr
        assert '; source=local' in result.stderr, result.stderr
        # Every completed, valid transaction has one start and one result.
        pending = {}
        for line in result.stderr.splitlines():
            if not line.startswith('[DoH]') or ' -> ' not in line:
                continue
            key, detail = line.split(' -> ', 1)
            if detail == 'query started':
                pending[key] = pending.get(key, 0) + 1
            elif key in pending:
                assert pending[key] > 0 and '; elapsed=' in detail, line
                lifetime = re.search(r'; cache_ttl=(\d+)s;', detail)
                if detail.startswith('NOERROR') and '; cache=hit' not in detail:
                    assert lifetime and 0 <= int(lifetime[1]) <= 3600, ('Missing effective cache lifetime', line)
                else:
                    assert 'cache_ttl=' not in detail, ('Cache hits and failures keep their original format', line)
                pending[key] -= 1
        assert pending and not any(pending.values()), pending
        if failure:
            assert 'SERVFAIL; reason=' in result.stderr, result.stderr
            assert '; cache=hit' not in result.stderr, result.stderr
        elif query_name == 'example.org':
            assert '; addresses=' in result.stderr, result.stderr
            assert '; cache=hit' in result.stderr and '; shared=yes' in result.stderr, result.stderr
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
