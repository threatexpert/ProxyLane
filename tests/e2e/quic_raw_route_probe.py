"""Custom ALPN through the shipping injected Hook/PRC UDP route, no OS trust edits."""
import asyncio, json, os, socket, subprocess, sys, time
from contextlib import asynccontextmanager
from pathlib import Path
import quic_mitm_probe as p
from quic_raw_probe import ALPN, Peer
from quic_live_route_probe import Host, ROOT, RUNTIME
from quic_late_hook_probe import SlowHTTPS
from quic_hook_certificates import proxylane_key
from aioquic.quic.connection import QuicConnection
from cryptography.hazmat.primitives import serialization

@asynccontextmanager
async def connected(port, config, ip):
    transport, peer = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: Peer(QuicConnection(configuration=config)), remote_addr=(ip, port))
    try:
        peer.connect((ip, port))
        await asyncio.wait_for(peer.wait_connected(), 20)
        yield peer
    finally:
        peer.close()
        await peer.wait_closed()
        transport.close()

async def child(port, ca, ip):
    assert await asyncio.to_thread(input) == 'start'
    config = p.QuicConfiguration(is_client=True, alpn_protocols=[ALPN],
                                server_name=p.NAME, supported_versions=[1],max_datagram_frame_size=65536)
    config.load_verify_locations(cafile=ca)
    async with connected(int(port), config, ip) as peer:
        data = bytes(range(256)) * 8192
        sid = peer.send(data)
        assert await peer.completed(sid) == data
        from quic_raw_probe import until
        peer.send_datagram(b'route datagram')
        await until(lambda:b'route datagram' in peer.datagrams,10)
        print(json.dumps({'bytes': len(data), 'stream': sid}), flush=True)
        assert await asyncio.to_thread(input) == 'after'
        sid = peer.send(b'new raw stream after monitoring stopped')
        assert await peer.completed(sid) == b'new raw stream after monitoring stopped'
        peer.send_datagram(b'datagram after stop')
        await until(lambda:b'datagram after stop' in peer.datagrams,10)
        print(json.dumps({'after_stop': True}), flush=True)

async def run(route):
    p.isolate()
    work = ROOT / 'build/quic-raw-route' / (route + '-' + str(time.time_ns()))
    work.mkdir(parents=True)
    pki = Path(os.environ['LOCALAPPDATA']) / 'ProxyLane'
    origin = SlowHTTPS(work, pki)
    ca, _ = proxylane_key(pki / 'ca.json')
    (work / 'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    config = p.QuicConfiguration(is_client=False, alpn_protocols=[ALPN], supported_versions=[1],max_datagram_frame_size=65536)
    config.load_cert_chain(str(origin.cert), str(origin.key))
    port = p.port()
    server = await p.serve('0.0.0.0', port, configuration=config,
                          create_protocol=lambda *a, **k: Peer(*a, server=True, **k))
    processes = p.Processes(work)
    relay_port = p.port()
    if route == 'socks':
        processes.start('relay', [sys.executable, str(ROOT / 'tests/e2e/socks5_udp_server.py'),
                                 '--port', str(relay_port), '--log', str(work / 'relay.log')])
        for _ in range(100):
            if (work / 'relay.log').exists(): break
            await asyncio.sleep(.05)
    host = Host(work, proxy='SOCKS5' if route == 'socks' else 'NOPROXY', port=relay_port)
    client = None
    log = open(work / 'client.log', 'w')
    try:
        opts = (await asyncio.to_thread(host.call, type='mitm_options'))['settings']
        await asyncio.to_thread(host.call, type='mitm_options', settings=opts)
        await asyncio.to_thread(host.call, type='monitor_start', decrypt=False, quic=True)
        ip = '203.0.113.10' if route == 'socks' else next(
            x for x in socket.gethostbyname_ex(socket.gethostname())[2] if not x.startswith('127.'))
        client = subprocess.Popen([sys.executable, __file__, 'child', str(port),
                                   str(work / 'ca.pem'), ip],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                                  text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        attached = await asyncio.to_thread(host.call, type='attach', pid=client.pid)
        assert attached['result'] == 0xff01, attached
        await asyncio.sleep(.5)
        client.stdin.write('start\n'); client.stdin.flush()
        first = await asyncio.wait_for(asyncio.to_thread(client.stdout.readline), 60)
        assert first, 'client failed; see ' + str(work / 'client.log')
        await asyncio.sleep(.5)
        records = await asyncio.to_thread(host.call, type='poll', limit=512)
        streams = [r for r in records.get('records', []) if r.get('type') == 'stream'
                   and r.get('protocol') == 'quic_stream']
        assert streams, records
        assert all(r['connection']['pid'] == client.pid for r in streams)
        assert all(r['connection']['quic_alpn'] == ALPN for r in streams)
        assert any(r['connection']['quic_stream_id'] == 0 for r in streams)
        assert any(r.get('protocol')=='quic_datagram' and r['connection']['pid']==client.pid for r in records['records'])
        await asyncio.to_thread(host.call, type='monitor_stop')
        snapshot = await asyncio.to_thread(host.call, type='poll', limit=512)
        client.stdin.write('after\n'); client.stdin.flush()
        after = await asyncio.wait_for(asyncio.to_thread(client.stdout.readline), 20)
        assert json.loads(after)['after_stop']
        await asyncio.sleep(.3)
        assert (await asyncio.to_thread(host.call, type='poll', limit=512))['next'] == snapshot['next']
        report = dict(route=route, non_browser=True, non_443_port=port,
                      transparent_udp_route=True, stream_records=len(streams),
                      process_identity=True, stop_preserves_connection=True, transfer=json.loads(first))
        (work / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf8')
        print(json.dumps(report), flush=True)
    finally:
        if client and client.poll() is None: client.kill(); client.wait()
        host.close(); server.close(); processes.close(); log.close()

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'child': asyncio.run(child(*sys.argv[2:]))
    else: asyncio.run(run(sys.argv[1] if len(sys.argv) > 1 else 'noproxy'))
