"""Low parser limits must never reject or serialize QUIC forwarding.
Uses local independent aioquic peers; artifacts stay in build/, no trust changes.
"""
import asyncio
import json
import os
import time
from pathlib import Path
import quic_mitm_probe as p
from quic_live_ffi_probe import Engine, Bridge
from quic_late_hook_probe import SlowHTTPS
from quic_hook_certificates import proxylane_key
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[2]

class BatchedOrigin(p.Peer):
    def __init__(self, *args, **kw):
        super().__init__(*args, origin=True, **kw)
        self.held = []
        self.batch = 16
        self.slow = False
        self.tasks = set()
        self.send_data = self.h3.send_data
        self.h3.send_data = self.hold

    def hold(self, stream, data, **kw):
        if self.slow:
            async def send():
                for start in range(0, len(data), 16384):
                    end = min(start + 16384, len(data))
                    self.send_data(stream, data[start:end], end_stream=end == len(data))
                    self.transmit()
                    await asyncio.sleep(.002)
            task = asyncio.create_task(send())
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            return
        self.held.append((stream, data, kw))
        if len(self.held) >= self.batch:
            for stream, data, kw in self.held:
                self.send_data(stream, data, **kw)
            self.held.clear()
            self.transmit()

async def until(predicate):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(.01)
    raise TimeoutError("test progress did not arrive")

async def run():
    p.isolate()
    work = ROOT / 'build/quic-live' / f'analysis-isolation-{time.time_ns()}'
    work.mkdir(parents=True)
    os.environ['PROXYLANE_PROTOCOL_CACHE_ROOT'] = str(work / 'cache')
    pki = Path(os.environ['LOCALAPPDATA']) / 'ProxyLane'
    cert = SlowHTTPS(work, pki)
    ca, _ = proxylane_key(pki / 'ca.json')
    config = p.QuicConfiguration(is_client=False, alpn_protocols=['h3'], supported_versions=[1])
    config.load_cert_chain(str(cert.cert), str(cert.key))
    origins = []
    def factory(*args, **kw):
        peer = BatchedOrigin(*args, **kw)
        origins.append(peer)
        return peer
    port = p.port()
    server = await p.serve('127.0.0.1', port, configuration=config, create_protocol=factory)
    engine = Engine()
    settings = engine.query(type='mitm_options')['settings']
    settings.update(pending_requests=1, connections=1)
    settings['recording'] = dict(enabled=True, directory=str(work/'recordings'), capacity_mib=256, reserve_mib=16)
    engine.query(type='mitm_options', settings=settings)
    engine.query(type='analysis_start')
    transport, bridge = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: Bridge(engine, port), local_addr=('127.0.0.1', 0))
    client_config = p.QuicConfiguration(is_client=True, alpn_protocols=['h3'], server_name=p.NAME, supported_versions=[1])
    client_config.load_verify_locations(cadata=ca.public_bytes(serialization.Encoding.PEM))
    try:
        async with p.connect('127.0.0.1', transport.get_extra_info('sockname')[1],
                             configuration=client_config, create_protocol=p.Peer) as client:
            # Responses withheld until 16 requests arrive: serializing at the
            # parser limit of 1 deadlocks; resetting above 1 also fails this test.
            bodies = [(i.to_bytes(4, 'big') * 1024) for i in range(160)]
            replies = await asyncio.gather(*(client.request('POST', b, i) for i, b in enumerate(bodies)))
            assert all(bytes(r['body']) == b for r, b in zip(replies, bodies))
            print('PASS 160 concurrent HTTP/3 requests with parser limits set to 1', flush=True)
            origins[0].batch = 1
            sid = client._quic.get_next_available_stream_id()
            client.h3.send_headers(sid, [(b':method', b'POST'), (b':scheme', b'https'),
                (b':authority', p.NAME.encode()), (b':path', b'/cancel')])
            client.h3.send_data(sid, b'partial', end_stream=False)
            client.transmit()
            await asyncio.sleep(.1)
            client._quic.reset_stream(sid, 0x10c)
            client._quic.stop_stream(sid, 0x10c)
            client.transmit()
            assert bytes((await client.request('POST', b'after cancellation', 500))['body']) == b'after cancellation'
            origins[0].slow = True
            body = bytes(range(256)) * 32768
            active = asyncio.create_task(client.request('POST', body, 900, timeout=120))
            try:
                await until(lambda: active.done() or any(65536 <= len(v['body']) < len(body) for v in client.streams.values()))
                if active.done():
                    await active
                    raise AssertionError("large response completed before stop checkpoint")
            except Exception:
                print('large transfer progress', {sid: len(v['body']) for sid,v in origins[0].streams.items()},
                      'client', {sid: len(v['body']) for sid,v in client.streams.items()}, flush=True)
                active.cancel()
                await asyncio.gather(active, return_exceptions=True)
                raise
            assert not active.done()
            engine.query(type='analysis_stop')
            recording = Path(engine.query(type='recording_status')['directory'])
            def files():
                return {str(f.relative_to(recording)): (f.stat().st_size, f.stat().st_mtime_ns)
                        for f in recording.rglob('*') if f.is_file()}
            frozen = files()
            assert bytes((await active)['body']) == body
            origins[0].slow = False
            assert bytes((await client.request('POST', b'after stop', 901))['body']) == b'after stop'
            await asyncio.sleep(.3)
            assert files() == frozen
            events = [json.loads(line) for f in sorted(recording.glob('events-*.jsonl'))
                      for line in f.read_text(encoding='utf-8').splitlines()]
            ends = [e for e in events if e['type'] == 'exchange_end']
            assert len({(e['context']['connection']['id'], e['exchange_id']) for e in ends}) == len(ends)
            complete = sum(bool((e.get('response') or {}).get('complete')) for e in ends)
            manifest = json.loads((recording/'manifest.json').read_text())
            # Saturation may slow forwarding, but must not sacrifice recording.
            quality = manifest['quality']
            assert complete >= 161, (complete, manifest)
            assert quality['gap_count'] == 0 and not quality['capture_incomplete'], manifest
            assert manifest['quality']['analysis_fallback_count'] == 0
            reasons = [e['reason'] for e in events if e['type'] == 'capture_end']
            assert 'HTTP/3 request and response completed' in reasons
            assert 'monitoring stopped' in reasons
            assert any('application request body:' in r and 'H3_REQUEST_CANCELLED' in r for r in reasons), reasons
            heads = [e for e in events if e['type'] == 'message_head']
            assert heads and all(e.get('observed_unix_ms', 0) > 0 for e in heads)
            report = dict(concurrent_requests=160, parser_limit=1, cancelled_stream_isolated=True,
                          stop_during_transfer_bytes=len(body), stopped_files_unchanged=True,
                          completed_recorded_responses=complete,
                          recording=str(recording), quality=manifest['quality'])
            (work/'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
            print(json.dumps(report), flush=True)
    finally:
        for origin in origins:
            for task in list(origin.tasks):
                task.cancel()
        bridge.close()
        server.close()
        engine.query(type='shutdown')
        await asyncio.sleep(.2)

if __name__ == '__main__':
    asyncio.run(run())
