"""Automatic ALPN selection + independent QUIC DATAGRAM forwarding and durable boundaries."""
import asyncio,json,os,time
from pathlib import Path
import quic_mitm_probe as p
from quic_raw_probe import Peer,ALPN,Lossy,until,ROOT
from quic_live_ffi_probe import Engine
from quic_late_hook_probe import SlowHTTPS
from quic_hook_certificates import proxylane_key
from cryptography.hazmat.primitives import serialization

async def run():
    p.isolate()
    work=ROOT/'build/quic-auto'/str(time.time_ns());work.mkdir(parents=True)
    os.environ['PROXYLANE_PROTOCOL_CACHE_ROOT']=str(work/'cache')
    pki=Path(os.environ['LOCALAPPDATA'])/'ProxyLane'
    origin=SlowHTTPS(work,pki);ca,_=proxylane_key(pki/'ca.json')
    cfg=p.QuicConfiguration(is_client=False,alpn_protocols=[ALPN],supported_versions=[1],max_datagram_frame_size=65536)
    cfg.load_cert_chain(str(origin.cert),str(origin.key))
    peers=[]
    def factory(*a,**kw):
        peer=Peer(*a,server=True,**kw);peers.append(peer);return peer
    port=p.port();server=await p.serve('127.0.0.1',port,configuration=cfg,create_protocol=factory)
    engine=Engine();opts=engine.query(type='mitm_options')['settings']
    assert 'quic_raw_enabled' not in opts and 'quic_raw_alpns' not in opts
    opts['recording']=dict(enabled=True,directory=str(work/'recordings'),capacity_mib=256,reserve_mib=16)
    opts['history_rows']=1024
    engine.query(type='mitm_options',settings=opts);engine.query(type='analysis_start')
    transport,bridge=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Lossy(engine,port),local_addr=('127.0.0.1',0))
    cfg=p.QuicConfiguration(is_client=True,alpn_protocols=['h3','other-protocol',ALPN],server_name=p.NAME,
                           supported_versions=[1],max_datagram_frame_size=65536)
    cfg.load_verify_locations(cadata=ca.public_bytes(serialization.Encoding.PEM))
    try:
        async with p.connect('127.0.0.1',transport.get_extra_info('sockname')[1],configuration=cfg,create_protocol=Peer) as client:
            assert client.alpn==ALPN and peers[0].alpn==ALPN
            assert client._quic._remote_max_datagram_frame_size
            # Datagram boundaries include empty payloads. Server can send independently.
            data=[b'',b'a',b'DNS-like\x00\x01',bytes(range(250))*4]
            for packet in data:
                client.send_datagram(packet)
                await until(lambda:packet in client.datagrams,10)
            peers[0].send_datagram(b'server initiated datagram')
            await until(lambda:b'server initiated datagram' in client.datagrams,10)
            assert peers[0].datagrams==data
            print('PASS automatic mixed-ALPN selection and bidirectional/empty DATAGRAMs',flush=True)
            # Concurrent reliable transfer and datagram burst. Loss applies to QUIC
            # packets, not synthesized payloads: reliable streams must recover exactly.
            large=bytes(range(256))*8192
            bridge.loss=True
            ids=[client.send(large),client.send(large)]
            burst=[b'burst:'+n.to_bytes(4,'big')+b'x'*512 for n in range(400)]
            for i,packet in enumerate(burst):
                client.send_datagram(packet)
                if i%8==0:await asyncio.sleep(.003)
            assert all(x==large for x in await asyncio.gather(*(client.completed(s) for s in ids)))
            await asyncio.sleep(.5);bridge.loss=False
            received=[x for x in client.datagrams if x.startswith(b'burst:')]
            assert received and all(x in burst for x in received)
            assert len(received)==len(set(received)) # QUIC duplicate packets must not duplicate application datagrams.
            # Normal traffic still works after congestion/loss.
            marker=client.send(b'after datagrams');assert await client.completed(marker)==b'after datagrams'
            await asyncio.sleep(.5)
            status=engine.query(type='recording_status');recording=Path(status['directory'])
            assert not status.get('quality',{}).get('capture_incomplete'),status
            engine.query(type='analysis_stop')
            events=[json.loads(x) for f in recording.glob('*.jsonl') for x in f.read_text(encoding='utf8').splitlines()]
            # Cache context carries protocol and connection identity on each event.
            dg=[e for e in events if e.get('type')=='datagram' and e.get('context',{}).get('protocol')=='quic_datagram']
            if not dg:
                (work/'event-sample.json').write_text(json.dumps(events[:25],indent=2),encoding='utf8')
            assert dg,events[:5]
            for side,expected in [(0,peers[0].datagrams),(1,client.datagrams)]:
                records=[e for e in dg if e['side']==side]
                assert records
                # Received client payloads are a subset of captured inbound data;
                # DATAGRAM is intentionally unreliable under loss.
                recovered=[]
                for e in records:
                    cid=e['cache_id']
                    path=recording/f'payload/{cid//1000:06}/{cid:012}.{"request" if side==0 else "response"}.bin'
                    payload=path.read_bytes()
                    recovered.append(payload[e['offset']:e['offset']+e['length']])
                    connection=e['context']['connection']
                    assert connection['quic_datagrams'] and 'quic_stream_id' not in connection
                assert all(x in recovered for x in expected)
                assert recovered[:4]==data
            frozen={str(f):(f.stat().st_size,f.stat().st_mtime_ns) for f in recording.rglob('*') if f.is_file()}
            client.send_datagram(b'after stop')
            await until(lambda:b'after stop' in client.datagrams,10)
            sid=client.send(b'stream after stop');assert await client.completed(sid)==b'stream after stop'
            await asyncio.sleep(.3)
            assert frozen=={str(f):(f.stat().st_size,f.stat().st_mtime_ns) for f in recording.rglob('*') if f.is_file()}
            report=dict(automatic_alpn=True,datagram_boundaries=True,empty_datagrams=True,
                        concurrent_stream_bytes=2*len(large),datagrams_sent=len(burst),datagrams_echoed=len(received),
                        lost_packets=bridge.dropped,duplicated_packets=bridge.duplicated,
                        recorded_datagrams=len(dg),stop_preserves_datagrams_and_streams=True,recording=str(recording))
            (work/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
            print(json.dumps(report),flush=True)
    finally:
        bridge.close();server.close();engine.query(type='shutdown');await asyncio.sleep(.2)
if __name__=='__main__':asyncio.run(run())
