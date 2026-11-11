"""A target's small DATAGRAM limit cannot close independent reliable streams."""
import asyncio,json,os,time
from pathlib import Path
import quic_mitm_probe as p
from quic_raw_probe import Peer,ALPN,ROOT,until
from quic_live_ffi_probe import Engine,Bridge
from quic_late_hook_probe import SlowHTTPS
from quic_hook_certificates import proxylane_key
from cryptography.hazmat.primitives import serialization

async def run():
    p.isolate()
    work=ROOT/'build/quic-datagram-limit'/str(time.time_ns());work.mkdir(parents=True)
    os.environ['PROXYLANE_PROTOCOL_CACHE_ROOT']=str(work/'cache')
    pki=Path(os.environ['LOCALAPPDATA'])/'ProxyLane';origin=SlowHTTPS(work,pki)
    ca,_=proxylane_key(pki/'ca.json')
    cfg=p.QuicConfiguration(is_client=False,alpn_protocols=[ALPN],supported_versions=[1],max_datagram_frame_size=64)
    cfg.load_cert_chain(str(origin.cert),str(origin.key))
    port=p.port()
    server=await p.serve('127.0.0.1',port,configuration=cfg,create_protocol=lambda *a,**k:Peer(*a,server=True,**k))
    engine=Engine();opts=engine.query(type='mitm_options')['settings']
    opts['recording']=dict(enabled=True,directory=str(work/'recordings'),capacity_mib=64,reserve_mib=16)
    engine.query(type='mitm_options',settings=opts);engine.query(type='analysis_start')
    transport,bridge=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Bridge(engine,port),local_addr=('127.0.0.1',0))
    cfg=p.QuicConfiguration(is_client=True,alpn_protocols=[ALPN],server_name=p.NAME,supported_versions=[1],max_datagram_frame_size=65536)
    cfg.load_verify_locations(cadata=ca.public_bytes(serialization.Encoding.PEM))
    try:
        async with p.connect('127.0.0.1',transport.get_extra_info('sockname')[1],configuration=cfg,create_protocol=Peer) as client:
            client.send_datagram(b'fits')
            await until(lambda:b'fits' in client.datagrams,10)
            client.send_datagram(b'x'*1000)
            await asyncio.sleep(.3)
            sid=client.send(b'still reliable')
            assert await client.completed(sid)==b'still reliable'
            client.send_datagram(b'after oversized')
            await until(lambda:b'after oversized' in client.datagrams,10)
            await asyncio.sleep(.3)
            records=engine.query(type='poll',limit=512)['records']
            assert any(r.get('protocol')=='quic_datagram' and 'forwarding dropped' in (r.get('stream',{}).get('problem') or '') for r in records),records
            path=Path(engine.query(type='recording_status')['directory'])
            engine.query(type='analysis_stop')
            events=[json.loads(line) for f in path.glob('*.jsonl') for line in f.read_text(encoding='utf8').splitlines()]
            assert any(e.get('type')=='transport_note' and 'forwarding dropped' in e['message'] for e in events)
            report=dict(small_peer_limit=True,oversized_drop_visible=True,drop_recorded=True,
                        reliable_stream_survives=True,subsequent_datagrams_survive=True)
            (work/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
            print(json.dumps(report),flush=True)
    finally:
        bridge.close();server.close();engine.query(type='shutdown');await asyncio.sleep(.2)
if __name__=='__main__':asyncio.run(run())
