"""Opaque QUIC MITM: independent aioquic peers, loss/duplicates/reordering.
Only owned local endpoints and build/ artifacts; no OS trust or browser changes.
"""
import asyncio, base64, ctypes as C, hashlib, json, os, time
from pathlib import Path
import quic_mitm_probe as p
from quic_live_ffi_probe import Engine, Bridge
from quic_late_hook_probe import SlowHTTPS
from quic_hook_certificates import proxylane_key
from aioquic.quic.events import StreamDataReceived, StreamReset, StopSendingReceived, HandshakeCompleted, DatagramFrameReceived
from cryptography.hazmat.primitives import serialization

ALPN='proxylane-raw-test/1'
ROOT=Path(__file__).resolve().parents[2]
class Peer(p.QuicConnectionProtocol):
    def __init__(self,*a,server=False,**kw):
        super().__init__(*a,**kw);self.server=server
        self.data={};self.done={};self.resets=[];self.stops=[];self.alpn=None;self.datagrams=[]
    def quic_event_received(self,e):
        if isinstance(e,HandshakeCompleted):
            self.alpn=e.alpn_protocol
            if self.server:
                for uni in [False,True]:
                    sid=self._quic.get_next_available_stream_id(is_unidirectional=uni)
                    self._quic.send_stream_data(sid,b'server-first-'+str(sid).encode(),end_stream=True)
                self.transmit()
        elif isinstance(e,StreamDataReceived):
            buf=self.data.setdefault(e.stream_id,bytearray());buf.extend(e.data)
            if e.end_stream:self.done[e.stream_id]=bytes(buf)
            initiated_server=e.stream_id&1
            if not (e.stream_id&2) and bool(initiated_server)!=self.server:
                if self.server and bytes(buf).startswith(b'CANCEL'):return
                if self.server and bytes(buf).startswith(b'STOP'):
                    self._quic.stop_stream(e.stream_id,0x55);self._quic.reset_stream(e.stream_id,0x56)
                else:self._quic.send_stream_data(e.stream_id,e.data,end_stream=e.end_stream)
                self.transmit()
        elif isinstance(e,StreamReset):self.resets.append((e.stream_id,e.error_code))
        elif isinstance(e,StopSendingReceived):self.stops.append((e.stream_id,e.error_code))
        elif isinstance(e,DatagramFrameReceived):
            self.datagrams.append(bytes(e.data))
            if self.server:self.send_datagram(e.data)
    def send_datagram(self,data):
        self._quic.send_datagram_frame(data);self.transmit()
    def send(self,data,uni=False,sid=None,end=True):
        if sid is None:sid=self._quic.get_next_available_stream_id(is_unidirectional=uni)
        self._quic.send_stream_data(sid,data,end_stream=end);self.transmit();return sid
    async def completed(self,sid):
        await until(lambda:sid in self.done);return self.done[sid]

async def until(check,timeout=240):
    end=time.monotonic()+timeout
    while not check():
        if time.monotonic()>end:raise TimeoutError('QUIC condition timed out')
        await asyncio.sleep(.01)

class Lossy(Bridge):
    def __init__(self,*a,**k):
        super().__init__(*a,**k);self.loss=False;self.count=0;self.dropped=0;self.duplicated=0;self.reordered=0
    def datagram_received(self,data,addr):
        self.count+=1
        if self.loss:
            if self.count%97==0:self.dropped+=1;return
            if self.count%101==0:
                self.reordered+=1;self.loop.call_later(.025,super().datagram_received,data,addr);return
        super().datagram_received(data,addr)
        if self.loss and self.count%211==0:
            self.duplicated+=1;super().datagram_received(data,addr)

async def run():
    p.isolate()
    work=ROOT/'build/quic-raw'/str(time.time_ns());work.mkdir(parents=True)
    os.environ['PROXYLANE_PROTOCOL_CACHE_ROOT']=str(work/'cache')
    pki=Path(os.environ['LOCALAPPDATA'])/'ProxyLane'
    origin=SlowHTTPS(work,pki);ca,_=proxylane_key(pki/'ca.json')
    server_config=p.QuicConfiguration(is_client=False,alpn_protocols=[ALPN],supported_versions=[1],max_data=16*1024*1024,max_stream_data=4*1024*1024)
    server_config.load_cert_chain(str(origin.cert),str(origin.key))
    peers=[]
    def factory(*a,**kw):
        peer=Peer(*a,server=True,**kw);peers.append(peer);return peer
    port=p.port();server=await p.serve('127.0.0.1',port,configuration=server_config,create_protocol=factory)
    engine=Engine();options=engine.query(type='mitm_options')['settings']
    # A tiny HTTP parser quota must not control opaque QUIC stream forwarding.
    options.update(connections=1,pending_requests=1)
    options['recording']=dict(enabled=True,directory=str(work/'recordings'),capacity_mib=256,reserve_mib=16)
    engine.query(type='mitm_options',settings=options);engine.query(type='analysis_start')
    transport,bridge=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Lossy(engine,port),local_addr=('127.0.0.1',0))
    config=p.QuicConfiguration(is_client=True,alpn_protocols=['h3','unknown',ALPN],server_name=p.NAME,supported_versions=[1],max_data=16*1024*1024,max_stream_data=4*1024*1024)
    config.load_verify_locations(cadata=ca.public_bytes(serialization.Encoding.PEM))
    report={}
    try:
        async with p.connect('127.0.0.1',transport.get_extra_info('sockname')[1],configuration=config,create_protocol=Peer) as client:
            assert client.alpn==ALPN
            assert client._quic.tls._peer_certificate.public_bytes(serialization.Encoding.PEM)!=origin.cert.read_bytes()
            await until(lambda:peers and 1 in peers[0].done and 3 in client.done)
            assert peers[0].done[1]==b'server-first-1' and client.done[3]==b'server-first-3'
            # A higher stream ID transmits before lower IDs. IDs must survive the bridge.
            for sid in [0,4]:client._quic._get_or_create_stream_for_send(sid)
            high=client.send(b'high before low',sid=8);await client.completed(high)
            for sid in [0,4]:
                data=b'late lower stream '+str(sid).encode();client.send(data,sid=sid)
                assert await client.completed(sid)==data and peers[0].done[sid]==data
            uni=client.send(b'client uni',uni=True)
            await until(lambda:uni in peers[0].done);assert peers[0].done[uni]==b'client uni'
            print("PASS four stream types and out-of-order stream IDs",flush=True)
            bridge.loss=True
            payloads={}
            for i in range(8):
                body=bytes([i])+bytes(range(256))*8192
                payloads[client.send(body)]=body
            replies=await asyncio.wait_for(asyncio.gather(*(client.completed(s) for s in payloads)),300)
            for (sid,body),reply in zip(payloads.items(),replies):
                assert hashlib.sha256(reply).digest()==hashlib.sha256(body).digest()
                assert peers[0].done[sid]==body
            report.update(parallel_streams=8,bytes_each=len(body),loss_packets=bridge.dropped,duplicates=bridge.duplicated,reordered=bridge.reordered)
            assert all(report[k]>0 for k in ['loss_packets','duplicates','reordered'])
            print("PASS concurrent large streams with loss/duplicates/reordering",flush=True)
            bridge.loss=False
            sid=client.send(b'CANCEL partial upload',end=False)
            await until(lambda:sid in peers[0].data)
            client._quic.reset_stream(sid,0x42);client._quic.stop_stream(sid,0x43);client.transmit()
            await until(lambda:(sid,0x42) in peers[0].resets and (sid,0x43) in peers[0].stops)
            stopped=client.send(b'STOP upload',end=False)
            await until(lambda:(stopped,0x55) in client.stops)
            okay=client.send(b'after cancellation');assert await client.completed(okay)==b'after cancellation'
            print("PASS reset/stop cancellation leaves other streams usable",flush=True)
            # Wait for capture queues to persist complete transfers, then verify bytes by stream identity.
            await asyncio.sleep(1)
            rows=engine.query(type='poll',limit=512)['records']
            streams={r['connection']['quic_stream_id']:r for r in rows if r.get('protocol')=='quic_stream' and r['type']=='stream'}
            assert set(payloads)<=set(streams),streams.keys()
            status=engine.query(type='recording_status');recording=Path(status['directory'])
            assert not status.get('quality',{}).get('capture_incomplete'),status
            for sid,body in payloads.items():
                row=streams[sid];cache=row['stream']['cache']['id']
                for side in ['request','response']:
                    path=recording/f'payload/{cache//1000:06}/{cache:012}.{side}.bin'
                    assert path.read_bytes()==body,(sid,side,path)
            stats=engine.query(type='stats')
            report.update(four_stream_types=True,ids_preserved=True,reset_stop_codes_preserved=True,recorded_payload_hashes=True,recording=str(recording),stats=stats)
            # Stop while an existing stream still has megabytes in flight.
            large=bytes(range(256))*32768
            active=client.send(large)
            await until(lambda:len(client.data.get(active,b''))>=65536)
            assert active not in client.done
            engine.query(type='analysis_stop')
            frozen={str(f.relative_to(recording)):(f.stat().st_size,f.stat().st_mtime_ns) for f in recording.rglob('*') if f.is_file()}
            assert await client.completed(active)==large
            later=client.send(b'new stream on existing connection after stop')
            assert await client.completed(later)==b'new stream on existing connection after stop'
            await asyncio.sleep(.5)
            assert frozen=={str(f.relative_to(recording)):(f.stat().st_size,f.stat().st_mtime_ns) for f in recording.rglob('*') if f.is_file()}
            report.update(stop_during_transfer_bytes=len(large),stop_preserves_connection=True,stopped_recording_unchanged=True)
        (work/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report),flush=True)
    finally:
        error=C.create_string_buffer(2048)
        if bridge.handle:engine.dll.plm_quic_io(bridge.handle,5,0,error,len(error))
        print('bridge:',bridge.failure,error.value.decode(),flush=True)
        bridge.close();server.close();engine.query(type='shutdown');await asyncio.sleep(.2)
if __name__=='__main__':asyncio.run(run())
