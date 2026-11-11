"""Exercise the shipping QUIC engine with independent aioquic peers; no trust changes."""
import asyncio
import ctypes as C
import json
import os
from pathlib import Path
import sys
import tempfile
import quic_mitm_probe as probe
from quic_hook_certificates import proxylane_key
from quic_late_hook_probe import SlowHTTPS
from cryptography.hazmat.primitives import serialization, hashes

ROOT = Path(__file__).resolve().parents[2]
CALLBACK = C.CFUNCTYPE(None, C.c_size_t)

class Engine:
    def __init__(self):
        self.dll = C.CDLL(os.environ.get('PROXYLANE_TEST_MITM_DLL') or str(ROOT/'src/ProxyLaneMitm/target/x86_64-pc-windows-msvc/release/proxylane_mitm.dll'))
        self.dll.plm_protocol.argtypes=[C.c_char_p,C.c_void_p,C.c_size_t]
        self.dll.plm_quic_open.argtypes=[C.c_char_p,C.c_char_p,C.c_void_p,C.c_size_t,C.c_void_p,CALLBACK,C.c_size_t,C.POINTER(C.c_void_p),C.c_void_p,C.c_size_t]
        self.dll.plm_quic_io.argtypes=[C.c_void_p,C.c_uint32,C.c_uint32,C.c_void_p,C.c_size_t]
    def query(self, **kw):
        b=C.create_string_buffer(4*1024*1024)
        n=self.dll.plm_protocol(json.dumps(kw).encode(),b,len(b))
        assert 0<n<=len(b),(n,b.value)
        return json.loads(b.value)

class Bridge(asyncio.DatagramProtocol):
    serial=0
    def __init__(self, engine, origin):
        Bridge.serial+=1;self.id=Bridge.serial
        self.engine=engine;self.origin=origin;self.client=None;self.handle=C.c_void_p();self.failure=None
        self.loop=asyncio.get_running_loop()
        self.callback=CALLBACK(lambda _:self.loop.call_soon_threadsafe(self.drain))
    def connection_made(self, transport): self.transport=transport
    def datagram_received(self,data,addr):
        side=int(addr[1]==self.origin)
        if not self.handle:
            self.client=addr
            meta=dict(connection_id=self.id,pid=os.getpid(),process_create_time=1,socket=1,socket_generation=1,destination='127.0.0.1',port=self.origin,transport='udp')
            error=C.create_string_buffer(2048)
            n=self.engine.dll.plm_quic_open(probe.NAME.encode(),json.dumps(meta).encode(),data,len(data),None,self.callback,0,C.byref(self.handle),error,len(error))
            if n!=1:self.failure=(n,error.value.decode());return
        else:self.engine.dll.plm_quic_io(self.handle,0,side,data,len(data))
        self.drain()
    def drain(self):
        if not self.handle:return
        data=C.create_string_buffer(65536)
        for side in range(2):
            while (n:=self.engine.dll.plm_quic_io(self.handle,1,side,data,len(data)))>0:
                self.transport.sendto(data.raw[:n],('127.0.0.1',self.origin) if side else self.client)
                self.engine.dll.plm_quic_io(self.handle,2,side,None,0)
    def close(self):
        if self.handle:self.engine.dll.plm_quic_io(self.handle,3,0,None,0);self.handle=C.c_void_p()
        self.transport.close()

async def negative_upstream(engine,work,client_config):
    probe.origin_pki(work)
    config=probe.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1])
    config.load_cert_chain(str(work/'origin-cert.pem'),str(work/'origin-key.pem'))
    port=probe.port();events=[]
    server=await probe.serve('127.0.0.1',port,configuration=config,create_protocol=lambda *a,**k:probe.Peer(*a,origin=True,events=events,**k))
    try:
        for skip in (False,True):
            engine.query(type='mitm_options',skip_upstream_verify=skip);engine.query(type='analysis_start')
            transport,bridge=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Bridge(engine,port),local_addr=('127.0.0.1',0))
            try:
                failed=False
                try:
                    async with probe.connect('127.0.0.1',transport.get_extra_info('sockname')[1],configuration=client_config,create_protocol=probe.Peer) as peer:
                        reply=await peer.request('GET')
                        assert bytes(reply['body'])==probe.MARKER
                except ConnectionError:failed=True
                assert failed== (not skip),('upstream certificate policy',skip,failed)
                if not skip:
                    assert not any(e['event']=='request' for e in events)
                    # Final lifecycle follows transport close/draining, not the client's first error.
                    rows=[]
                    for _ in range(80):
                        rows.extend(engine.query(type='poll',limit=512)['records'])
                        if any(r.get('status')=='Failed' and 'UnknownIssuer' in r.get('detail','') for r in rows):break
                        await asyncio.sleep(.05)
                    else:raise AssertionError(rows)
            finally:bridge.close()
        print('PASS strict upstream rejection and explicit verification override')
    finally:server.close();engine.query(type='mitm_options',skip_upstream_verify=False)

async def run():
    probe.isolate()
    base=ROOT/'build/quic-live';base.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=base) as directory:
        work=Path(directory);pki=Path(os.environ['LOCALAPPDATA'])/'ProxyLane'
        os.environ['PROXYLANE_PROTOCOL_CACHE_ROOT']=str(work/'cache')
        origin=SlowHTTPS(work,pki)
        ca,_=proxylane_key(pki/'ca.json')
        config=probe.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1])
        config.load_cert_chain(str(origin.cert),str(origin.key))
        origin_port=probe.port();events=[]
        def origin_peer(*a,**k):
            peer=probe.Peer(*a,origin=True,events=events,**k);send_headers=peer.h3.send_headers
            def send(stream,headers,**kw):
                if dict(headers).get(b':status')==b'200':send_headers(stream,[(b':status',b'103'),(b'link',b'</hint>; rel=preload')])
                return send_headers(stream,headers,**kw)
            peer.h3.send_headers=send;return peer
        server=await probe.serve('127.0.0.1',origin_port,configuration=config,create_protocol=origin_peer)
        engine=Engine();engine.query(type='analysis_start')
        transport,bridge=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Bridge(engine,origin_port),local_addr=('127.0.0.1',0))
        client_config=probe.QuicConfiguration(is_client=True,alpn_protocols=['custom-first','h3'],server_name=probe.NAME,supported_versions=[1])
        client_config.load_verify_locations(cadata=ca.public_bytes(serialization.Encoding.PEM))
        try:
            async with probe.connect('127.0.0.1',transport.get_extra_info('sockname')[1],configuration=client_config,create_protocol=probe.Peer) as peer:
                assert peer._quic.tls._peer_certificate.public_bytes(serialization.Encoding.PEM)!=origin.cert.read_bytes()
                payload=bytes(range(256))*4096
                result=await peer.request('POST',payload)
                assert bytes(result['body'])==payload
                await asyncio.sleep(.3)
                records=engine.query(type='poll',limit=512)
                h3=[r for r in records['records'] if r.get('protocol')=='h3' and r.get('type')=='exchange']
                assert h3,records
                assert any((r['exchange'].get('response') or {}).get('status')==200 for r in h3),h3
                assert any(r['exchange'].get('informational') for r in h3)
                engine.query(type='analysis_stop')
                stopped=engine.query(type='poll',limit=512)
                result=await peer.request('POST',b'forwarding after monitoring stopped',1)
                assert bytes(result['body'])==b'forwarding after monitoring stopped'
                await asyncio.sleep(.3)
                after=engine.query(type='poll',limit=512)
                assert after['next']==stopped['next'],(stopped,after)
                report=dict(non_browser=True,non_443_port=origin_port,mitm_leaf=True,echo_bytes=len(payload),http3_records=len(h3),stop_preserves_connection=True,stop_no_new_records=True,records=records)
                (base/'ffi-result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
                print(json.dumps({k:v for k,v in report.items() if k!='records'}))
            await negative_upstream(engine,work,client_config)
            report['strict_upstream_rejection']=True;report['explicit_verification_override']=True
            (base/'ffi-result.json').write_text(json.dumps(report,indent=2),encoding='utf8')
        finally:
            if bridge.handle:
                error=C.create_string_buffer(2048);engine.dll.plm_quic_io(bridge.handle,5,0,error,len(error))
                print('bridge',bridge.failure,error.value.decode())
            bridge.close();server.close();engine.query(type='shutdown');await asyncio.sleep(.2)

if __name__=='__main__': asyncio.run(run())
