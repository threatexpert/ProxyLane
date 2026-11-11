"""Bounded streaming/cancellation/GOAWAY regression against the shipping MITM DLL.

Uses explicit client roots and temporary local endpoints, never changes OS trust.
All results and temporary payloads live under build/reliability-audit.
"""
import asyncio, ctypes as C, hashlib, json, os, sys, tempfile, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/e2e'))
import quic_mitm_probe as p
from quic_live_ffi_probe import Engine,Bridge
from quic_late_hook_probe import SlowHTTPS
from quic_hook_certificates import proxylane_key
from cryptography.hazmat.primitives import serialization
from aioquic.quic.events import StreamReset,StopSendingReceived,ConnectionTerminated,StreamDataReceived
from aioquic.h3.connection import encode_frame,FrameType
from aioquic.buffer import encode_uint_var, Buffer, BufferReadError

CHUNK=bytes(range(256))*64
EVENTS=[]
class Origin(p.QuicConnectionProtocol):
    def __init__(self,*a,**kw):
        super().__init__(*a,**kw);self.h3=p.H3Connection(self._quic);self.tasks=set();self.stopped=set()
    def quic_event_received(self,event):
        if isinstance(event,StopSendingReceived):
            self.stopped.add(event.stream_id);EVENTS.append(dict(origin_stop=event.error_code,stream=event.stream_id))
        for item in self.h3.handle_event(event):
            if isinstance(item,p.HeadersReceived):
                path=dict(item.headers)[b':path'].decode();sid=item.stream_id
                EVENTS.append(dict(request=path,stream=sid))
                t=asyncio.create_task(self.respond(sid,path));self.tasks.add(t);t.add_done_callback(self.tasks.discard)
    async def respond(self,sid,path):
        try:
            size=int(path.split('/')[-1]) if path.startswith('/body/') else (256*1024 if path=='/early' else 32)
            self.h3.send_headers(sid,[(b':status',b'413' if path=='/early' else b'200'),(b'content-length',str(size).encode())])
            if path=='/early':self._quic.stop_stream(sid,0x100)
            self.transmit()
            if path=='/early':await asyncio.sleep(.1)
            for offset in range(0,size,len(CHUNK)):
                if sid in self.stopped:break
                self.h3.send_data(sid,CHUNK[:min(len(CHUNK),size-offset)],end_stream=offset+len(CHUNK)>=size)
                self.transmit();await asyncio.sleep(.001)
            if path=='/goaway':
                self._quic.send_stream_data(self.h3._local_control_stream_id,encode_frame(FrameType.GOAWAY,encode_uint_var(sid+4)))
                self.transmit()
        except Exception as e:EVENTS.append(dict(origin_error=str(e)))

class Client(p.QuicConnectionProtocol):
    def __init__(self,*a,**kw):
        super().__init__(*a,**kw);self.h3=p.H3Connection(self._quic);self.rows={};self.when_data=None;self.goaways=[];self.stop_upload_on_response=False
        self.uni_data={}
    def quic_event_received(self,event):
        if isinstance(event,StreamDataReceived) and event.stream_id%4==3:
            # Inspect wire GOAWAY independently of aioquic's optional GOAWAY handling.
            wire=self.uni_data[event.stream_id]=self.uni_data.get(event.stream_id,b'')+event.data
            buf=Buffer(data=wire)
            try:
                if buf.pull_uint_var()==0:
                    ids=[]
                    while not buf.eof():
                        kind=buf.pull_uint_var();data=buf.pull_bytes(buf.pull_uint_var())
                        if kind==FrameType.GOAWAY:ids.append(Buffer(data=data).pull_uint_var())
                    self.goaways=ids
            except BufferReadError:pass
        if isinstance(event,StreamReset):
            row=self.rows.get(event.stream_id)
            if row and not row['future'].done():row['future'].set_result(dict(reset=event.error_code,bytes=row['bytes'],headers=row['headers']))
        if isinstance(event,ConnectionTerminated):
            for row in self.rows.values():
                if not row['future'].done():row['future'].set_result(dict(connection_error=event.error_code,bytes=row['bytes']))
        for item in self.h3.handle_event(event):
            if not isinstance(item,(p.HeadersReceived,p.DataReceived)):continue
            row=self.rows.get(item.stream_id)
            if not row:continue
            if isinstance(item,p.HeadersReceived):
                row['headers']+= [(k.decode(),v.decode()) for k,v in item.headers]
                if self.stop_upload_on_response:
                    self._quic.reset_stream(item.stream_id,0x100);self.transmit()
            else:
                row['bytes']+=len(item.data);row['hash'].update(item.data)
                if self.when_data:self.when_data(self,item.stream_id,row['bytes'])
            if item.stream_ended and not row['future'].done():row['future'].set_result(dict(bytes=row['bytes'],headers=row['headers'],sha256=row['hash'].hexdigest(),complete=True))
    async def request(self,path,early=False,timeout=8):
        sid=self._quic.get_next_available_stream_id()
        row=self.rows[sid]=dict(bytes=0,hash=hashlib.sha256(),headers=[],future=asyncio.get_running_loop().create_future())
        headers=[(b':method',b'POST' if early else b'GET'),(b':scheme',b'https'),(b':authority',p.NAME.encode()),(b':path',path.encode())]
        if early:headers.append((b'content-length',b'8388608'))
        self.h3.send_headers(sid,headers,end_stream=not early)
        if early and not self.stop_upload_on_response:self.h3.send_data(sid,CHUNK,end_stream=False)
        self.transmit()
        try:return await asyncio.wait_for(asyncio.shield(row['future']),timeout)
        except TimeoutError:return dict(timeout=True,bytes=row['bytes'],headers=row['headers'])

async def run():
    p.isolate();base=ROOT/'build/reliability-audit';base.mkdir(parents=True,exist_ok=True);report={}
    with tempfile.TemporaryDirectory(dir=base) as tmp:
        work=Path(tmp);os.environ['PROXYLANE_PROTOCOL_CACHE_ROOT']=str(work/'cache')
        pki=Path(os.environ['LOCALAPPDATA'])/'ProxyLane';cert=SlowHTTPS(work,pki);ca,_=proxylane_key(pki/'ca.json')
        sc=p.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1]);sc.load_cert_chain(str(cert.cert),str(cert.key))
        cc=p.QuicConfiguration(is_client=True,alpn_protocols=['h3'],server_name=p.NAME,supported_versions=[1]);cc.load_verify_locations(cadata=ca.public_bytes(serialization.Encoding.PEM))
        port=p.port();server=await p.serve('127.0.0.1',port,configuration=sc,create_protocol=Origin)
        engine=Engine();engine.query(type='mitm_options',settings={'entry_mib':1,'total_mib':16});engine.query(type='analysis_start')
        bridges=[]
        async def get_bridge():
            t,b=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Bridge(engine,port),local_addr=('127.0.0.1',0));bridges.append(b)
            return t.get_extra_info('sockname')[1],b
        try:
            async with p.connect('127.0.0.1',port,configuration=cc,create_protocol=Client) as peer:
                report['early_direct']=await peer.request('/early',early=True)
            bp,b=await get_bridge()
            async with p.connect('127.0.0.1',bp,configuration=cc,create_protocol=Client) as peer:
                report['early_mitm']=await peer.request('/early',early=True)
                peer.stop_upload_on_response=True
                report['early_client_stops_upload']=await peer.request('/early',early=True)
                peer.stop_upload_on_response=False
                report['after_early_other_request']=await peer.request('/ok')
            print('early',report,flush=True)
            assert report['early_mitm']==report['early_direct'],report
            assert report['early_client_stops_upload']==report['early_direct'],report
            assert report['after_early_other_request'].get('complete'),report
            bp,idle_bridge=await get_bridge()
            cc.idle_timeout=.5
            async with p.connect('127.0.0.1',bp,configuration=cc,create_protocol=Client) as peer:
                report['before_idle_timeout']=await peer.request('/ok')
                assert report['before_idle_timeout'].get('complete')
                await asyncio.sleep(3)
                rows=engine.query(type='poll',limit=512)['records']
                closed=[r for r in rows if r.get('type')=='connection' and 'connection ended:' in r.get('detail','')]
                report['idle_connection_statuses']=[{'status':r.get('status'),'detail':r.get('detail')} for r in closed]
                assert any(r['status']=='Closed' and 'timed out' in r['detail'].lower() for r in closed),report['idle_connection_statuses']
            cc.idle_timeout=60
            bp,b=await get_bridge()
            async with p.connect('127.0.0.1',bp,configuration=cc,create_protocol=Client) as peer:
                inflight=asyncio.create_task(peer.request('/body/8388608',timeout=60))
                await asyncio.sleep(.1)
                report['goaway_first']=await peer.request('/goaway');await asyncio.sleep(.2)
                report['goaway_next']=await peer.request('/ok')
                report['goaway_inflight']=await inflight
                for _ in range(100):
                    if peer.goaways:break
                    await asyncio.sleep(.02)
                report['downstream_goaway_ids']=peer.goaways
            print('goaway',report['goaway_next'],flush=True)
            assert report['goaway_next'].get('reset')==0x10b,report['goaway_next']
            assert report['goaway_inflight'].get('complete') and report['goaway_inflight']['bytes']==8388608
            assert report['downstream_goaway_ids'] and min(report['downstream_goaway_ids'])>4,report['downstream_goaway_ids']
            if '--quick' in sys.argv:return
            # aioquic in this Python harness can be CPU/timer limited on Windows.
            # Measure the same workload without MITM; keep a finite deadline and
            # validate every byte instead of treating 90 s as a product SLA.
            start=time.monotonic()
            async with p.connect('127.0.0.1',port,configuration=cc,create_protocol=Client) as peer:
                direct=await asyncio.gather(*(peer.request('/body/16777216',timeout=300) for _ in range(4)))
            expected=hashlib.sha256(CHUNK*1024).hexdigest()
            report['direct_4x16MiB']={'seconds':time.monotonic()-start,'responses':direct}
            assert all(r.get('complete') and r['bytes']==16777216 and r['sha256']==expected for r in direct),direct
            print('direct bulk',report['direct_4x16MiB']['seconds'],flush=True)
            bp,b=await get_bridge()
            async with p.connect('127.0.0.1',bp,configuration=cc,create_protocol=Client) as peer:
                start=time.monotonic()
                rows=await asyncio.gather(*(peer.request('/body/16777216',timeout=300) for _ in range(4)))
                expected=hashlib.sha256(CHUNK*1024).hexdigest()
                report['concurrent_4x16MiB']={'seconds':time.monotonic()-start,'pass':all(r.get('complete') and r['bytes']==16777216 and r['sha256']==expected for r in rows),'responses':rows}
                assert report['concurrent_4x16MiB']['pass'],rows
                print('mitm bulk',report['concurrent_4x16MiB']['seconds'],flush=True)
                cancelled=set()
                def cancel(client,sid,count):
                    if count>=65536 and sid not in cancelled:
                        cancelled.add(sid);client._quic.stop_stream(sid,0x10c);client.transmit();client.when_data=None
                peer.when_data=None
                survivor=asyncio.create_task(peer.request('/body/8388608',timeout=60))
                await asyncio.sleep(.01)
                # Cancel only the newly created stream, not the parallel survivor.
                target=peer._quic.get_next_available_stream_id()
                peer.when_data=lambda c,s,n:cancel(c,s,n) if s==target else None
                report['cancel_download']=await peer.request('/body/8388608',timeout=5)
                report['cancel_survivor']=await survivor
                report['after_cancel_other_request']=await peer.request('/ok')
                assert report['cancel_survivor'].get('complete') and report['cancel_survivor']['bytes']==8388608
                assert report['after_cancel_other_request'].get('complete')
                engine.query(type='analysis_start');stopped=[]
                def stop(client,sid,count):
                    if count>=1048576 and not stopped:
                        t=time.monotonic();engine.query(type='analysis_stop');stopped.append(time.monotonic()-t)
                        report['stop_snapshot']=engine.query(type='poll',limit=512)['next']
                peer.when_data=stop
                report['stop_mid_64MiB']=await peer.request('/body/67108864',timeout=300)
                report['stop_call_seconds']=stopped;await asyncio.sleep(.3)
                report['stop_no_new_records']=engine.query(type='poll',limit=512)['next']==report['stop_snapshot']
                stopped_result=report['stop_mid_64MiB']
                expected_hash=hashlib.sha256()
                for _ in range(4096):expected_hash.update(CHUNK)
                assert stopped_result.get('complete') and stopped_result['bytes']==67108864 and stopped_result['sha256']==expected_hash.hexdigest(),stopped_result
                assert report['stop_no_new_records']
            report['finished_handles_retained']=[engine.dll.plm_quic_io(b.handle,4,0,None,0) for b in bridges]
            report['events']=EVENTS
        finally:
            for b in bridges:b.close()
            server.close();engine.query(type='shutdown');await asyncio.sleep(.2)
            (base/'quic-results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='events'},indent=2),flush=True)
if __name__=='__main__':asyncio.run(run())
