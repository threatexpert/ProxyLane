"""Real PRC/Hook HTTP/3 recording soak. Own endpoints, explicit CA, no OS trust changes."""
import asyncio, hashlib, json, os, socket, subprocess, sys, time
from pathlib import Path
import psutil
import quic_mitm_probe as p
from quic_live_route_probe import Host
from quic_late_hook_probe import SlowHTTPS
from quic_hook_certificates import proxylane_key
from mitm_transport_reliability import Origin
from mitm_host_reliability import connected, digest
from recording_capture import read_events
from cryptography import x509
from cryptography.hazmat.primitives import serialization

ROOT=Path(__file__).resolve().parents[2]
class HeldOrigin(Origin):
    async def respond(self,sid,path):
        if path=='/body/131072': await asyncio.sleep(1)
        await super().respond(sid,path)

async def child(ip,port,ca,origin,seconds):
    assert await asyncio.to_thread(input)=='start'
    cfg=p.QuicConfiguration(is_client=True,alpn_protocols=['h3'],server_name=p.NAME,supported_versions=[1])
    cfg.load_verify_locations(cafile=ca)
    async with connected(ip,int(port),cfg) as peer:
        assert peer._quic.tls._peer_certificate.public_bytes(serialization.Encoding.DER)!=Path(origin).read_bytes()
        replies=await asyncio.gather(*(peer.request('/body/131072',timeout=90) for _ in range(96)))
        assert all(r.get('complete') and r['sha256']==digest(131072) for r in replies),replies
        total=96;peer.rows.clear();begin=time.monotonic()
        while time.monotonic()-begin<float(seconds):
            replies=await asyncio.gather(*(peer.request('/body/4096',timeout=30) for _ in range(8)))
            assert all(r.get('complete') and r['sha256']==digest(4096) for r in replies),replies
            total+=len(replies);peer.rows.clear();await asyncio.sleep(.25)
        print(json.dumps({'requests':total,'concurrency':96,'elapsed_seconds':time.monotonic()-begin}),flush=True)
        assert await asyncio.to_thread(input)=='after'
        reply=await peer.request('/body/131072',timeout=30)
        assert reply.get('complete') and reply['sha256']==digest(131072),reply
        print('forwarding-after-stop-ok',flush=True)

async def run(seconds):
    p.isolate();work=ROOT/'build/recording-validation'/('concurrency-'+str(time.time_ns()));work.mkdir(parents=True)
    cert=SlowHTTPS(work,Path(os.environ['LOCALAPPDATA'])/'ProxyLane')
    ca,_=proxylane_key(Path(os.environ['LOCALAPPDATA'])/'ProxyLane/ca.json')
    (work/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (work/'origin.der').write_bytes(x509.load_pem_x509_certificate(cert.cert.read_bytes()).public_bytes(serialization.Encoding.DER))
    cfg=p.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1]);cfg.load_cert_chain(str(cert.cert),str(cert.key))
    port=p.port();server=await p.serve('0.0.0.0',port,configuration=cfg,create_protocol=HeldOrigin)
    host=Host(work);client=None;log=open(work/'client.log','w',encoding='utf-8');samples=[]
    try:
        settings=(await asyncio.to_thread(host.call,type='mitm_options'))['settings']
        assert settings['connections']==128,settings
        # More than 32 live H3 requests in one connection; retain the default parser limit.
        settings['pending_requests']=128
        settings['recording']={'enabled':True,'directory':str(work/'recordings'),'capacity_mib':8192,'reserve_mib':16}
        await asyncio.to_thread(host.call,type='mitm_options',settings=settings)
        await asyncio.to_thread(host.call,type='monitor_start',decrypt=False,quic=True)
        archive=Path((await asyncio.to_thread(host.call,type='recording_status'))['directory'])
        assert len(archive.name.split('-')[-1])==16
        ip=next(i for i in socket.gethostbyname_ex(socket.gethostname())[2] if not i.startswith('127.'))
        client=subprocess.Popen([sys.executable,__file__,'child',ip,str(port),str(work/'ca.pem'),str(work/'origin.der'),str(seconds)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        assert (await asyncio.to_thread(host.call,type='attach',pid=client.pid))['result']==0xff01
        await asyncio.sleep(.5);client.stdin.write('start\n');client.stdin.flush()
        result=asyncio.create_task(asyncio.to_thread(client.stdout.readline));begin=time.monotonic();proc=psutil.Process(host.p.pid)
        peak=0
        while not result.done():
            await asyncio.sleep(.5)
            status=await asyncio.to_thread(host.call,type='recording_status')
            assert not status['stopped'],status
            stats=await asyncio.to_thread(host.call,type='stats')
            peak=max(peak,stats['active_connections'])
            samples.append({'seconds':round(time.monotonic()-begin,2),'rss':proc.memory_info().rss,'cpu':sum(proc.cpu_times()[:2]),
                'active':stats['active_connections'],'parsers':stats['active_parsers'],'used':status['used_bytes'],'quality':status['quality']})
            if len(samples)%60==0:print(json.dumps({'progress_seconds':samples[-1]['seconds'],'peak_active':peak,'sample':samples[-1]}),flush=True)
            assert time.monotonic()-begin<seconds+150,'soak timeout'
        line=await result;assert line,(work/'client.log').read_text();report=json.loads(line)
        await asyncio.to_thread(host.call,type='monitor_stop')
        status=await asyncio.to_thread(host.call,type='recording_status');assert not status['stopped'],status
        before={str(f.relative_to(archive)):(f.stat().st_size,f.stat().st_mtime_ns) for f in archive.rglob('*') if f.is_file()}
        client.stdin.write('after\n');client.stdin.flush()
        assert (await asyncio.wait_for(asyncio.to_thread(client.stdout.readline),45)).strip()=='forwarding-after-stop-ok'
        assert await asyncio.to_thread(client.wait,20)==0
        assert before=={str(f.relative_to(archive)):(f.stat().st_size,f.stat().st_mtime_ns) for f in archive.rglob('*') if f.is_file()}
        lines=read_events(archive)
        heads=[e for e in lines if e['type']=='message_head' and e['side']==1 and e['context']['protocol']=='h3']
        assert len(heads)==report['requests'],(len(heads),report,status)
        expected={131072:digest(131072),4096:digest(4096)}
        for head in heads:
            file=archive/payload_path(head['cache_id']);body=file.read_bytes()
            assert hashlib.sha256(body).hexdigest()==expected[len(body)],str(file)
        manifest=json.loads((archive/'manifest.json').read_text())
        assert manifest['status']=='completed' and manifest['quality']['gap_count']==0,manifest
        assert peak>32,peak
        report.update(recording=str(archive),peak_active=peak,all_recorded_payloads_verified=len(heads),
            peak_rss=max(s['rss'] for s in samples),initial_rss=samples[0]['rss'],final_rss=samples[-1]['rss'],
            cpu_seconds=samples[-1]['cpu']-samples[0]['cpu'],quality=manifest['quality'],after_stop_forwarding=True)
        (work/'samples.json').write_text(json.dumps(samples),encoding='utf-8')
        (work/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report),flush=True)
    finally:
        if client and client.poll() is None:client.kill();await asyncio.to_thread(client.wait)
        host.close();server.close();log.close()

def payload_path(id):return f'payload/{id//1000:06}/{id:012}.response.bin'
if __name__=='__main__':
    if sys.argv[1]=='child':asyncio.run(child(*sys.argv[2:]))
    else:asyncio.run(run(int(sys.argv[1])))
