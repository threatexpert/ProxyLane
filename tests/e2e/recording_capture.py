"""Persistent recordings through the real PRC/Hook. Own endpoints/processes only.
No system trust changes; test executables and reports stay under build/.
"""
import asyncio, hashlib, json, os, socket, ssl, subprocess, sys, time
from pathlib import Path
from contextlib import asynccontextmanager
import quic_mitm_probe as p
from quic_live_route_probe import Host
from quic_late_hook_probe import SlowHTTPS
from quic_hook_certificates import proxylane_key
from mitm_transport_reliability import Client, Origin, CHUNK
from mitm_host_reliability import connected, digest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'build/recording-validation'

def check_certificate(s, origin, mitm):
    assert (s.getpeercert(binary_form=True)!=origin)==mitm,'wrong interception state'

def tls_child(ip,port,ca,der,size):
    assert input()=='start';size=int(size);ctx=ssl.create_default_context(cafile=ca);origin=Path(der).read_bytes()
    def get(s,n):
        s.sendall(f'GET /{n} HTTP/1.1\r\nHost: {p.NAME}\r\n\r\n'.encode());head=b''
        while b'\r\n\r\n' not in head:head+=s.recv(1)
        assert head.startswith(b'HTTP/1.1 200');h=hashlib.sha256();count=0
        while count<n:
            data=s.recv(min(16384,n-count));assert data,('early EOF',count,n);count+=len(data);h.update(data)
        assert h.hexdigest()==digest(n)
    with socket.create_connection((ip,int(port)),30) as raw:
        with ctx.wrap_socket(raw,server_hostname=p.NAME) as s:
            s.settimeout(90);check_certificate(s,origin,True);get(s,size)
            print('download-complete',flush=True);assert input()=='after'
            get(s,131072)
    with socket.create_connection((ip,int(port)),30) as raw:
        with ctx.wrap_socket(raw,server_hostname=p.NAME) as s:
            check_certificate(s,origin,False);get(s,131072)
    print(json.dumps({'sha256':digest(size),'bytes':size,'existing_connection_survives':True,'new_connection_passthrough':True}),flush=True)

async def quic_child(ip,port,ca,der,size):
    assert await asyncio.to_thread(input)=='start';size=int(size);origin=Path(der).read_bytes()
    cfg=p.QuicConfiguration(is_client=True,alpn_protocols=['h3'],server_name=p.NAME,supported_versions=[1]);cfg.load_verify_locations(cafile=ca)
    async with connected(ip,int(port),cfg) as peer:
        assert peer._quic.tls._peer_certificate.public_bytes(serialization.Encoding.DER)!=origin
        reply=await peer.request(f'/body/{size}',timeout=120)
        assert reply.get('complete') and reply['sha256']==digest(size),reply
        print('download-complete',flush=True);assert await asyncio.to_thread(input)=='after'
        reply=await peer.request('/body/131072',timeout=30);assert reply.get('complete') and reply['sha256']==digest(131072),reply
    await asyncio.sleep(2.5)
    async with connected(ip,int(port),cfg) as peer:
        assert peer._quic.tls._peer_certificate.public_bytes(serialization.Encoding.DER)==origin
        reply=await peer.request('/body/131072',timeout=30);assert reply.get('complete'),reply
    print(json.dumps({'sha256':digest(size),'bytes':size,'existing_connection_survives':True,'new_connection_passthrough':True}),flush=True)

def read_events(path):
    return [json.loads(line) for f in sorted(path.glob('events-*.jsonl')) for line in f.read_text(encoding='utf-8').splitlines()]

async def run(mode,limited):
    p.isolate();work=BASE/(mode+('-capacity' if limited else '-complete')+'-'+str(time.time_ns()));work.mkdir(parents=True)
    cert=SlowHTTPS(work,Path(os.environ['LOCALAPPDATA'])/'ProxyLane')
    ca,_=proxylane_key(Path(os.environ['LOCALAPPDATA'])/'ProxyLane/ca.json')
    (work/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (work/'origin.der').write_bytes(x509.load_pem_x509_certificate(cert.cert.read_bytes()).public_bytes(serialization.Encoding.DER))
    port=p.port();size=(32 if limited else 33)*1024*1024
    async def http(reader,writer):
        try:
            while True:
                header=await reader.readuntil(b'\r\n\r\n');n=int(header.split(b' ')[1][1:])
                writer.write(f'HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nContent-Type: application/octet-stream\r\nX-Repeat: first\r\nX-Repeat: second\r\n\r\n'.encode())
                for at in range(0,n,len(CHUNK)):
                    writer.write(CHUNK[:min(len(CHUNK),n-at)]);await writer.drain();await asyncio.sleep(.001)
        except (ConnectionError,asyncio.IncompleteReadError):pass
        finally:writer.close()
    if mode=='https':
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert.cert,cert.key)
        server=await asyncio.start_server(http,'0.0.0.0',port,ssl=ctx)
    else:
        cfg=p.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1]);cfg.load_cert_chain(str(cert.cert),str(cert.key))
        server=await p.serve('0.0.0.0',port,configuration=cfg,create_protocol=Origin)
    host=Host(work);client=None;clientlog=open(work/'client.log','w',encoding='utf-8')
    try:
        settings=(await asyncio.to_thread(host.call,type='mitm_options'))['settings']
        settings['recording']={'enabled':True,'directory':str(work/'recordings'),'capacity_mib':16 if limited else 128,'reserve_mib':16}
        await asyncio.to_thread(host.call,type='mitm_options',settings=settings)
        await asyncio.to_thread(host.call,type='test_tcp_policy',enabled=mode=='https')
        await asyncio.to_thread(host.call,type='monitor_start',decrypt=mode=='https',quic=mode=='quic')
        status=await asyncio.to_thread(host.call,type='recording_status');archive=Path(status['directory'])
        assert (archive/'manifest.json').exists(), 'manifest not created before monitoring'
        ip=next(ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith('127.'))
        client=subprocess.Popen([sys.executable,__file__,'child',mode,ip,str(port),str(work/'ca.pem'),str(work/'origin.der'),str(size)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=clientlog,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        assert (await asyncio.to_thread(host.call,type='attach',pid=client.pid))['result']==0xff01
        await asyncio.sleep(.5);client.stdin.write('start\n');client.stdin.flush()
        line=await asyncio.wait_for(asyncio.to_thread(client.stdout.readline),150)
        assert line.strip()=='download-complete',(line,client.poll(),(work/'client.log').read_text())
        if limited:
            for _ in range(100):
                if not (await asyncio.to_thread(host.call,type='monitor_status'))['monitoring']:break
                await asyncio.sleep(.1)
            assert not (await asyncio.to_thread(host.call,type='monitor_status'))['monitoring']
            status=await asyncio.to_thread(host.call,type='recording_status')
            assert status['stopped'] and 'capacity' in status['reason'],status
        else:
            await asyncio.to_thread(host.call,type='stats')
            status=await asyncio.to_thread(host.call,type='recording_status');assert not status['stopped'],status
            await asyncio.to_thread(host.call,type='monitor_stop')
        # Wait for terminal manifest; watchdog drains on its own worker.
        for _ in range(100):
            manifest=json.loads((archive/'manifest.json').read_text(encoding='utf-8'))
            if manifest['status']!='recording':break
            await asyncio.sleep(.1)
        assert manifest['status']==('stopped' if limited else 'completed'),manifest
        before={str(f.relative_to(archive)):(f.stat().st_size,f.stat().st_mtime_ns) for f in archive.rglob('*') if f.is_file()}
        client.stdin.write('after\n');client.stdin.flush()
        report=await asyncio.wait_for(asyncio.to_thread(client.stdout.readline),60);assert report, (work/'client.log').read_text()
        report=json.loads(report);assert await asyncio.to_thread(client.wait,20)==0
        after={str(f.relative_to(archive)):(f.stat().st_size,f.stat().st_mtime_ns) for f in archive.rglob('*') if f.is_file()};assert before==after,'recording changed after stop'
        lines=read_events(archive)
        heads=[e for e in lines if e['type']=='message_head'];assert heads
        assert any(e['context']['connection']['pid']==client.pid and e['context']['connection']['process_name'] for e in heads)
        assert any(e['context']['connection']['process_path'] for e in heads)
        cid=heads[0]['cache_id']
        # Registration correctly has null paths until bytes exist. Inspect the
        # recorded source body, including a prefix preserved after capacity stop.
        body=archive/f'payload/{cid//1000:06}/{cid:012}.response.bin';saved=body.read_bytes()
        assert hashlib.sha256(saved).hexdigest()==digest(len(saved))
        assert (0<len(saved)<size) if limited else len(saved)==size
        total=sum(f.stat().st_size for f in archive.rglob('*') if f.is_file());assert total<=settings['recording']['capacity_mib']*1024*1024
        report.update(mode=mode,limited=limited,recording=str(archive),saved_body_bytes=len(saved),recording_bytes=total,manifest=manifest['status'],records=len(lines))
        (work/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report),flush=True)
        return report
    finally:
        if client and client.poll() is None:client.kill();await asyncio.to_thread(client.wait)
        host.close();server.close();clientlog.close()

if __name__=='__main__':
    if sys.argv[1]=='child':
        if sys.argv[2]=='https':tls_child(*sys.argv[3:])
        else:asyncio.run(quic_child(*sys.argv[3:]))
    else:asyncio.run(run(sys.argv[1],len(sys.argv)>2 and sys.argv[2]=='capacity'))
