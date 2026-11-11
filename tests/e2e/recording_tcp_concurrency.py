"""128 simultaneous HTTPS/TCP analyzers through the production Hook/PRC."""
import asyncio, hashlib, json, os, socket, ssl, subprocess, sys, threading, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import psutil
import quic_mitm_probe as p
from quic_live_route_probe import Host
from quic_late_hook_probe import SlowHTTPS
from quic_hook_certificates import proxylane_key
from mitm_host_reliability import digest,CHUNK
from recording_capture import read_events
from cryptography.hazmat.primitives import serialization

ROOT=Path(__file__).resolve().parents[2]
def child(ip,port,ca):
    assert input()=='start';barrier=threading.Barrier(128,timeout=60);ctx=ssl.create_default_context(cafile=ca)
    def get(i):
        with socket.create_connection((ip,int(port)),30) as raw:
            with ctx.wrap_socket(raw,server_hostname=p.NAME) as s:
                s.settimeout(60);barrier.wait()
                s.sendall(f'GET /{i} HTTP/1.1\r\nHost: {p.NAME}\r\nConnection: close\r\n\r\n'.encode())
                data=b''
                while b'\r\n\r\n' not in data:data+=s.recv(16384)
                header,data=data.split(b'\r\n\r\n',1);assert header.startswith(b'HTTP/1.1 200')
                while len(data)<131072:
                    b=s.recv(16384);assert b;data+=b
                assert hashlib.sha256(data).hexdigest()==digest(131072)
        return i
    with ThreadPoolExecutor(max_workers=128) as pool:assert len(list(pool.map(get,range(128))))==128
    print('128-requests-complete',flush=True)

async def run():
    p.isolate();work=ROOT/'build/recording-validation'/('tcp128-'+str(time.time_ns()));work.mkdir(parents=True)
    cert=SlowHTTPS(work,Path(os.environ['LOCALAPPDATA'])/'ProxyLane');ca,_=proxylane_key(Path(os.environ['LOCALAPPDATA'])/'ProxyLane/ca.json')
    (work/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    async def serve(reader,writer):
        try:
            await reader.readuntil(b'\r\n\r\n');await asyncio.sleep(2)
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 131072\r\nConnection: close\r\n\r\n');await writer.drain()
            for _ in range(8):writer.write(CHUNK);await writer.drain();await asyncio.sleep(.03)
        finally:writer.close()
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert.cert,cert.key)
    server=await asyncio.start_server(serve,'0.0.0.0',0,ssl=ctx);port=server.sockets[0].getsockname()[1]
    host=Host(work);client=None;log=open(work/'client.log','w');samples=[]
    try:
        settings=(await asyncio.to_thread(host.call,type='mitm_options'))['settings']
        parser_limit=int(os.environ.get('PROXYLANE_TEST_PARSERS','128'));settings['connections']=parser_limit
        settings['recording']={'enabled':True,'directory':str(work/'recordings'),'capacity_mib':8192,'reserve_mib':16}
        await asyncio.to_thread(host.call,type='mitm_options',settings=settings)
        await asyncio.to_thread(host.call,type='test_tcp_policy',enabled=True)
        await asyncio.to_thread(host.call,type='monitor_start',decrypt=True,quic=False)
        archive=Path((await asyncio.to_thread(host.call,type='recording_status'))['directory'])
        ip=next(i for i in socket.gethostbyname_ex(socket.gethostname())[2] if not i.startswith('127.'))
        client=subprocess.Popen([sys.executable,__file__,'child',ip,str(port),str(work/'ca.pem')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=log,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        assert (await asyncio.to_thread(host.call,type='attach',pid=client.pid))['result']==0xff01
        await asyncio.sleep(.5);client.stdin.write('start\n');client.stdin.flush()
        done=asyncio.create_task(asyncio.to_thread(client.stdout.readline));proc=psutil.Process(host.p.pid)
        while not done.done():
            await asyncio.sleep(.1);stats=await asyncio.to_thread(host.call,type='stats')
            samples.append({'parsers':stats['active_parsers'],'rss':proc.memory_info().rss})
        assert (await done).strip()=='128-requests-complete',(work/'client.log').read_text()
        assert await asyncio.to_thread(client.wait,20)==0
        await asyncio.to_thread(host.call,type='monitor_stop')
        status=await asyncio.to_thread(host.call,type='recording_status');assert not status['stopped'],status
        assert status['quality']['gap_count']==0 and status['quality']['analysis_deferred_count']==0,status
        heads=[e for e in read_events(archive) if e['type']=='message_head' and e['side']==1]
        assert len(heads)==128,len(heads)
        for h in heads:
            id=h['cache_id'];body=(archive/f'payload/{id//1000:06}/{id:012}.response.bin').read_bytes()
            assert len(body)==131072 and hashlib.sha256(body).hexdigest()==digest(131072)
        report={'requests':128,'peak_parsers':max(s['parsers'] for s in samples),'peak_rss':max(s['rss'] for s in samples),
            'quality':status['quality'],'recording':str(archive)}
        assert 0 < report['peak_parsers'] <= parser_limit,report
        (work/'result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report),flush=True)
    finally:
        if client and client.poll() is None:client.kill();await asyncio.to_thread(client.wait)
        host.close();server.close();await server.wait_closed();log.close()

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='child':child(*sys.argv[2:])
    else:asyncio.run(run())
