"""Native Hook/PRC HTTPS: concurrent full gzip recordings and stop on live connections."""
import asyncio,base64,gzip,hashlib,json,os,pathlib,socket,ssl,subprocess,sys,threading,time
from concurrent.futures import ThreadPoolExecutor
import psutil
import quic_mitm_probe as p
from quic_live_route_probe import Host
from quic_late_hook_probe import SlowHTTPS
from quic_hook_certificates import proxylane_key
from cryptography.hazmat.primitives import serialization
ROOT=pathlib.Path(__file__).resolve().parents[2]
BODY=bytes(range(256))*32768
ENCODED=gzip.compress(BODY,mtime=0)
COUNT=16
def child(ip,port,ca):
    assert input()=='start';ctx=ssl.create_default_context(cafile=ca)
    done=threading.Barrier(COUNT+1,timeout=90);resume=threading.Event()
    def worker(i):
        with socket.create_connection((ip,int(port)),20) as raw,ctx.wrap_socket(raw,server_hostname=p.NAME) as s:
            s.settimeout(90);f=s.makefile('rb')
            def request(tag):
                s.sendall(f'GET /{tag}/{i} HTTP/1.1\r\nHost: {p.NAME}\r\n\r\n'.encode())
                assert b'200' in f.readline();headers={}
                while (line:=f.readline())!=b'\r\n':
                    k,v=line.decode().split(':',1);headers[k.lower()]=v.strip()
                if headers.get('transfer-encoding')=='chunked':
                    body=bytearray()
                    while True:
                        n=int(f.readline(),16)
                        if n==0:assert f.readline()==b'\r\n';break
                        body.extend(f.read(n));assert f.read(2)==b'\r\n'
                    body=bytes(body)
                else:body=f.read(int(headers['content-length']))
                assert body==ENCODED and gzip.decompress(body)==BODY
            request('recorded');done.wait();assert resume.wait(90);request('after-stop')
    with ThreadPoolExecutor(max_workers=COUNT) as pool:
        jobs=[pool.submit(worker,i) for i in range(COUNT)]
        done.wait();print('ready',flush=True);assert input()=='after';resume.set()
        for job in jobs:job.result()
    print('after-stop-ok',flush=True)
async def run():
    p.isolate();work=ROOT/'build/recording-validation'/f'decoded-bodies-{time.time_ns()}';work.mkdir(parents=True)
    origin=SlowHTTPS(work,pathlib.Path(os.environ['LOCALAPPDATA'])/'ProxyLane')
    ca,_=proxylane_key(pathlib.Path(os.environ['LOCALAPPDATA'])/'ProxyLane/ca.json')
    (work/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    async def serve(r,w):
        try:
            while True:
                head=await r.readuntil(b'\r\n\r\n');i=int(head.split(b' ')[1].split(b'/')[-1])
                if i%2:
                    w.write(b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n')
                    for offset in range(0,len(ENCODED),997):
                        b=ENCODED[offset:offset+997];w.write(f'{len(b):x}\r\n'.encode()+b+b'\r\n')
                    w.write(b'0\r\n\r\n')
                else:w.write(f'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {len(ENCODED)}\r\n\r\n'.encode()+ENCODED)
                await w.drain()
        except (asyncio.IncompleteReadError,ConnectionError):pass
        finally:w.close()
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(origin.cert,origin.key)
    server=await asyncio.start_server(serve,'0.0.0.0',0,ssl=ctx);port=server.sockets[0].getsockname()[1]
    host=Host(work);client=None;log=(work/'client.log').open('w');samples=[];sampling=None
    async def sample():
        while True:
            samples.append(psutil.Process(host.p.pid).memory_info().rss);await asyncio.sleep(.02)
    try:
        settings=(await asyncio.to_thread(host.call,type='mitm_options'))['settings']
        settings.update(decode_mib=1)
        quota=int(os.environ.get('PROXYLANE_TEST_RECORDING_MIB','8192'))
        settings['recording']={'enabled':True,'directory':str(work/'recordings'),'capacity_mib':quota,'reserve_mib':16}
        await asyncio.to_thread(host.call,type='mitm_options',settings=settings)
        await asyncio.to_thread(host.call,type='test_tcp_policy',enabled=True)
        await asyncio.to_thread(host.call,type='monitor_start',decrypt=True,quic=False)
        run_id=(await asyncio.to_thread(host.call,type='stats'))['run_id']
        archive=pathlib.Path((await asyncio.to_thread(host.call,type='recording_status'))['directory'])
        ip=next(i for i in socket.gethostbyname_ex(socket.gethostname())[2] if not i.startswith('127.'))
        client=subprocess.Popen([sys.executable,__file__,'child',ip,str(port),str(work/'ca.pem')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
        assert (await asyncio.to_thread(host.call,type='attach',pid=client.pid))['result']==0xff01
        sampling=asyncio.create_task(sample());await asyncio.sleep(.5)
        client.stdin.write('start\n');client.stdin.flush()
        assert (await asyncio.wait_for(asyncio.to_thread(client.stdout.readline),120)).strip()=='ready'
        await asyncio.to_thread(host.call,type='monitor_stop')
        def files():return {str(f.relative_to(archive)):(f.stat().st_size,f.stat().st_mtime_ns) for f in archive.rglob('*') if f.is_file()}
        frozen=files();client.stdin.write('after\n');client.stdin.flush()
        assert (await asyncio.wait_for(asyncio.to_thread(client.stdout.readline),60)).strip()=='after-stop-ok'
        assert await asyncio.to_thread(client.wait,10)==0
        assert files()==frozen
        events=[json.loads(l) for f in archive.glob('events-*.jsonl') for l in f.read_text(encoding='utf8').splitlines()]
        results=[e for e in events if e['type']=='body_decode' and e['side']==1 and e['state']=='complete']
        if quota==8192:assert len(results)==COUNT
        else:assert len(results)<COUNT
        for e in results:
            assert (archive/e['source_file']).read_bytes()==ENCODED
            assert (archive/e['file']).read_bytes()==BODY
            preview=(await asyncio.to_thread(host.call,type='cache_decode',run_id=run_id,cache_id=e['cache_id'],direction='server',preview_bytes=65536))['payload']
            assert base64.b64decode(preview['data_base64'])==BODY[:65536]
            assert preview['decoded_bytes']==len(BODY)
        m=json.loads((archive/'manifest.json').read_text())
        if quota==8192:
            assert m['body_decoding']['pending']==0 and m['body_decoding']['incomplete']==0
            assert m['quality']['gap_count']==0
        else:
            assert m['status']=='stopped' and m['stop_reason']=='recording capacity reached'
            assert m['used_bytes']<=quota*1024*1024
            partial=m['body_decoding']['last_result'];assert partial['state']=='partial'
            assert (archive/partial['file']).read_bytes()==BODY[:partial['decoded_bytes']]
            assert (archive/partial['source_file']).read_bytes()==ENCODED
        report=dict(concurrent_connections=COUNT,decoded_body_bytes=len(BODY),expected_total_body_bytes=len(BODY)*COUNT,
            completed_decoded_total_bytes=sum(e['decoded_bytes'] for e in results),
            preview_decode_limit_mib=1,exact_raw_and_decoded=True,stopped_files_unchanged=True,existing_connections_after_stop=True,
            peak_host_rss=max(samples),directory=str(work),body_decoding=m['body_decoding'],
            quota_mib=quota,stop_reason=m['stop_reason'],completed_decoded_bodies=len(results))
        (work/'result.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps(report))
    finally:
        if sampling:sampling.cancel()
        if client and client.poll() is None:client.kill();client.wait()
        host.close();server.close();log.close()
if __name__=='__main__':
    if len(sys.argv)>1:child(*sys.argv[2:])
    else:asyncio.run(run())
