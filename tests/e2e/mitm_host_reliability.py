"""Actual PRC/Hook forwarding regression. Test executables remain in build/quic-live.

Explicit client trust only; no system certificates, user processes or profiles changed.
"""
import asyncio, hashlib, json, os, socket, ssl, subprocess, sys, tempfile, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
import quic_mitm_probe as p
from quic_live_route_probe import Host, RUNTIME
from quic_late_hook_probe import SlowHTTPS
from quic_hook_certificates import proxylane_key
from mitm_transport_reliability import Client, Origin, CHUNK
from aioquic.quic.connection import QuicConnection
from cryptography.hazmat.primitives import serialization

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'build/reliability-audit'
def digest(size):
    h=hashlib.sha256()
    for at in range(0,size,len(CHUNK)):h.update(CHUNK[:min(len(CHUNK),size-at)])
    return h.hexdigest()

@asynccontextmanager
async def connected(ip,port,config):
    t,c=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Client(QuicConnection(configuration=config)),remote_addr=(ip,port))
    try:
        c.connect((ip,port));await asyncio.wait_for(c.wait_connected(),15)
        yield c
    finally:
        c.close();await asyncio.wait_for(c.wait_closed(),10);t.close()

async def quic_child(ip,port,ca,origin_der):
    assert await asyncio.to_thread(input)=='start'
    config=p.QuicConfiguration(is_client=True,alpn_protocols=['h3'],server_name=p.NAME,supported_versions=[1])
    config.load_verify_locations(cafile=ca)
    # The PRC deliberately reuses the destination route in this same process.
    # A limit of two must not prevent eight sequential MITM connections.
    for i in range(8):
        async with connected(ip,int(port),config) as peer:
            assert peer._quic.tls._peer_certificate.public_bytes(serialization.Encoding.DER)!=Path(origin_der).read_bytes(), 'unexpected passthrough'
            r=await peer.request('/body/131072');assert r.get('complete') and r['sha256']==digest(131072),r
        await asyncio.sleep(2.5)
    print(json.dumps({'reused_route_connections':8,'all_mitm':True}),flush=True)
    async with connected(ip,int(port),config) as peer:
        sent=False
        def progress(c,s,n):
            nonlocal sent
            if n>=1048576 and not sent:sent=True;print('stop-now',flush=True)
        peer.when_data=progress
        r=await peer.request('/body/33554432',timeout=120)
        assert r.get('complete') and r['sha256']==digest(33554432),r
        print(json.dumps({'stop_download_bytes':r['bytes']}),flush=True)
        r=await peer.request('/ok');assert r.get('complete') and r['bytes']==32,r
        print(json.dumps({'existing_connection_after_stop':True}),flush=True)
    await asyncio.sleep(2.5)
    async with connected(ip,int(port),config) as peer:
        assert peer._quic.tls._peer_certificate.public_bytes(serialization.Encoding.DER)==Path(origin_der).read_bytes()
        r=await peer.request('/ok');assert r.get('complete') and r['bytes']==32,r
    print(json.dumps({'new_connection_after_stop_passthrough':True}),flush=True)

def tls_child(ip,port,ca,origin_der):
    assert input()=='start'
    ctx=ssl.create_default_context(cafile=ca)
    def download(size,cancel=False,progress=False,abrupt=False,mitm=True):
        with socket.create_connection((ip,int(port)),20) as raw:
            if abrupt:raw.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096)
            with ctx.wrap_socket(raw,server_hostname=p.NAME) as s:
                assert (s.getpeercert(binary_form=True)!=Path(origin_der).read_bytes())==mitm, 'unexpected certificate'
                path='abrupt' if abrupt else str(size)
                s.settimeout(60);s.sendall(f'GET /{path} HTTP/1.1\r\nHost: {p.NAME}\r\n\r\n'.encode())
                buf=b''
                while b'\r\n\r\n' not in buf:buf+=s.recv(4096)
                head,buf=buf.split(b'\r\n\r\n',1);assert head.startswith(b'HTTP/1.1 200')
                h=hashlib.sha256(buf);total=len(buf);sent=False
                while total<size:
                    b=s.recv(min(1024 if abrupt else 16384,size-total));assert b,('truncated',total,size)
                    total+=len(b);h.update(b)
                    if abrupt:time.sleep(.002)
                    if cancel and total>=65536:return total
                    if progress and total>=1048576 and not sent:sent=True;print('stop-now',flush=True)
                assert h.hexdigest()==digest(size),(size,total)
                return total
    with ThreadPoolExecutor(max_workers=5) as pool:
        keep=[pool.submit(download,8388608) for _ in range(4)]
        cancelled=pool.submit(download,8388608,True)
        assert cancelled.result()<8388608
        assert all(f.result()==8388608 for f in keep)
    print(json.dumps({'parallel_4x8MiB':True,'cancel_isolated':True}),flush=True)
    assert download(131072,abrupt=True)==131072
    print(json.dumps({'slow_receiver_unclean_tls_eof_bytes':131072}),flush=True)
    assert download(67108864,progress=True)==67108864
    print(json.dumps({'stop_download_bytes':67108864}),flush=True)
    assert download(131072,mitm=False)==131072
    print(json.dumps({'new_connection_after_stop_passthrough':True}),flush=True)

async def run(mode):
    p.isolate();BASE.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=BASE) as tmp:
        work=Path(tmp);cert=SlowHTTPS(work,Path(os.environ['LOCALAPPDATA'])/'ProxyLane')
        ca,_=proxylane_key(Path(os.environ['LOCALAPPDATA'])/'ProxyLane/ca.json')
        (work/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        from cryptography import x509
        (work/'origin.der').write_bytes(x509.load_pem_x509_certificate(cert.cert.read_bytes()).public_bytes(serialization.Encoding.DER))
        port=p.port();writers=set()
        async def http(reader,writer):
            writers.add(writer)
            try:
                head=await reader.readuntil(b'\r\n\r\n');path=head.split(b' ')[1][1:]
                size=131072 if path==b'abrupt' else int(path)
                writer.write(f'HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n'.encode())
                for at in range(0,size,len(CHUNK)):
                    writer.write(CHUNK[:min(len(CHUNK),size-at)]);await writer.drain()
                    if path!=b'abrupt':await asyncio.sleep(.001)
                if path==b'abrupt':
                    await asyncio.sleep(.05);writer.transport.abort()
            except (ConnectionError,asyncio.IncompleteReadError):pass
            finally:writer.close();writers.discard(writer)
        if mode=='quic':
            config=p.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1]);config.load_cert_chain(str(cert.cert),str(cert.key))
            server=await p.serve('0.0.0.0',port,configuration=config,create_protocol=Origin)
        else:server=await asyncio.start_server(http,'0.0.0.0',port,ssl=cert.context)
        host=Host(work);child=None;log=open(BASE/(mode+'-host-client.log'),'w');rows=[]
        try:
            await asyncio.to_thread(host.call,type='test_tcp_policy',enabled=mode=='tls')
            await asyncio.to_thread(host.call,type='mitm_options',settings={'connections':2 if mode=='quic' else 32,'entry_mib':1,'total_mib':16})
            await asyncio.to_thread(host.call,type='monitor_start',decrypt=mode=='tls',quic=mode=='quic')
            ip=next(ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith('127.'))
            child=subprocess.Popen([sys.executable,__file__,'child',mode,ip,str(port),str(work/'ca.pem'),str(work/'origin.der')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
            assert (await asyncio.to_thread(host.call,type='attach',pid=child.pid))['result']==0xff01
            await asyncio.sleep(.5);child.stdin.write('start\n');child.stdin.flush();snapshot=None
            while True:
                line=await asyncio.wait_for(asyncio.to_thread(child.stdout.readline),180)
                if not line:break
                if line.strip()=='stop-now':
                    await asyncio.to_thread(host.call,type='monitor_stop')
                    snapshot=(await asyncio.to_thread(host.call,type='poll',limit=512))['next']
                else:rows.append(json.loads(line));print(mode,line.strip(),flush=True)
            assert await asyncio.to_thread(child.wait)==0,('child failed',mode)
            assert snapshot is not None
            await asyncio.sleep(.3)
            final=await asyncio.to_thread(host.call,type='poll',limit=512)
            assert final['next']==snapshot,('capture changed after stop',snapshot,final['next'])
            assert any(r.get('connection',{}).get('pid')==child.pid for r in final['records']),final
            (BASE/(mode+'-host-results.json')).write_text(json.dumps(dict(results=rows,stop_no_new_records=True),indent=2))
        finally:
            if child and child.poll() is None:child.kill();child.wait()
            host.close();server.close();log.close()
            for w in writers:w.close()
            (BASE/(mode+'-host.log')).write_bytes((work/'host.log').read_bytes())
            await asyncio.sleep(.3)

if __name__=='__main__':
    if sys.argv[1]=='child':
        if sys.argv[2]=='quic':asyncio.run(quic_child(*sys.argv[3:]))
        else:tls_child(*sys.argv[3:])
    else:asyncio.run(run(sys.argv[1]))
