"""Shipping Hook + shipping MITM, controlled non-443 HTTP/3 origin. No CA changes."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import socket
from contextlib import asynccontextmanager
import quic_mitm_probe as probe
from aioquic.quic.connection import QuicConnection
from quic_hook_certificates import proxylane_key
from quic_late_hook_probe import SlowHTTPS
from cryptography.hazmat.primitives import serialization

ROOT=Path(__file__).resolve().parents[2]
RUNTIME=ROOT/'build/quic-live'

class Host:
    def __init__(self,work,name='host',proxy='NOPROXY',port=0):
        self.log=open(work/(name+'.log'),'wb')
        env=dict(os.environ,PROXYLANE_MITM='0',PROXYLANE_PROTOCOL_CACHE_ROOT=str(work/(name+'-cache')))
        self.p=subprocess.Popen([str(RUNTIME/'host.exe'),proxy,str(port)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.log,text=True,encoding='utf-8',env=env,creationflags=subprocess.CREATE_NO_WINDOW)
    def call(self,**q):
        self.p.stdin.write(json.dumps(q)+'\n');self.p.stdin.flush()
        line=self.p.stdout.readline()
        if not line:raise RuntimeError('Host exited: '+str(self.p.poll()))
        result=json.loads(line)
        if 'error' in result:raise RuntimeError(result['error'])
        return result
    def close(self):
        if self.p.poll() is None:
            self.p.stdin.write('{"type":"quit"}\n');self.p.stdin.flush()
            try:self.p.wait(timeout=10)
            except subprocess.TimeoutExpired:self.p.kill();self.p.wait()
        self.log.close()

@asynccontextmanager
async def connected(port,config,ip):
    # A normal connected UDP client; the OS pins its peer, as Chromium does.
    loop=asyncio.get_running_loop();remote=(ip,port)
    if not ip[0].isdigit():remote=(socket.gethostbyname(ip),port)
    transport,peer=await loop.create_datagram_endpoint(lambda:probe.Peer(QuicConnection(configuration=config)),remote_addr=remote)
    try:
        peer.connect(remote);await asyncio.wait_for(peer.wait_connected(),20)
        yield peer
    finally:
        peer.close();await peer.wait_closed();transport.close()

async def child(port,ca,ip):
    # Intentionally keep inherited/injected Hook; this is the application under test.
    assert await asyncio.to_thread(input)=='start'
    config=probe.QuicConfiguration(is_client=True,alpn_protocols=['h3'],server_name=probe.NAME,supported_versions=[1])
    config.load_verify_locations(cafile=ca)
    async with connected(int(port),config,ip) as peer:
        body=bytes(range(256))*4096
        response=await peer.request('POST',body)
        assert bytes(response['body'])==body
        if os.environ.get('QUIC_TEST_CANCEL') == '1':
            payloads=[body[:-1]+bytes([i]) for i in range(4)]
            replies=await asyncio.gather(*(peer.request('POST',data,i) for i,data in enumerate(payloads)))
            assert all(bytes(reply['body'])==data for reply,data in zip(replies,payloads))
            # A cancelled request with a partial HEADERS frame must not kill
            # independent streams or the whole multiplexed connection.
            stream=peer._quic.get_next_available_stream_id()
            peer._quic.send_stream_data(stream,b'\x01',end_stream=False)
            peer.transmit()
            await asyncio.sleep(.2)
            response=await peer.request('POST',b'while other headers are incomplete')
            assert bytes(response['body'])==b'while other headers are incomplete'
            peer._quic.reset_stream(stream,0x10c)
            peer.transmit()
            await asyncio.sleep(.2)
            response=await peer.request('POST',b'after cancelled headers')
            assert bytes(response['body'])==b'after cancelled headers'
        print(json.dumps({'echo':len(body)}),flush=True)
        assert await asyncio.to_thread(input)=='after'
        response=await peer.request('POST',b'after stop')
        assert bytes(response['body'])==b'after stop'
        print(json.dumps({'after_stop':True}),flush=True)

async def run(route="noproxy"):
    probe.isolate();RUNTIME.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=RUNTIME) as tmp:
        work=Path(tmp);pki=Path(os.environ['LOCALAPPDATA'])/'ProxyLane'
        origin=SlowHTTPS(work,pki);ca,_=proxylane_key(pki/'ca.json')
        (work/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        config=probe.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1]);config.load_cert_chain(str(origin.cert),str(origin.key))
        port=probe.port();events=[]
        server=await probe.serve('0.0.0.0',port,configuration=config,create_protocol=lambda *a,**k:probe.Peer(*a,origin=True,events=events,**k))
        processes=probe.Processes(work);relay_port=probe.port()
        if route!='noproxy':
            processes.start('relay',[sys.executable,str(ROOT/'tests/e2e/socks5_udp_server.py'),'--port',str(relay_port),'--log',str(work/'relay.log')])
            for _ in range(100):
                if (work/'relay.log').exists():break
                await asyncio.sleep(.05)
        host=Host(work,proxy='NOPROXY' if route=='noproxy' else 'SOCKS5',port=relay_port);client=None
        clientlog=open(RUNTIME/'route-client.log','w')
        try:
            await asyncio.to_thread(host.call,type='monitor_start',decrypt=False,quic=True)
            client=subprocess.Popen([sys.executable,__file__,'child',str(port),str(work/'ca.pem'),('origin.quic.test' if route=='domain' else '203.0.113.10' if route=='socks' else next(ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith('127.')))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=clientlog,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
            attached=await asyncio.to_thread(host.call,type='attach',pid=client.pid)
            assert attached['result']==0xff01,attached
            await asyncio.sleep(.8)
            client.stdin.write('start\n');client.stdin.flush()
            first=await asyncio.wait_for(asyncio.to_thread(client.stdout.readline),30)
            assert first,'client exited or timed out; see route-client.log'
            print(first.strip(),flush=True)
            await asyncio.sleep(.5)
            records=await asyncio.to_thread(host.call,type='poll',limit=512)
            h3=[r for r in records.get('records',[]) if r.get('type')=='exchange' and r.get('protocol')=='h3']
            assert h3,records
            assert all(r['connection']['pid']==client.pid for r in h3)
            await asyncio.to_thread(host.call,type='monitor_stop')
            snapshot=await asyncio.to_thread(host.call,type='poll',limit=512)
            client.stdin.write('after\n');client.stdin.flush()
            after=await asyncio.wait_for(asyncio.to_thread(client.stdout.readline),20)
            assert json.loads(after)['after_stop']
            await asyncio.sleep(.3)
            assert (await asyncio.to_thread(host.call,type='poll',limit=512))['next']==snapshot['next']
            report={'route':route,'non_browser':True,'port':port,'transparent_udp_route':True,'pid':client.pid,'h3_records':len(h3),'stop_preserves_connection':True,'partial_headers_and_cancel_isolated':os.environ.get('QUIC_TEST_CANCEL')=='1','records':records}
            (RUNTIME/(route+'-result.json')).write_text(json.dumps(report,indent=2),encoding='utf8')
            print(json.dumps({k:v for k,v in report.items() if k!='records'}))
        finally:
            if client and client.poll() is None:client.kill();client.wait()
            try:
                diagnostic=await asyncio.to_thread(host.call,type='poll',limit=512)
                (RUNTIME/'route-last-records.json').write_text(json.dumps(diagnostic,indent=2),encoding='utf8')
            except Exception: pass
            host.close();server.close();clientlog.close();processes.close()
            if (work/'relay.log').exists():(RUNTIME/(route+'-relay.log')).write_bytes((work/'relay.log').read_bytes())
            # Preserve useful diagnostics outside the temporary private-key directory.
            (RUNTIME/'route-host.log').write_bytes((work/'host.log').read_bytes())

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='child':asyncio.run(child(*sys.argv[2:]))
    else:asyncio.run(run(sys.argv[1] if len(sys.argv)>1 else 'noproxy'))
