"""Exercise real PRC readiness admission with an ordinary QUIC application.
The test client explicitly reports states through its own authenticated pipe.
"""
import asyncio, ctypes, json, os, socket, struct, subprocess, sys, tempfile, time
from pathlib import Path
import quic_mitm_probe as probe
from quic_live_route_probe import Host, RUNTIME, connected
from quic_late_hook_probe import SlowHTTPS
from quic_hook_certificates import proxylane_key
from cryptography.hazmat.primitives import serialization

def report(pipe,status):
    k=ctypes.windll.kernel32
    k.GetCurrentProcess.restype=ctypes.c_void_p
    k.CreateFileW.argtypes=[ctypes.c_wchar_p,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_void_p]
    k.CreateFileW.restype=ctypes.c_void_p
    k.GetProcessTimes.argtypes=[ctypes.c_void_p]+[ctypes.c_void_p]*4
    k.WriteFile.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_void_p]
    k.ReadFile.argtypes=k.WriteFile.argtypes;k.CloseHandle.argtypes=[ctypes.c_void_p]
    times=[ctypes.c_ulonglong() for _ in range(4)]
    assert k.GetProcessTimes(k.GetCurrentProcess(),*[ctypes.byref(t) for t in times])
    h=k.CreateFileW(pipe,0xc0000000,3,None,3,0,None)
    assert h!=ctypes.c_void_p(-1).value,ctypes.get_last_error()
    try:
        n=ctypes.c_ulong()
        for data in [struct.pack('<BBI',17,1,16),struct.pack('<QII',times[0].value,status,0)]:
            assert k.WriteFile(h,data,len(data),ctypes.byref(n),None) and n.value==len(data)
        ack=ctypes.create_string_buffer(6)
        assert k.ReadFile(h,ack,6,ctypes.byref(n),None) and ack.raw==struct.pack('<BBI',0,1,0)
    finally:k.CloseHandle(h)

async def child(ip,port,ca,mode):
    pipe=await asyncio.to_thread(input)
    if mode!='unknown':report(pipe,3 if mode=='failed' else 1)
    config=probe.QuicConfiguration(is_client=True,alpn_protocols=['h3'],server_name=probe.NAME,supported_versions=[1]);config.load_verify_locations(cafile=ca)
    async def ready():
        await asyncio.sleep(.25);await asyncio.to_thread(report,pipe,2)
    ready_task=asyncio.create_task(ready()) if mode=='ready' else None
    start=time.perf_counter()
    async with connected(int(port),config,ip) as peer:
        reply=await peer.request('POST',b'admission');assert bytes(reply['body'])==b'admission'
        elapsed=time.perf_counter()-start
        if mode=='timeout':
            report(pipe,2) # Too late: must NOT upgrade this existing passthrough route.
            reply=await peer.request('POST',b'after timeout');assert bytes(reply['body'])==b'after timeout'
        print(json.dumps({'elapsed_ms':round(elapsed*1000),'mode':mode}),flush=True)
    if ready_task:await ready_task

async def run():
    probe.isolate();results=[]
    with tempfile.TemporaryDirectory(dir=RUNTIME) as tmp:
        work=Path(tmp);pki=Path(os.environ['LOCALAPPDATA'])/'ProxyLane';origin=SlowHTTPS(work,pki)
        ca,_=proxylane_key(pki/'ca.json');(work/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        config=probe.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1]);config.load_cert_chain(str(origin.cert),str(origin.key))
        port=probe.port();events=[];server=await probe.serve('0.0.0.0',port,configuration=config,create_protocol=lambda *a,**kw:probe.Peer(*a,origin=True,events=events,**kw))
        ip=next(x for x in socket.gethostbyname_ex(socket.gethostname())[2] if not x.startswith('127.'))
        try:
            for mode in ['unknown','ready','failed','timeout']:
                host=Host(work,mode);client=None
                try:
                    await asyncio.to_thread(host.call,type='monitor_start',decrypt=False,quic=True)
                    pipe=(await asyncio.to_thread(host.call,type='test_pipe'))['pipe']
                    with open(RUNTIME/(mode+'-admission-client.log'),'w') as log:
                        client=subprocess.Popen([sys.executable,__file__,'child',ip,str(port),str(work/'ca.pem'),mode],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
                        assert (await asyncio.to_thread(host.call,type='attach',pid=client.pid))['result']==0xff01
                        await asyncio.sleep(.2);client.stdin.write(pipe+'\n');client.stdin.flush()
                        line=await asyncio.wait_for(asyncio.to_thread(client.stdout.readline),15);assert line,(mode,client.poll())
                        result=json.loads(line);await asyncio.sleep(.3)
                        rows=(await asyncio.to_thread(host.call,type='poll',limit=512)).get('records',[])
                        h3=[r for r in rows if r.get('protocol')=='h3' and r.get('type')=='exchange']
                        assert bool(h3)==(mode in ['unknown','ready']),(mode,rows)
                        if mode=='timeout':assert 1900<=result['elapsed_ms']<3500,result
                        else:assert result['elapsed_ms']<1000,result
                        result['http3_captured']=bool(h3);results.append(result);print(result,flush=True)
                finally:
                    if client and client.poll() is None:client.terminate();client.wait(timeout=5)
                    host.close();(RUNTIME/(mode+'-admission-host.log')).write_bytes((work/(mode+'.log')).read_bytes())
            (RUNTIME/'admission-results.json').write_text(json.dumps(results,indent=2))
        finally:server.close()
if __name__=='__main__':
    if len(sys.argv)>1:asyncio.run(child(*sys.argv[2:]))
    else:asyncio.run(run())
