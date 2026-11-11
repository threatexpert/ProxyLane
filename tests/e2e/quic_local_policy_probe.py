"""Local compatibility lifecycle and eligibility; all artifacts stay in build/quic-live."""
import asyncio, ctypes, json, os, socket, subprocess, sys, tempfile, time
from pathlib import Path
import quic_mitm_probe as probe
from quic_live_route_probe import Host, RUNTIME

def child(ip, port):
    k=ctypes.windll.kernel32;k.GetModuleHandleW.restype=ctypes.c_void_p
    k.LoadLibraryExW.restype=ctypes.c_void_p
    udp=None
    for line in sys.stdin:
        q=json.loads(line);op=q['op'];error=None
        try:
            if op=='load':
                assert k.LoadLibraryExW(str(RUNTIME/'chrome.dll'),None,0)
            elif op=='connect':
                udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.connect((ip,int(port)))
            elif op=='send':
                udp.send(b'local eligibility probe')
            elif op=='sendto':
                udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.sendto(b'local eligibility probe',(ip,int(port)))
            elif op=='tcp':
                with socket.create_connection((ip,int(port)),timeout=2) as tcp:tcp.sendall(b'tcp only')
        except OSError as e:error=e.winerror
        print(json.dumps({'op':op,'error':error,'locator_loaded':bool(k.GetModuleHandleW('ProxyLaneMitm64.dll'))}),flush=True)

async def run():
    probe.isolate();results=[]
    ip=next(x for x in socket.gethostbyname_ex(socket.gethostname())[2] if not x.startswith('127.'))
    tcp=await asyncio.start_server(lambda r,w:w.close(),'0.0.0.0',0);port=tcp.sockets[0].getsockname()[1]
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('0.0.0.0',port));udp.setblocking(False)
    with tempfile.TemporaryDirectory(dir=RUNTIME) as temp:
        work=Path(temp)
        try:
            for mode in ['ordinary','candidate','blocked','disabled','late_load']:
                host=Host(work,mode);client=None
                try:
                    await asyncio.to_thread(host.call,type='quic_injection_policy',enabled=mode!='disabled')
                    await asyncio.to_thread(host.call,type='test_udp_policy',blocked=mode=='blocked')
                    client=subprocess.Popen([sys.executable,__file__,'child',ip,str(port)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
                    assert (await asyncio.to_thread(host.call,type='attach',pid=client.pid))['result']==0xff01
                    await asyncio.sleep(.3)
                    async def call(op):
                        client.stdin.write(json.dumps({'op':op})+'\n');client.stdin.flush()
                        line=await asyncio.wait_for(asyncio.to_thread(client.stdout.readline),5)
                        assert line,(mode,op,client.poll())
                        return json.loads(line)
                    assert not (await call('state'))['locator_loaded']
                    if mode=='late_load':
                        assert not (await call('sendto'))['locator_loaded']
                    if mode!='ordinary':
                        assert not (await call('load'))['locator_loaded']
                    assert not (await call('tcp'))['locator_loaded']
                    connected=await call('connect')
                    assert not connected['locator_loaded']
                    sent=await call('send' if not connected['error'] else 'sendto')
                    await asyncio.sleep(1.5)
                    state=await call('state');expected=mode in ['candidate','late_load']
                    assert state['locator_loaded']==expected,(mode,state)
                    if mode=='blocked':assert connected['error']==10013 or sent['error']==10013,(connected,sent)
                    if expected:
                        log=(work/(mode+'.log')).read_text(errors='replace')
                        assert 'compatibility unavailable:' in log,log # Fake DLL must fail conservatively.
                    results.append({'case':mode,'pass':True,'locator_loaded':state['locator_loaded'],'send_error':sent['error']})
                    print(mode,'PASS',flush=True)
                finally:
                    if client:client.terminate();client.wait(timeout=5)
                    host.close()
                    (RUNTIME/(mode+'-local-policy.log')).write_bytes((work/(mode+'.log')).read_bytes())
            (RUNTIME/'local-policy-results.json').write_text(json.dumps(results,indent=2))
        finally:
            udp.close();tcp.close();await tcp.wait_closed()
if __name__=='__main__':
    if len(sys.argv)>1:child(*sys.argv[2:])
    else:asyncio.run(run())
