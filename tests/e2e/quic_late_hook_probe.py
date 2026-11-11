"""Busy-browser, process-level Hook installation and NetworkService restart.

No shipping/GUI changes. Hook is process-wide and independent of routing.
No UDP buffering or per-connection host/port/leaf authorization is involved.
"""
import asyncio
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request
import uuid
import quic_mitm_probe as probe
import psutil
from quic_hook_probe import BROWSERS, adopt_browser, RUNTIME, ROOT
from quic_hook_control import Hook, network_process, OpenProcess, CloseHandle, check, EnumModules, ModuleName, ptr
from quic_hook_certificates import proxylane_key
from quic_ssl_policy_probe import CDP, attach, netlog_evidence
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import ctypes as C
from ctypes import wintypes as W

SIZE=4*1024*1024
PAYLOAD=(bytes(range(251))*(SIZE//251+1))[:SIZE]
DIGEST=hashlib.sha256(PAYLOAD).hexdigest()

class RecordingCDP(CDP):
    def call(self,method,params=None):
        self.serial+=1
        self.ws.send(json.dumps({'id':self.serial,'method':method,'params':params or {}}))
        while True:
            message=json.loads(self.ws.recv())
            if message.get('method')=='Network.responseReceived':
                r=message['params']['response']
                self.records.append({k:r.get(k) for k in ('url','protocol','connectionId','connectionReused','status','fromDiskCache')})
            if message.get('id')==self.serial:
                assert 'error' not in message,message
                return message.get('result',{})

def recording(client):
    client.__class__=RecordingCDP; client.records=[]; client.call('Network.enable'); return client

async def tab(root,debug):
    target=(await asyncio.to_thread(root.call,'Target.createTarget',{'url':'about:blank'}))['targetId']
    def create():
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f'http://127.0.0.1:{debug}/json/list',timeout=2) as r: pages=json.load(r)
        return recording(CDP(next(p['webSocketDebuggerUrl'] for p in pages if p['id']==target)))
    return await asyncio.to_thread(create)

async def eval_async(client,expression):
    r=await asyncio.to_thread(client.call,'Runtime.evaluate',
        {'expression':expression,'returnByValue':True,'awaitPromise':True})
    assert 'exceptionDetails' not in r,r
    return r['result'].get('value')

class SlowHTTPS:
    def __init__(self,work,pki):
        ca,key=proxylane_key(pki/'ca.json'); leafkey=ec.generate_private_key(ec.SECP256R1())
        now=dt.datetime.now(dt.timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,probe.NAME)]))
            .issuer_name(ca.subject).public_key(leafkey.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(probe.NAME)]),False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False)
            .sign(key,hashes.SHA256()))
        self.key=work/'slow-key.pem'; self.cert=work/'slow-cert.pem'
        self.key.write_bytes(leafkey.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(self.cert),str(self.key)); self.context.set_alpn_protocols(['http/1.1'])
        self.events=[]; self.writers=set(); self.serial=0; self.port=probe.port()
    async def start(self):
        self.server=await asyncio.start_server(self.handle,'127.0.0.1',self.port,ssl=self.context)
    async def handle(self,reader,writer):
        self.writers.add(writer); self.serial+=1; serial=self.serial
        event={'connection_id':serial,'started':time.perf_counter(),'sent':0}
        try:
            head=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),5)
            path=head.split(b' ')[1].decode(); event['path']=path
            slow=path.startswith('/slow')
            body=PAYLOAD if slow else b'<!doctype html><title>Existing HTTPS traffic</title>'
            writer.write(f'HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nContent-Type: {"application/octet-stream" if slow else "text/html"}\r\nCache-Control: no-store\r\nX-Test-Connection: {serial}\r\nConnection: close\r\n\r\n'.encode())
            self.events.append(event)
            for offset in range(0,len(body),16384):
                writer.write(body[offset:offset+16384]); await writer.drain()
                event['sent']=min(len(body),offset+16384)
                if slow: await asyncio.sleep(.06)
            event['complete']=True
        except Exception as e: event['error']=str(e)
        finally:
            event['ended']=time.perf_counter(); writer.close(); self.writers.discard(writer)
    async def close(self):
        self.server.close(); await self.server.wait_closed()
        for writer in list(self.writers): writer.close()
        self.key.unlink(missing_ok=True)

START_DOWNLOADS="""(() => {
window.dl=[0,1].map(i=>({i,bytes:0,done:false,error:null}));
for(const s of dl)(async()=>{try{
 const r=await fetch('/slow?phase=PHASE&i='+s.i,{cache:'no-store'});
 s.connection=r.headers.get('x-test-connection');const reader=r.body.getReader();const chunks=[];
 while(true){const p=await reader.read();if(p.done)break;chunks.push(p.value);s.bytes+=p.value.length;}
 const all=new Uint8Array(s.bytes);let offset=0;for(const c of chunks){all.set(c,offset);offset+=c.length;}
 s.sha256=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',all)),x=>x.toString(16).padStart(2,'0')).join('');s.done=true;
 }catch(e){s.error=String(e);s.done=true;}})();return true;})()"""

async def start_downloads(client,slow,phase):
    await asyncio.to_thread(client.call,'Page.navigate',{'url':f'https://{probe.NAME}:{slow.port}/?phase={phase}'})
    for _ in range(80):
        if await eval_async(client,'document.title')=='Existing HTTPS traffic': break
        await asyncio.sleep(.1)
    else: raise TimeoutError('HTTPS page not ready')
    await eval_async(client,START_DOWNLOADS.replace('PHASE',phase))
    for _ in range(60):
        state=await eval_async(client,'dl')
        if len(state)==2 and all(s['bytes']>=32768 and not s['done'] for s in state): return state
        await asyncio.sleep(.1)
    raise AssertionError(('Continuous traffic missing',state))

async def finish_downloads(client,slow,phase):
    for _ in range(250):
        state=await eval_async(client,'dl')
        if all(s['done'] for s in state): break
        await asyncio.sleep(.1)
    assert all(s['done'] and s['error'] is None and s['bytes']==SIZE and s['sha256']==DIGEST for s in state),state
    for s in state:
        matches=[e for e in slow.events if e['connection_id']==int(s['connection'])]
        assert len(matches)==1 and phase in matches[0]['path'] and matches[0]['sent']==SIZE
    return state

def probe_loaded(pid):
    process=check(OpenProcess(0x410,False,pid))
    try:
        bases=(ptr*2048)();needed=W.DWORD();check(EnumModules(process,bases,C.sizeof(bases),C.byref(needed)))
        for base in list(bases)[:needed.value//C.sizeof(ptr)]:
            name=C.create_unicode_buffer(32768)
            if ModuleName(process,base,name,len(name)) and Path(name.value).name=='browser-trust-probe.dll':return True
        return False
    finally:CloseHandle(process)

async def fixture(work,processes,pki,relay,origin,stage):
    port=probe.port()
    config=dict(role='mitm',listen=f'127.0.0.1:{port}',ca_directory=str(pki),name=probe.NAME,
        upstream=f'origin.quic.test:{origin}',upstream_ca=str(work/'origin-ca.der'),
        ready=str(work/(stage+'-ready.json')),stop=str(work/(stage+'-stop')))
    path=work/(stage+'.json');path.write_text(json.dumps(config))
    process=processes.start(stage,[str(RUNTIME/'route-host.exe'),'SOCKS5',str(relay),
        subprocess.list2cmdline([str(RUNTIME/'quic-probe.exe'),str(path)])])
    metadata=await probe.wait_ready(Path(config['ready']),process)
    return port,metadata

async def install_busy(browser,slow_client,root_hash):
    pid=network_process(browser)
    assert not probe_loaded(pid), 'Trust hook was already installed'
    before=await eval_async(slow_client,'dl')
    assert all(0<s['bytes']<SIZE and not s['done'] for s in before)
    started=time.perf_counter()
    hook=await asyncio.to_thread(Hook,browser,RUNTIME/'browser-trust-probe.dll',root_hash)
    elapsed=time.perf_counter()-started
    try:
        after=await eval_async(slow_client,'dl')
        assert network_process(browser)==pid and all(s['error'] is None and not s['done'] for s in after)
        assert all(a['bytes']>b['bytes'] and a['connection']==b['connection'] for a,b in zip(after,before)),(before,after)
        return hook,{'pid':pid,'module':hook.module,'install_seconds':elapsed,
            'downloads_before':before,'downloads_after':after}
    except BaseException:hook.close();raise

async def verify_h3(client,port,log,hook):
    await asyncio.to_thread(client.call,'Page.navigate',{'url':f'https://{probe.NAME}:{port}/'})
    for _ in range(150):
        requests=[e for e in probe.events(log) if e.get('event')=='request']
        if len(requests)>=4:break
        await asyncio.sleep(.1)
    assert len(requests)>=4,('No new HTTP/3 requests',hook.events())
    answer=await eval_async(client,"(async()=>{let b=new Uint8Array(65536);for(let i=0;i<b.length;i++)b[i]=i%251;let r=await fetch('/late-binary',{method:'POST',body:b});let a=new Uint8Array(await r.arrayBuffer());return a.length===b.length&&a.every((v,i)=>v===b[i])})()")
    assert answer is True
    assert any(e['input']==0 and e['output']==0 and e['flags']&32 for e in hook.events())
    return {'post_echo':answer,'hook_events':hook.events(),'h3_requests':len(requests)}

def restart_rejection(work):
    port=int(json.loads((work/'unhooked-restart.json').read_text())['listen'].rsplit(':',1)[1])
    text=(work/'netlog.json').read_text(errors='replace')
    try:data=json.loads(text)
    except ValueError:data=json.loads(text.rstrip().rstrip(',')+']}')
    names={v:k for k,v in data['constants']['logEventTypes'].items()}
    ids={e['source']['id'] for e in data['events'] if names.get(e['type'])=='QUIC_SESSION'
        and e.get('params',{}).get('host')==probe.NAME and e.get('params',{}).get('port')==port}
    errors=[e.get('params',{}) for e in data['events'] if e['source']['id'] in ids
        and 'CERTIFICATE_VERIFY_FAILED' in e.get('params',{}).get('details','')]
    assert ids and errors,'Restarted, unhooked process did not exercise certificate rejection'
    return {'port':port,'quic_sources':sorted(ids),'errors':errors}

async def run_browser(work,name,index):
    work.mkdir(parents=True);pki=work/'pki';pki.mkdir()
    shutil.copyfile(Path(os.environ['LOCALAPPDATA'])/'ProxyLane/ca.json',pki/'ca.json')
    processes=probe.Processes(work);result={'browser':name,'round':index,'passed':False};clients=[];hooks=[];slow=None;origin=None
    try:
        slow=SlowHTTPS(work,pki);await slow.start()
        probe.origin_pki(work);origin_events=[];result['origin_events']=origin_events
        conf=probe.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1])
        conf.load_cert_chain(str(work/'origin-cert.pem'),str(work/'origin-key.pem'))
        origin_port,relay=probe.port(),probe.port()
        origin=await probe.serve('127.0.0.1',origin_port,configuration=conf,
            create_protocol=lambda *a,**kw:probe.Peer(*a,origin=True,events=origin_events,**kw))
        processes.start('socks',[sys.executable,str(ROOT/'tests/e2e/socks5_udp_server.py'),'--port',str(relay),'--log',str(work/'relay.log')])
        for _ in range(100):
            if (work/'relay.log').exists() and 'LISTEN' in (work/'relay.log').read_text():break
            await asyncio.sleep(.05)
        fixtures={}
        for stage in ['initial','unhooked-restart','reinstalled']:
            fixtures[stage]=await fixture(work,processes,pki,relay,origin_port,stage)
        debug=probe.port();profile=work/'profile'
        browser=processes.start(name,[str(BROWSERS[name]),'--headless=new','--no-first-run','--no-default-browser-check',
            '--disable-background-networking','--disable-component-update','--no-proxy-server',f'--user-data-dir={profile}',
            f'--remote-debugging-port={debug}','--host-resolver-rules=MAP quic-probe.test 127.0.0.1',
            f'--log-net-log={work}/netlog.json','about:blank'])
        root=recording(await attach(debug));clients.append(root)
        await asyncio.sleep(.5);browser=adopt_browser(browser,profile,processes)
        target=await tab(root,debug);clients.append(target)
        await start_downloads(root,slow,'initial')
        # Install while HTTPS streams are active, without any MITM connection input.
        hook,detail=await install_busy(browser,root,fixtures['initial'][1]['ca_sha256'])
        hooks.append(hook);result['late_install']=detail
        result['new_quic']=await verify_h3(target,fixtures['initial'][0],work/'initial.log',hook)
        result['first_downloads']=await finish_downloads(root,slow,'initial')
        original_pid=hook.pid;original_birth=hook.module['birth']
        result['old_hook_events']=hook.events()
        # Deliberate fault injection against ONLY the test profile's network child.
        assert original_pid==network_process(browser)
        owned=psutil.Process(original_pid);owned.kill();await asyncio.to_thread(owned.wait,10)
        hook.close();hooks.remove(hook)
        await asyncio.to_thread(root.call,'Page.navigate',{'url':f'https://{probe.NAME}:{slow.port}/?restart'})
        for _ in range(100):
            try:
                replacement=network_process(browser)
                if replacement!=original_pid:break
            except (RuntimeError,psutil.NoSuchProcess):pass
            await asyncio.sleep(.1)
        else:raise TimeoutError('NetworkService did not restart')
        assert not probe_loaded(replacement),'Hook unexpectedly survived process death'
        control=await tab(root,debug);clients.append(control)
        control_port,_=fixtures['unhooked-restart']
        await asyncio.to_thread(control.call,'Page.navigate',{'url':f'https://{probe.NAME}:{control_port}/'})
        await asyncio.sleep(3)
        assert not any(e.get('event')=='request' for e in probe.events(work/'unhooked-restart.log'))
        await asyncio.to_thread(control.call,'Page.navigate',{'url':'about:blank'})
        result['restart']={'old_pid':original_pid,'old_birth':original_birth,'new_pid':replacement,
            'hook_absent_before_reinstall':True,'unhooked_h3_requests':0}
        # A separate origin port prevents a cached failed Alt-Svc entry from
        # suppressing the new handshake; the test does not clear browser caches.
        next_target=await tab(root,debug);clients.append(next_target)
        await start_downloads(root,slow,'reinstalled')
        hook,detail=await install_busy(browser,root,fixtures['reinstalled'][1]['ca_sha256'])
        hooks.append(hook);result['reinstalled']=detail
        result['reinstalled_quic']=await verify_h3(next_target,fixtures['reinstalled'][0],work/'reinstalled.log',hook)
        assert hook.pid==replacement and hook.module['birth']!=original_birth
        result['second_downloads']=await finish_downloads(root,slow,'reinstalled')
        assert sum(e.get('method')=='POST' and e.get('bytes')==65536 for e in origin_events)==2
        assert 'DOMAIN:origin.quic.test' in (work/'relay.log').read_text()
        result['passed']=True
    except BaseException:
        import traceback
        result['error']=traceback.format_exc();raise
    finally:
        for h in hooks:h.close()
        for c in clients:
            try:c.ws.close()
            except Exception:pass
        processes.close()
        if origin:origin.close()
        if slow:
            result['slow_https_events']=slow.events
            await slow.close()
        (pki/'ca.json').unlink(missing_ok=True);(work/'origin-key.pem').unlink(missing_ok=True)
        if (work/'netlog.json').exists():result['netlog']=netlog_evidence(work/'netlog.json')
        if result['passed']:
            try:result['restart_rejection']=restart_rejection(work)
            except Exception as e:result['passed']=False;result['error']=str(e)
        result['cdp_responses']=[r for c in clients for r in c.records]
        (work/'results.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(name,index,'PASS' if result['passed'] else 'FAIL',work/'results.json',flush=True)
    assert result['passed'],result.get('error')
    return result

async def main():
    probe.isolate();work=ROOT/'build/qa'/('quic-late-hook-'+uuid.uuid4().hex[:12]);work.mkdir()
    rounds=int(sys.argv[sys.argv.index('--rounds')+1]) if '--rounds' in sys.argv else 3
    names=[sys.argv[sys.argv.index('--browser')+1]] if '--browser' in sys.argv else list(BROWSERS)
    results={'work':str(work),'cases':[],'passed':False};print('WORK',work,flush=True)
    try:
        for name in names:
            for index in range(rounds):results['cases'].append(await run_browser(work/f'{name}-{index}',name,index))
        results['passed']=True
    finally:
        (work/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
        print('RESULT',work/'results.json',flush=True)

if __name__=='__main__':asyncio.run(main())
