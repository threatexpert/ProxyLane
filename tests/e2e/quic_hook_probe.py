"""Current Chrome/Edge private-CA QUIC hook integration test, isolated profiles only."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import sys
import uuid
import subprocess
import quic_mitm_probe as probe
import psutil
from quic_hook_certificates import generate
from quic_ssl_policy_probe import attach, netlog_evidence
from quic_hook_control import Hook

ROOT=Path(__file__).resolve().parents[2]
RUNTIME=ROOT/'build/quic-probe'
BROWSERS={
    'chrome':Path(r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'),
    'edge':Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')}

class OwnedProcess:
    def __init__(self, process): self.process=process; self.pid=process.pid
    def poll(self): return None if self.process.is_running() else 0
    def wait(self,timeout): return self.process.wait(timeout)

def adopt_browser(launcher,profile,processes):
    if launcher.poll() is None: return launcher
    # Edge may relaunch itself for the Windows compatibility layer. Match BOTH
    # parent PID and our exact new profile, then retain psutil's birth identity.
    expected='--user-data-dir='+str(profile)
    for process in psutil.process_iter(['pid','ppid','cmdline']):
        if process.info['ppid']==launcher.pid and expected in (process.info['cmdline'] or []):
            owned=OwnedProcess(process); processes.items.append(owned); return owned
    raise RuntimeError('Owned browser relaunch not found')

async def browser_case(work, processes, name, metadata, listen, log, mode='enabled', close_path=None):
    target=BROWSERS[name]; debug=probe.port(); hook=None; cdp=None; result={}
    netlog=work/f'{name}-{mode}-netlog.json'
    args=[str(target),'--headless=new','--no-first-run','--no-default-browser-check',
          '--disable-background-networking','--disable-component-update','--no-proxy-server',
          f'--user-data-dir={work/name/mode}',f'--remote-debugging-port={debug}',
          '--host-resolver-rules=MAP quic-probe.test 127.0.0.1',f'--log-net-log={netlog}','about:blank']
    assert not any('ignore-certificate' in a or 'force-quic' in a or 'no-sandbox' in a for a in args)
    browser=processes.start(f'{name}-{mode}',args)
    before=len(probe.events(log))
    try:
        cdp=await attach(debug)
        await asyncio.sleep(.5)
        browser=adopt_browser(browser,work/name/mode,processes)
        hook=await asyncio.to_thread(Hook,browser,RUNTIME/'browser-trust-probe.dll',
            ('00'*32 if mode=='wrong-root' else metadata['ca_sha256']),
            enabled=mode!='disabled',bad_hash=mode=='bad-hash')
        result.update(module=hook.module,init=hook.init_result,init_error=hook.c.error)
        cdp.call('Page.navigate',{'url':f'https://quic-probe.test:{listen}/'})
        await asyncio.sleep(10)
        result['title']=cdp.evaluate('document.title')
        if mode=='enabled':
            async def evaluate(expression):
                response=await asyncio.to_thread(cdp.call,'Runtime.evaluate',
                    {'expression':expression,'returnByValue':True,'awaitPromise':True})
                assert 'exceptionDetails' not in response,response
                return response['result'].get('value')
            # Binary POST echo traverses browser -> Rust -> actual Hook UDP route -> independent origin.
            result['post_echo']=await evaluate("(async()=>{let b=new Uint8Array(65536);for(let i=0;i<b.length;i++)b[i]=i%251;let r=await fetch('/binary-echo',{method:'POST',body:b});let a=new Uint8Array(await r.arrayBuffer());return a.length===b.length&&a.every((v,i)=>v===b[i])})()")
            assert result['post_echo'] is True
            before_stop=[e for e in probe.events(log)[before:] if e.get('event')=='request']
            hook.stop()
            result['after_stop_existing']=await evaluate("fetch('/after-stop-existing',{cache:'no-store'}).then(r=>r.text())")
            after=[e for e in probe.events(log)[before:] if e.get('event')=='request' and 'after-stop-existing' in e.get('uri','')]
            assert after and after[-1]['connection_id']==before_stop[-1]['connection_id'], 'Existing h3 connection was interrupted'
            result['existing_connection_id']=after[-1]['connection_id']
            event_count=len(hook.events())
            # Explicitly close the test connection only after the existing-transfer assertion.
            close_path.touch(); await asyncio.sleep(.3); close_path.unlink()
            for n in range(4):
                await evaluate(f"fetch('/after-stop-new?i={n}',{{cache:'no-store'}}).then(r=>r.status).catch(e=>String(e))")
                await asyncio.sleep(.5)
            new_events=hook.events()[event_count:]
            result['after_stop_new_events']=new_events
            assert any(e['input']==0 and e['output']==-380 and not e['flags']&32 for e in new_events), 'New handshake after stop not exercised/rejected'
            assert not any(e.get('event')=='request' and 'after-stop-new' in e.get('uri','') for e in probe.events(log)[before:])
        result['hook_events']=hook.events()
        ev=probe.events(log)[before:]
        result['h3_requests']=[e for e in ev if e.get('event')=='request']
        result['tcp_requests']=sum(e.get('event')=='tcp_bootstrap' for e in ev)
        if mode=='enabled':
            assert len(result['h3_requests'])>=10
            assert any(e['input']==0 and e['output']==0 and e['flags']&32 for e in result['hook_events'])
        else:
            assert not result['h3_requests'], 'Negative case unexpectedly accepted HTTP/3'
            assert not any(e['flags']&32 for e in result['hook_events'])
            if mode=='bad-hash': assert hook.c.initialized==0 and hook.c.error==5
            else:
                assert result['hook_events'], 'Negative did not reach certificate verification'
                if mode=='other-trusted-ca':
                    assert any(e['input']==0 and e['output']==-380 and e['flags']&2 and not e['flags']&4 for e in result['hook_events'])
                elif mode in ('expired','wrong-host','same-name-untrusted-ca'):
                    assert all(e['input']!=0 and e['output']!=0 for e in result['hook_events'])
                else: assert any(e['input']==0 and e['output']==-380 for e in result['hook_events'])
        result['passed']=True
    finally:
        if hook:
            result['hook_events']=hook.events()
            hook.close()
        if cdp: cdp.ws.close()
        processes.stop(browser)
        if netlog.exists(): result['netlog']=netlog_evidence(netlog)
        (work/f'{name}-{mode}-result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(name,mode,'h3=',len(result.get('h3_requests',[])),'gate=',[(e['input'],e['output'],e['flags']) for e in result.get('hook_events',[])],flush=True)
    return result

async def main(case_runner=None, modes_override=None, prefix='quic-hook-'):
    probe.isolate()
    work=ROOT/'build/qa'/(prefix+uuid.uuid4().hex[:12]); work.mkdir(parents=True)
    pki=work/'pki'; pki.mkdir()
    shutil.copyfile(Path(os.environ['LOCALAPPDATA'])/'ProxyLane/ca.json',pki/'ca.json')
    print('WORK',work,flush=True)
    processes=probe.Processes(work); results={'work':str(work),'cases':[],'passed':False}; origin=None
    try:
        certificates=generate(work,pki/'ca.json')
        probe.origin_pki(work)
        origin_config=probe.QuicConfiguration(is_client=False,alpn_protocols=['h3'],supported_versions=[1])
        origin_config.load_cert_chain(str(work/'origin-cert.pem'),str(work/'origin-key.pem'))
        origin_port,relay_port=probe.port(),probe.port()
        origin_events=[]; results['origin_events']=origin_events
        origin=await probe.serve('127.0.0.1',origin_port,configuration=origin_config,
            create_protocol=lambda *a,**kw: probe.Peer(*a,origin=True,events=origin_events,**kw))
        processes.start('socks',[sys.executable,str(ROOT/'tests/e2e/socks5_udp_server.py'),
            '--port',str(relay_port),'--log',str(work/'relay.log')])
        for _ in range(100):
            if (work/'relay.log').exists() and 'LISTEN' in (work/'relay.log').read_text(): break
            await asyncio.sleep(.05)
        else: raise TimeoutError('SOCKS relay missing')
        modes=['enabled'] if '--smoke' in sys.argv else ['enabled','disabled','bad-hash','wrong-root',*certificates]
        if modes_override is not None: modes=modes_override
        if '--mode' in sys.argv: modes=[sys.argv[sys.argv.index('--mode')+1]]
        names=['chrome'] if '--smoke' in sys.argv else list(BROWSERS)
        if '--browser' in sys.argv: names=[sys.argv[sys.argv.index('--browser')+1]]
        for mode in modes:
            listen=probe.port(); close_path=work/(mode+'-close-connections')
            config=dict(role='mitm',listen=f'127.0.0.1:{listen}',ca_directory=str(pki),name=probe.NAME,
                ready=str(work/(mode+'-ready.json')),stop=str(work/(mode+'-stop')),close_connections=str(close_path),
                upstream=f'origin.quic.test:{origin_port}',upstream_ca=str(work/'origin-ca.der'))
            certificate_mode=mode.removeprefix('force-')
            if certificate_mode in certificates:
                config.update({k:v for k,v in certificates[certificate_mode].items() if k.startswith('quic_')})
            path=work/(mode+'-config.json'); path.write_text(json.dumps(config))
            server=processes.start('mitm-'+mode,[str(RUNTIME/'route-host.exe'),'SOCKS5',str(relay_port),
                subprocess.list2cmdline([str(RUNTIME/'quic-probe.exe'),str(path)])])
            metadata=await probe.wait_ready(Path(config['ready']),server)
            assert metadata['current_user_trust']
            for name in names:
                case=await (case_runner or browser_case)(work,processes,name,metadata,listen,work/('mitm-'+mode+'.log'),mode,close_path)
                case.update(browser=name,mode=mode,metadata=metadata)
                results['cases'].append(case)
                (work/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
            Path(config['stop']).touch()
            await asyncio.sleep(.4); processes.stop(server)
        if 'enabled' in modes and case_runner is None:
            assert 'DOMAIN:origin.quic.test' in (work/'relay.log').read_text()
            assert sum(e.get('method')=='POST' and e.get('bytes')==65536 for e in origin_events)==len(names)
        results['passed']=True
    except BaseException:
        import traceback
        results['error']=traceback.format_exc()
        raise
    finally:
        if origin: origin.close()
        processes.close(); (pki/'ca.json').unlink(missing_ok=True)
        (work/'origin-key.pem').unlink(missing_ok=True)
        for path in work.glob('*-key.der'): path.unlink()
        (work/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
        print('RESULT',work/'results.json',flush=True)
    return results

if __name__=='__main__': asyncio.run(main())
