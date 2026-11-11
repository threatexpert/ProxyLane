"""Single QUIC policy Hook and launch-argument comparison; no shipping UI changes.

The isolated options.json demonstrates the independent, default-off switch and
approved description. No CA installation, user profile or bin changes.
"""
import asyncio
import json
from pathlib import Path
import sys
import quic_mitm_probe as probe
from quic_hook_probe import main as matrix, BROWSERS, RUNTIME, adopt_browser
from quic_ssl_policy_probe import attach, netlog_evidence
from quic_policy_hook_control import Hook, LABEL, DESCRIPTION

MODES=['disabled','enabled','other-trusted-ca','same-name-untrusted-ca','expired','wrong-host','bad-hash','bad-code',
       'force-enabled','force-other-trusted-ca','force-same-name-untrusted-ca','force-expired','force-wrong-host']

async def evaluate(cdp,expression):
    r=await asyncio.to_thread(cdp.call,'Runtime.evaluate',{'expression':expression,'returnByValue':True,'awaitPromise':True})
    assert 'exceptionDetails' not in r,r
    return r['result'].get('value')

def cert_errors(path):
    text=path.read_text(errors='replace')
    try:d=json.loads(text)
    except ValueError:d=json.loads(text.rstrip().rstrip(',')+']}')
    names={v:k for k,v in d['constants']['logEventTypes'].items()}
    # Only certificate verifier jobs for our fixture hostname.
    ids={e['source']['id'] for e in d['events'] if 'CERT_VERIFIER' in names.get(e['type'],'')
         and e.get('params',{}).get('host')==probe.NAME}
    return [e['params'] for e in d['events'] if e['source']['id'] in ids and 'net_error' in e.get('params',{})]

async def browser_case(work,processes,name,metadata,listen,log,mode,close_path):
    debug=probe.port();hook=None;cdp=None;result={'passed':False};netlog=work/f'{name}-{mode}-netlog.json'
    force=mode.startswith('force-');certmode=mode.removeprefix('force-')
    launch_only=force or mode=='webtransport'
    positive=certmode in ('enabled','other-trusted-ca')
    options={'quic_decryption':False,'label':LABEL,'description':DESCRIPTION}
    options_path=work/f'{name}-{mode}-options.json';options_path.write_text(json.dumps(options,ensure_ascii=False,indent=2),encoding='utf-8')
    args=[str(BROWSERS[name]),'--headless=new','--no-first-run','--no-default-browser-check',
          '--disable-background-networking','--disable-component-update','--no-proxy-server',
          f'--user-data-dir={work/name/mode}',f'--remote-debugging-port={debug}',
          '--host-resolver-rules=MAP quic-probe.test 127.0.0.1',f'--log-net-log={netlog}']
    if force:args.append(f'--origin-to-force-quic-on={probe.NAME}:{listen}')
    if mode=='webtransport':args.append('--webtransport-developer-mode')
    args.append('about:blank')
    assert not any('ignore-certificate' in a or 'no-sandbox' in a for a in args)
    browser=processes.start(f'{name}-{mode}',args);before=len(probe.events(log))
    try:
        cdp=await attach(debug);await asyncio.sleep(.5)
        browser=adopt_browser(browser,work/name/mode,processes)
        if not launch_only:
            hook=await asyncio.to_thread(Hook,browser,RUNTIME/'browser-quic-policy-probe.dll',
                                        bad_hash=mode=='bad-hash',bad_code=mode=='bad-code')
            assert hook.c.enabled==0
            result.update(module=hook.module,descriptor=hook.descriptor,init_error=hook.c.error,default_off=True)
            if mode not in ('disabled','bad-hash','bad-code'):
                options['quic_decryption']=True
                options_path.write_text(json.dumps(options,ensure_ascii=False,indent=2),encoding='utf-8')
                hook.set_enabled(options['quic_decryption'])
        await asyncio.to_thread(cdp.call,'Page.navigate',{'url':f'https://quic-probe.test:{listen}/'})
        if force and positive:
            # Forced QUIC skips our TCP bootstrap HTML, so drive requests here.
            for n in range(4):
                await evaluate(cdp,f"fetch('/forced-probe?i={n}',{{cache:'no-store'}}).then(r=>r.text())")
        await asyncio.sleep(10)
        result['title']=await evaluate(cdp,'document.title')
        if positive:
            assert len([e for e in probe.events(log)[before:] if e.get('event')=='request'])>=4,'No h3'
            result['post_echo']=await evaluate(cdp,"(async()=>{let b=new Uint8Array(65536);for(let i=0;i<b.length;i++)b[i]=i%251;let r=await fetch('/single-hook-binary',{method:'POST',body:b});let a=new Uint8Array(await r.arrayBuffer());return a.length===b.length&&a.every((v,i)=>v===b[i])})()")
            assert result['post_echo'] is True
            if hook:
                events=hook.events()
                assert any(e['allowed'] and e['enabled'] and e['caller_matched'] and not e['original'] for e in events)
                previous=[e for e in probe.events(log)[before:] if e.get('event')=='request'][-1]['connection_id']
                hook.set_enabled(False)
                await evaluate(cdp,"fetch('/after-stop-existing',{cache:'no-store'}).then(r=>r.text())")
                after=[e for e in probe.events(log)[before:] if e.get('event')=='request' and 'after-stop-existing' in e.get('uri','')]
                assert after and after[-1]['connection_id']==previous
                result['existing_after_stop']=True
                count=len(hook.events());close_path.touch();await asyncio.sleep(.3);close_path.unlink()
                for n in range(4):
                    await evaluate(cdp,f"fetch('/after-stop-new?i={n}',{{cache:'no-store'}}).then(r=>r.status).catch(e=>String(e))")
                    await asyncio.sleep(.5)
                later=hook.events()[count:]
                assert any(e['caller_matched'] and not e['allowed'] and not e['enabled'] for e in later),later
                assert not any(e.get('event')=='request' and 'after-stop-new' in e.get('uri','') for e in probe.events(log)[before:])
                result['new_after_stop_rejected']=True
        requests=[e for e in probe.events(log)[before:] if e.get('event')=='request']
        result['h3_requests']=requests
        if not positive:assert not requests,'Negative case reached HTTP/3'
        if hook:
            if mode=='bad-hash':assert hook.c.initialized==0 and hook.c.error==5
            elif mode=='bad-code':assert hook.c.initialized==0 and hook.c.error==7
            elif mode=='disabled':assert any(not e['enabled'] and not e['allowed'] and e['caller_matched'] for e in hook.events())
        result['passed']=True
    except BaseException:
        import traceback
        result['error']=traceback.format_exc()
        raise
    finally:
        if hook:result['hook_events']=hook.events();hook.close()
        if cdp:cdp.ws.close()
        processes.stop(browser)
        if netlog.exists():
            result['netlog']=netlog_evidence(netlog)
            result['certificate_errors']=cert_errors(netlog)
        if result['passed'] and certmode in ('same-name-untrusted-ca','expired','wrong-host'):
            expected={'same-name-untrusted-ca':-202,'expired':-201,'wrong-host':-200}[certmode]
            if not any(e.get('net_error')==expected for e in result.get('certificate_errors',[])):
                result['passed']=False;result['error']=f'Expected certificate error {expected} missing'
        if result['passed'] and mode=='webtransport':
            errors=result.get('netlog',{}).get('quic_proof_errors',[])
            if not any('CERTIFICATE_VERIFY_FAILED' in e.get('details','') for e in errors):
                result['passed']=False;result['error']='Ordinary HTTP/3 certificate rejection not observed'
        (work/f'{name}-{mode}-result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    assert result['passed'],result.get('error')
    print(name,mode,'PASS h3=',len(result['h3_requests']),flush=True)
    return result

async def main():
    modes=['enabled'] if '--smoke' in sys.argv else MODES
    results=await matrix(browser_case,modes,'quic-single-hook-')
    positive=[c for c in results['cases'] if c['mode'].removeprefix('force-') in ('enabled','other-trusted-ca')]
    assert all(c.get('post_echo') for c in positive)
    assert sum(e.get('method')=='POST' and e.get('bytes')==65536 for e in results['origin_events'])==len(positive)

if __name__=='__main__':asyncio.run(main())
