"""Compare force-QUIC launch switches against a trusted TCP-only HTTPS origin."""
import asyncio
import json
import os
from pathlib import Path
import uuid
import quic_mitm_probe as probe
from quic_hook_probe import ROOT, BROWSERS, adopt_browser
from quic_late_hook_probe import SlowHTTPS
from quic_ssl_policy_probe import attach, netlog_evidence

async def main():
    probe.isolate()
    work=ROOT/'build/qa'/('quic-launch-flags-'+uuid.uuid4().hex[:12]);work.mkdir(parents=True)
    processes=probe.Processes(work);slow=SlowHTTPS(work,Path(os.environ['LOCALAPPDATA'])/'ProxyLane')
    results={'passed':False,'cases':[]};await slow.start();print('WORK',work,flush=True)
    try:
        for name,exe in BROWSERS.items():
            for mode in ('normal','force-origin','force-wildcard'):
                debug=probe.port();profile=work/f'{name}-{mode}';netlog=work/f'{name}-{mode}-netlog.json'
                args=[str(exe),'--headless=new','--no-first-run','--no-default-browser-check',
                      '--disable-background-networking','--disable-component-update','--no-proxy-server',
                      f'--user-data-dir={profile}',f'--remote-debugging-port={debug}',
                      '--host-resolver-rules=MAP quic-probe.test 127.0.0.1',f'--log-net-log={netlog}']
                if mode!='normal':args.append('--origin-to-force-quic-on='+('*' if mode=='force-wildcard' else f'{probe.NAME}:{slow.port}'))
                args.append('about:blank');browser=processes.start(f'{name}-{mode}',args);cdp=None
                row={'browser':name,'mode':mode,'url':f'https://{probe.NAME}:{slow.port}/{name}-{mode}'}
                try:
                    cdp=await attach(debug);await asyncio.sleep(.5);browser=adopt_browser(browser,profile,processes)
                    try:row['navigation']=await asyncio.to_thread(cdp.call,'Page.navigate',{'url':row['url']})
                    except TimeoutError:row['navigation_timeout_seconds']=8
                    await asyncio.sleep(1)
                    row['title']=await asyncio.to_thread(cdp.evaluate,'document.title')
                    row['tcp_requests']=[e for e in slow.events if e.get('path')==f'/{name}-{mode}']
                finally:
                    if cdp:cdp.ws.close()
                    processes.stop(browser)
                    row['netlog']=netlog_evidence(netlog)
                    results['cases'].append(row)
                if mode=='normal':assert row['tcp_requests'] and row['title']=='Existing HTTPS traffic'
                else:assert not row['tcp_requests'] and row['netlog']['target_quic_sources']
                row['passed']=True;print(name,mode,'TCP requests',len(row['tcp_requests']),row.get('navigation'),flush=True)
        results['passed']=True
    finally:
        processes.close();await slow.close()
        (work/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8');print('RESULT',work/'results.json',flush=True)

if __name__=='__main__':asyncio.run(main())
