"""Isolated Chromium ECH retry evidence through shipping PRC/Hook/MITM.
No system/browser trust changes, certificate bypass or personal profiles.
"""
import asyncio,json,time,os
from pathlib import Path
import quic_mitm_probe as probe
from quic_live_route_probe import Host,RUNTIME
from quic_hook_probe import BROWSERS,adopt_browser
from quic_hook_control import network_process
from quic_ssl_policy_probe import attach

async def run():
    probe.isolate()
    work=RUNTIME/('ech-recording-'+time.strftime('%Y%m%d-%H%M%S'));work.mkdir()
    processes=probe.Processes(work);results=[]
    try:
        for name in ['chrome','edge']:
            host=Host(work,name);browser=cdp=None
            try:
                settings=host.call(type='mitm_options')['settings']
                settings['recording']={'enabled':True,'directory':str(work/'recordings'),'capacity_mib':512,'reserve_mib':16}
                host.call(type='mitm_options',settings=settings,skip_upstream_verify=False)
                host.call(type='test_tcp_policy',enabled=True)
                host.call(type='monitor_start',decrypt=True,quic=False)
                debug=probe.port();profile=work/(name+'-profile');profile.mkdir()
                # An isolated preference makes DNS HTTPS/ECH discovery repeatable.
                (profile/'Local State').write_text(json.dumps({'dns_over_https':{'mode':'secure','templates':'https://cloudflare-dns.com/dns-query'}}))
                browser=processes.start(name,[str(BROWSERS[name]),'--headless=new','--no-first-run',
                    '--no-default-browser-check','--disable-background-networking','--disable-component-update',
                    '--disable-quic','--no-proxy-server','--user-data-dir='+str(profile),
                    '--remote-debugging-port='+str(debug),'--log-net-log='+str(work/(name+'-netlog.json')),'about:blank'])
                cdp=await attach(debug)
                cdp.ws.settimeout(30)
                await asyncio.sleep(.5);browser=adopt_browser(browser,profile,processes)
                pid=network_process(browser);assert host.call(type='attach',pid=pid)['result']==0xff01
                await asyncio.sleep(.5)
                for domain in ['ifconfig.io','linux.do']:
                    await asyncio.to_thread(cdp.call,'Runtime.evaluate',{'expression':'location.href='+json.dumps('https://'+domain+'/')})
                    await asyncio.sleep(10)
                    dom=await asyncio.to_thread(cdp.call,'Runtime.evaluate',{'expression':'JSON.stringify({url:location.href,title:document.title,state:document.readyState,body:document.body?.innerText.length})','returnByValue':True})
                    results.append({'browser':name,'domain':domain,'dom':dom})
                await asyncio.to_thread(host.call,type='monitor_stop')
                archive=Path(host.call(type='recording_status')['directory'])
                connections=[json.loads(p.read_text('utf8')) for p in (archive/'connections').glob('*.json')]
                ech=[v for v in connections if 'ECH negotiation rejected' in v.get('detail','')]
                exchanges=[]
                for p in (archive/'payload').rglob('*.json'):
                    if p.name.endswith('.cache.json'):continue
                    v=json.loads(p.read_text('utf8'))
                    if v.get('type')=='exchange':exchanges.append(v)
                # Avoid retaining tokens/headers in the concise evidence summary.
                evidence={'browser':name,'archive':str(archive),'ech':[
                    {'id':v['connection']['id'],'status':v['status'],'host':v['connection']['server_name']} for v in ech],
                    'responses':[{'host':v['connection']['server_name'],'status':(v['exchange'].get('response') or {}).get('status'),
                        'complete':(v['exchange'].get('response') or {}).get('complete')} for v in exchanges]}
                results.append(evidence);print(json.dumps(evidence),flush=True)
                assert ech,'ECH was not exercised; inspect isolated DNS/netlog before claiming coverage'
                assert all(v['status']=='Closed' for v in ech)
                assert any(v['connection']['server_name']=='ifconfig.io' and (v['exchange'].get('response') or {}).get('complete') for v in exchanges)
            finally:
                if cdp:cdp.ws.close()
                if browser:processes.stop(browser)
                host.close()
                (work/'results.json').write_text(json.dumps(results,indent=2),encoding='utf8')
    finally:processes.close();print('Evidence:',work,flush=True)

if __name__=='__main__':asyncio.run(run())
