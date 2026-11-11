"""Isolated-browser transport comparison. No user profiles or CA changes."""
import asyncio
import json
import os
from pathlib import Path
import sys
import time
import quic_mitm_probe as probe
from quic_live_route_probe import Host, RUNTIME
from quic_hook_probe import BROWSERS, adopt_browser
from quic_hook_control import network_process
from quic_ssl_policy_probe import CDP, attach

class EvidenceCDP(CDP):
    def call(self, method, params=None):
        deadline = time.monotonic() + 30
        self.serial += 1
        self.ws.send(json.dumps(dict(id=self.serial, method=method, params=params or {})))
        while True:
            if time.monotonic() > deadline: raise TimeoutError(method)
            message = json.loads(self.ws.recv())
            if message.get('method', '').startswith('Network.'):
                self.events.append(message)
            if message.get('id') == self.serial:
                assert 'error' not in message, message
                return message.get('result', {})

async def run():
    probe.isolate()
    work = RUNTIME / ('web-reliability-' + time.strftime('%Y%m%d-%H%M%S'))
    work.mkdir()
    results = []
    processes = probe.Processes(work)
    try:
        for mode in sys.argv[1:] or ['off', 'raw', 'https', 'quic', 'both']:
            host = Host(work, mode)
            browser = cdp = None
            try:
                host.call(type='test_tcp_policy', enabled=True)
                host.call(type='quic_injection_policy', enabled=mode in ('quic', 'both'))
                # Test-host only: isolate forwarding from external PKI/AIA differences.
                if os.environ.get('TEST_SKIP_UPSTREAM') == '1':
                    host.call(type='mitm_options', skip_upstream_verify=True)
                if mode != 'off':
                    host.call(type='monitor_start', decrypt=mode in ('https', 'both'), quic=mode in ('quic', 'both'))
                debug = probe.port()
                profile = work / (mode+'-profile')
                browser = processes.start(mode, [str(BROWSERS['edge']), '--headless=new', '--no-first-run',
                    '--no-default-browser-check', '--disable-background-networking', '--disable-component-update',
                    '--no-proxy-server', '--user-data-dir='+str(profile), '--remote-debugging-port='+str(debug), 'about:blank'])
                cdp = await attach(debug)
                cdp.__class__ = EvidenceCDP
                cdp.events = []
                cdp.call('Network.enable')
                cdp.call('Network.setCacheDisabled', {'cacheDisabled':True})
                await asyncio.sleep(.5)
                browser = adopt_browser(browser, profile, processes)
                pid = network_process(browser)
                assert host.call(type='attach', pid=pid)['result'] == 0xff01
                await asyncio.sleep(.5)
                for url in ['https://www.msn.com/ja-jp', 'https://github.com/']:
                    cdp.events = []
                    await asyncio.to_thread(cdp.call, 'Runtime.evaluate', {'expression':'location.href='+json.dumps(url)})
                    await asyncio.sleep(18)
                    dom = await asyncio.to_thread(cdp.call, 'Runtime.evaluate', {'expression':
                        'JSON.stringify({title:document.title,text:document.body?.innerText.length,html:document.documentElement.outerHTML.length,state:document.readyState})', 'returnByValue':True})
                    requests = {e['params']['requestId']:e['params']['request']['url'] for e in cdp.events if e['method']=='Network.requestWillBeSent'}
                    failed = [dict(url=requests.get(e['params']['requestId']), **e['params']) for e in cdp.events if e['method']=='Network.loadingFailed']
                    responses = [e['params']['response'] for e in cdp.events if e['method']=='Network.responseReceived']
                    result = dict(mode=mode,url=url,dom=dom,failed=failed,responses=responses,events=cdp.events)
                    results.append(result)
                    (work/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
                    print(mode,url,dom.get('result',{}).get('value'), 'failures',len(failed),
                        [(x['url'],x['errorText']) for x in failed[:4]], flush=True)
                if mode != 'off':
                    (work/(mode+'-capture.json')).write_text(json.dumps(host.call(type='poll',limit=512),indent=2),encoding='utf-8')
            finally:
                if cdp: cdp.ws.close()
                if browser: processes.stop(browser)
                host.close()
    finally:
        processes.close()
    print('Evidence:',work,flush=True)

if __name__ == '__main__': asyncio.run(run())
